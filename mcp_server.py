from __future__ import annotations

import argparse
import http.client
import io
import json
import math
import re
import sqlite3
import sys
import time
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any, Callable, Literal

from mcp.server.fastmcp import FastMCP, Image

from database import TABLE_DESCRIPTIONS, NetTraceDB, readonly_connection

mcp = FastMCP("snagbox")
_db_path = Path("./data/nettrace.sqlite").resolve()
_ghost_api: tuple[str, int, str] | None = None
_snagbox_node_id: str | None = None
_upstream_http_proxy: dict[str, str] = {"proxy_url": "", "username": "", "password": ""}
_proxy_settings_setter: Callable[[dict[str, str]], dict[str, Any]] | None = None
_https_inspection_controller: Callable[[str], dict[str, Any]] | None = None
MAX_ROWS = 500
DEFAULT_ROWS = 100
MAX_RESPONSE_CHARS = 80_000
MAX_QUERY_SECONDS = 5.0
MAX_GHOST_RESPONSE_BYTES = 512 * 1024
MAX_GHOST_PROCESS_STATS_BYTES = 4 * 1024 * 1024


def configure_ghost_bridge(api_base: str, token: str, proxy_port: int) -> dict[str, Any]:
    """Bind the plugin token and configure the generic Ghost upstream API."""
    global _ghost_api, _snagbox_node_id
    parsed = urlsplit(api_base)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "http" or host not in ("127.0.0.1", "localhost") or not parsed.port:
        raise ValueError("Ghost apiBase must be an HTTP loopback URL")
    if not token or len(token) > 1024 or not 1 <= int(proxy_port) <= 65535:
        raise ValueError("Invalid Ghost plugin handshake")
    _ghost_api = (host, parsed.port, token)
    _snagbox_node_id = None
    result = _ensure_snagbox_upstream(int(proxy_port))
    if result.get("status") != "ok" or not result.get("nodeId"):
        _ghost_api = None
        raise RuntimeError(f"Ghost could not configure the snagbox upstream: {result}")
    _snagbox_node_id = str(result["nodeId"])
    return result


def normalize_upstream_http_proxy(proxy_url: str, username: str = "", password: str = "") -> dict[str, str]:
    """Validate and normalize an optional HTTP proxy used as mitmproxy's upstream."""
    if not all(isinstance(value, str) for value in (proxy_url, username, password)):
        raise ValueError("proxy_url, username, and password must be strings")
    proxy_url = proxy_url.strip()
    username = username.strip()
    if not proxy_url:
        if username or password:
            raise ValueError("username and password require proxy_url")
        return {"proxy_url": "", "username": "", "password": ""}
    try:
        parsed = urlsplit(proxy_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("proxy_url must be http://host:port") from exc
    if (parsed.scheme.lower() != "http" or not parsed.hostname or port is None
            or not 1 <= port <= 65535 or parsed.username is not None
            or parsed.password is not None or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise ValueError("proxy_url must be http://host:port without credentials, path, query, or fragment")
    if bool(username) != bool(password) or ":" in username or any(ord(ch) < 32 for ch in username + password):
        raise ValueError("provide both username and password; username cannot contain ':'")
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    return {"proxy_url": f"http://{host}:{port}", "username": username, "password": password}


def load_upstream_http_proxy(data_dir: Path) -> dict[str, str]:
    """Load the optional local proxy-chain configuration; malformed config fails closed."""
    path = data_dir / "upstream_http_proxy.json"
    if not path.exists():
        return normalize_upstream_http_proxy("")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("configuration must be an object")
        return normalize_upstream_http_proxy(
            value.get("proxy_url", ""), value.get("username", ""), value.get("password", "")
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"invalid upstream HTTP proxy configuration: {exc}") from exc


def configure_proxy_settings(
    settings: dict[str, str], setter: Callable[[dict[str, str]], dict[str, Any]]
) -> None:
    global _upstream_http_proxy, _proxy_settings_setter
    _upstream_http_proxy = dict(settings)
    _proxy_settings_setter = setter


def configure_https_inspection(controller: Callable[[str], dict[str, Any]]) -> None:
    global _https_inspection_controller
    _https_inspection_controller = controller


def _control_https_inspection(action: str) -> dict[str, Any]:
    if _https_inspection_controller is None:
        return {"status": "error", "error": "https_inspection_control_unavailable"}
    return _https_inspection_controller(action)


@mcp.tool()
def get_https_inspection_status() -> dict[str, Any]:
    """Show whether Snagbox's root CA is trusted and synchronize HTTPS interception accordingly."""
    return _control_https_inspection("status")


@mcp.tool()
def install_https_root_certificate() -> dict[str, Any]:
    """Install Snagbox's mitmproxy CA in the current user's Windows Root store and enable HTTPS inspection."""
    return _control_https_inspection("install")


@mcp.tool()
def uninstall_https_root_certificate() -> dict[str, Any]:
    """Remove only Snagbox's mitmproxy CA from the current user's Windows Root store and disable HTTPS inspection."""
    return _control_https_inspection("uninstall")


@mcp.tool()
def get_upstream_http_proxy() -> dict[str, Any]:
    """Show the HTTP proxy chained after Snagbox. Credentials are never returned."""
    return {
        "status": "ok",
        "enabled": bool(_upstream_http_proxy["proxy_url"]),
        "proxy_url": _upstream_http_proxy["proxy_url"] or None,
        "authenticated": bool(_upstream_http_proxy["username"]),
    }


@mcp.tool()
def set_upstream_http_proxy(proxy_url: str = "", username: str = "", password: str = "") -> dict[str, Any]:
    """Set or clear the HTTP proxy Snagbox uses for outbound traffic; blank proxy_url clears it."""
    global _upstream_http_proxy
    try:
        settings = normalize_upstream_http_proxy(proxy_url, username, password)
    except ValueError as exc:
        return {"status": "error", "error": "invalid_upstream_http_proxy", "detail": str(exc)}
    if _proxy_settings_setter is None:
        return {"status": "error", "error": "proxy_control_unavailable"}
    result = _proxy_settings_setter(settings)
    if result.get("status") != "ok":
        return result
    _upstream_http_proxy = settings
    return {
        "status": "ok",
        "enabled": bool(settings["proxy_url"]),
        "proxy_url": settings["proxy_url"] or None,
        "authenticated": bool(settings["username"]),
        "existing_connections_may_need_reconnect": True,
    }


def _ghost_request(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    max_response_bytes: int = MAX_GHOST_RESPONSE_BYTES,
) -> dict[str, Any]:
    if _ghost_api is None:
        return {"status": "error", "error": "ghost_bridge_unavailable"}
    host, port, token = _ghost_api
    conn = http.client.HTTPConnection(host, port, timeout=4.0)
    try:
        payload = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {"X-Ghost-Plugin-Token": token, "Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        raw = response.read(max_response_bytes + 1)
        if len(raw) > max_response_bytes:
            return {
                "status": "error",
                "error": "ghost_response_too_large",
                "http_status": response.status,
                "limit_bytes": max_response_bytes,
            }
        if response.status < 200 or response.status >= 300:
            try:
                error = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                error = {"error": "ghost_api_error"}
            return {"status": "error", "http_status": response.status, **error}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return {
                "status": "error", "error": "invalid_ghost_response",
                "http_status": response.status,
                "content_type": response.getheader("Content-Type"),
                "bytes_read": len(raw),
            }
        return parsed if isinstance(parsed, dict) else {
            "status": "error", "error": "invalid_ghost_response",
            "http_status": response.status,
            "json_type": type(parsed).__name__,
        }
    except (OSError, http.client.HTTPException) as exc:
        return {"status": "error", "error": "ghost_api_unavailable", "detail": str(exc)[:500]}
    finally:
        conn.close()


def ghost_log(message: str, level: str = "info", fields: dict[str, Any] | None = None) -> None:
    """Ingest plugin execution logs into Ghost Proxifier system log."""
    if _ghost_api is None:
        return
    try:
        payload: dict[str, Any] = {"level": level, "message": message}
        if fields:
            payload["fields"] = fields
        _ghost_request("POST", "/api/plugin/v1/log/ingest", payload)
    except Exception:
        pass


def ghost_toast(title: str, message: str, level: str = "info") -> None:
    """Send a safe plain-text toast notification to Ghost Proxifier host UI."""
    if _ghost_api is None:
        return
    try:
        _ghost_request("POST", "/api/plugin/v1/ui/toast", {
            "title": title,
            "message": message,
            "level": level,
        })
    except Exception:
        pass


def _ensure_snagbox_upstream(proxy_port: int) -> dict[str, Any]:
    """Ensure a dedicated snagbox upstream node exists via ghost.upstream.v1 API."""
    list_res = _ghost_request("GET", "/api/plugin/v1/upstream/list")
    if list_res.get("status") == "error":
        return {"status": "error", "error": list_res.get("error", "upstream_list_failed")}

    nodes = list_res.get("nodes", []) if isinstance(list_res.get("nodes"), list) else []
    target_node = None
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("name") == "snagbox":
            host = node.get("host")
            port = node.get("port")
            if host in ("127.0.0.1", "localhost") and port == proxy_port and str(node.get("type", "")).lower() == "http":
                target_node = node
                break
            else:
                old_id = node.get("id")
                if old_id:
                    _ghost_request("POST", "/api/plugin/v1/upstream/delete", {"nodeId": old_id})

    if target_node and target_node.get("id"):
        return {"status": "ok", "nodeId": target_node["id"], "reused": True}

    create_res = _ghost_request("POST", "/api/plugin/v1/upstream/create", {
        "name": "snagbox",
        "type": "http",
        "host": "127.0.0.1",
        "port": proxy_port,
    })
    if create_res.get("status") != "ok" or not create_res.get("nodeId"):
        return {"status": "error", "error": create_res.get("error", "upstream_create_failed"), "detail": create_res}

    return {"status": "ok", "nodeId": create_res["nodeId"], "reused": False}


def _list_snagbox_targets() -> dict[str, Any]:
    """List plugin-owned targets from Ghost Target API."""
    if not _snagbox_node_id:
        return {"error": "snagbox_upstream_unavailable"}
    res = _ghost_request("GET", "/api/plugin/v1/targets/list")
    if res.get("status") != "ok" or not isinstance(res.get("targets"), list):
        return {"error": res.get("error", "targets_list_failed"), "detail": res.get("detail")}
    targets = [
        t for t in res.get("targets", [])
        if isinstance(t, dict) and (not _snagbox_node_id or t.get("proxyNodeId") == _snagbox_node_id)
    ]
    return {"status": "ok", "nodeId": _snagbox_node_id, "targets": targets}


@mcp.tool()
def list_snagbox_processes() -> dict[str, Any]:
    """List Ghost targets currently configured or running under snagbox upstream."""
    return _list_snagbox_targets()


@mcp.tool()
def start_snagbox_program(target_path: str, arguments: str = "") -> dict[str, Any]:
    """Launch or resume a program routed through snagbox via Ghost Target API."""
    if not isinstance(target_path, str) or not target_path.strip() or not isinstance(arguments, str):
        return {"error": "invalid_arguments"}
    if not _snagbox_node_id:
        return {"error": "snagbox_upstream_unavailable"}
    path = Path(target_path.strip()).expanduser()
    if not path.is_absolute():
        return {"error": "target_path_must_be_absolute", "target_path": target_path}
    if not path.is_file():
        return {"error": "target_executable_not_found", "target_path": str(path)}
    target_abs = str(path.resolve())

    list_res = _ghost_request("GET", "/api/plugin/v1/targets/list")
    if list_res.get("status") != "ok" or not isinstance(list_res.get("targets"), list):
        return {"error": list_res.get("error", "targets_list_failed"), "detail": list_res.get("detail")}

    target_name = path.name
    existing = None
    for t in list_res["targets"]:
        if not isinstance(t, dict):
            continue
        env_exe = t.get("env", {}).get("SNAGBOX_EXE_PATH") if isinstance(t.get("env"), dict) else None
        if env_exe and Path(env_exe).resolve() == Path(target_abs).resolve():
            existing = t
            break
        if str(t.get("name", "")).casefold() in (target_name.casefold(), target_abs.casefold()):
            existing = t
            break

    args_list = arguments.split() if arguments.strip() else []

    if existing is not None:
        target_id = existing.get("targetId")
        if not target_id:
            return {"error": "target_missing_id"}

        if existing.get("proxyNodeId") != _snagbox_node_id or str(existing.get("dnsMode", "")).casefold() != "dot":
            _ghost_request("POST", "/api/plugin/v1/targets/update", {
                "targetId": target_id,
                "proxyNodeId": _snagbox_node_id,
                "dnsMode": "dot",
            })

        if existing.get("status") == "running":
            return {
                "status": "ok",
                "nodeId": _snagbox_node_id,
                "path": target_abs,
                "targetId": target_id,
                "reusedTargetGroup": True,
                "alreadyRunning": True,
                "startedNewProcess": False,
                "dnsMode": "dot",
                "pid": existing.get("pid"),
            }

        launch_res = _ghost_request("POST", "/api/plugin/v1/targets/launch", {"targetId": target_id})
        if launch_res.get("status") != "ok":
            return {
                "error": launch_res.get("error", "launch_failed"),
                "detail": launch_res.get("detail"),
                "targetId": target_id,
            }

        ghost_toast("进程已启动", f"已成功启动 {target_name} 并接入流量采集。")
        ghost_log(f"Launched target {target_name} (ID: {target_id}) routed via snagbox.")
        return {
            "status": "ok",
            "nodeId": _snagbox_node_id,
            "path": target_abs,
            "targetId": target_id,
            "reusedTargetGroup": True,
            "alreadyRunning": False,
            "startedNewProcess": True,
            "dnsMode": "dot",
            "ghost": launch_res,
        }

    create_res = _ghost_request("POST", "/api/plugin/v1/targets/create", {
        "name": target_name,
        "exePath": target_abs,
        "args": args_list,
        "proxyNodeId": _snagbox_node_id,
        "dnsMode": "dot",
        "env": {
            "SNAGBOX_MANAGED": "1",
            "SNAGBOX_EXE_PATH": target_abs,
        },
    })
    if create_res.get("status") != "ok" or not create_res.get("targetId"):
        return {
            "error": create_res.get("error", "target_create_failed"),
            "detail": create_res.get("detail"),
        }

    target_id = create_res["targetId"]
    launch_res = _ghost_request("POST", "/api/plugin/v1/targets/launch", {"targetId": target_id})
    if launch_res.get("status") != "ok":
        return {
            "error": launch_res.get("error", "launch_failed"),
            "detail": launch_res.get("detail"),
            "targetId": target_id,
        }

    ghost_toast("进程已创建并启动", f"已成功创建并启动 {target_name}。")
    ghost_log(f"Created and launched new target {target_name} (ID: {target_id}) routed via snagbox.")
    return {
        "status": "ok",
        "nodeId": _snagbox_node_id,
        "path": target_abs,
        "targetId": target_id,
        "startedNewProcess": True,
        "reusedTargetGroup": False,
        "dnsMode": "dot",
        "ghost": launch_res,
    }


@mcp.tool()
def stop_snagbox_program(process_name: str) -> dict[str, Any]:
    """Stop matching targets only inside snagbox-managed targets."""
    if not isinstance(process_name, str) or not process_name.strip():
        return {"error": "process_name_required"}
    query = Path(process_name.strip()).name.casefold()
    raw_query = process_name.strip().casefold()

    list_res = _ghost_request("GET", "/api/plugin/v1/targets/list")
    if list_res.get("status") != "ok" or not isinstance(list_res.get("targets"), list):
        return {"error": list_res.get("error", "targets_list_failed")}

    matched_targets = []
    for t in list_res["targets"]:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("targetId", "")).casefold()
        tname = str(t.get("name", "")).casefold()
        tfile = Path(str(t.get("name", ""))).name.casefold()
        env_exe = ""
        if isinstance(t.get("env"), dict):
            env_exe = Path(str(t["env"].get("SNAGBOX_EXE_PATH", ""))).name.casefold()

        if query in (tid, tname, tfile, env_exe) or raw_query in (tid, tname):
            matched_targets.append(t)

    stopped_ids: list[str] = []
    errors: list[dict[str, Any]] = []

    for t in matched_targets:
        tid = t.get("targetId")
        if not tid:
            continue
        stop_res = _ghost_request("POST", "/api/plugin/v1/targets/stop", {"targetId": tid})
        if stop_res.get("status") == "ok":
            stopped_ids.append(tid)
        else:
            errors.append({"targetId": tid, "error": stop_res.get("error", "target_stop_failed")})

    if stopped_ids:
        ghost_toast("进程已停止", f"已停止 {len(stopped_ids)} 个 snagbox 目标。")
        ghost_log(f"Stopped {len(stopped_ids)} target(s): {', '.join(stopped_ids)}.")

    return {
        "status": "ok" if not errors else "partial",
        "processName": query,
        "matched": len(matched_targets),
        "stoppedTargetIds": stopped_ids,
        "errors": errors,
    }


def _open() -> sqlite3.Connection:
    return readonly_connection(_db_path)


def _open_control() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path, timeout=10.0)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def _change_capture_state(state: str) -> dict[str, Any]:
    conn = _open_control()
    try:
        previous = conn.execute(
            "SELECT state FROM capture_control WHERE singleton_id=1"
        ).fetchone()
        if previous is None:
            return {"error": "capture_control_not_initialized"}
        conn.execute(
            "UPDATE capture_control SET state=?, updated_at=strftime('%s','now') WHERE singleton_id=1",
            (state,),
        )
        conn.commit()
        return {"state": state, "previous_state": previous[0]}
    except sqlite3.Error as exc:
        conn.rollback()
        return {"error": "sqlite_error", "detail": str(exc)[:1000]}
    finally:
        conn.close()


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {
            "type": "blob",
            "length": len(value),
            "hex_preview": value[:256].hex(),
            "preview_truncated": len(value) > 256,
        }
    return value


@mcp.tool()
def list_event_tables() -> dict[str, Any]:
    """List the available snagbox event tables, their descriptions, and row counts."""
    conn = _open()
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
            "AND name != 'capture_control' ORDER BY name"
        ).fetchall()
        tables = []
        for row in rows:
            name = row[0]
            count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
            tables.append({"name": name, "description": TABLE_DESCRIPTIONS.get(name, ""), "row_count": count})
        return {"database": str(_db_path), "tables": tables}
    finally:
        conn.close()


@mcp.tool()
def get_data_relationships() -> str:
    """Read the relationship guide before analyzing across Snagbox event tables."""
    guide_path = Path(__file__).with_name("DATA_RELATIONSHIPS.md")
    try:
        return guide_path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"Could not read the Snagbox data relationship guide: {exc}"


@mcp.tool()
def describe_event_table(table_name: str) -> dict[str, Any]:
    """Describe table columns; use get_data_relationships for cross-table join semantics."""
    if table_name not in TABLE_DESCRIPTIONS:
        return {"error": "unknown_table", "table_name": table_name, "available_tables": sorted(TABLE_DESCRIPTIONS)}
    conn = _open()
    try:
        rows = conn.execute(f'PRAGMA table_info("{table_name}")').fetchall()
        columns = [
            {
                "name": row["name"],
                "type": row["type"],
                "not_null": bool(row["notnull"]),
                "primary_key": bool(row["pk"]),
            }
            for row in rows
        ]
        return {
            "table": table_name,
            "description": TABLE_DESCRIPTIONS.get(table_name, ""),
            "columns": columns,
        }
    finally:
        conn.close()


@mcp.tool()
def query_events_sql(sql: str, row_limit: int = DEFAULT_ROWS) -> dict[str, Any]:
    """Execute one read-only SELECT/WITH query. Consult get_data_relationships before joining event tables."""
    if not isinstance(sql, str) or not sql.strip():
        return {"error": "empty_sql"}
    if not re.match(r"^\s*(SELECT|WITH)\b", sql, flags=re.IGNORECASE):
        return {"error": "read_only_query_required", "detail": "Only SELECT or WITH queries are accepted."}
    try:
        row_limit = int(row_limit)
    except (TypeError, ValueError):
        row_limit = DEFAULT_ROWS
    row_limit = max(1, min(row_limit, MAX_ROWS))

    conn = _open()
    deadline = time.monotonic() + MAX_QUERY_SECONDS
    conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    try:
        cursor = conn.execute(sql)
        names = [item[0] for item in (cursor.description or [])]
        fetched = cursor.fetchmany(row_limit + 1)
        truncated = len(fetched) > row_limit
        fetched = fetched[:row_limit]
        results = []
        for row in fetched:
            results.append({name: _json_value(row[index]) for index, name in enumerate(names)})
        response = {"columns": names, "rows": results, "row_count": len(results), "truncated": truncated}
        encoded = json.dumps(response, ensure_ascii=False, default=str)
        while len(encoded) > MAX_RESPONSE_CHARS and results:
            results.pop()
            truncated = True
            response["rows"] = results
            response["row_count"] = len(results)
            response["truncated"] = True
            encoded = json.dumps(response, ensure_ascii=False, default=str)
        return response
    except sqlite3.OperationalError as exc:
        message = str(exc)
        if "interrupted" in message.lower():
            return {"error": "query_timeout", "max_seconds": MAX_QUERY_SECONDS}
        return {"error": "sql_error", "detail": message[:1000]}
    except sqlite3.Error as exc:
        return {"error": "sql_error", "detail": str(exc)[:1000]}
    finally:
        conn.close()


@mcp.tool()
def render_chart(
    chart_type: Literal["line", "bar", "stacked_bar", "scatter", "histogram"],
    title: str,
    data: list[dict[str, Any]],
    x_field: str = "",
    y_field: str = "",
    series_field: str = "",
    x_label: str = "",
    y_label: str = "",
) -> Image:
    """Render query-result rows as PNG. Use field names from data; histogram uses y_field values, other charts use x_field/y_field. series_field optionally splits series. This tool only renders; it does not analyze or aggregate."""
    if not title.strip():
        raise ValueError("title_required")
    if not isinstance(data, list) or not data:
        raise ValueError("data_must_be_a_non_empty_list")
    if len(data) > 10_000:
        raise ValueError("too_many_points: maximum is 10000 rows")

    required = [y_field] if chart_type == "histogram" else [x_field, y_field]
    if any(not field for field in required):
        raise ValueError("x_field_and_y_field_required" if chart_type != "histogram" else "y_field_required")
    missing = sorted({field for field in required + ([series_field] if series_field else [])
                      if any(field not in row for row in data)})
    if missing:
        raise ValueError(f"fields_not_found_in_data: {', '.join(missing)}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError("Chart rendering requires matplotlib; install project requirements") from exc

    def number(value: Any, field: str) -> float:
        if isinstance(value, bool):
            raise ValueError(f"{field}_must_be_numeric")
        try:
            result = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field}_must_be_numeric") from exc
        if not math.isfinite(result):
            raise ValueError(f"{field}_must_be_finite")
        return result

    matplotlib.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "Noto Sans CJK SC", "DejaVu Sans"]
    matplotlib.rcParams["axes.unicode_minus"] = False
    fig, ax = plt.subplots(figsize=(11, 6), constrained_layout=True)
    try:
        if chart_type == "histogram":
            values = [number(row[y_field], y_field) for row in data]
            ax.hist(values, bins="auto", color="#3478c7", edgecolor="white")
            ax.set_xlabel(x_label or y_field)
            ax.set_ylabel(y_label or "Count")
        elif chart_type == "scatter":
            groups: dict[str, list[dict[str, Any]]] = {}
            for row in data:
                label = str(row.get(series_field, "value")) if series_field else "value"
                groups.setdefault(label, []).append(row)
            for label, rows in groups.items():
                ax.scatter([number(row[x_field], x_field) for row in rows],
                           [number(row[y_field], y_field) for row in rows], label=label, alpha=0.8)
            if series_field:
                ax.legend(title=series_field)
            ax.set_xlabel(x_label or x_field)
            ax.set_ylabel(y_label or y_field)
        else:
            raw_x: dict[str, Any] = {}
            for row in data:
                raw_x.setdefault(str(row[x_field]), row[x_field])
            x_values = list(raw_x)
            series_names = list(dict.fromkeys(str(row.get(series_field, "value")) if series_field else "value"
                                              for row in data))
            values = {name: {str(row[x_field]): number(row[y_field], y_field)
                             for row in data
                             if (str(row.get(series_field, "value")) if series_field else "value") == name}
                      for name in series_names}
            positions = list(range(len(x_values)))
            if chart_type == "line":
                x_coordinates: list[Any] = positions
                categorical_x = True
                if all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in raw_x.values()):
                    x_coordinates = [number(raw_x[key], x_field) for key in x_values]
                    categorical_x = False
                elif all(isinstance(value, str) for value in raw_x.values()):
                    from datetime import datetime
                    try:
                        parsed_dates = [datetime.fromisoformat(raw_x[key].replace("Z", "+00:00")) for key in x_values]
                    except ValueError:
                        parsed_dates = []
                    if parsed_dates:
                        import matplotlib.dates as mdates
                        x_coordinates = [mdates.date2num(value) for value in parsed_dates]
                        ax.xaxis.set_major_formatter(mdates.ConciseDateFormatter(ax.xaxis.get_major_locator()))
                        categorical_x = False
                for name in series_names:
                    ys = [values[name].get(x) for x in x_values]
                    ax.plot(x_coordinates, ys, marker="o", label=name)
                if categorical_x:
                    ax.set_xticks(positions, x_values, rotation=35, ha="right")
            elif chart_type == "bar":
                width = 0.8 / len(series_names)
                for index, name in enumerate(series_names):
                    offsets = [position - 0.4 + width * (index + 0.5) for position in positions]
                    ax.bar(offsets, [values[name].get(x, 0) for x in x_values], width=width, label=name)
            elif chart_type == "stacked_bar":
                bottoms = [0.0] * len(x_values)
                for name in series_names:
                    ys = [values[name].get(x, 0) for x in x_values]
                    ax.bar(positions, ys, bottom=bottoms, label=name)
                    bottoms = [bottom + value for bottom, value in zip(bottoms, ys)]
            if chart_type != "line":
                ax.set_xticks(positions, x_values, rotation=35, ha="right")
            if series_field:
                ax.legend(title=series_field or None)
            ax.set_xlabel(x_label or x_field)
            ax.set_ylabel(y_label or y_field)

        ax.set_title(title)
        ax.grid(axis="y", alpha=0.2)
        output = io.BytesIO()
        fig.savefig(output, format="png", dpi=140)
        return Image(data=output.getvalue(), format="png")
    finally:
        plt.close(fig)


@mcp.tool()
def start_listening() -> dict[str, Any]:
    """Start recording traffic events to SQLite. The proxy keeps forwarding traffic."""
    return _change_capture_state("listening")


@mcp.tool()
def suspend_listening() -> dict[str, Any]:
    """Temporarily stop recording traffic while leaving the proxy running."""
    return _change_capture_state("suspended")


@mcp.tool()
def resume_listening() -> dict[str, Any]:
    """Resume recording traffic after it has been suspended."""
    return _change_capture_state("listening")


@mcp.tool()
def stop_listening() -> dict[str, Any]:
    """Stop event capture and clear existing event rows; Snagbox, MCP and proxy forwarding keep running."""
    result = _clear_capture_data()
    if "error" not in result:
        result["operation"] = "stop_listening"
        result["cleared_existing_data"] = True
        result["snagbox_service"] = "running"
        result["proxy_forwarding"] = "continues; event capture is stopped and old event rows were cleared"
    return result


def _clear_capture_data() -> dict[str, Any]:
    """Stop capture and atomically clear event rows while preserving the service/session."""
    conn = _open_control()
    tables = ("tcp_message", "udp_message", "http", "dns", "conn")
    try:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT state, active_session_id FROM capture_control WHERE singleton_id=1"
        ).fetchone()
        if current is None:
            conn.rollback()
            return {"error": "capture_control_not_initialized"}
        conn.execute(
            "UPDATE capture_control SET state='stopped', updated_at=strftime('%s','now') WHERE singleton_id=1"
        )
        deleted: dict[str, int] = {}
        for table in tables:
            cursor = conn.execute(f'DELETE FROM "{table}"')
            deleted[table] = cursor.rowcount
        if current[1]:
            cursor = conn.execute(
                "DELETE FROM capture_session WHERE session_id != ?", (current[1],)
            )
        else:
            cursor = conn.execute("DELETE FROM capture_session")
        deleted["capture_session"] = cursor.rowcount
        conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('tcp_message', 'udp_message')")
        conn.commit()
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        return {
            "state": "stopped",
            "previous_state": current[0],
            "deleted_rows": deleted,
            "snagbox_service": "running",
            "proxy_forwarding": "continues; traffic is no longer recorded",
        }
    except sqlite3.Error as exc:
        conn.rollback()
        return {"error": "sqlite_error", "detail": str(exc)[:1000]}
    finally:
        conn.close()


@mcp.tool()
def install_filter(name: str, code: str, description: str = "", priority: int = 100) -> dict[str, Any]:
    """Install or update a dynamic Python filter for request/response rewriting, mocking, or blocking.

    [Arguments]:
    - `name`: Unique alphanumeric identifier for this filter (e.g. 'auto_sign_v1', 'mock_user_profile')
    - `code`: The complete Python code defining `on_request(flow)` and/or `on_response(flow)`
    - `description`: Clear summary of what this filter does (e.g. 'Injects HMAC signature into /api/v1 headers')
    - `priority`: Execution order (lower integer executes earlier; default 100)

    [Execution Environment & Pre-injected Modules]:
    The filter executes in a secure sandbox with the following modules pre-injected globally (do NOT re-import):
    - `http`: mitmproxy.http module (use http.Response.make(status, content, headers) for mocking)
    - `json`: standard json library
    - `re`: regular expressions (for URL matching and text parsing)
    - `base64`: base64 encoding/decoding
    - `hashlib`: md5, sha1, sha256 hashing (for calculating signatures)
    - `hmac`: keyed-hashing for message authentication
    - `random`: random number and string generation
    - `time`: time and timestamps
    - `urlparse`: urllib.parse module

    [Required Functions]:
    The script MUST define at least one of these two functions:
    1. `def on_request(flow):`
       - Modify headers: `flow.request.headers["X-Custom"] = "val"`
       - Modify query: `flow.request.query["param"] = "val"`
       - Modify text/body: `flow.request.text = json.dumps(...)`
       - Mock response (short-circuit network):
         `flow.response = http.Response.make(200, b'{"mock": true}', {"Content-Type": "application/json"})`
       - Block request: `flow.kill()`
    2. `def on_response(flow):`
       - Modify status code: `flow.response.status_code = 200`
       - Modify response headers or body: `flow.response.text = '{"tampered": true}'`

    [Disallowed Modules]:
    Importing system-level modules (os, subprocess, sys, shutil, socket, ctypes) is strictly forbidden and rejected.
    """
    if not isinstance(name, str) or not name.strip():
        return {"error": "filter_name_required"}
    name = name.strip()
    if not isinstance(code, str) or not code.strip():
        return {"error": "filter_code_required"}

    # AST syntax and safety check
    import ast
    try:
        parsed = ast.parse(code, filename=f"<filter:{name}>")
    except SyntaxError as exc:
        return {"error": "syntax_error", "detail": str(exc), "lineno": exc.lineno}

    for node in ast.walk(parsed):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.name.split(".")[0] for alias in node.names]
            for n in names:
                if n in {"os", "subprocess", "sys", "shutil", "socket", "ctypes"}:
                    return {"error": "disallowed_module", "detail": f"Importing '{n}' is forbidden in filters"}

    has_request_hook = any(
        isinstance(n, ast.FunctionDef) and n.name == "on_request" for n in parsed.body
    )
    has_response_hook = any(
        isinstance(n, ast.FunctionDef) and n.name == "on_response" for n in parsed.body
    )
    if not (has_request_hook or has_response_hook):
        return {
            "error": "missing_hooks",
            "detail": "Filter must define at least 'on_request(flow)' or 'on_response(flow)' function",
        }

    conn = _open_control()
    try:
        conn.execute(
            """
            INSERT INTO filter_registry(name, code, description, priority, enabled, created_at, updated_at, error)
            VALUES (?, ?, ?, ?, 1, strftime('%s','now'), strftime('%s','now'), NULL)
            ON CONFLICT(name) DO UPDATE SET
                code=excluded.code,
                description=excluded.description,
                priority=excluded.priority,
                enabled=1,
                updated_at=strftime('%s','now'),
                error=NULL
            """,
            (name, code, description.strip(), priority),
        )
        conn.commit()
        return {
            "status": "ok",
            "filter_name": name,
            "description": description.strip(),
            "priority": priority,
            "enabled": True,
            "hooks": {
                "on_request": has_request_hook,
                "on_response": has_response_hook,
            },
        }
    except sqlite3.Error as exc:
        conn.rollback()
        return {"error": "sqlite_error", "detail": str(exc)[:1000]}
    finally:
        conn.close()


@mcp.tool()
def list_filters() -> dict[str, Any]:
    """List all installed dynamic filters with their status, hit counts, and execution metrics."""
    conn = _open()
    try:
        rows = conn.execute(
            """
            SELECT r.name, r.code, r.description, r.priority, r.enabled, r.created_at, r.updated_at, r.error,
                   COUNT(h.id) AS total_hits,
                   MAX(h.ts) AS last_hit_ts,
                   SUM(CASE WHEN h.status = 'ERROR' THEN 1 ELSE 0 END) AS error_hits
            FROM filter_registry r
            LEFT JOIN filter_hits h ON r.name = h.filter_name
            GROUP BY r.name
            ORDER BY r.priority ASC, r.name ASC
            """
        ).fetchall()
        filters = []
        for r in rows:
            filters.append({
                "name": r["name"],
                "description": r["description"] or "",
                "priority": r["priority"],
                "enabled": bool(r["enabled"]),
                "total_hits": r["total_hits"] or 0,
                "error_hits": r["error_hits"] or 0,
                "last_hit_ts": r["last_hit_ts"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "error": r["error"],
                "code_preview": r["code"][:200] + ("..." if len(r["code"]) > 200 else ""),
            })
        return {"filters": filters, "total": len(filters)}
    finally:
        conn.close()


@mcp.tool()
def get_filter_hits(
    filter_name: str | None = None,
    action: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Retrieve recent filter interception records (Mock, Rewrite, Block, Tag) with diff summaries.

    [Arguments]:
    - `filter_name`: Optional filter name to narrow down hits (e.g. 'auto_sign_v1')
    - `action`: Optional action filter ('MOCK', 'REWRITE', 'BLOCK', 'TAG')
    - `limit`: Maximum number of records to return (1-200, default 20)
    """
    limit = max(1, min(int(limit), 200))
    clauses = []
    params: list[Any] = []
    if filter_name and filter_name.strip():
        clauses.append("filter_name = ?")
        params.append(filter_name.strip())
    if action and action.strip():
        clauses.append("action = ?")
        params.append(action.strip().upper())

    where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id, ts, flow_uid, filter_name, hook_type, action, target_url, diff_summary, execution_time_ms, status, error
        FROM filter_hits
        {where_sql}
        ORDER BY id DESC
        LIMIT ?
    """
    params.append(limit)

    conn = _open()
    try:
        rows = conn.execute(sql, params).fetchall()
        hits = []
        for r in rows:
            diff_obj = None
            if r["diff_summary"]:
                try:
                    diff_obj = json.loads(r["diff_summary"])
                except Exception:
                    diff_obj = r["diff_summary"]

            hits.append({
                "hit_id": r["id"],
                "timestamp": r["ts"],
                "flow_uid": r["flow_uid"],
                "filter_name": r["filter_name"],
                "hook_type": r["hook_type"],
                "action": r["action"],
                "target_url": r["target_url"],
                "diff": diff_obj,
                "execution_time_ms": r["execution_time_ms"],
                "status": r["status"],
                "error": r["error"],
            })
        return {
            "hits": hits,
            "count": len(hits),
            "filter_name": filter_name,
            "action": action,
        }
    finally:
        conn.close()


@mcp.tool()
def remove_filter(name: str) -> dict[str, Any]:
    """Remove an installed dynamic filter by name."""
    if not isinstance(name, str) or not name.strip():
        return {"error": "filter_name_required"}
    name = name.strip()
    conn = _open_control()
    try:
        cursor = conn.execute("DELETE FROM filter_registry WHERE name=?", (name,))
        conn.commit()
        if cursor.rowcount == 0:
            return {"error": "filter_not_found", "filter_name": name}
        return {"status": "ok", "removed_filter": name}
    except sqlite3.Error as exc:
        conn.rollback()
        return {"error": "sqlite_error", "detail": str(exc)[:1000]}
    finally:
        conn.close()


@mcp.tool()
def toggle_filter(name: str, enabled: bool) -> dict[str, Any]:
    """Enable or disable an installed dynamic filter without deleting its code."""
    if not isinstance(name, str) or not name.strip():
        return {"error": "filter_name_required"}
    name = name.strip()
    conn = _open_control()
    try:
        cursor = conn.execute(
            "UPDATE filter_registry SET enabled=?, updated_at=strftime('%s','now') WHERE name=?",
            (int(enabled), name),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return {"error": "filter_not_found", "filter_name": name}
        return {"status": "ok", "filter_name": name, "enabled": bool(enabled)}
    except sqlite3.Error as exc:
        conn.rollback()
        return {"error": "sqlite_error", "detail": str(exc)[:1000]}
    finally:
        conn.close()


@mcp.tool()
def replay_request(uid: str, modifications: dict[str, Any] | None = None) -> dict[str, Any]:
    """Replay an HTTP request previously recorded in the 'http' table by uid, optionally applying modifications.
    Modifications can override: 'method', 'uri', 'headers' (dict), or 'body' (str).
    """
    if not isinstance(uid, str) or not uid.strip():
        return {"error": "uid_required"}
    uid = uid.strip()

    conn = _open()
    try:
        row = conn.execute(
            "SELECT method, host, uri, request_headers, request_body FROM http WHERE uid=?",
            (uid,),
        ).fetchone()
        if row is None:
            return {"error": "request_not_found", "uid": uid}
        method = row["method"] or "GET"
        host = row["host"] or ""
        uri = row["uri"] or "/"
        raw_headers = row["request_headers"]
        raw_body = row["request_body"]
    finally:
        conn.close()

    # Parse headers
    headers: dict[str, str] = {}
    if raw_headers:
        try:
            pairs = json.loads(raw_headers)
            if isinstance(pairs, list):
                for item in pairs:
                    if isinstance(item, list) and len(item) == 2:
                        headers[str(item[0])] = str(item[1])
        except Exception:
            pass

    # Remove hop-by-hop headers
    for h in ("Host", "Content-Length", "Transfer-Encoding", "Connection"):
        headers.pop(h, None)
        headers.pop(h.lower(), None)

    # Apply modifications
    body = raw_body or b""
    if isinstance(body, str):
        body = body.encode("utf-8")

    if modifications and isinstance(modifications, dict):
        if "method" in modifications:
            method = str(modifications["method"]).upper()
        if "uri" in modifications:
            uri = str(modifications["uri"])
        if "headers" in modifications and isinstance(modifications["headers"], dict):
            for k, v in modifications["headers"].items():
                headers[str(k)] = str(v)
        if "body" in modifications:
            new_body = modifications["body"]
            if isinstance(new_body, str):
                body = new_body.encode("utf-8")
            elif isinstance(new_body, bytes):
                body = new_body

    # Construct target URL
    scheme = "https" if ":443" in host or not (":80" in host or ":8080" in host) else "http"
    if uri.startswith("http://") or uri.startswith("https://"):
        target_url = uri
    else:
        target_url = f"{scheme}://{host}{uri}"

    import urllib.error
    import urllib.request
    req = urllib.request.Request(target_url, data=body if method not in ("GET", "HEAD") else None, method=method)
    for k, v in headers.items():
        req.add_header(k, v)

    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            resp_body = resp.read(4096)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            return {
                "status": "ok",
                "replayed_uid": uid,
                "target_url": target_url,
                "method": method,
                "response_status": resp.status,
                "response_headers": dict(resp.headers),
                "response_body_preview": resp_body[:512].decode("utf-8", errors="replace"),
                "elapsed_ms": elapsed_ms,
            }
    except urllib.error.HTTPError as exc:
        resp_body = exc.read(4096) if hasattr(exc, "read") else b""
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "status": "http_error",
            "replayed_uid": uid,
            "target_url": target_url,
            "response_status": exc.code,
            "response_body_preview": resp_body[:512].decode("utf-8", errors="replace"),
            "elapsed_ms": elapsed_ms,
        }
    except Exception as exc:
        return {
            "status": "network_error",
            "replayed_uid": uid,
            "target_url": target_url,
            "error": str(exc),
        }


def main() -> None:
    global _db_path
    parser = argparse.ArgumentParser(description="snagbox SQLite MCP server")
    parser.add_argument("--db", default="./data/nettrace.sqlite", help="SQLite database path")
    parser.add_argument("--init", action="store_true", help="Create an empty database before starting MCP")
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio", help="MCP transport")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP MCP bind address")
    parser.add_argument("--port", type=int, default=8000, help="HTTP MCP port")
    args = parser.parse_args()
    _db_path = Path(args.db).expanduser().resolve()
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    if not _db_path.exists():
        if not args.init:
            print(f"Database not found: {_db_path}. Start addon.py first or pass --init.", file=sys.stderr)
            raise SystemExit(2)
    db = NetTraceDB(_db_path)
    db.close()
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
