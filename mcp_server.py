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
        payload = None if body is None else json.dumps(body, ensure_ascii=False)
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


def _ghost_process_stats() -> dict[str, Any]:
    # Ghost's default process-stats response repeats large base64 icons for each
    # process and group. iconRefs=1 sends each distinct icon once; the larger
    # bounded limit accommodates hosts with many injected processes.
    return _ghost_request(
        "GET", "/process-stats?iconRefs=1",
        max_response_bytes=MAX_GHOST_PROCESS_STATS_BYTES,
    )


def _ensure_snagbox_upstream(proxy_port: int) -> dict[str, Any]:
    """Use Ghost's generic config read/write APIs to keep one named node."""
    config = _ghost_request("GET", "/config")
    if config.get("status") == "error" or not isinstance(config.get("upstream"), list):
        return {"status": "error", "error": config.get("error", "config_read_failed")}
    upstream = config["upstream"]
    matches = [i for i, node in enumerate(upstream)
               if isinstance(node, dict) and str(node.get("name", "")).casefold() == "snagbox"]
    canonical_id = ""
    changed = False
    duplicate_ids: set[str] = set()
    if matches:
        chosen = next((i for i in matches if upstream[i].get("id") == "snagbox"), matches[0])
        node = upstream[chosen]
        canonical_id = str(node.get("id") or "")
        if not canonical_id:
            canonical_id = "snagbox"
            used = {str(x.get("id", "")) for x in upstream if isinstance(x, dict)}
            suffix = 0
            while canonical_id in used:
                suffix += 1
                canonical_id = f"snagbox-{suffix}"
        active = any(bool(upstream[i].get("active", False)) for i in matches)
        for i in matches:
            if i != chosen:
                dup_id = str(upstream[i].get("id", ""))
                if dup_id and dup_id != canonical_id:
                    duplicate_ids.add(dup_id)
        fixed = dict(node)
        fixed.update({"id": canonical_id, "name": "snagbox", "type": "HTTP",
                      "addr": f"127.0.0.1:{proxy_port}", "user": "", "pass": "",
                      "active": active, "builtin": False})
        if fixed.get("addr") != node.get("addr") or fixed.get("type") != node.get("type"):
            fixed.pop("udpRelay", None)
        if fixed != node or len(matches) > 1:
            changed = True
        upstream[chosen] = fixed
        for i in reversed(matches):
            if i != chosen:
                del upstream[i]
    else:
        ids = {str(x.get("id", "")) for x in upstream if isinstance(x, dict)}
        canonical_id = "snagbox"
        suffix = 0
        while canonical_id in ids:
            suffix += 1
            canonical_id = f"snagbox-{suffix}"
        upstream.append({"id": canonical_id, "name": "snagbox", "type": "HTTP",
                         "addr": f"127.0.0.1:{proxy_port}", "user": "", "pass": "",
                         "icon": "default.png", "active": False, "builtin": False})
        changed = True
    if changed:
        saved = _ghost_request("POST", "/save-config", config)
        if saved.get("status") not in ("saved", "ok"):
            return {"status": "error", "error": saved.get("error", "config_write_failed")}
        if duplicate_ids:
            _migrate_duplicate_upstream_targets(duplicate_ids, canonical_id)
    return {"status": "ok", "nodeId": canonical_id, "changed": changed,
            "duplicatesRemoved": len(duplicate_ids)}


def _migrate_duplicate_upstream_targets(duplicate_ids: set[str], canonical_id: str) -> None:
    stats = _ghost_process_stats()
    for group in stats.get("groups", []) if isinstance(stats.get("groups"), list) else []:
        if not isinstance(group, dict) or str(group.get("nodeId", "")) not in duplicate_ids:
            continue
        target_id = str(group.get("id", ""))
        if target_id:
            _ghost_request("POST", "/api/update-target-config", {"id": target_id, "nodeId": canonical_id})


def _list_snagbox_groups() -> dict[str, Any]:
    if not _snagbox_node_id:
        return {"error": "snagbox_upstream_unavailable"}
    response = _ghost_process_stats()
    if response.get("error") or not isinstance(response.get("groups"), list):
        return {"error": response.get("error", "process_list_failed"), "detail": response.get("detail")}
    groups = response.get("groups", [])
    targets = [group for group in groups if isinstance(group, dict)
               and str(group.get("nodeId", "")) == _snagbox_node_id]
    return {"status": "ok", "nodeId": _snagbox_node_id, "targets": targets}


def _ensure_target_dot(target_id: str) -> dict[str, Any]:
    """Keep the saved Ghost target configuration on the DOT DNS mode."""
    return _ghost_request("POST", "/api/update-target-config", {"id": target_id, "dnsMode": "dot"})


@mcp.tool()
def list_snagbox_processes() -> dict[str, Any]:
    """List Ghost process groups currently routed through the snagbox upstream."""
    return _list_snagbox_groups()


@mcp.tool()
def start_snagbox_program(target_path: str, arguments: str = "") -> dict[str, Any]:
    """Reuse a snagbox target group by executable path, creating one only when absent."""
    if not isinstance(target_path, str) or not target_path.strip() or not isinstance(arguments, str):
        return {"error": "invalid_arguments"}
    if not _snagbox_node_id:
        return {"error": "snagbox_upstream_unavailable"}
    path = Path(target_path.strip()).expanduser()
    if not path.is_absolute():
        return {"error": "target_path_must_be_absolute", "target_path": target_path}
    if not path.is_file():
        return {"error": "target_executable_not_found", "target_path": str(path)}
    target = str(path.resolve())

    stats = _ghost_process_stats()
    if stats.get("error") or not isinstance(stats.get("groups"), list):
        return {"error": stats.get("error", "process_list_failed"),
                "detail": stats.get("detail", "Ghost returned no target groups")}

    target_key = target.replace("/", "\\").casefold()
    matches = [group for group in stats["groups"]
               if isinstance(group, dict)
               and str(group.get("nodeId", "")) == _snagbox_node_id
               and str(group.get("path", "")).replace("/", "\\").casefold() == target_key]
    # Prefer the live group when earlier starts left duplicate entries; otherwise
    # reuse a stopped group. Both cases avoid adding another Ghost target group.
    def _active_count(group: dict[str, Any]) -> int:
        try:
            return int(group.get("activeCount", 0) or 0)
        except (TypeError, ValueError):
            return 0

    existing = next((group for group in matches if _active_count(group) > 0), None)
    if existing is None and matches:
        existing = matches[0]
    if existing is not None:
        target_id = str(existing.get("id", ""))
        if not target_id:
            return {"error": "target_group_missing_id", "path": target}
        # Avoid a permission-gated no-op write: Ghost may reject target config
        # writes even when the saved DNS mode is already DOT.
        if str(existing.get("dnsMode", "")).casefold() != "dot":
            configured = _ensure_target_dot(target_id)
            if configured.get("status") != "ok":
                return {"error": configured.get("error", "dns_config_update_failed"),
                        "detail": configured.get("detail"), "targetId": target_id}
        if _active_count(existing) > 0:
            return {"status": "ok", "nodeId": _snagbox_node_id, "path": target,
                    "targetId": target_id, "reusedTargetGroup": True,
                    "alreadyRunning": True, "startedNewProcess": False,
                    "dnsMode": "dot", "dnsConfigUpdated": True,
                    "activeProcessMayNeedRestart": True}
        # The plugin's target.launch grant authorizes Ghost's generic /inject
        # API (target.add). Supplying the existing GUID makes Ghost relaunch
        # that saved target instead of creating a duplicate process group.
        result = _ghost_request("POST", "/inject", {
            "target": target, "arguments": arguments, "nodeId": _snagbox_node_id,
            "mode": "manual", "dnsMode": "dot", "sync": False, "guid": target_id
        })
        if result.get("status") != "ok":
            return {"error": result.get("error", "launch_failed"), "detail": result.get("detail"),
                    "targetId": target_id}
        return {"status": "ok", "nodeId": _snagbox_node_id, "path": target,
                "targetId": target_id, "reusedTargetGroup": True,
                "alreadyRunning": False, "startedNewProcess": True,
                "dnsMode": "dot", "dnsConfigUpdated": True, "ghost": result}

    result = _ghost_request("POST", "/inject", {
        "target": target, "arguments": arguments, "nodeId": _snagbox_node_id,
        "mode": "manual", "dnsMode": "dot", "sync": False
    })
    if result.get("status") != "ok":
        return {"error": result.get("error", "launch_failed"), "detail": result.get("detail")}
    return {"status": "ok", "nodeId": _snagbox_node_id, "path": target,
            "startedNewProcess": True, "reusedTargetGroup": False,
            "dnsMode": "dot", "ghost": result}


@mcp.tool()
def stop_snagbox_program(process_name: str) -> dict[str, Any]:
    """Stop matching processes only inside Ghost groups using the snagbox node."""
    if not isinstance(process_name, str) or not process_name.strip():
        return {"error": "process_name_required"}
    query = Path(process_name.strip()).name.casefold()
    groups = _list_snagbox_groups()
    if "error" in groups:
        return groups
    matched: list[int] = []
    errors: list[dict[str, Any]] = []
    for group in groups.get("targets", []):
        for proc in group.get("children", []) if isinstance(group.get("children"), list) else []:
            pid = proc.get("pid") if isinstance(proc, dict) else None
            name = Path(str(proc.get("name", ""))).name.casefold() if isinstance(proc, dict) else ""
            if not isinstance(pid, int) or pid <= 0 or name != query:
                continue
            result = _ghost_request("POST", "/api/kill-process-tree", {"pid": pid})
            if result.get("status") == "ok":
                matched.append(pid)
            else:
                errors.append({"pid": pid, "error": result.get("error", "process_stop_failed")})
    return {"status": "ok" if not errors else "partial", "processName": query,
            "matched": len(matched) + len(errors), "stoppedPids": matched, "errors": errors}


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
