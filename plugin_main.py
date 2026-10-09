from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


PROXY_PORT = 8080


def _write_line(value: dict[str, Any]) -> None:
    sys.stdout.buffer.write((json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_port(port: int, server_thread: threading.Thread | None = None, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server_thread is not None and not server_thread.is_alive():
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _mitmproxy_ca_certificate(data_dir: Path) -> Path:
    return data_dir / "mitmproxy" / "mitmproxy-ca-cert.cer"


def _certificate_thumbprint(certificate_path: Path) -> str:
    certificate = certificate_path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in certificate:
        certificate_der = ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
    else:
        certificate_der = certificate
    return hashlib.sha1(certificate_der).hexdigest().upper()


def _is_current_user_root_certificate_installed(thumbprint: str) -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    store_key = (
        "Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\"
        f"{thumbprint}"
    )
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, store_key):
            return True
    except FileNotFoundError:
        return False


def _run_certutil(*arguments: str) -> tuple[int, str]:
    certutil = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "certutil.exe"
    if not certutil.is_file():
        raise RuntimeError("Windows certutil.exe was not found")
    result = subprocess.run(
        [str(certutil), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.returncode, result.stdout[-2000:]


def _apply_https_interception(master, loop: asyncio.AbstractEventLoop, enabled: bool) -> None:
    ignore_hosts = [] if enabled else [".*"]

    async def update_options() -> None:
        # With no trusted CA, keep TLS opaque but expose the ignored tunnel as a
        # TCP flow so the addon can store encrypted byte chunks and its conn row.
        # This only applies to TLS tunnels; ordinary HTTP remains an HTTP flow.
        master.options.update(
            ignore_hosts=ignore_hosts,
            show_ignored_hosts=not enabled,
        )

    future = asyncio.run_coroutine_threadsafe(update_options(), loop)
    future.result(timeout=10.0)


def _configure_https_inspection(data_dir: Path, master, loop: asyncio.AbstractEventLoop):
    certificate_path = _mitmproxy_ca_certificate(data_dir)

    def certificate_info() -> tuple[str, bool]:
        if not certificate_path.is_file():
            raise RuntimeError("Snagbox's mitmproxy CA certificate is not available")
        thumbprint = _certificate_thumbprint(certificate_path)
        return thumbprint, _is_current_user_root_certificate_installed(thumbprint)

    def result(thumbprint: str, installed: bool, **extra: Any) -> dict[str, Any]:
        return {
            "status": "ok",
            "certificate_installed": installed,
            "https_mode": "intercept" if installed else "passthrough",
            "certificate_thumbprint": thumbprint,
            **extra,
        }

    def control(action: str) -> dict[str, Any]:
        if sys.platform != "win32":
            return {"status": "error", "error": "certificate_store_unsupported"}
        try:
            thumbprint, installed = certificate_info()
        except (OSError, RuntimeError, UnicodeError) as exc:
            return {"status": "error", "error": "certificate_status_failed", "detail": str(exc)[:300]}

        if action == "status":
            try:
                _apply_https_interception(master, loop, installed)
            except Exception as exc:
                return {"status": "error", "error": "https_policy_update_failed", "detail": str(exc)[:300]}
            return result(thumbprint, installed, existing_connections_may_need_reconnect=True)

        if action == "install":
            added = False
            if not installed:
                try:
                    _code, output = _run_certutil("-f", "-user", "-addstore", "Root", str(certificate_path))
                    _, installed = certificate_info()
                except Exception as exc:
                    return {"status": "error", "error": "certificate_install_failed", "detail": str(exc)[:500]}
                if not installed:
                    return {
                        "status": "error", "error": "certificate_install_failed",
                        "detail": output[-500:] or "Certificate was not found in the current user's Root store",
                    }
                added = True
            try:
                _apply_https_interception(master, loop, True)
            except Exception as exc:
                if added:
                    try:
                        _run_certutil("-user", "-delstore", "Root", thumbprint)
                    except Exception:
                        pass
                return {"status": "error", "error": "https_policy_update_failed", "detail": str(exc)[:300]}
            return result(thumbprint, True, existing_connections_may_need_reconnect=True)

        if action == "uninstall":
            try:
                # Stop presenting a locally generated certificate before removing its trust.
                _apply_https_interception(master, loop, False)
            except Exception as exc:
                return {"status": "error", "error": "https_policy_update_failed", "detail": str(exc)[:300]}
            if installed:
                try:
                    _code, output = _run_certutil("-user", "-delstore", "Root", thumbprint)
                    _, installed = certificate_info()
                except Exception as exc:
                    return {
                        "status": "error", "error": "certificate_uninstall_failed",
                        "https_mode": "passthrough", "detail": str(exc)[:500],
                    }
                if installed:
                    return {
                        "status": "error", "error": "certificate_uninstall_failed",
                        "https_mode": "passthrough", "certificate_installed": True,
                        "certificate_thumbprint": thumbprint,
                        "detail": output[-500:] or "Certificate remains in the current user's Root store",
                    }
            return result(thumbprint, False, existing_connections_may_need_reconnect=True)

        return {"status": "error", "error": "invalid_certificate_action"}

    return control


def _start_proxy(data_dir: Path, proxy_settings: dict[str, str]):
    try:
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster
        from addon import NetTraceAddon
    except ImportError as exc:
        raise RuntimeError(f"Python dependency missing: {exc}") from exc

    db_path = data_dir / "snagbox.sqlite"
    confdir = data_dir / "mitmproxy"
    confdir.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", PROXY_PORT))
        except OSError as exc:
            raise RuntimeError(f"proxy port 127.0.0.1:{PROXY_PORT} is unavailable: {exc}") from exc
    upstream_url = proxy_settings["proxy_url"]
    mode = f"upstream:{upstream_url}" if upstream_url else "regular"
    upstream_auth = (
        f"{proxy_settings['username']}:{proxy_settings['password']}"
        if proxy_settings["username"] else None
    )
    opts = options.Options(
        listen_host="127.0.0.1",
        listen_port=PROXY_PORT,
        mode=[mode],
        confdir=str(confdir),
    )
    loop = asyncio.new_event_loop()
    started = threading.Event()
    failed: list[str] = []
    holder: dict[str, Any] = {}

    def run_proxy() -> None:
        asyncio.set_event_loop(loop)
        try:
            master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            master.options.update(upstream_auth=upstream_auth)
            ca_certificate = _mitmproxy_ca_certificate(data_dir)
            try:
                certificate_trusted = (
                    ca_certificate.is_file()
                    and _is_current_user_root_certificate_installed(
                        _certificate_thumbprint(ca_certificate)
                    )
                )
            except (OSError, UnicodeError):
                certificate_trusted = False
            # Without this CA in the current user's Root store, tunnel HTTPS unchanged.
            master.options.update(
                ignore_hosts=[] if certificate_trusted else [".*"],
                show_ignored_hosts=not certificate_trusted,
            )
            master.addons.add(NetTraceAddon())
            master.options.update(nettrace_db=str(db_path), nettrace_label="snagbox")
            holder["master"] = master
            started.set()
            loop.run_until_complete(master.run())
        except Exception as exc:  # reported to the host without leaking handshake data
            failed.append(f"{type(exc).__name__}: {exc}")
            started.set()
        finally:
            try:
                loop.close()
            except Exception:
                pass

    thread = threading.Thread(target=run_proxy, name="snagbox-mitmproxy", daemon=True)
    thread.start()
    if not started.wait(5.0) or "master" not in holder:
        raise RuntimeError(f"mitmproxy failed to initialize: {failed[0] if failed else 'timeout'}")
    if not _wait_port(PROXY_PORT, thread, 8.0):
        holder["master"].shutdown()
        raise RuntimeError(f"mitmproxy did not listen on 127.0.0.1:{PROXY_PORT}")
    return holder["master"], loop, thread


def _configure_proxy_settings(data_dir: Path, master, loop: asyncio.AbstractEventLoop):
    import mcp_server
    from mitmproxy.proxy import mode_specs

    config_path = data_dir / "upstream_http_proxy.json"

    def _apply(settings: dict[str, str]) -> dict[str, Any]:
        old = dict(mcp_server._upstream_http_proxy)
        mode = f"upstream:{settings['proxy_url']}" if settings["proxy_url"] else "regular"
        auth = f"{settings['username']}:{settings['password']}" if settings["username"] else None
        expected = mode_specs.ProxyMode.parse(mode)

        async def apply_runtime(mode_value: str, auth_value: str | None, expected_mode):
            master.options.update(mode=[mode_value], upstream_auth=auth_value)
            proxyserver = master.addons.get("proxyserver")
            deadline = time.monotonic() + 12.0
            while time.monotonic() < deadline:
                if not proxyserver.servers.is_updating and expected_mode in proxyserver.servers._instances:
                    return True
                await asyncio.sleep(0.05)
            return False

        try:
            future = asyncio.run_coroutine_threadsafe(apply_runtime(mode, auth, expected), loop)
            if not future.result(timeout=15.0):
                raise RuntimeError("mitmproxy did not activate the requested upstream mode")
            payload = json.dumps(settings, ensure_ascii=False, indent=2).encode("utf-8")
            temp_path = config_path.with_suffix(".json.tmp")
            temp_path.write_bytes(payload)
            os.replace(temp_path, config_path)
            return {"status": "ok"}
        except Exception as exc:
            old_mode = f"upstream:{old['proxy_url']}" if old["proxy_url"] else "regular"
            old_auth = f"{old['username']}:{old['password']}" if old["username"] else None
            try:
                old_expected = mode_specs.ProxyMode.parse(old_mode)
                rollback = asyncio.run_coroutine_threadsafe(
                    apply_runtime(old_mode, old_auth, old_expected), loop
                )
                rollback.result(timeout=15.0)
            except Exception:
                pass
            return {"status": "error", "error": "proxy_update_failed", "detail": str(exc)[:500]}

    return _apply


def _start_mcp(data_dir: Path, port: int):
    try:
        import uvicorn
        import mcp_server
        from database import NetTraceDB
    except ImportError as exc:
        raise RuntimeError(f"Python dependency missing: {exc}") from exc

    db_path = data_dir / "snagbox.sqlite"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = NetTraceDB(db_path)
    db.close()
    mcp_server._db_path = db_path.resolve()
    mcp_server.mcp.settings.host = "127.0.0.1"
    mcp_server.mcp.settings.port = port
    app = mcp_server.mcp.streamable_http_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="snagbox-mcp", daemon=True)
    thread.start()
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline and not server.started and thread.is_alive():
        time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        raise RuntimeError("MCP Streamable HTTP server failed to start")
    return server, thread


def _start_ui(mcp_port: int, proxy_port: int):
    route = "/" + secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            expected_host = f"127.0.0.1:{server.server_address[1]}"
            if self.path != route or self.headers.get("Host", "") != expected_host:
                self.send_error(404)
                return
            page = f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>snagbox</title>
<style>body{{font:14px system-ui,sans-serif;margin:24px;color:#e6e9ef;background:#151922}}h1{{font-size:20px}}code{{color:#91d5ff}}li{{margin:10px 0}}</style>
<h1>snagbox 已启动</h1><ul><li>Ghost 上游节点：<code>snagbox</code> → <code>127.0.0.1:{proxy_port}</code></li>
<li>代理入口：<code>HTTP CONNECT 127.0.0.1:{proxy_port}</code></li>
<li>MCP：<code>http://127.0.0.1:{mcp_port}/mcp</code></li>
<li>进程控制 MCP：<code>list_snagbox_processes</code>、<code>start_snagbox_program</code>、<code>stop_snagbox_program</code></li>
<li>上游 HTTP 代理 MCP：<code>get_upstream_http_proxy</code>、<code>set_upstream_http_proxy</code></li>
<li>HTTPS 根证书 MCP：<code>get_https_inspection_status</code>、<code>install_https_root_certificate</code>、<code>uninstall_https_root_certificate</code></li></ul>
<p>启动会创建一个新进程；停止只作用于 Ghost 识别为 snagbox 目标的进程。</p>
<p>新注入程序使用 DOT DNS；可通过 MCP 为 Snagbox 设置或清除链式 HTTP 代理。</p>
<p><code>stop_listening</code> 会停止采集并清除已有事件行；Snagbox、MCP 和代理转发继续运行。</p></html>"""
            body = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors http://127.0.0.1:23551 http://localhost:23551")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, name="snagbox-ui", daemon=True)
    thread.start()
    port = int(server.server_address[1])
    return server, thread, f"http://127.0.0.1:{port}{route}"


def _wait_for_stop(name: str) -> None:
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenEventW.restype = wintypes.HANDLE
    k32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    handle = k32.OpenEventW(0x00100000, False, name)
    if not handle:
        while True:
            time.sleep(3600)
    try:
        k32.WaitForSingleObject(handle, 0xFFFFFFFF)
    finally:
        k32.CloseHandle(handle)


def run_hosted() -> int:
    proxy_master = mcp_server = None
    ui_server = None
    mcp_thread = proxy_thread = None
    replied = False
    try:
        handshake = json.loads(sys.stdin.buffer.readline().decode("utf-8"))
        if not isinstance(handshake, dict) or type(handshake.get("v")) is not int or handshake["v"] != 1:
            raise ValueError("unsupported plugin protocol")
        stop_event = handshake.get("stopEvent")
        api_base = handshake.get("apiBase")
        token = handshake.get("token")
        data_path = handshake.get("dataDir")
        if not all(isinstance(value, str) and value for value in (stop_event, api_base, token, data_path)):
            raise ValueError("incomplete Ghost plugin handshake")
        data_dir = Path(data_path).resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        sys.path.insert(0, str(Path(__file__).resolve().parent))

        import mcp_server as mcp_module
        proxy_settings = mcp_module.load_upstream_http_proxy(data_dir)
        proxy_master, proxy_loop, proxy_thread = _start_proxy(data_dir, proxy_settings)
        mcp_module.configure_proxy_settings(
            proxy_settings, _configure_proxy_settings(data_dir, proxy_master, proxy_loop)
        )
        mcp_module.configure_https_inspection(
            _configure_https_inspection(data_dir, proxy_master, proxy_loop)
        )
        node = mcp_module.configure_ghost_bridge(api_base, token, PROXY_PORT)

        mcp_port = _free_loopback_port()
        mcp_server, mcp_thread = _start_mcp(data_dir, mcp_port)
        ui_server, _ui_thread, ui_url = _start_ui(mcp_port, PROXY_PORT)
        _write_line({"v": 1, "ok": True, "uiUrl": ui_url})
        replied = True

        _wait_for_stop(stop_event)
        return 0
    except Exception as exc:
        if not replied:
            try:
                _write_line({"v": 1, "ok": False, "error": f"{type(exc).__name__}: {exc}"[:512]})
            except Exception:
                pass
        return 1
    finally:
        if mcp_server is not None:
            mcp_server.should_exit = True
        if ui_server is not None:
            ui_server.shutdown()
            ui_server.server_close()
        if proxy_master is not None:
            proxy_master.shutdown()
        if mcp_thread is not None:
            mcp_thread.join(timeout=4.0)
        if proxy_thread is not None:
            proxy_thread.join(timeout=5.0)


def main() -> int:
    if "GHOST_PLUGIN_ID" not in os.environ:
        print("Run snagbox through Ghost Proxifier's plugin center.", file=sys.stderr)
        return 2
    return run_hosted()


if __name__ == "__main__":
    raise SystemExit(main())
