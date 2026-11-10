from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import re
import sqlite3
import threading
import time
import traceback
import urllib
import urllib.parse
from pathlib import Path
from typing import Any, Callable

from mitmproxy import ctx, http

from database import AsyncNetTraceDB, read_capture_state, readonly_connection
from proc_resolver import resolve_process_and_target


def flow_uid(flow: Any) -> str:
    return "NT" + hashlib.sha256(str(flow.id).encode("utf-8")).hexdigest()[:20].upper()


def endpoint(value: Any) -> tuple[str | None, int | None]:
    if not value or not isinstance(value, (tuple, list)) or len(value) < 2:
        return None, None
    try:
        return str(value[0]), int(value[1])
    except (TypeError, ValueError):
        return str(value[0]), None


def addresses(flow: Any) -> tuple[str | None, int | None, str | None, int | None]:
    client = endpoint(getattr(getattr(flow, "client_conn", None), "peername", None))
    server_conn = getattr(flow, "server_conn", None)
    server = endpoint(getattr(server_conn, "address", None))
    if server == (None, None):
        server = endpoint(getattr(server_conn, "peername", None))
    return client[0], client[1], server[0], server[1]


def stamp(value: Any = None) -> float:
    try:
        return float(value) if value is not None else time.time()
    except (TypeError, ValueError):
        return time.time()


def local_flag(host: str | None) -> int | None:
    if not host:
        return None
    return int(host in {"127.0.0.1", "::1", "localhost"})


def safe_log(msg: str, level: str = "info") -> None:
    try:
        log_obj = getattr(ctx, "log", None)
        if log_obj is not None:
            fn = getattr(log_obj, level, None)
            if callable(fn):
                fn(msg)
    except Exception:
        pass


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def header_pairs_json(headers: Any) -> str | None:
    """Serialize all HTTP header pairs without collapsing repeated field names."""
    if headers is None:
        return None
    try:
        pairs = headers.items(multi=True)
    except (AttributeError, TypeError):
        pairs = headers.items()
    return json_text([[str(name), str(value)] for name, value in pairs])


class FilterInstance:
    def __init__(self, name: str, code: str, priority: int, updated_at: float):
        self.name = name
        self.code = code
        self.priority = priority
        self.updated_at = updated_at
        self.on_request_fn: Callable[[Any], Any] | None = None
        self.on_response_fn: Callable[[Any], Any] | None = None
        self.consecutive_errors = 0
        self.is_tripped = False
        self.compile_error: str | None = None

    def compile(self) -> bool:
        env = {
            "__builtins__": __builtins__,
            "http": http,
            "json": json,
            "time": time,
            "re": re,
            "base64": base64,
            "hashlib": hashlib,
            "hmac": hmac,
            "random": random,
            "urllib": urllib,
            "urlparse": urllib.parse,
        }
        try:
            compiled = compile(self.code, f"<filter:{self.name}>", "exec")
            exec(compiled, env)
            self.on_request_fn = env.get("on_request")
            self.on_response_fn = env.get("on_response")
            self.compile_error = None
            return True
        except Exception as exc:
            self.compile_error = f"{type(exc).__name__}: {exc}"
            return False


class FilterManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.filters: dict[str, FilterInstance] = {}
        self.lock = threading.Lock()
        self._active_request_filters: tuple[FilterInstance, ...] = ()
        self._active_response_filters: tuple[FilterInstance, ...] = ()
        self._last_state_sig: tuple[int, float] = (-1, -1.0)

    def has_request_filters(self) -> bool:
        return bool(self._active_request_filters)

    def has_response_filters(self) -> bool:
        return bool(self._active_response_filters)

    def sync_from_db(self) -> None:
        if not self.db_path.exists():
            return
        try:
            conn = readonly_connection(self.db_path)
            sig_row = conn.execute(
                "SELECT count(*), COALESCE(max(updated_at), 0) FROM filter_registry WHERE enabled=1"
            ).fetchone()
            if not sig_row:
                conn.close()
                return
            count, max_upd = int(sig_row[0]), float(sig_row[1])
            if (count, max_upd) == self._last_state_sig:
                conn.close()
                return

            rows = conn.execute(
                "SELECT name, code, priority, enabled, updated_at, error "
                "FROM filter_registry WHERE enabled=1 ORDER BY priority ASC, name ASC"
            ).fetchall()
            conn.close()
        except Exception:
            return

        active_names = set()
        with self.lock:
            for row in rows:
                name, code, priority, enabled, updated_at, err = (
                    row["name"], row["code"], row["priority"], row["enabled"], row["updated_at"], row["error"]
                )
                active_names.add(name)
                existing = self.filters.get(name)
                if existing is None or existing.updated_at != updated_at or existing.code != code:
                    instance = FilterInstance(name, code, priority, updated_at)
                    if instance.compile():
                        self.filters[name] = instance
                        safe_log(f"Loaded dynamic filter: {name}", "info")
                    else:
                        safe_log(f"Failed to compile dynamic filter {name}: {instance.compile_error}", "warn")
                        self._record_filter_error(name, instance.compile_error or "compile_failed")

            # Remove filters that are disabled or deleted
            for name in list(self.filters.keys()):
                if name not in active_names:
                    del self.filters[name]
                    safe_log(f"Unloaded dynamic filter: {name}", "info")

            self._active_request_filters = tuple(sorted(
                [f for f in self.filters.values() if f.on_request_fn and not f.is_tripped],
                key=lambda f: f.priority
            ))
            self._active_response_filters = tuple(sorted(
                [f for f in self.filters.values() if f.on_response_fn and not f.is_tripped],
                key=lambda f: f.priority
            ))
            self._last_state_sig = (count, max_upd)

    def _record_filter_error(self, name: str, error_msg: str, trip: bool = False) -> None:
        def update_db():
            try:
                conn = sqlite3.connect(self.db_path, timeout=5.0)
                if trip:
                    conn.execute(
                        "UPDATE filter_registry SET enabled=0, error=?, updated_at=strftime('%s','now') WHERE name=?",
                        (f"TRIPPED (熔断): {error_msg}", name)
                    )
                else:
                    conn.execute(
                        "UPDATE filter_registry SET error=? WHERE name=?",
                        (error_msg, name)
                    )
                conn.commit()
                conn.close()
            except Exception:
                pass
        threading.Thread(target=update_db, daemon=True).start()

    def handle_request(self, flow: Any, uid: str, db: AsyncNetTraceDB) -> None:
        filters = self._active_request_filters
        if not filters:
            return

        request = getattr(flow, "request", None)
        if request is None:
            return

        for filt in filters:
            pre_url = str(request.url)
            pre_headers = dict(request.headers)
            pre_body_len = len(request.raw_content or b"")
            had_response = getattr(flow, "response", None) is not None

            t0 = time.perf_counter()
            error_str = None
            status = "SUCCESS"
            action = "PASSTHROUGH"

            try:
                result = filt.on_request_fn(flow)
                filt.consecutive_errors = 0
            except Exception as exc:
                filt.consecutive_errors += 1
                status = "ERROR"
                error_str = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-500:]}"
                if filt.consecutive_errors >= 3:
                    filt.is_tripped = True
                    self._record_filter_error(filt.name, f"Consecutive errors limit reached: {exc}", trip=True)

            elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

            # Analyze action & diff
            if status == "SUCCESS":
                has_response = getattr(flow, "response", None) is not None
                is_killed = bool(getattr(flow, "error", None) and "killed" in str(getattr(flow, "error", "")).lower())

                if not had_response and has_response:
                    action = "MOCK"
                elif is_killed:
                    action = "BLOCK"
                elif str(request.url) != pre_url or dict(request.headers) != pre_headers or len(request.raw_content or b"") != pre_body_len:
                    action = "REWRITE"
                elif isinstance(result, dict) and "action" in result:
                    action = str(result["action"]).upper()

            diff = {
                "url_changed": str(request.url) != pre_url,
                "old_url": pre_url if str(request.url) != pre_url else None,
                "new_url": str(request.url) if str(request.url) != pre_url else None,
                "header_count_delta": len(request.headers) - len(pre_headers),
                "body_len_delta": len(request.raw_content or b"") - pre_body_len,
            }
            if getattr(flow, "response", None):
                diff["mocked_status"] = flow.response.status_code

            # Log hit if action is taken or filter errored
            if action != "PASSTHROUGH" or status == "ERROR":
                db.add_filter_hit({
                    "ts": time.time(),
                    "flow_uid": uid,
                    "filter_name": filt.name,
                    "hook_type": "request",
                    "action": action,
                    "target_url": pre_url,
                    "diff_summary": json_text(diff),
                    "execution_time_ms": elapsed_ms,
                    "status": status,
                    "error": error_str,
                })

            # If request was mocked or blocked, do not continue filter chain
            if getattr(flow, "response", None) is not None or getattr(flow, "error", None) is not None:
                break

    def handle_response(self, flow: Any, uid: str, db: AsyncNetTraceDB) -> None:
        filters = self._active_response_filters
        if not filters:
            return

        response = getattr(flow, "response", None)
        if response is None:
            return

        for filt in filters:
            pre_status = response.status_code
            pre_headers = dict(response.headers)
            pre_body_len = len(response.raw_content or b"")

            t0 = time.perf_counter()
            error_str = None
            status = "SUCCESS"
            action = "PASSTHROUGH"

            try:
                result = filt.on_response_fn(flow)
                filt.consecutive_errors = 0
            except Exception as exc:
                filt.consecutive_errors += 1
                status = "ERROR"
                error_str = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-500:]}"
                if filt.consecutive_errors >= 3:
                    filt.is_tripped = True
                    self._record_filter_error(filt.name, f"Consecutive errors limit reached: {exc}", trip=True)

            elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

            if status == "SUCCESS":
                if response.status_code != pre_status or dict(response.headers) != pre_headers or len(response.raw_content or b"") != pre_body_len:
                    action = "REWRITE"
                elif isinstance(result, dict) and "action" in result:
                    action = str(result["action"]).upper()

            diff = {
                "status_code_changed": response.status_code != pre_status,
                "old_status": pre_status if response.status_code != pre_status else None,
                "new_status": response.status_code if response.status_code != pre_status else None,
                "body_len_delta": len(response.raw_content or b"") - pre_body_len,
            }

            if action != "PASSTHROUGH" or status == "ERROR":
                target_url = str(flow.request.url) if getattr(flow, "request", None) else ""
                db.add_filter_hit({
                    "ts": time.time(),
                    "flow_uid": uid,
                    "filter_name": filt.name,
                    "hook_type": "response",
                    "action": action,
                    "target_url": target_url,
                    "diff_summary": json_text(diff),
                    "execution_time_ms": elapsed_ms,
                    "status": status,
                    "error": error_str,
                })


class NetTraceAddon:
    def __init__(self) -> None:
        self.db: AsyncNetTraceDB | None = None
        self.filter_manager: FilterManager | None = None
        self.session_id = ""
        self.label = "capture"
        self.started: dict[str, float] = {}
        self.ensured: set[str] = set()
        self.capture_state = "stopped"
        self.capture_state_lock = threading.Lock()
        self.control_stop = threading.Event()
        self.control_thread: threading.Thread | None = None
        self.db_path: Path | None = None

    def load(self, loader) -> None:
        loader.add_option(
            name="nettrace_db",
            typespec=str,
            default="./data/nettrace.sqlite",
            help="SQLite file used by snagbox",
        )
        loader.add_option(
            name="nettrace_label",
            typespec=str,
            default="capture",
            help="Human-readable label for this capture session",
        )

    def running(self) -> None:
        path = Path(ctx.options.nettrace_db).expanduser().resolve()
        self.db_path = path
        self.label = ctx.options.nettrace_label or "capture"
        self.db = AsyncNetTraceDB(path)
        self.filter_manager = FilterManager(path)
        self.filter_manager.sync_from_db()
        version = "unknown"
        try:
            from importlib.metadata import version as package_version
            version = package_version("mitmproxy")
        except Exception:
            pass
        self.session_id = self.db.start_session(self.label, version)
        self.capture_state = read_capture_state(path)
        self.control_stop.clear()
        self.control_thread = threading.Thread(
            target=self._poll_capture_state,
            name="nettrace-capture-control",
            daemon=True,
        )
        self.control_thread.start()
        ctx.log.info(f"snagbox SQLite database: {path}")
        ctx.log.info(f"snagbox capture label: {self.label} (session {self.session_id})")
        ctx.log.info(f"snagbox capture state: {self.capture_state}")

    def _poll_capture_state(self) -> None:
        last_filter_sync = 0.0
        while not self.control_stop.wait(0.5):
            if self.db_path is None:
                continue
            try:
                state = read_capture_state(self.db_path)
            except Exception:
                continue
            with self.capture_state_lock:
                self.capture_state = state
            now = time.monotonic()
            if self.filter_manager and (now - last_filter_sync >= 2.0):
                last_filter_sync = now
                try:
                    self.filter_manager.sync_from_db()
                except Exception:
                    pass

    def _is_listening(self) -> bool:
        with self.capture_state_lock:
            return self.capture_state == "listening"

    def _require_db(self) -> AsyncNetTraceDB:
        if self.db is None:
            raise RuntimeError("snagbox addon is not initialized")
        return self.db

    def _ensure_conn(self, flow: Any, proto: str, ts: float | None = None) -> str | None:
        if not self._is_listening():
            return None
        uid = flow_uid(flow)
        if uid in self.ensured:
            return uid
        orig_h, orig_p, resp_h, resp_p = addresses(flow)
        proc_info = resolve_process_and_target(orig_p, max_ancestor_depth=5)
        queued = self._require_db().ensure_conn(
            uid, stamp(ts), proto, orig_h, orig_p, resp_h, resp_p,
            self.session_id, self.label, local_flag(orig_h), local_flag(resp_h),
            pid=proc_info.get("pid"),
            process_name=proc_info.get("process_name"),
            process_path=proc_info.get("process_path"),
            root_pid=proc_info.get("root_pid"),
            root_process_name=proc_info.get("root_process_name"),
            target_id=proc_info.get("target_id"),
        )
        if queued:
            self.ensured.add(uid)
            return uid
        return None

    def _save_message(self, flow: Any, table: str, message: Any, index: int) -> None:
        is_client = bool(getattr(message, "from_client", False))
        content = bytes(getattr(message, "content", b"") or b"")
        uid = self._ensure_conn(flow, "tcp" if table == "tcp_message" else "udp", getattr(message, "timestamp", None))
        if uid is None:
            return
        self._require_db().add_transport_message(
            table=table,
            uid=uid,
            session_id=self.session_id,
            ts=stamp(getattr(message, "timestamp", None)),
            message_index=index,
            from_client=is_client,
            content=content,
        )

    def tcp_start(self, flow) -> None:
        if not self._is_listening():
            return
        uid = self._ensure_conn(flow, "tcp", getattr(flow, "timestamp_created", None))
        if uid is None:
            return
        self.started[uid] = stamp(getattr(flow, "timestamp_created", None))

    def tcp_message(self, flow) -> None:
        if not self._is_listening():
            return
        if not flow.messages:
            return
        uid = self._ensure_conn(flow, "tcp")
        if uid is None:
            return
        self.started.setdefault(uid, stamp(getattr(flow, "timestamp_created", None)))
        self._save_message(flow, "tcp_message", flow.messages[-1], len(flow.messages) - 1)

    def tcp_end(self, flow) -> None:
        self._finish_transport(flow, "SF", None)

    def tcp_error(self, flow) -> None:
        self._finish_transport(flow, "OTH", str(getattr(flow, "error", "TCP error")))

    def _finish_transport(self, flow: Any, state: str, error: str | None) -> None:
        if not self._is_listening():
            return
        uid = self._ensure_conn(flow, "tcp")
        if uid is None:
            return
        start = self.started.pop(uid, stamp(getattr(flow, "timestamp_created", None)))
        end = stamp(getattr(flow, "timestamp_end", None))
        self._require_db().finish_conn(uid, max(0.0, end - start), state, error)
        self.ensured.discard(uid)

    def udp_start(self, flow) -> None:
        if not self._is_listening():
            return
        uid = self._ensure_conn(flow, "udp", getattr(flow, "timestamp_created", None))
        if uid is None:
            return
        self.started[uid] = stamp(getattr(flow, "timestamp_created", None))

    def udp_message(self, flow) -> None:
        if not self._is_listening():
            return
        if not flow.messages:
            return
        uid = self._ensure_conn(flow, "udp")
        if uid is None:
            return
        self.started.setdefault(uid, stamp(getattr(flow, "timestamp_created", None)))
        self._save_message(flow, "udp_message", flow.messages[-1], len(flow.messages) - 1)

    def udp_end(self, flow) -> None:
        self._finish_udp(flow, "SF", None)

    def udp_error(self, flow) -> None:
        self._finish_udp(flow, "OTH", str(getattr(flow, "error", "UDP error")))

    def _finish_udp(self, flow: Any, state: str, error: str | None) -> None:
        if not self._is_listening():
            return
        uid = self._ensure_conn(flow, "udp")
        if uid is None:
            return
        start = self.started.pop(uid, stamp(getattr(flow, "timestamp_created", None)))
        end = stamp(getattr(flow, "timestamp_end", None))
        self._require_db().finish_conn(uid, max(0.0, end - start), state, error)
        self.ensured.discard(uid)

    def request(self, flow) -> None:
        if not self._is_listening():
            return
        if not self.filter_manager or not self.filter_manager.has_request_filters():
            return
        uid = flow_uid(flow)
        try:
            self.filter_manager.handle_request(flow, uid, self._require_db())
        except Exception as exc:
            safe_log(f"Error handling request filter: {exc}", "warn")

    def response(self, flow) -> None:
        if not self._is_listening():
            return
        uid = self._ensure_conn(flow, "tcp", getattr(flow, "timestamp_start", None))
        if uid is None:
            return
        if self.filter_manager and self.filter_manager.has_response_filters():
            try:
                self.filter_manager.handle_response(flow, uid, self._require_db())
            except Exception as exc:
                safe_log(f"Error handling response filter: {exc}", "warn")
        request = flow.request
        response = flow.response
        request_body = bytes(request.raw_content) if request and request.raw_content is not None else None
        response_body = bytes(response.raw_content) if response and response.raw_content is not None else None
        orig_h, orig_p, resp_h, resp_p = addresses(flow)
        row = {
            "uid": uid,
            "ts": stamp(getattr(request, "timestamp_start", None)),
            "id.orig_h": orig_h,
            "id.orig_p": orig_p,
            "id.resp_h": resp_h,
            "id.resp_p": resp_p,
            "trans_depth": None,
            "method": getattr(request, "method", None),
            "host": getattr(request, "host", None),
            "uri": getattr(request, "path", None),
            "referrer": request.headers.get("referer") if request else None,
            "version": getattr(request, "http_version", None),
            "user_agent": request.headers.get("user-agent") if request else None,
            "request_headers": header_pairs_json(getattr(request, "headers", None)),
            "response_headers": header_pairs_json(getattr(response, "headers", None)),
            "request_body_len": len(request_body) if request_body is not None else 0,
            "response_body_len": len(response_body) if response_body is not None else 0,
            "request_body": request_body,
            "response_body": response_body,
            "status_code": getattr(response, "status_code", None),
            "status_msg": getattr(response, "reason", None),
            "tags": json_text(sorted(getattr(flow, "tags", set()))),
            "session_id": self.session_id,
            "capture_label": self.label,
            "error": None,
        }
        self._require_db().add_http(row)
        self.ensured.discard(uid)

    def error(self, flow) -> None:
        if not self._is_listening():
            return
        request = getattr(flow, "request", None)
        request_body = bytes(request.raw_content) if request and request.raw_content is not None else None
        uid = self._ensure_conn(flow, "tcp", getattr(flow, "timestamp_start", None))
        if uid is None:
            return
        orig_h, orig_p, resp_h, resp_p = addresses(flow)
        row = {
            "uid": uid,
            "ts": stamp(getattr(request, "timestamp_start", None)),
            "id.orig_h": orig_h,
            "id.orig_p": orig_p,
            "id.resp_h": resp_h,
            "id.resp_p": resp_p,
            "trans_depth": None,
            "method": getattr(request, "method", None),
            "host": getattr(request, "host", None),
            "uri": getattr(request, "path", None),
            "referrer": request.headers.get("referer") if request else None,
            "version": getattr(request, "http_version", None),
            "user_agent": request.headers.get("user-agent") if request else None,
            "request_headers": header_pairs_json(getattr(request, "headers", None)),
            "response_headers": None,
            "request_body_len": len(request_body) if request_body is not None else 0,
            "response_body_len": None,
            "request_body": request_body,
            "response_body": None,
            "status_code": None,
            "status_msg": None,
            "tags": json_text(sorted(getattr(flow, "tags", set()))),
            "session_id": self.session_id,
            "capture_label": self.label,
            "error": str(getattr(flow, "error", "HTTP flow error")),
        }
        self._require_db().add_http(row)
        self.ensured.discard(uid)

    def dns_response(self, flow) -> None:
        self._save_dns(flow, None)

    def dns_error(self, flow) -> None:
        self._save_dns(flow, str(getattr(flow, "error", "DNS error")))

    def _save_dns(self, flow: Any, error: str | None) -> None:
        if not self._is_listening():
            return
        request = getattr(flow, "request", None)
        response = getattr(flow, "response", None)
        question = getattr(request, "question", None) if request else None
        orig_h, orig_p, resp_h, resp_p = addresses(flow)
        answers = list(getattr(response, "answers", []) or []) if response else []
        rcode = getattr(response, "response_code", None) if response else None
        row = {
            "uid": flow_uid(flow),
            "ts": stamp(getattr(request, "timestamp", None)),
            "id.orig_h": orig_h,
            "id.orig_p": orig_p,
            "id.resp_h": resp_h,
            "id.resp_p": resp_p,
            "proto": "udp",
            "trans_id": getattr(request, "id", None),
            "rtt": (stamp(getattr(response, "timestamp", None)) - stamp(getattr(request, "timestamp", None))) if response and getattr(response, "timestamp", None) and getattr(request, "timestamp", None) else None,
            "query": getattr(question, "name", None),
            "qclass": getattr(question, "class_", None),
            "qclass_name": str(getattr(question, "class_", "")) or None,
            "qtype": getattr(question, "type", None),
            "qtype_name": str(getattr(question, "type", "")) or None,
            "rcode": rcode,
            "rcode_name": str(rcode) if rcode is not None else None,
            "AA": int(bool(getattr(response, "authoritative_answer", False))) if response else None,
            "TC": int(bool(getattr(response, "truncation", False))) if response else None,
            "RD": int(bool(getattr(request, "recursion_desired", False))) if request else None,
            "RA": int(bool(getattr(response, "recursion_available", False))) if response else None,
            "Z": getattr(response, "reserved", None) if response else None,
            "answers": json_text([str(answer) for answer in answers]),
            "TTLs": json_text([getattr(answer, "ttl", None) for answer in answers]),
            "rejected": int(error is not None),
            "session_id": self.session_id,
            "capture_label": self.label,
            "error": error,
        }
        self._require_db().add_dns(row)

    def done(self) -> None:
        if self.db is not None:
            self.control_stop.set()
            if self.control_thread is not None:
                self.control_thread.join(timeout=1.0)
            try:
                self.db.finish_session(self.session_id)
            finally:
                dropped = self.db.dropped
                self.db.close()
                if dropped:
                    ctx.log.warn(f"snagbox dropped {dropped} events because the SQLite write queue was full")
                self.db = None


addons = [NetTraceAddon()]
