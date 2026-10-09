from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

from mitmproxy import ctx

from database import AsyncNetTraceDB, read_capture_state


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


class NetTraceAddon:
    def __init__(self) -> None:
        self.db: AsyncNetTraceDB | None = None
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
        while not self.control_stop.wait(0.25):
            if self.db_path is None:
                continue
            try:
                state = read_capture_state(self.db_path)
            except Exception:
                continue
            with self.capture_state_lock:
                self.capture_state = state

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
        queued = self._require_db().ensure_conn(
            uid, stamp(ts), proto, orig_h, orig_p, resp_h, resp_p,
            self.session_id, self.label, local_flag(orig_h), local_flag(resp_h),
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

    def response(self, flow) -> None:
        if not self._is_listening():
            return
        request = flow.request
        response = flow.response
        request_body = bytes(request.raw_content) if request and request.raw_content is not None else None
        response_body = bytes(response.raw_content) if response and response.raw_content is not None else None
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
