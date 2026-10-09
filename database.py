from __future__ import annotations

import sqlite3
import logging
import queue
import threading
import uuid
from pathlib import Path
from typing import Any

SCHEMA = r'''
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS capture_control (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    state TEXT NOT NULL CHECK (state IN ('listening', 'suspended', 'stopped')),
    active_session_id TEXT,
    updated_at REAL NOT NULL
);
INSERT OR IGNORE INTO capture_control(singleton_id, state, updated_at)
VALUES (1, 'listening', strftime('%s','now'));

CREATE TABLE IF NOT EXISTS capture_session (
    session_id TEXT PRIMARY KEY,
    started_at REAL NOT NULL,
    ended_at REAL,
    capture_label TEXT NOT NULL,
    notes TEXT,
    mitmproxy_version TEXT
);

CREATE TABLE IF NOT EXISTS conn (
    uid TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    "id.orig_h" TEXT,
    "id.orig_p" INTEGER,
    "id.resp_h" TEXT,
    "id.resp_p" INTEGER,
    proto TEXT NOT NULL,
    service TEXT,
    duration REAL,
    orig_bytes INTEGER,
    resp_bytes INTEGER,
    conn_state TEXT,
    local_orig INTEGER,
    local_resp INTEGER,
    missed_bytes INTEGER,
    history TEXT,
    orig_pkts INTEGER,
    orig_ip_bytes INTEGER,
    resp_pkts INTEGER,
    resp_ip_bytes INTEGER,
    session_id TEXT NOT NULL,
    capture_label TEXT NOT NULL,
    error TEXT,
    FOREIGN KEY(session_id) REFERENCES capture_session(session_id)
);
CREATE INDEX IF NOT EXISTS idx_conn_ts ON conn(ts);
CREATE INDEX IF NOT EXISTS idx_conn_orig ON conn("id.orig_h", "id.orig_p");
CREATE INDEX IF NOT EXISTS idx_conn_resp ON conn("id.resp_h", "id.resp_p");

CREATE TABLE IF NOT EXISTS http (
    uid TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    "id.orig_h" TEXT,
    "id.orig_p" INTEGER,
    "id.resp_h" TEXT,
    "id.resp_p" INTEGER,
    trans_depth INTEGER,
    method TEXT,
    host TEXT,
    uri TEXT,
    referrer TEXT,
    version TEXT,
    user_agent TEXT,
    request_headers TEXT,
    response_headers TEXT,
    request_body_len INTEGER,
    response_body_len INTEGER,
    request_body BLOB,
    response_body BLOB,
    status_code INTEGER,
    status_msg TEXT,
    tags TEXT,
    session_id TEXT NOT NULL,
    capture_label TEXT NOT NULL,
    error TEXT,
    FOREIGN KEY(session_id) REFERENCES capture_session(session_id)
);
CREATE INDEX IF NOT EXISTS idx_http_ts ON http(ts);
CREATE INDEX IF NOT EXISTS idx_http_host ON http(host);

CREATE TABLE IF NOT EXISTS dns (
    uid TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    "id.orig_h" TEXT,
    "id.orig_p" INTEGER,
    "id.resp_h" TEXT,
    "id.resp_p" INTEGER,
    proto TEXT,
    trans_id INTEGER,
    rtt REAL,
    query TEXT,
    qclass INTEGER,
    qclass_name TEXT,
    qtype INTEGER,
    qtype_name TEXT,
    rcode INTEGER,
    rcode_name TEXT,
    AA INTEGER,
    TC INTEGER,
    RD INTEGER,
    RA INTEGER,
    Z INTEGER,
    answers TEXT,
    TTLs TEXT,
    rejected INTEGER,
    session_id TEXT NOT NULL,
    capture_label TEXT NOT NULL,
    error TEXT,
    FOREIGN KEY(session_id) REFERENCES capture_session(session_id)
);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns(ts);
CREATE INDEX IF NOT EXISTS idx_dns_query ON dns(query);

CREATE TABLE IF NOT EXISTS tcp_message (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ts REAL NOT NULL,
    message_index INTEGER NOT NULL,
    from_client INTEGER NOT NULL,
    content BLOB NOT NULL,
    content_len INTEGER NOT NULL,
    FOREIGN KEY(uid) REFERENCES conn(uid),
    FOREIGN KEY(session_id) REFERENCES capture_session(session_id)
);
CREATE INDEX IF NOT EXISTS idx_tcp_message_uid ON tcp_message(uid, message_index);

CREATE TABLE IF NOT EXISTS udp_message (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ts REAL NOT NULL,
    message_index INTEGER NOT NULL,
    from_client INTEGER NOT NULL,
    content BLOB NOT NULL,
    content_len INTEGER NOT NULL,
    FOREIGN KEY(uid) REFERENCES conn(uid),
    FOREIGN KEY(session_id) REFERENCES capture_session(session_id)
);
CREATE INDEX IF NOT EXISTS idx_udp_message_uid ON udp_message(uid, message_index);

CREATE TRIGGER IF NOT EXISTS capture_conn_insert_guard BEFORE INSERT ON conn
WHEN (SELECT state FROM capture_control WHERE singleton_id=1) != 'listening'
BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER IF NOT EXISTS capture_conn_update_guard BEFORE UPDATE ON conn
WHEN (SELECT state FROM capture_control WHERE singleton_id=1) != 'listening'
BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER IF NOT EXISTS capture_http_insert_guard BEFORE INSERT ON http
WHEN (SELECT state FROM capture_control WHERE singleton_id=1) != 'listening'
BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER IF NOT EXISTS capture_dns_insert_guard BEFORE INSERT ON dns
WHEN (SELECT state FROM capture_control WHERE singleton_id=1) != 'listening'
BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER IF NOT EXISTS capture_tcp_message_insert_guard BEFORE INSERT ON tcp_message
WHEN (SELECT state FROM capture_control WHERE singleton_id=1) != 'listening'
BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER IF NOT EXISTS capture_udp_message_insert_guard BEFORE INSERT ON udp_message
WHEN (SELECT state FROM capture_control WHERE singleton_id=1) != 'listening'
BEGIN SELECT RAISE(IGNORE); END;
'''

TABLE_DESCRIPTIONS = {
    "capture_session": "本机采集批次与人工标签。",
    "conn": "Zeek conn.log 风格的传输连接记录；包数及 IP 层字节数不可得时为 NULL。",
    "http": "HTTP 请求/响应元数据、完整头字段（JSON 键值对数组）及请求体/响应体原始实体字节（BLOB）。",
    "dns": "Zeek dns.log 风格的 DNS 查询与响应。",
    "tcp_message": "扩展表：mitmproxy 收到的 TCP 字节块；未信任根证书时可包含加密 TLS 隧道字节；块边界不等于协议消息边界。",
    "udp_message": "扩展表：mitmproxy 收到的独立 UDP datagram。",
}


class NetTraceDB:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=10.0)
        self.conn.execute("PRAGMA busy_timeout=10000")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        # Keep existing user databases usable when HTTP capture columns are added.
        http_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(http)")}
        for column, column_type in (
            ("request_headers", "TEXT"),
            ("response_headers", "TEXT"),
            ("request_body", "BLOB"),
            ("response_body", "BLOB"),
        ):
            if column not in http_columns:
                self.conn.execute(f"ALTER TABLE http ADD COLUMN {column} {column_type}")
        self.conn.commit()

    def start_session(self, label: str, mitmproxy_version: str = "unknown", notes: str = "") -> str:
        session_id = uuid.uuid4().hex
        self.conn.execute(
            "INSERT INTO capture_session(session_id, started_at, capture_label, notes, mitmproxy_version) "
            "VALUES (?, strftime('%s','now'), ?, ?, ?)",
            (session_id, label, notes, mitmproxy_version),
        )
        self.conn.execute(
            "UPDATE capture_control SET active_session_id=?, updated_at=strftime('%s','now') WHERE singleton_id=1",
            (session_id,),
        )
        self.conn.commit()
        return session_id

    def finish_session(self, session_id: str) -> None:
        self.conn.execute(
            "UPDATE capture_session SET ended_at=strftime('%s','now') WHERE session_id=?",
            (session_id,),
        )
        self.conn.execute(
            "UPDATE capture_control SET active_session_id=NULL, updated_at=strftime('%s','now') "
            "WHERE singleton_id=1 AND active_session_id=?",
            (session_id,),
        )
        self.conn.commit()

    def ensure_conn(
        self,
        uid: str,
        ts: float,
        proto: str,
        orig_h: str | None,
        orig_p: int | None,
        resp_h: str | None,
        resp_p: int | None,
        session_id: str,
        capture_label: str,
        local_orig: int | None = None,
        local_resp: int | None = None,
    ) -> None:
        self.conn.execute(
            '''INSERT OR IGNORE INTO conn
               (uid, ts, "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", proto,
                service, duration, orig_bytes, resp_bytes, conn_state, local_orig, local_resp,
                missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes,
                session_id, capture_label)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?,
                       NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)''',
            (uid, ts, orig_h, orig_p, resp_h, resp_p, proto, local_orig, local_resp, session_id, capture_label),
        )
        self.conn.commit()

    def add_transport_message(
        self,
        table: str,
        uid: str,
        session_id: str,
        ts: float,
        message_index: int,
        from_client: bool,
        content: bytes,
    ) -> None:
        if table not in {"tcp_message", "udp_message"}:
            raise ValueError("unsupported transport table")
        self.conn.execute(
            f"INSERT INTO {table}(uid, session_id, ts, message_index, from_client, content, content_len) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (uid, session_id, ts, message_index, int(from_client), sqlite3.Binary(content), len(content)),
        )
        self.conn.execute(
            "UPDATE conn SET orig_bytes=COALESCE(orig_bytes,0)+?, resp_bytes=COALESCE(resp_bytes,0)+? WHERE uid=?",
            (len(content) if from_client else 0, 0 if from_client else len(content), uid),
        )
        self.conn.commit()

    def finish_conn(self, uid: str, duration: float | None, state: str, error: str | None = None) -> None:
        self.conn.execute(
            "UPDATE conn SET duration=?, conn_state=?, error=? WHERE uid=?",
            (duration, state, error, uid),
        )
        self.conn.commit()

    def add_http(self, row: dict[str, Any]) -> None:
        cols = [
            "uid", "ts", '"id.orig_h"', '"id.orig_p"', '"id.resp_h"', '"id.resp_p"',
            "trans_depth", "method", "host", "uri", "referrer", "version", "user_agent",
            "request_headers", "response_headers",
            "request_body_len", "response_body_len", "request_body", "response_body",
            "status_code", "status_msg", "tags",
            "session_id", "capture_label", "error",
        ]
        values = [row.get(c.strip('"')) for c in cols]
        placeholders = ",".join("?" for _ in cols)
        self.conn.execute(f"INSERT OR REPLACE INTO http ({','.join(cols)}) VALUES ({placeholders})", values)
        self.conn.commit()

    def add_dns(self, row: dict[str, Any]) -> None:
        cols = [
            "uid", "ts", '"id.orig_h"', '"id.orig_p"', '"id.resp_h"', '"id.resp_p"',
            "proto", "trans_id", "rtt", "query", "qclass", "qclass_name", "qtype",
            "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD", "RA", "Z", "answers",
            "TTLs", "rejected", "session_id", "capture_label", "error",
        ]
        values = [row.get(c.strip('"')) for c in cols]
        placeholders = ",".join("?" for _ in cols)
        self.conn.execute(f"INSERT OR REPLACE INTO dns ({','.join(cols)}) VALUES ({placeholders})", values)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class AsyncNetTraceDB:
    """Non-blocking facade for mitmproxy hooks; SQLite is owned by one worker thread."""

    _STOP = object()

    def __init__(self, path: str | Path, max_queue_items: int = 8192, max_queue_bytes: int = 64 * 1024 * 1024):
        self.path = Path(path).expanduser().resolve()
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=max_queue_items)
        self._max_queue_bytes = max_queue_bytes
        self._pending_bytes = 0
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None
        self._logger = logging.getLogger("nettrace.sqlite")
        self._dropped = 0
        self._thread = threading.Thread(target=self._run, name="nettrace-sqlite-writer", daemon=True)
        self._thread.start()
        self._ready.wait()
        if self._startup_error:
            raise RuntimeError("Could not start NetTrace SQLite writer") from self._startup_error

    def _run(self) -> None:
        db: NetTraceDB | None = None
        try:
            db = NetTraceDB(self.path)
        except BaseException as exc:
            self._startup_error = exc
        finally:
            self._ready.set()
        if db is None:
            return
        while True:
            item = self._queue.get()
            if item is self._STOP:
                self._queue.task_done()
                break
            method, args, kwargs, size, result = item
            try:
                value = getattr(db, method)(*args, **kwargs)
                if result is not None:
                    result.put(value)
            except Exception as exc:
                self._logger.exception("NetTrace SQLite write failed (%s)", method)
                if result is not None:
                    result.put(exc)
            finally:
                with self._lock:
                    self._pending_bytes -= size
                self._queue.task_done()
        db.close()

    def start_session(self, label: str, mitmproxy_version: str = "unknown", notes: str = "") -> str:
        # Initialization is a one-time startup operation; wait for its result before accepting hooks.
        result: queue.Queue[Any] = queue.Queue(maxsize=1)
        self._queue.put(("start_session", (label, mitmproxy_version, notes), {}, 0, result))
        value = result.get()
        if isinstance(value, BaseException):
            raise RuntimeError("Could not create NetTrace capture session") from value
        return value

    def _submit(self, method: str, *args: Any, **kwargs: Any) -> bool:
        content = kwargs.get("content")
        size = len(content) if isinstance(content, (bytes, bytearray, memoryview)) else 0
        if method == "add_http" and args and isinstance(args[0], dict):
            row = args[0]
            size += sum(
                len(value)
                for key in ("request_body", "response_body")
                if isinstance((value := row.get(key)), (bytes, bytearray, memoryview))
            )
        with self._lock:
            # Let one oversized body drain when the queue is otherwise empty. This
            # preserves complete HTTP bodies while keeping multiple large blobs
            # from accumulating in the asynchronous writer queue.
            if self._pending_bytes and self._pending_bytes + size > self._max_queue_bytes:
                self._dropped += 1
                return False
            try:
                self._queue.put_nowait((method, args, kwargs, size, None))
            except queue.Full:
                self._dropped += 1
                return False
            self._pending_bytes += size
        return True

    def ensure_conn(self, *args: Any, **kwargs: Any) -> bool:
        return self._submit("ensure_conn", *args, **kwargs)

    def add_transport_message(self, *args: Any, **kwargs: Any) -> bool:
        return self._submit("add_transport_message", *args, **kwargs)

    def finish_conn(self, *args: Any, **kwargs: Any) -> bool:
        return self._submit("finish_conn", *args, **kwargs)

    def add_http(self, *args: Any, **kwargs: Any) -> bool:
        return self._submit("add_http", *args, **kwargs)

    def add_dns(self, *args: Any, **kwargs: Any) -> bool:
        return self._submit("add_dns", *args, **kwargs)

    def finish_session(self, *args: Any, **kwargs: Any) -> bool:
        return self._submit("finish_session", *args, **kwargs)

    def close(self) -> None:
        self._queue.join()
        self._queue.put(self._STOP)
        self._thread.join()

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped


def readonly_connection(path: str | Path) -> sqlite3.Connection:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"SQLite database does not exist: {p}")
    uri = p.as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def read_capture_state(path: str | Path) -> str:
    conn = readonly_connection(path)
    try:
        row = conn.execute(
            "SELECT state FROM capture_control WHERE singleton_id=1"
        ).fetchone()
        return str(row[0]) if row else "stopped"
    finally:
        conn.close()
