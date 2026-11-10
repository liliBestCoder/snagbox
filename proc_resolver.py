from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import socket
import time
from typing import Any, Callable

# Win32 Structures
class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", wintypes.DWORD),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_void_p),
        ("BasePriority", wintypes.DWORD),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]

# Windows API loading
_iphlpapi = ctypes.WinDLL("iphlpapi.dll") if os.name == "nt" else None
_kernel32 = ctypes.WinDLL("kernel32.dll") if os.name == "nt" else None
_ntdll = ctypes.WinDLL("ntdll.dll") if os.name == "nt" else None

MAX_PATH = 260
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Cache for child PID -> target attribution
# {pid: (root_pid, root_proc_name, target_id, expire_ts)}
_pid_target_cache: dict[int, tuple[int | None, str | None, str | None, float]] = {}
_targets_cache: tuple[dict[int, dict[str, Any]], float] = ({}, 0.0)
TARGET_CACHE_TTL = 3.0  # seconds
PID_TARGET_TTL = 30.0   # seconds


def get_process_info_by_pid(pid: int) -> tuple[str | None, str | None]:
    """Return (process_name, process_path) for the given PID."""
    if not _kernel32 or pid <= 4:
        return ("System" if pid == 4 else None, None)
    
    h = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return (None, None)
    try:
        buf = (ctypes.c_wchar * MAX_PATH)()
        size = wintypes.DWORD(MAX_PATH)
        if _kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            path = buf.value
            return (os.path.basename(path), path)
        return (None, None)
    finally:
        _kernel32.CloseHandle(h)


def get_parent_pid(pid: int) -> int:
    """Return parent PID using NtQueryInformationProcess."""
    if not _ntdll or not _kernel32 or pid <= 4:
        return 0
    h = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return 0
    try:
        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = wintypes.ULONG()
        status = _ntdll.NtQueryInformationProcess(
            h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
        )
        if status == 0 and pbi.InheritedFromUniqueProcessId:
            return int(pbi.InheritedFromUniqueProcessId)
        return 0
    finally:
        _kernel32.CloseHandle(h)


def find_pid_by_client_port(client_port: int) -> int | None:
    """Find the owning process ID for an inbound TCP connection by client source port."""
    if not _iphlpapi or client_port <= 0:
        return None

    size = wintypes.DWORD(0)
    # AF_INET = 2, TCP_TABLE_OWNER_PID_ALL = 5
    _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), True, 2, 5, 0)
    buf = (ctypes.c_byte * size.value)()
    if _iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), True, 2, 5, 0) != 0:
        return None

    num_entries = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
    p_entries = ctypes.cast(ctypes.byref(buf, 4), ctypes.POINTER(MIB_TCPROW_OWNER_PID))

    for i in range(num_entries):
        row = p_entries[i]
        local_port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        if local_port == client_port:
            return int(row.dwOwningPid)

    return None


def _get_active_targets(target_provider: Callable[[], list[dict[str, Any]]] | None = None) -> dict[int, dict[str, Any]]:
    """Return mapping of rootPid -> target info, cached for TARGET_CACHE_TTL seconds."""
    global _targets_cache
    now = time.monotonic()
    targets_map, last_ts = _targets_cache
    if now - last_ts < TARGET_CACHE_TTL:
        return targets_map

    if target_provider is None:
        try:
            from mcp_server import _list_snagbox_targets
            res = _list_snagbox_targets()
            targets_list = res.get("targets", []) if isinstance(res, dict) else []
        except Exception:
            targets_list = []
    else:
        try:
            targets_list = target_provider() or []
        except Exception:
            targets_list = []

    new_map: dict[int, dict[str, Any]] = {}
    for t in targets_list:
        if not isinstance(t, dict):
            continue
        pid = t.get("pid")
        if pid and isinstance(pid, int) and pid > 0 and t.get("status") == "running":
            new_map[pid] = t

    _targets_cache = (new_map, now)
    return new_map


def resolve_process_and_target(
    client_port: int | None,
    max_ancestor_depth: int = 5,
    target_provider: Callable[[], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """
    Resolve client port to:
      - pid: physical process ID
      - process_name: process executable name
      - process_path: full executable path
      - root_pid: root target process ID (if matched within max_ancestor_depth)
      - root_process_name: root target process name
      - target_id: matched Ghost target ID
    """
    result = {
        "pid": None,
        "process_name": None,
        "process_path": None,
        "root_pid": None,
        "root_process_name": None,
        "target_id": None,
    }

    if not client_port or client_port <= 0:
        return result

    pid = find_pid_by_client_port(client_port)
    if not pid:
        return result

    result["pid"] = pid
    proc_name, proc_path = get_process_info_by_pid(pid)
    result["process_name"] = proc_name
    result["process_path"] = proc_path

    # Check cache for PID -> Target attribution
    now = time.monotonic()
    if pid in _pid_target_cache:
        cached_root_pid, cached_root_name, cached_target_id, exp = _pid_target_cache[pid]
        if now < exp:
            result["root_pid"] = cached_root_pid
            result["root_process_name"] = cached_root_name
            result["target_id"] = cached_target_id
            return result

    # Up to max_ancestor_depth levels to find Ghost target rootPid
    root_targets = _get_active_targets(target_provider)
    curr = pid
    matched_target = None
    visited = set()

    for _ in range(max_ancestor_depth):
        if curr <= 0 or curr in visited:
            break
        visited.add(curr)

        if curr in root_targets:
            matched_target = root_targets[curr]
            break

        curr = get_parent_pid(curr)

    if matched_target is not None:
        result["root_pid"] = matched_target.get("pid")
        result["root_process_name"] = matched_target.get("name")
        result["target_id"] = matched_target.get("targetId")

    # Cache result for this child PID
    _pid_target_cache[pid] = (
        result["root_pid"],
        result["root_process_name"],
        result["target_id"],
        now + PID_TARGET_TTL,
    )

    return result
