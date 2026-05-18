"""Best-effort strace parser for ModelFP runtime evidence.

This parser intentionally extracts only a compact subset useful for ModelFP rules:
open/read/write/connect/execve and fd mappings. Raw logs are still preserved.
"""
from __future__ import annotations

import glob
import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

OPEN_RE = re.compile(r'(?P<syscall>openat|open)\([^\"]*"(?P<path>[^"]+)"(?P<rest>.*?)\)\s+=\s+(?P<ret>-?\d+)')
EXEC_RE = re.compile(r'execve\("(?P<path>[^"]+)".*\)\s+=\s+(?P<ret>-?\d+)')
READ_RE = re.compile(r'read\((?P<fd>\d+),.*\)\s+=\s+(?P<ret>-?\d+)')
WRITE_RE = re.compile(r'write\((?P<fd>\d+),.*\)\s+=\s+(?P<ret>-?\d+)')
CONNECT_RE = re.compile(r'connect\((?P<fd>\d+),.*?(sin_addr=inet_addr\("(?P<ip>[^"]+)"\)|inet_addr\("(?P<ip2>[^"]+)"\)).*\)\s+=\s+(?P<ret>-?\d+)')
TIME_RE = re.compile(r'^(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+')

SECRET_PATTERNS = [
    re.compile(r"/home/[^/]+/\.ssh/"),
    re.compile(r"/root/\.ssh/"),
    re.compile(r"/home/[^/]+/\.aws/credentials"),
    re.compile(r"/home/[^/]+/\.config/gcloud/"),
    re.compile(r"/home/[^/]+/\.kube/config"),
]
SHELL_PATHS = {"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash"}


def _result(ret: int) -> str:
    return "success" if ret >= 0 else "failure"


def _path_class(path: str) -> Optional[str]:
    if path in SHELL_PATHS:
        return "shell"
    if path == "/var/run/docker.sock":
        return "docker_socket"
    if path in {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}:
        return "system_sensitive"
    if any(p.search(path) for p in SECRET_PATTERNS):
        return "secret"
    return None


def _dst_type(ip: str) -> str:
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local:
            return "internal"
        return "external"
    except ValueError:
        return "unknown"


def _pid_from_filename(path: str) -> Optional[int]:
    suffix = Path(path).name.split(".")[-1]
    try:
        return int(suffix)
    except Exception:
        return None


def parse_strace_logs(strace_base: str | Path, model: str, revision: str, run_id: str, phase: str = "LOAD") -> List[Dict[str, Any]]:
    base = str(strace_base)
    files = sorted(glob.glob(base + "*"))
    evidence: List[Dict[str, Any]] = []
    fd_labels: Dict[tuple[int | None, int], Dict[str, Any]] = {}
    idx = 1

    for file_path in files:
        if os.path.isdir(file_path):
            continue
        pid = _pid_from_filename(file_path)
        try:
            lines = Path(file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for line in lines:
            raw = line[:2000]
            time_match = TIME_RE.match(line)
            time_value = time_match.group("time") if time_match else None
            body = TIME_RE.sub("", line, count=1)

            ev: Optional[Dict[str, Any]] = None
            m = OPEN_RE.search(body)
            if m:
                ret = int(m.group("ret"))
                path = m.group("path")
                rest = m.group("rest")
                mode = "write_or_create" if any(flag in rest for flag in ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"]) else "read"
                ev = {
                    "op": "open",
                    "path": path,
                    "mode": mode,
                    "result": _result(ret),
                    "fd": ret if ret >= 0 else None,
                    "path_class": _path_class(path),
                }
                if ret >= 0:
                    fd_labels[(pid, ret)] = {"path": path, "path_class": ev.get("path_class"), "fd_kind": "file"}
            else:
                m = EXEC_RE.search(body)
                if m:
                    ret = int(m.group("ret"))
                    path = m.group("path")
                    ev = {"op": "execve", "path": path, "result": _result(ret), "path_class": _path_class(path)}
                else:
                    m = CONNECT_RE.search(body)
                    if m:
                        ret = int(m.group("ret"))
                        fd = int(m.group("fd"))
                        ip = m.group("ip") or m.group("ip2") or ""
                        ev = {"op": "connect", "fd": fd, "dst_ip": ip, "dst_type": _dst_type(ip), "result": _result(ret)}
                        if ret >= 0:
                            fd_labels[(pid, fd)] = {"dst_ip": ip, "dst_type": ev.get("dst_type"), "fd_kind": "socket"}
                    else:
                        m = READ_RE.search(body)
                        if m:
                            fd = int(m.group("fd")); ret = int(m.group("ret"))
                            label = fd_labels.get((pid, fd), {})
                            ev = {"op": "read", "fd": fd, "result": _result(ret), **label}
                        else:
                            m = WRITE_RE.search(body)
                            if m:
                                fd = int(m.group("fd")); ret = int(m.group("ret"))
                                label = fd_labels.get((pid, fd), {})
                                ev = {"op": "write", "fd": fd, "result": _result(ret), **label}

            if ev is not None:
                ev.update({
                    "id": f"E{idx:06d}",
                    "evidence_type": "runtime_event",
                    "source": "strace",
                    "phase": phase,
                    "pid": pid,
                    "time": idx,  # monotonic event index; raw_time keeps strace clock when available
                    "raw_time": time_value,
                    "raw": raw,
                    "model": model,
                    "revision": revision,
                    "run_id": run_id,
                    "severity": "info",
                })
                evidence.append(ev)
                idx += 1
    return evidence
