"""Normalize strace and Python audit logs into ModelFP runtime evidence nodes."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

STRACE_RE = re.compile(r"^(?:(?P<ts>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?(?P<syscall>[A-Za-z_][A-Za-z0-9_]*)\((?P<args>.*)\)\s+=\s+(?P<ret>.+?)(?:\s+<(?P<dur>[0-9.]+)>)?$")
QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
PORT_RE = re.compile(r"sin_port=htons\((\d+)\)")
IP_RE = re.compile(r"inet_addr\(\"([^\"]+)\"\)|inet_pton\([^,]+, \"([^\"]+)\"")

SECRET_PATH_PATTERNS = [
    re.compile(r"/\.ssh/"), re.compile(r"/\.aws/credentials"), re.compile(r"/\.config/gcloud/"),
    re.compile(r"/\.kube/config"), re.compile(r"/etc/shadow"), re.compile(r"/etc/sudoers"),
]
SYSTEM_PATHS = [re.compile(r"^/etc/passwd$"), re.compile(r"^/etc/shadow$"), re.compile(r"^/etc/sudoers")]
SHELLS = {"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash", "/bin/zsh", "/usr/bin/zsh"}

TYPE_MAP = {
    "repository": "repo_finding",
    "repo_finding": "repo_finding",
    "malware_static": "malware_static_finding",
    "malware_static_finding": "malware_static_finding",
    "static_fusion": "static_fusion_finding",
    "static_fusion_finding": "static_fusion_finding",
    "static_code": "static_code_finding",
    "static_code_finding": "static_code_finding",
    "config": "config_finding",
    "config_risk": "config_finding",
    "config_finding": "config_finding",
    "static_artifact": "static_artifact_finding",
    "static_artifact_finding": "static_artifact_finding",
    "environment": "environment_finding",
    "environment_finding": "environment_finding",
    "runtime_event": "runtime_event",
    "literature_grounding": "literature_grounding",
}


def _result_success(ret: str) -> bool:
    return not ret.strip().startswith("-1")


def _parse_ret_fd(ret: str) -> Optional[int]:
    m = re.match(r"(\d+)", ret.strip())
    return int(m.group(1)) if m else None


def _first_quoted(args: str) -> Optional[str]:
    m = QUOTED_RE.search(args)
    return m.group(1) if m else None


def _path_class(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    if path in SHELLS:
        return "shell"
    if path == "/var/run/docker.sock":
        return "docker_socket"
    if any(p.search(path) for p in SECRET_PATH_PATTERNS):
        return "secret"
    if any(p.search(path) for p in SYSTEM_PATHS):
        return "system_sensitive"
    if path.startswith("/tmp/") and path.endswith((".py", ".sh", ".so", ".elf")):
        return "tmp_executable"
    return None


def _is_external_ip(ip: Optional[str]) -> Optional[bool]:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved)
    except Exception:
        return None


def _parse_fd_arg(args: str) -> Optional[int]:
    first = args.split(",", 1)[0].strip()
    m = re.match(r"(\d+)", first)
    return int(m.group(1)) if m else None


def parse_strace_file(path: Path, id_start: int = 1) -> Tuple[List[Dict[str, Any]], int]:
    nodes: List[Dict[str, Any]] = []
    next_id = id_start
    pid = path.name.rsplit(".", 1)[-1] if "." in path.name else None
    fd_labels: Dict[int, Dict[str, Any]] = {}

    for line_no, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("+++") or line.startswith("---"):
            continue
        m = STRACE_RE.match(line)
        if not m:
            continue
        syscall = m.group("syscall")
        args = m.group("args")
        ret = m.group("ret")
        success = _result_success(ret)
        node: Dict[str, Any] = {
            "id": f"E{next_id:06d}",
            "source": "strace",
            "evidence_type": "runtime_event",
            "time": time.time(),
            "trace_time": m.group("ts"),
            "pid": int(pid) if pid and pid.isdigit() else pid,
            "phase": "LOAD_AND_INFERENCE",
            "op": syscall,
            "result": "success" if success else "failure",
            "raw": line[:3000],
            "line_no": line_no,
            "file": str(path),
        }

        if syscall in {"open", "openat", "creat"}:
            p = _first_quoted(args)
            node["op"] = "open"
            node["path"] = p
            node["path_class"] = _path_class(p)
            node["mode"] = "write_or_create" if any(flag in args for flag in ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"]) else "read"
            fd = _parse_ret_fd(ret) if success else None
            if fd is not None:
                node["fd"] = fd
                fd_labels[fd] = {"path": p, "path_class": node.get("path_class"), "mode": node.get("mode")}
        elif syscall == "execve":
            p = _first_quoted(args)
            node["path"] = p
            node["path_class"] = _path_class(p)
        elif syscall in {"unlink", "unlinkat", "rename", "renameat", "renameat2", "chmod", "fchmod", "ftruncate"}:
            p = _first_quoted(args)
            node["path"] = p
            node["path_class"] = _path_class(p)
        elif syscall in {"socket"}:
            fd = _parse_ret_fd(ret) if success else None
            if fd is not None:
                node["fd"] = fd
                fd_labels[fd] = {"fd_type": "socket"}
        elif syscall in {"connect"}:
            fd = _parse_fd_arg(args)
            node["fd"] = fd
            pm = PORT_RE.search(args)
            if pm:
                node["port"] = int(pm.group(1))
            im = IP_RE.search(args)
            ip = None
            if im:
                ip = im.group(1) or im.group(2)
                node["dst"] = ip
                external = _is_external_ip(ip)
                node["dst_type"] = "external" if external else ("internal" if external is False else "unknown")
            if fd is not None:
                fd_labels.setdefault(fd, {})["fd_type"] = "socket"
                fd_labels[fd]["dst_type"] = node.get("dst_type", "unknown")
                fd_labels[fd]["dst"] = node.get("dst")
        elif syscall in {"read", "write", "sendto", "recvfrom"}:
            fd = _parse_fd_arg(args)
            node["fd"] = fd
            if fd is not None and fd in fd_labels:
                node.update({f"fd_{k}": v for k, v in fd_labels[fd].items()})
            if syscall in {"sendto"}:
                node["op"] = "write"
            elif syscall in {"recvfrom"}:
                node["op"] = "read"

        # Simple risk hints for downstream chunking/GPT payload.
        hints = []
        if node.get("path_class") in {"secret", "system_sensitive", "docker_socket", "shell", "tmp_executable"}:
            hints.append(str(node["path_class"]))
        if node.get("dst_type") == "external":
            hints.append("external_network")
        if node["op"] in {"execve", "connect", "open", "write"} and hints:
            node["risk_hints"] = hints

        nodes.append(node)
        next_id += 1
    return nodes, next_id


def parse_audit_jsonl(path: Path, id_start: int) -> Tuple[List[Dict[str, Any]], int]:
    nodes: List[Dict[str, Any]] = []
    next_id = id_start
    if not path.exists():
        return nodes, next_id
    for line_no, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        op = rec.get("op") or rec.get("event")
        node = {
            "id": f"E{next_id:06d}",
            "source": "python_audit",
            "evidence_type": "runtime_event",
            "time": rec.get("time", time.time()),
            "pid": rec.get("pid"),
            "ppid": rec.get("ppid"),
            "phase": rec.get("phase", "LOAD_AND_INFERENCE"),
            "op": op,
            "args": rec.get("args", []),
            "result": rec.get("result", "observed"),
            "raw": rec,
            "line_no": line_no,
        }
        hints = []
        if op in {"os.system", "subprocess.Popen", "exec", "eval", "compile", "socket.connect", "socket.create_connection", "open", "os.open"}:
            hints.append("python_sensitive_event")
        if hints:
            node["risk_hints"] = hints
        nodes.append(node)
        next_id += 1
    return nodes, next_id


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out


def _canonical_type(ev: Dict[str, Any]) -> str:
    evidence_type = str(ev.get("evidence_type") or ev.get("type") or "unknown")
    return TYPE_MAP.get(evidence_type, evidence_type)


def normalize_node(ev: Dict[str, Any], model: str, revision: str, run_id: str) -> Dict[str, Any]:
    """Add the stable fields expected by the public evidence schema."""
    node = dict(ev)
    node.setdefault("model", model)
    node.setdefault("revision", revision)
    node.setdefault("run_id", run_id)
    node.setdefault("type", _canonical_type(node))
    node.setdefault("evidence_type", node["type"])
    node["run_context"] = {
        "model": str(node.get("model", model)),
        "revision": str(node.get("revision", revision)),
        "run_id": str(node.get("run_id", run_id)),
    }
    return node


def build_evidence_graph(out_dir: Path, model: str = "local/model", revision: str = "local", run_id: str = "local-run") -> Dict[str, Any]:
    evidence: List[Dict[str, Any]] = []
    for name in [
        "all_files_static_evidence.jsonl",
        "repo_evidence.jsonl",
        "repo_hygiene_evidence.jsonl",
        "malware_static_evidence.jsonl",
        "python_ast_evidence.jsonl",
        "config_evidence.jsonl",
        "env_evidence.jsonl",
        "h5_static_evidence.jsonl",
        "pickle_static_evidence.jsonl",
        "modelscan_evidence.jsonl",
        "static_fusion_evidence.jsonl",
    ]:
        evidence.extend(read_jsonl(out_dir / "evidence" / name))

    next_id = 1
    runtime: List[Dict[str, Any]] = []
    for sf in sorted((out_dir / "traces").glob("strace*")):
        if sf.name.endswith(".log") or sf.name.startswith("strace"):
            parsed, next_id = parse_strace_file(sf, next_id)
            runtime.extend(parsed)
    audit_nodes, next_id = parse_audit_jsonl(out_dir / "traces" / "python_audit.jsonl", next_id)
    runtime.extend(audit_nodes)
    evidence.extend(runtime)
    evidence = [normalize_node(ev, model, revision, run_id) for ev in evidence]

    return {
        "schema": "modelfp.evidence_graph.v1",
        "model": model,
        "revision": revision,
        "run_id": run_id,
        "generated_at": time.time(),
        "evidence_count": len(evidence),
        "runtime_event_count": len(runtime),
        "evidence": evidence,
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="/workspace/out")
    parser.add_argument("--output", default="/workspace/out/evidence_graph.json")
    parser.add_argument("--model", default="local/model")
    parser.add_argument("--revision", default="local")
    parser.add_argument("--run-id", default="local-run")
    args = parser.parse_args()
    graph = build_evidence_graph(Path(args.out_dir), model=args.model, revision=args.revision, run_id=args.run_id)
    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
