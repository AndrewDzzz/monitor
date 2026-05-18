"""Collect ModelFP environment evidence inside the runtime container."""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

SECRET_KEY_HINTS = (
    "TOKEN", "SECRET", "PASSWORD", "PASSWD", "KEY", "CREDENTIAL", "AWS_", "GCP_",
    "AZURE_", "OPENAI_", "ANTHROPIC_", "HF_", "HUGGINGFACE_",
)

DEFAULT_IGNORED_SECRET_ENV_KEYS = {
    # Present in official Python base images as release-verification metadata,
    # not as a runtime credential for the audited target.
    "GPG_KEY",
}


def _node(idx: int, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": f"ENV{idx:04d}",
        "source": "env_probe",
        "evidence_type": "environment",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def collect_environment_evidence() -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    i = 1
    ignored_secret_keys = set(DEFAULT_IGNORED_SECRET_ENV_KEYS)
    ignored_secret_keys.update(
        key.strip()
        for key in os.environ.get("MODELFP_ENV_IGNORE_KEYS", "").split(",")
        if key.strip()
    )

    if os.geteuid() == 0:
        nodes.append(_node(i, "running_as_root", "high", "The model process is running as root inside the container.")); i += 1

    for key in sorted(os.environ):
        if key in ignored_secret_keys:
            continue
        if any(hint in key.upper() for hint in SECRET_KEY_HINTS):
            nodes.append(_node(i, "secret_like_environment_variable_exposed", "high", f"Environment variable {key} is visible to the target process.", env_key=key)); i += 1

    sensitive_paths = [
        ("/var/run/docker.sock", "docker_socket_available", "critical", "Docker socket is visible; this may allow host/container control."),
        (str(Path.home() / ".ssh"), "ssh_directory_visible", "critical", "SSH directory is visible to the target process."),
        (str(Path.home() / ".aws"), "aws_directory_visible", "critical", "AWS credential directory is visible to the target process."),
        (str(Path.home() / ".config/gcloud"), "gcloud_directory_visible", "critical", "GCloud credential directory is visible to the target process."),
        ("/root/.ssh", "root_ssh_directory_visible", "critical", "Root SSH directory is visible to the target process."),
    ]
    for path, finding, severity, meaning in sensitive_paths:
        try:
            exists = Path(path).exists()
        except PermissionError:
            nodes.append(_node(i, "sensitive_path_permission_denied", "medium", f"Permission denied while checking sensitive path {path}.", path=path)); i += 1
            continue
        if exists:
            nodes.append(_node(i, finding, severity, meaning, path=path)); i += 1

    # Mount inspection: highlight read-write host-looking mounts.
    mounts = []
    proc_mounts = Path("/proc/mounts")
    if proc_mounts.exists():
        for line in proc_mounts.read_text(errors="ignore").splitlines():
            parts = line.split()
            if len(parts) >= 4:
                src, dst, fstype, opts = parts[:4]
                mounts.append({"src": src, "dst": dst, "fstype": fstype, "opts": opts})
                if "rw" in opts.split(",") and dst in {"/", "/workspace", "/workspace/out", "/mnt", "/home"}:
                    sev = "medium" if dst == "/workspace/out" else "high"
                    nodes.append(_node(i, "read_write_mount", sev, f"Read-write mount visible at {dst}.", mount={"src": src, "dst": dst, "opts": opts})); i += 1

    nodes.append(_node(i, "environment_snapshot", "info", "Container environment snapshot collected.", uid=os.geteuid(), gid=os.getegid(), cwd=os.getcwd(), mounts_count=len(mounts)))
    return nodes


def main() -> int:
    out = Path(os.environ.get("MODELFP_ENV_EVIDENCE", "/workspace/out/evidence/env_evidence.jsonl"))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fp:
        for node in collect_environment_evidence():
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
