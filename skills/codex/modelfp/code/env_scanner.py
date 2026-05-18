"""Environment evidence collection for ModelFP."""
from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any, Dict, List

SECRET_ENV_MARKERS = (
    "TOKEN", "SECRET", "PASSWORD", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL",
)

COMMON_SECRET_PATHS = [
    ("ssh_key_mounted", Path.home() / ".ssh"),
    ("aws_credentials_mounted", Path.home() / ".aws"),
    ("gcloud_credentials_mounted", Path.home() / ".config" / "gcloud"),
    ("kube_config_mounted", Path.home() / ".kube"),
    ("docker_socket_mounted", Path("/var/run/docker.sock")),
]


def _ev(eid: str, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    node = {
        "id": eid,
        "evidence_type": "environment_finding",
        "source": "env_scanner",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
    }
    node.update(extra)
    return node


def collect_environment_evidence(model: str, revision: str, run_id: str) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    idx = 1

    if os.geteuid() == 0:
        evidence.append(_ev(f"ENV{idx:04d}", "running_as_root", "high", "Target process runs as root inside the container.", model=model, revision=revision, run_id=run_id)); idx += 1

    for finding, path in COMMON_SECRET_PATHS:
        if path.exists():
            severity = "critical" if finding == "docker_socket_mounted" else "high"
            evidence.append(_ev(f"ENV{idx:04d}", finding, severity, f"Sensitive path exists in runtime filesystem: {path}", path=str(path), model=model, revision=revision, run_id=run_id)); idx += 1

    exposed_names = []
    for name, value in os.environ.items():
        upper = name.upper()
        if any(marker in upper for marker in SECRET_ENV_MARKERS) and value:
            exposed_names.append(name)
    if exposed_names:
        evidence.append(_ev(
            f"ENV{idx:04d}",
            "secret_env_exposed",
            "critical",
            "One or more secret-like environment variables are exposed to the target process.",
            env_names=sorted(exposed_names),
            model=model,
            revision=revision,
            run_id=run_id,
        )); idx += 1

    # DNS/network heuristic. This is not a guarantee; runtime trace remains primary evidence.
    try:
        socket.getaddrinfo("example.com", 80)
        evidence.append(_ev(f"ENV{idx:04d}", "network_resolution_available", "medium", "The container can resolve external DNS names.", model=model, revision=revision, run_id=run_id)); idx += 1
    except Exception:
        evidence.append(_ev(f"ENV{idx:04d}", "network_resolution_blocked", "info", "External DNS resolution appears unavailable.", model=model, revision=revision, run_id=run_id)); idx += 1

    return evidence
