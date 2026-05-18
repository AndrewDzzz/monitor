"""Hugging Face config evidence collection for ModelFP."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def _node(eid: str, file: str, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    node = {
        "id": eid,
        "evidence_type": "config_risk",
        "source": "config_scanner",
        "file": file,
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
    }
    node.update(extra)
    return node


def scan_config(model_dir: str | Path, model: str, revision: str, run_id: str) -> List[Dict[str, Any]]:
    model_dir = Path(model_dir)
    evidence: List[Dict[str, Any]] = []
    idx = 1

    for name in ["config.json", "tokenizer_config.json", "generation_config.json"]:
        path = model_dir / name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            evidence.append(_node(f"C{idx:04d}", name, "config_parse_error", "medium", f"Could not parse {name}: {exc}", model=model, revision=revision, run_id=run_id)); idx += 1
            continue

        if isinstance(data, dict) and "auto_map" in data:
            evidence.append(_node(f"C{idx:04d}", name, "auto_map_present", "high", "Config can route loading to custom Python code via auto_map.", keys=list(data.get("auto_map", {}).keys()) if isinstance(data.get("auto_map"), dict) else [], model=model, revision=revision, run_id=run_id)); idx += 1

        if isinstance(data, dict) and data.get("trust_remote_code") is True:
            evidence.append(_node(f"C{idx:04d}", name, "trust_remote_code_true", "critical", "Config explicitly indicates trust_remote_code=true.", model=model, revision=revision, run_id=run_id)); idx += 1

        architectures = data.get("architectures") if isinstance(data, dict) else None
        if isinstance(architectures, list):
            suspicious = [a for a in architectures if isinstance(a, str) and any(x in a.lower() for x in ["loader", "remote", "custom"])]
            if suspicious:
                evidence.append(_node(f"C{idx:04d}", name, "suspicious_architecture_name", "medium", "Architecture names suggest custom loading or remote behavior.", architectures=suspicious, model=model, revision=revision, run_id=run_id)); idx += 1

    # Repository-level custom code indicator from common HF filenames.
    custom_files = []
    for pattern in ["modeling_*.py", "tokenization_*.py", "configuration_*.py", "loader.py", "install.py", "setup.py"]:
        custom_files.extend(str(p.relative_to(model_dir)) for p in model_dir.glob(pattern))
    if custom_files:
        evidence.append(_node(f"C{idx:04d}", "<repo>", "custom_python_files_present", "medium", "Repository contains custom Python files that may execute during loading or setup.", files=sorted(set(custom_files)), model=model, revision=revision, run_id=run_id)); idx += 1

    return evidence
