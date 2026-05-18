"""Collect ModelFP config evidence from a local Hugging Face model repo."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List

URL_RE = re.compile(r"https?://", re.I)


def _evidence(idx: int, file: str, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": f"C{idx:04d}",
        "source": "config_probe",
        "evidence_type": "config",
        "file": file,
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def scan_config(repo: Path) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    i = 1
    scanned_files: List[str] = []
    for name in ["config.json", "tokenizer_config.json", "generation_config.json", "preprocessor_config.json"]:
        path = repo / name
        if not path.exists():
            continue
        scanned_files.append(name)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            nodes.append(_evidence(i, name, "invalid_json", "medium", f"{name} is not valid JSON: {exc}")); i += 1
            continue

        if "auto_map" in data:
            nodes.append(_evidence(i, name, "auto_map_present", "high", "Config auto_map may route loading to custom Python code.", value=data.get("auto_map"))); i += 1
        if any("trust_remote_code" in str(k).lower() or "trust_remote_code" in str(v).lower() for k, v in data.items()):
            nodes.append(_evidence(i, name, "trust_remote_code_reference", "high", "Config references trust_remote_code, indicating custom code loading risk.")); i += 1
        if "architectures" in data and data.get("architectures"):
            nodes.append(_evidence(i, name, "architectures_declared", "info", "Config declares model architecture classes.", value=data.get("architectures"))); i += 1
        if "model_type" not in data and name == "config.json":
            nodes.append(_evidence(i, name, "model_type_missing", "low", "config.json does not declare model_type.")); i += 1

        text = json.dumps(data, ensure_ascii=False)
        if URL_RE.search(text):
            nodes.append(_evidence(i, name, "external_url_reference", "medium", "Config contains external URL references.")); i += 1

    nodes.append(_evidence(
        i,
        "<repo>",
        "config_static_summary",
        "info",
        "Config static judgment completed.",
        config_files_scanned=scanned_files,
        high_or_critical_count=sum(1 for node in nodes if node.get("severity") in {"high", "critical"}),
        medium_count=sum(1 for node in nodes if node.get("severity") == "medium"),
    ))
    return nodes


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out", default="/workspace/out/evidence/config_evidence.jsonl")
    parser.add_argument("--raw-report", default=None)
    args = parser.parse_args()
    nodes = scan_config(Path(args.repo))
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")
    if args.raw_report:
        raw = Path(args.raw_report)
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(json.dumps({
            "schema": "modelfp.config_static_report.v1",
            "generated_at_unix": time.time(),
            "repo": str(Path(args.repo)),
            "findings": nodes,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
