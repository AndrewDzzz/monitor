"""Run ModelScan and normalize its output into ModelFP static evidence nodes."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _node(idx: int, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": f"S{idx:04d}",
        "source": "modelscan",
        "evidence_type": "static_artifact",
        "finding": finding,
        "severity": severity.lower(),
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def _walk(obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def normalize_modelscan_report(report: Any) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    idx = 1
    seen = set()
    for item in _walk(report):
        severity = item.get("severity") or item.get("Severity") or item.get("level") or item.get("risk")
        if not severity:
            continue
        sev = str(severity).lower()
        if sev not in {"critical", "high", "medium", "low", "info"}:
            continue
        finding = (
            item.get("message") or item.get("description") or item.get("finding") or
            item.get("scanner") or item.get("operator") or item.get("unsafe_operator") or "modelscan_finding"
        )
        file_name = item.get("file") or item.get("path") or item.get("source") or item.get("module")
        key = (sev, str(finding), str(file_name))
        if key in seen:
            continue
        seen.add(key)
        nodes.append(_node(idx, "modelscan_reported_issue", sev, "ModelScan reported a static model artifact issue.", file=file_name, raw=item)); idx += 1
    return nodes


def run_modelscan(path: Path, report_json: Path) -> Dict[str, Any]:
    report_json.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["modelscan", "-p", str(path), "-r", "json", "-o", str(report_json), "--show-skipped"]
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = {
        "command": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-10000:],
        "stderr": proc.stderr[-10000:],
    }
    if report_json.exists():
        try:
            result["json_report"] = json.loads(report_json.read_text(encoding="utf-8"))
        except Exception as exc:
            result["json_parse_error"] = str(exc)
    return result


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True, help="Model repo/artifact path to scan")
    parser.add_argument("--out", default="/workspace/out/evidence/modelscan_evidence.jsonl")
    parser.add_argument("--raw-report", default="/workspace/out/static/modelscan_report.json")
    args = parser.parse_args()

    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    raw_report = Path(args.raw_report)
    try:
        run_result = run_modelscan(Path(args.path), raw_report)
        nodes = normalize_modelscan_report(run_result.get("json_report", {}))
        if not nodes:
            sev = "info" if run_result["returncode"] == 0 else "medium"
            nodes = [_node(1, "modelscan_no_normalized_findings", sev, "ModelScan ran but no issue nodes were normalized.", raw_run=run_result)]
    except FileNotFoundError:
        nodes = [_node(1, "modelscan_not_available", "medium", "modelscan command is not installed in this environment.")]
    except Exception as exc:
        nodes = [_node(1, "modelscan_failed", "medium", f"ModelScan failed: {exc}")]

    with out.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
