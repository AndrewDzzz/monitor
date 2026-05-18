"""Aggregate per-artifact pickle runtime outputs."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List


def _load(path: Path) -> Dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def aggregate(out_root: Path) -> Dict[str, Any]:
    artifacts: List[Dict[str, Any]] = []
    for artifact_dir in sorted((out_root / "artifacts").glob("*")):
        if not artifact_dir.is_dir():
            continue
        obs = _load(artifact_dir / "pickle_runtime_observations.json") or {}
        graph = _load(artifact_dir / "evidence_graph.json") or {}
        certs = _load(artifact_dir / "harm_certificates.json") or {}
        artifacts.append({
            "artifact_dir": artifact_dir.name,
            "observation": obs,
            "evidence_count": graph.get("evidence_count"),
            "runtime_event_count": graph.get("runtime_event_count"),
            "certificate_count": certs.get("count"),
            "verified_certificate_count": certs.get("verified_count"),
            "certificates": certs.get("certificates", []),
        })
    return {
        "schema": "modelfp.pickle_runtime_summary.v1",
        "generated_at_unix": time.time(),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Aggregate pickle runtime detonation results")
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    root = Path(args.out_root)
    summary = aggregate(root)
    out = Path(args.out) if args.out else root / "pickle_runtime_summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
