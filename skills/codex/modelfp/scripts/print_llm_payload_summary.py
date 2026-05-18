#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
p = Path(sys.argv[1] if len(sys.argv) > 1 else "workspace/out/llm_payload.json")
data = json.loads(p.read_text(encoding="utf-8"))
print(json.dumps({
    "schema": data.get("schema"),
    "evidence_summary": data.get("evidence_summary"),
    "harm_certificate_count": len(data.get("harm_certificates", [])),
    "relevant_evidence_count": len(data.get("suspicious_or_relevant_evidence", [])),
}, ensure_ascii=False, indent=2))
