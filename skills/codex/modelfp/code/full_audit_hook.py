"""Full Python audit event recorder for ModelFP.

This module records Python audit events as JSONL. It is intentionally telemetry-only:
it does not enforce policy and it does not decide whether an event is malicious.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable


_SECRET_PATTERNS = [
    re.compile(r"(?i)hf_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)AKIA[0-9A-Z]{12,}"),
    re.compile(r"(?i)((?:AWS|GCP|AZURE|HF|OPENAI|ANTHROPIC)[A-Z0-9_\-]*=)[^,\s)'\"]+"),
    re.compile(r"(?i)((?:TOKEN|SECRET|PASSWORD|KEY)=)[^,\s)'\"]+"),
]


def _redact(text: str) -> str:
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: (m.group(1) + "<REDACTED>") if m.lastindex else "<REDACTED>", out)
    return out


def _safe_repr(value: Any, max_len: int = 600) -> str:
    try:
        text = repr(value)
    except Exception:
        text = "<unrepresentable>"
    text = _redact(text)
    if len(text) > max_len:
        return text[:max_len] + "...<truncated>"
    return text


class AuditRecorder:
    def __init__(self, output_path: str | os.PathLike[str]):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = self.output_path.open("a", encoding="utf-8")

    def hook(self, event: str, args: Iterable[Any]) -> None:
        record = {
            "time": time.time(),
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "source": "python_audit",
            "event": event,
            "args": [_safe_repr(a) for a in args],
        }
        self._fp.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._fp.flush()


def register_audit_recorder(output_path: str | os.PathLike[str]) -> AuditRecorder:
    recorder = AuditRecorder(output_path)
    sys.addaudithook(recorder.hook)
    return recorder
