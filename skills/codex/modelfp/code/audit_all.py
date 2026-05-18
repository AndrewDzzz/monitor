"""ModelFP Python audit-hook recorder.

Records Python audit events as JSONL for ModelFP runtime evidence.
This is telemetry, not a sandbox. Run the target inside a separate container/VM.
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


def safe_repr(obj: Any, max_len: int = 700) -> str:
    try:
        value = repr(obj)
    except Exception:
        value = "<unrepresentable>"
    value = _redact(value)
    if len(value) > max_len:
        value = value[:max_len] + "...<truncated>"
    return value


def _open_log_file() -> Any:
    log_path = os.environ.get("MODELFP_AUDIT_LOG", "/workspace/out/traces/python_audit.jsonl")
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    return open(log_path, "a", encoding="utf-8", buffering=1)


_LOG_FP = None
_IN_HOOK = False


def audit_all_hook(event: str, args: Iterable[Any]) -> None:
    global _IN_HOOK, _LOG_FP
    if _IN_HOOK:
        return
    _IN_HOOK = True
    try:
        if _LOG_FP is None:
            _LOG_FP = _open_log_file()
        record = {
            "time": time.time(),
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "phase": os.environ.get("MODELFP_PHASE", "RUNTIME"),
            "source": "python_audit",
            "op": event,
            "args": [safe_repr(a) for a in args],
            "result": "observed",
        }
        _LOG_FP.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        # Audit hooks should not crash the target unless enforcement is explicitly enabled.
        pass
    finally:
        _IN_HOOK = False


def register_all_audit_hook() -> None:
    global _LOG_FP
    try:
        _LOG_FP = _open_log_file()
    except Exception:
        _LOG_FP = None
    sys.addaudithook(audit_all_hook)


if __name__ == "__main__":
    register_all_audit_hook()
    print("ModelFP audit hook registered", flush=True)
