"""Run a target Python script with ModelFP audit hooks enabled."""

from __future__ import annotations

import argparse
import os
import runpy
import sys
from pathlib import Path

# Allow running this file directly from the ModelFP package tree.
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from audit_all import register_all_audit_hook  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="ModelFP target runner with Python audit logging")
    parser.add_argument("--script", required=True, help="Target Python script to execute")
    parser.add_argument("--audit-log", default="/workspace/out/traces/python_audit.jsonl")
    parser.add_argument("--phase", default="LOAD_AND_INFERENCE")
    parser.add_argument("script_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    os.environ["MODELFP_AUDIT_LOG"] = args.audit_log
    os.environ["MODELFP_PHASE"] = args.phase
    Path(args.audit_log).parent.mkdir(parents=True, exist_ok=True)

    register_all_audit_hook()
    sys.argv = [args.script] + [x for x in args.script_args if x != "--"]
    runpy.run_path(args.script, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
