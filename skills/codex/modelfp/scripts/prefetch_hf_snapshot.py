#!/usr/bin/env python3
"""Prefetch a Hugging Face snapshot in the network-enabled Docker download stage.

Usage:
  python scripts/prefetch_hf_snapshot.py --repo-id owner/model --out workspace/models/model
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
from huggingface_hub import snapshot_download


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--revision", default=None)
    parser.add_argument("--out", default="workspace/models/model")
    parser.add_argument("--allow-pattern", action="append", default=None, help="Optional Hugging Face allow pattern; repeat for multiple patterns")
    parser.add_argument("--ignore-pattern", action="append", default=None, help="Optional Hugging Face ignore pattern; repeat for multiple patterns")
    parser.add_argument("--max-size-note", default="ModelFP MVP recommends <=1B params or <=1GB artifacts")
    args = parser.parse_args()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    token = os.environ.get("MODELFP_HF_TOKEN") or os.environ.get("HF_TOKEN")
    path = snapshot_download(
        repo_id=args.repo_id,
        revision=args.revision,
        local_dir=str(out),
        local_dir_use_symlinks=False,
        allow_patterns=args.allow_pattern,
        ignore_patterns=args.ignore_pattern,
        token=token,
    )
    print(path)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
