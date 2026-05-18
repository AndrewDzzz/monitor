#!/usr/bin/env python3
"""Collect Hugging Face repository metadata in the network-enabled stage.

This script must not execute model code. It only calls Hugging Face Hub APIs and
writes a portable JSON record for the later offline Docker audit stages.
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import time
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping

from huggingface_hub import HfApi


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "__dict__"):
        return {
            str(k): _jsonable(v)
            for k, v in vars(value).items()
            if not str(k).startswith("_")
        }
    return str(value)


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default)


def _commit_to_record(commit: Any) -> Dict[str, Any]:
    return {
        "commit_id": _attr(commit, "commit_id"),
        "authors": _jsonable(_attr(commit, "authors", [])),
        "created_at": _jsonable(_attr(commit, "created_at")),
        "title": _attr(commit, "title"),
        "message": _attr(commit, "message"),
    }


def _sibling_to_record(sibling: Any) -> Dict[str, Any]:
    return {
        "rfilename": _attr(sibling, "rfilename"),
        "size": _attr(sibling, "size"),
        "blob_id": _attr(sibling, "blob_id"),
        "lfs": _jsonable(_attr(sibling, "lfs")),
    }


def _model_info_to_record(info: Any) -> Dict[str, Any]:
    siblings = _attr(info, "siblings", []) or []
    return {
        "id": _attr(info, "id"),
        "sha": _attr(info, "sha"),
        "pipeline_tag": _attr(info, "pipeline_tag"),
        "tags": _jsonable(_attr(info, "tags", [])),
        "library_name": _attr(info, "library_name"),
        "cardData": _jsonable(_attr(info, "cardData")),
        "last_modified": _jsonable(_attr(info, "last_modified")),
        "downloads": _attr(info, "downloads"),
        "likes": _attr(info, "likes"),
        "siblings": [_sibling_to_record(s) for s in siblings],
    }


def _call_with_supported_kwargs(func: Any, **kwargs: Any) -> Any:
    sig = inspect.signature(func)
    supported = {k: v for k, v in kwargs.items() if k in sig.parameters and v is not None}
    return func(**supported)


def collect(repo_id: str, revision: str | None) -> tuple[Dict[str, Any], bool]:
    token = os.environ.get("MODELFP_HF_TOKEN") or os.environ.get("HF_TOKEN")
    api = HfApi(token=token)
    errors: List[Dict[str, str]] = []
    out: Dict[str, Any] = {
        "schema": "modelfp.hf_repo_metadata.v1",
        "repo_id": repo_id,
        "repo_type": "model",
        "revision": revision,
        "generated_at_unix": time.time(),
        "model_info": None,
        "commits": [],
        "errors": errors,
    }

    try:
        info = _call_with_supported_kwargs(
            api.model_info,
            repo_id=repo_id,
            repo_type="model",
            revision=revision,
            token=token,
        )
        out["model_info"] = _model_info_to_record(info)
    except Exception as exc:
        errors.append({"stage": "model_info", "error": repr(exc)})

    try:
        commits = _call_with_supported_kwargs(
            api.list_repo_commits,
            repo_id=repo_id,
            repo_type="model",
            revision=revision,
            token=token,
        )
        out["commits"] = [_commit_to_record(c) for c in (commits or [])]
    except Exception as exc:
        errors.append({"stage": "list_repo_commits", "error": repr(exc)})

    return out, not errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect Hugging Face metadata for ModelFP audits")
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--revision", default=None)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    data, ok = collect(args.repo_id, args.revision)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(str(out))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
