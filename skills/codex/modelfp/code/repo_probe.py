"""Collect repository-level evidence for a local Hugging Face model snapshot."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List

SUSPICIOUS_NAMES = {
    "loader.py", "load.py", "install.py", "setup.py", "post_install.py", "download.py",
    "run.sh", "install.sh", "payload.py", "requirements.txt",
}
CUSTOM_CODE_PREFIXES = ("modeling_", "tokenization_", "configuration_", "processing_")
HIGH_RISK_SUFFIXES = (".pkl", ".pickle", ".joblib", ".dill", ".pt", ".pth", ".ckpt", ".bin")
LOWER_RISK_SUFFIXES = (".safetensors", ".onnx", ".gguf")


def _node(idx: int, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": f"R{idx:04d}",
        "source": "repo_probe",
        "evidence_type": "repository",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def _looks_like_executable_script(path: Path, suffix: str) -> bool:
    if not os.access(path, os.X_OK):
        return False
    if suffix in {".sh", ".py"}:
        return True
    if suffix == "" and not path.name.startswith("."):
        try:
            return path.read_bytes()[:2] == b"#!"
        except Exception:
            return False
    return False


def scan_repo(repo: Path, max_files: int = 5000) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    i = 1
    files = []
    for p in repo.rglob("*"):
        rel_parts = p.relative_to(repo).parts
        if any(part in {".cache", ".git", "__pycache__"} for part in rel_parts):
            continue
        if len(files) >= max_files:
            nodes.append(_node(i, "file_tree_truncated", "medium", f"File tree exceeded {max_files} files and was truncated.")); i += 1
            break
        if p.is_file():
            rel = str(p.relative_to(repo))
            files.append(rel)
            name = p.name.lower()
            suffix = p.suffix.lower()
            if name in SUSPICIOUS_NAMES:
                nodes.append(_node(i, "suspicious_repository_file", "medium", f"Repository contains potentially security-relevant file {rel}.", path=rel)); i += 1
            if name.endswith(".py") and name.startswith(CUSTOM_CODE_PREFIXES):
                nodes.append(_node(i, "custom_huggingface_python_code", "high", f"Repository contains custom Hugging Face Python code {rel}.", path=rel)); i += 1
            if suffix in HIGH_RISK_SUFFIXES:
                nodes.append(_node(i, "high_risk_model_artifact_format", "medium", f"Repository contains pickle/torch-like model artifact {rel}.", path=rel, suffix=suffix)); i += 1
            if _looks_like_executable_script(p, suffix):
                nodes.append(_node(i, "executable_file_present", "medium", f"Repository contains executable file {rel}.", path=rel)); i += 1
    nodes.append(_node(i, "repository_file_tree_summary", "info", "Repository file tree summary collected.", file_count=len(files), files=files[:300]))
    return nodes


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out", default="/workspace/out/evidence/repo_evidence.jsonl")
    args = parser.parse_args()
    nodes = scan_repo(Path(args.repo))
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
