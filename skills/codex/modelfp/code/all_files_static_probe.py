"""All-file static inventory and text-pattern probe.

This collector scans every file in the mounted repository without executing
code. It complements model-specific scanners by preserving a full file
inventory and detecting non-model payload extensions, text instructions, URLs,
and other repo-level signals.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

PAYLOAD_SUFFIXES = {
    ".apk", ".app", ".bat", ".cmd", ".com", ".dll", ".dmg", ".exe", ".hta",
    ".jar", ".js", ".jse", ".lnk", ".msi", ".ps1", ".psm1", ".scr", ".vbe",
    ".vbs", ".wsf", ".zip",
}
ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz"}
MODEL_SUFFIXES = {
    ".bin", ".ckpt", ".gguf", ".h5", ".index", ".joblib", ".keras", ".model",
    ".msgpack", ".onnx", ".ot", ".pb", ".pickle", ".pkl", ".pt", ".pth",
    ".safetensors", ".spm", ".tflite",
}
MODEL_META_NAMES = {
    "config.json", "generation_config.json", "merges.txt", "preprocessor_config.json",
    "processor_config.json", "special_tokens_map.json", "tokenizer.json",
    "tokenizer_config.json", "vocab.json", "vocab.txt",
}
TEXT_SUFFIXES = {".bash", ".cmd", ".js", ".json", ".md", ".ps1", ".py", ".sh", ".toml", ".txt", ".yaml", ".yml"}
TEXT_NAMES = {"Dockerfile", "Jenkinsfile", "Makefile", "README"}

TEXT_PATTERNS = [
    ("curl_pipe_shell", "high", re.compile(r"\b(curl|wget)\b[^\n|]{0,180}\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.I)),
    ("powershell_download", "high", re.compile(r"\b(powershell|pwsh|invoke-webrequest|iwr|downloadstring)\b", re.I)),
    ("chmod_exec", "medium", re.compile(r"\bchmod\s+\+x\b", re.I)),
    ("pip_install", "medium", re.compile(r"\b(?:python(?:3)?\s+-m\s+pip|pip(?:3)?)\s+install\b", re.I)),
    ("make_build_or_package", "medium", re.compile(r"\bmake\s+(?:build|test|package|deploy|install|run)\b", re.I)),
    ("cloud_cli_deploy", "medium", re.compile(r"\b(?:aws|gcloud|az)\s+[^\n]*(?:deploy|update-function-code|lambda|functions|run|app)\b", re.I)),
    ("pickle_load_text", "medium", re.compile(r"\bpickle\.(?:load|loads)\b", re.I)),
    ("eval_exec_text", "medium", re.compile(r"\b(?:eval|exec)\s*\(", re.I)),
    ("shell_true_text", "high", re.compile(r"\bshell\s*=\s*True\b", re.I)),
    ("network_url", "info", re.compile(r"https?://[^\s\)\"'\]]+", re.I)),
]


def _node(idx: int, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": f"AF{idx:04d}",
        "source": "all_files_static_probe",
        "evidence_type": "repository",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in counts if count)


def _file_type(path: Path) -> str | None:
    try:
        proc = subprocess.run(["file", "-b", str(path)], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return None
    return proc.stdout.strip() or None


def _is_text_candidate(path: Path, suffix: str, size: int) -> bool:
    if size > 1024 * 1024:
        return False
    return suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES or path.suffix == ""


def _iter_files(repo: Path, max_files: int) -> tuple[List[Path], bool]:
    files: List[Path] = []
    truncated = False
    for path in sorted(repo.rglob("*")):
        if any(part in {".git", ".cache", "__pycache__"} for part in path.relative_to(repo).parts):
            continue
        if path.is_file():
            if len(files) >= max_files:
                truncated = True
                break
            files.append(path)
    return files, truncated


def scan_repo(repo: Path, max_files: int = 10000) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    idx = 1
    files, truncated = _iter_files(repo, max_files)
    records: List[Dict[str, Any]] = []
    for path in files:
        rel = path.relative_to(repo).as_posix()
        suffix = path.suffix.lower()
        size = path.stat().st_size
        try:
            head = path.read_bytes()[:262144]
        except Exception:
            head = b""
        rec: Dict[str, Any] = {
            "path": rel,
            "size": size,
            "suffix": suffix or "<none>",
            "sha256": _sha256(path),
            "entropy_head": round(_entropy(head), 4),
            "file_type": _file_type(path),
        }
        records.append(rec)

        if suffix in PAYLOAD_SUFFIXES:
            nodes.append(_node(idx, "non_model_payload_extension", "high", "Repository file has a non-model payload extension.", path=rel, suffix=suffix, size=size))
            idx += 1
        if suffix in ARCHIVE_SUFFIXES:
            nodes.append(_node(idx, "archive_file_present", "medium", "Repository contains an archive file that should be justified by model documentation.", path=rel, suffix=suffix, size=size))
            idx += 1
        if suffix in MODEL_SUFFIXES or path.name in MODEL_META_NAMES:
            nodes.append(_node(idx, "model_artifact_or_metadata_present", "info", "Repository contains a recognized model artifact or metadata file.", path=rel, suffix=suffix or "<none>", size=size))
            idx += 1
        if _is_text_candidate(path, suffix, size):
            text = path.read_text(errors="ignore")
            for line_no, line in enumerate(text.splitlines(), start=1):
                for label, severity, pattern in TEXT_PATTERNS:
                    if pattern.search(line):
                        nodes.append(_node(idx, "suspicious_text_pattern", severity, "Text file contains a command, URL, or code pattern relevant to supply-chain review.", path=rel, line_no=line_no, pattern=label, excerpt=line.strip()[:500]))
                        idx += 1

    suffix_counts: Dict[str, int] = {}
    for rec in records:
        suffix_counts[rec["suffix"]] = suffix_counts.get(rec["suffix"], 0) + 1
    nodes.append(_node(
        idx,
        "all_files_static_summary",
        "info",
        "All-file static inventory completed.",
        file_count=len(records),
        truncated=truncated,
        suffix_counts=dict(sorted(suffix_counts.items())),
        payload_extension_count=sum(1 for rec in records if rec["suffix"] in PAYLOAD_SUFFIXES),
        archive_count=sum(1 for rec in records if rec["suffix"] in ARCHIVE_SUFFIXES),
        model_artifact_or_metadata_count=sum(1 for rec in records if rec["suffix"] in MODEL_SUFFIXES or Path(rec["path"]).name in MODEL_META_NAMES),
        files=[rec["path"] for rec in records[:500]],
    ))
    report = {
        "schema": "modelfp.all_files_static_scan.v1",
        "generated_at_unix": time.time(),
        "repo": str(repo),
        "file_count": len(records),
        "truncated": truncated,
        "findings_count": len(nodes),
        "files": records,
    }
    return nodes, report


def write_jsonl(path: Path, nodes: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Run all-file static inventory and pattern checks")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out", default="/workspace/out/evidence/all_files_static_evidence.jsonl")
    parser.add_argument("--raw-report", default=None)
    parser.add_argument("--max-files", type=int, default=10000)
    args = parser.parse_args()

    nodes, report = scan_repo(Path(args.repo), max_files=args.max_files)
    write_jsonl(Path(args.out), nodes)
    if args.raw_report:
        raw = Path(args.raw_report)
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
