"""Offline repository hygiene probe for Hugging Face model snapshots.

The probe consumes only the mounted local repository plus optional remote
metadata collected earlier in the Docker download stage. It never calls network
APIs and never imports or executes repository code.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

try:
    import yaml
except Exception:  # pragma: no cover - PyYAML is installed in the Docker image.
    yaml = None  # type: ignore[assignment]


PAYLOAD_SUFFIXES = {
    ".apk", ".app", ".bat", ".cmd", ".com", ".dll", ".dmg", ".exe", ".hta",
    ".jar", ".js", ".jse", ".lnk", ".msi", ".ps1", ".psm1", ".scr", ".vbe",
    ".vbs", ".wsf",
    ".zip",
}
ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz"}
NATIVE_LIB_SUFFIXES = {".dylib", ".elf", ".so"}
SCRIPT_SUFFIXES = {".bash", ".cmd", ".ps1", ".py", ".sh"}
MODEL_ARTIFACT_SUFFIXES = {
    ".bin", ".ckpt", ".gguf", ".h5", ".index", ".joblib", ".keras", ".model", ".msgpack",
    ".onnx", ".ot", ".pb", ".pickle", ".pkl", ".pt", ".pth", ".safetensors",
    ".spm", ".tflite",
}
MODEL_META_NAMES = {
    "config.json", "generation_config.json", "merges.txt", "preprocessor_config.json",
    "processor_config.json", "special_tokens_map.json", "tokenizer.json",
    "tokenizer_config.json", "vocab.json", "vocab.txt",
}

README_PATTERNS = [
    ("curl_pipe_shell", "high", re.compile(r"\b(curl|wget)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:bash|sh)\b", re.I)),
    ("powershell_download", "high", re.compile(r"\b(powershell|pwsh|invoke-webrequest|iwr|downloadstring)\b", re.I)),
    ("external_executable", "high", re.compile(r"\b(?:download|install|run|execute|open)\b[^\n]{0,120}\.(?:apk|app|bat|cmd|dll|dmg|exe|jar|msi|ps1)\b", re.I)),
    ("chmod_run_script", "high", re.compile(r"\bchmod\s+\+x\b|\b(?:bash|sh)\s+[^\n]*(?:install|setup|run|download)[^\n]*\.sh\b", re.I)),
    ("python_remote_script", "high", re.compile(r"\bpython(?:3)?\s+[^\n]*(?:install|setup|download|payload|run)[^\n]*\.py\b", re.I)),
    ("pip_install_tooling", "medium", re.compile(r"\b(?:python(?:3)?\s+-m\s+pip|pip(?:3)?)\s+install\b[^\n]*(?:poetry|requirements|setup|--upgrade)", re.I)),
    ("make_build_test_package", "medium", re.compile(r"\bmake\s+(?:build|test|package|deploy|install|run)\b", re.I)),
    ("poetry_command", "medium", re.compile(r"\bpoetry\s+(?:install|run|build|publish|add|update)\b", re.I)),
    ("cloud_cli_deploy", "medium", re.compile(r"\b(?:aws|gcloud|az)\s+[^\n]*(?:deploy|update-function-code|lambda|functions|run|app)\b", re.I)),
]

TASK_FAMILIES = {
    "text-generation": "causal_lm",
    "text2text-generation": "seq2seq",
    "translation": "seq2seq",
    "summarization": "seq2seq",
    "conversational": "causal_lm",
    "fill-mask": "masked_lm",
    "feature-extraction": "encoder",
    "sentence-similarity": "encoder",
    "text-classification": "encoder",
    "token-classification": "encoder",
    "question-answering": "encoder",
    "image-classification": "vision",
    "object-detection": "vision",
    "image-to-text": "vision_language",
    "automatic-speech-recognition": "audio",
    "audio-classification": "audio",
}
MODEL_TYPE_FAMILIES = {
    "bert": "encoder",
    "roberta": "masked_lm",
    "xlm-roberta": "masked_lm",
    "deberta": "encoder",
    "distilbert": "encoder",
    "albert": "encoder",
    "t5": "seq2seq",
    "mt5": "seq2seq",
    "marian": "seq2seq",
    "mbart": "seq2seq",
    "m2m_100": "seq2seq",
    "nllb": "seq2seq",
    "bart": "seq2seq",
    "gpt2": "causal_lm",
    "gpt_neo": "causal_lm",
    "gpt_neox": "causal_lm",
    "llama": "causal_lm",
    "mistral": "causal_lm",
    "mixtral": "causal_lm",
    "qwen2": "causal_lm",
    "qwen3": "causal_lm",
    "falcon": "causal_lm",
    "bloom": "causal_lm",
    "clip": "vision_language",
    "vit": "vision",
    "swin": "vision",
    "wav2vec2": "audio",
    "whisper": "audio",
}
ARCHITECTURE_FAMILIES = [
    (re.compile(r"(ForCausalLM|LMHeadModel|GPT|Llama|Mistral|Qwen|Bloom|Falcon)", re.I), "causal_lm"),
    (re.compile(r"(ForConditionalGeneration|Seq2Seq|Marian|T5|MBart|Nllb)", re.I), "seq2seq"),
    (re.compile(r"(ForMaskedLM|MaskedLM)", re.I), "masked_lm"),
    (re.compile(r"(ForSequenceClassification|ForTokenClassification|ForQuestionAnswering)", re.I), "encoder"),
    (re.compile(r"(Vision|Image|ViT|Swin|CLIP)", re.I), "vision"),
    (re.compile(r"(Whisper|Wav2Vec|Audio)", re.I), "audio"),
]


def _node(idx: int, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": f"RH{idx:04d}",
        "source": "repo_hygiene_probe",
        "evidence_type": "repository",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_text(path: Path, max_bytes: int = 512_000) -> str:
    try:
        data = path.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _frontmatter(text: str) -> Dict[str, Any]:
    if yaml is None or not text.startswith("---"):
        return {}
    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", text, flags=re.S)
    if not match:
        return {}
    try:
        data = yaml.safe_load(match.group(1))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _list_files(repo: Path, max_files: int) -> tuple[List[Path], bool]:
    files: List[Path] = []
    truncated = False
    for path in sorted(repo.rglob("*")):
        rel_parts = path.relative_to(repo).parts
        if any(part in {".cache", ".git", "__pycache__"} for part in rel_parts):
            continue
        if path.is_file():
            if len(files) >= max_files:
                truncated = True
                break
            files.append(path)
    return files, truncated


def _rel(repo: Path, path: Path) -> str:
    return path.relative_to(repo).as_posix()


def _normal_commit_text(commit: Mapping[str, Any]) -> str:
    text = " ".join(str(commit.get(k) or "") for k in ("title", "message")).strip().lower()
    text = re.sub(r"\b[0-9a-f]{7,40}\b", "<hash>", text)
    text = re.sub(r"\d+", "<num>", text)
    return re.sub(r"\s+", " ", text)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _infer_config_family(config: Mapping[str, Any]) -> str | None:
    model_type = str(config.get("model_type") or "").lower()
    if model_type in MODEL_TYPE_FAMILIES:
        return MODEL_TYPE_FAMILIES[model_type]
    for arch in config.get("architectures") or []:
        arch_text = str(arch)
        for pattern, family in ARCHITECTURE_FAMILIES:
            if pattern.search(arch_text):
                return family
    return None


def _task_family(task: Any) -> str | None:
    if not task:
        return None
    task_text = str(task).strip().lower()
    return TASK_FAMILIES.get(task_text)


def _first_task(card_data: Mapping[str, Any], model_info: Mapping[str, Any]) -> str | None:
    for source in (card_data, model_info.get("cardData") if isinstance(model_info.get("cardData"), dict) else {}, model_info):
        if not isinstance(source, Mapping):
            continue
        value = source.get("pipeline_tag")
        if value:
            return str(value)
    tags: List[str] = []
    for source in (card_data, model_info.get("cardData") if isinstance(model_info.get("cardData"), dict) else {}, model_info):
        if not isinstance(source, Mapping):
            continue
        raw = source.get("tags") or []
        if isinstance(raw, str):
            tags.append(raw)
        elif isinstance(raw, Sequence):
            tags.extend(str(x) for x in raw)
    for tag in tags:
        if _task_family(tag):
            return tag
    return None


def _scan_readme(repo: Path) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    frontmatter: Dict[str, Any] = {}
    for path in sorted(repo.glob("README*")) + sorted(repo.glob("readme*")):
        if not path.is_file():
            continue
        text = _read_text(path)
        if not frontmatter:
            frontmatter = _frontmatter(text)
        for line_no, line in enumerate(text.splitlines(), start=1):
            for label, risk, pattern in README_PATTERNS:
                if pattern.search(line):
                    matches.append({
                        "path": _rel(repo, path),
                        "line_no": line_no,
                        "pattern": label,
                        "risk": risk,
                        "excerpt": line.strip()[:500],
                    })
    return matches, frontmatter


def _commit_nodes(start_idx: int, metadata: Mapping[str, Any] | None) -> tuple[List[Dict[str, Any]], int]:
    idx = start_idx
    nodes: List[Dict[str, Any]] = []
    if not metadata:
        nodes.append(_node(
            idx,
            "remote_commit_metadata_missing",
            "info",
            "Remote Hugging Face commit metadata was not mounted; commit-frequency and repeated-commit checks were unavailable.",
        ))
        return nodes, idx + 1

    commits = metadata.get("commits") or []
    if not isinstance(commits, list):
        commits = []
    timestamps = [_parse_time(c.get("created_at")) for c in commits if isinstance(c, Mapping)]
    timestamps = [t for t in timestamps if t is not None]
    by_hour: Dict[str, int] = defaultdict(int)
    by_day: Dict[str, int] = defaultdict(int)
    for dt in timestamps:
        by_hour[dt.strftime("%Y-%m-%dT%H:00Z")] += 1
        by_day[dt.strftime("%Y-%m-%d")] += 1

    title_counts = Counter(
        _normal_commit_text(c)
        for c in commits
        if isinstance(c, Mapping) and _normal_commit_text(c)
    )
    repeated = [(text, count) for text, count in title_counts.most_common(10) if count >= 2]
    max_hour = max(by_hour.values(), default=0)
    max_day = max(by_day.values(), default=0)
    duplicate_count = sum(count for _, count in repeated)
    duplicate_ratio = duplicate_count / len(commits) if commits else 0.0
    intervals: List[float] = []
    for left, right in zip(sorted(timestamps), sorted(timestamps)[1:]):
        intervals.append((right - left).total_seconds())

    nodes.append(_node(
        idx,
        "commit_history_summary",
        "info",
        "Remote commit metadata summarized for frequency and repeated-message checks.",
        commit_count=len(commits),
        timestamp_count=len(timestamps),
        max_commits_per_hour=max_hour,
        max_commits_per_day=max_day,
        median_seconds_between_commits=statistics.median(intervals) if intervals else None,
        repeated_message_examples=[{"normalized_message": text, "count": count} for text, count in repeated[:5]],
        metadata_errors=metadata.get("errors") or [],
    ))
    idx += 1

    if max_hour >= 5 or max_day >= 20:
        nodes.append(_node(
            idx,
            "abnormal_high_frequency_commits",
            "medium",
            "Repository has unusually dense commit activity for a model snapshot, which can indicate scripted churn or payload-hosting behavior.",
            max_commits_per_hour=max_hour,
            max_commits_per_day=max_day,
            busiest_hours=sorted(by_hour.items(), key=lambda x: x[1], reverse=True)[:5],
            busiest_days=sorted(by_day.items(), key=lambda x: x[1], reverse=True)[:5],
        ))
        idx += 1

    if len(commits) >= 10 and (duplicate_ratio >= 0.6 or any(count >= 5 for _, count in repeated)):
        nodes.append(_node(
            idx,
            "large_repeated_commit_messages",
            "medium",
            "Repository has many repeated commit titles/messages, suggesting low-information churn rather than ordinary model development history.",
            commit_count=len(commits),
            duplicate_ratio=round(duplicate_ratio, 4),
            repeated_message_examples=[{"normalized_message": text, "count": count} for text, count in repeated[:10]],
        ))
        idx += 1

    return nodes, idx


def scan_repo(repo: Path, metadata_path: Path | None, max_files: int = 10000) -> List[Dict[str, Any]]:
    metadata = _read_json(metadata_path) if metadata_path and metadata_path.exists() else None
    model_info = metadata.get("model_info") if isinstance(metadata, Mapping) and isinstance(metadata.get("model_info"), Mapping) else {}
    files, truncated = _list_files(repo, max_files=max_files)
    rel_files = [_rel(repo, p) for p in files]
    suffix_counts = Counter(p.suffix.lower() for p in files)
    payload_files = [
        _rel(repo, p) for p in files
        if p.suffix.lower() in PAYLOAD_SUFFIXES
    ]
    archive_files = [
        _rel(repo, p) for p in files
        if p.suffix.lower() in ARCHIVE_SUFFIXES
    ]
    native_files = [
        _rel(repo, p) for p in files
        if p.suffix.lower() in NATIVE_LIB_SUFFIXES
    ]
    script_files = [
        _rel(repo, p) for p in files
        if p.suffix.lower() in SCRIPT_SUFFIXES or p.name.lower() in {"install", "setup", "run", "payload"}
    ]
    model_artifact_files = [
        _rel(repo, p) for p in files
        if p.suffix.lower() in MODEL_ARTIFACT_SUFFIXES or p.name in MODEL_META_NAMES
    ]
    required_like = [name for name in MODEL_META_NAMES if (repo / name).exists()]

    nodes: List[Dict[str, Any]] = []
    idx = 1

    if payload_files:
        nodes.append(_node(
            idx,
            "non_model_payload_present",
            "high",
            "Repository contains executable/application payload formats that are not expected model artifacts.",
            paths=payload_files[:100],
            count=len(payload_files),
            suffix_counts=dict(Counter(Path(p).suffix.lower() for p in payload_files)),
        ))
        idx += 1

    non_model_payload_like = payload_files + archive_files + native_files
    if archive_files or native_files:
        nodes.append(_node(
            idx,
            "archive_or_native_payload_present",
            "medium",
            "Repository contains archive or native-library files that should be justified by model documentation and inspected as non-model payload surface.",
            archive_paths=archive_files[:100],
            native_library_paths=native_files[:100],
            archive_count=len(archive_files),
            native_library_count=len(native_files),
        ))
        idx += 1

    readme_matches, readme_frontmatter = _scan_readme(repo)
    if readme_matches:
        readme_severity = "high" if any(m.get("risk") == "high" for m in readme_matches) else "medium"
        nodes.append(_node(
            idx,
            "readme_runs_external_script_or_app",
            readme_severity,
            "README or model card includes instructions to install/run external apps, scripts, shells, or platform-specific executables.",
            matches=readme_matches[:50],
            match_count=len(readme_matches),
        ))
        idx += 1

    config = _read_json(repo / "config.json") if (repo / "config.json").exists() else {}
    config_family = _infer_config_family(config if isinstance(config, Mapping) else {})
    card_task = _first_task(readme_frontmatter, model_info if isinstance(model_info, Mapping) else {})
    card_family = _task_family(card_task)
    if card_task and config_family and card_family and card_family != config_family:
        allowed = {("masked_lm", "encoder"), ("encoder", "masked_lm")}
        if (card_family, config_family) not in allowed:
            nodes.append(_node(
                idx,
                "model_card_task_mismatch",
                "medium",
                "Model card or Hub metadata declares a task family that does not match the local config architecture family.",
                declared_task=card_task,
                declared_family=card_family,
                config_family=config_family,
                model_type=(config or {}).get("model_type") if isinstance(config, Mapping) else None,
                architectures=(config or {}).get("architectures") if isinstance(config, Mapping) else None,
            ))
            idx += 1
    elif not card_task:
        nodes.append(_node(
            idx,
            "model_card_missing_or_uninformative",
            "info",
            "No clear pipeline_tag or task tag was found in README frontmatter or Hub metadata, so task-to-artifact consistency is weakly evidenced.",
            config_family=config_family,
            readme_frontmatter_keys=sorted(str(k) for k in readme_frontmatter.keys()),
        ))
        idx += 1

    payload_like_count = len(non_model_payload_like)
    model_artifact_count = len(model_artifact_files)
    has_core_model_metadata = bool(required_like)
    malware_hosting_reasons: List[str] = []
    if payload_like_count >= 3 and model_artifact_count <= 2:
        malware_hosting_reasons.append("many non-model payload-like files but few model artifacts")
    if payload_files and not has_core_model_metadata:
        malware_hosting_reasons.append("executable/application payloads with missing core model metadata")
    if payload_like_count > 0 and model_artifact_count == 0:
        malware_hosting_reasons.append("payload-like files without recognizable model artifacts")
    if script_files and not has_core_model_metadata and model_artifact_count <= 1:
        malware_hosting_reasons.append("script-heavy tree with little model structure")
    if malware_hosting_reasons:
        nodes.append(_node(
            idx,
            "malware_hosting_like_file_tree",
            "high" if payload_files else "medium",
            "Repository file tree resembles payload hosting more than a normal model snapshot.",
            reasons=malware_hosting_reasons,
            file_count=len(files),
            model_artifact_count=model_artifact_count,
            payload_like_count=payload_like_count,
            script_count=len(script_files),
            core_model_metadata_present=has_core_model_metadata,
            sample_files=rel_files[:200],
        ))
        idx += 1

    commit_nodes, idx = _commit_nodes(idx, metadata if isinstance(metadata, Mapping) else None)
    nodes.extend(commit_nodes)

    nodes.append(_node(
        idx,
        "repo_hygiene_summary",
        "info",
        "Repository hygiene checks completed for non-model payloads, README execution guidance, task consistency, payload-hosting file tree shape, and remote commit metadata.",
        file_count=len(files),
        truncated=truncated,
        suffix_counts=dict(sorted((k or "<none>", v) for k, v in suffix_counts.items())),
        payload_count=len(payload_files),
        archive_count=len(archive_files),
        native_library_count=len(native_files),
        script_count=len(script_files),
        model_artifact_count=len(model_artifact_files),
        declared_task=card_task,
        declared_family=card_family,
        config_family=config_family,
        has_remote_metadata=metadata is not None,
        files=rel_files[:300],
    ))
    return nodes


def write_jsonl(path: Path, nodes: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run offline repository hygiene checks")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--metadata", default=None, help="Optional hf_repo_metadata.json collected in the network download stage")
    parser.add_argument("--out", default="/workspace/out/evidence/repo_hygiene_evidence.jsonl")
    parser.add_argument("--max-files", type=int, default=10000)
    args = parser.parse_args()

    metadata_path = Path(args.metadata) if args.metadata else None
    nodes = scan_repo(Path(args.repo), metadata_path, max_files=args.max_files)
    write_jsonl(Path(args.out), nodes)
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
