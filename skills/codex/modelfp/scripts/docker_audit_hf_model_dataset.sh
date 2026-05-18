#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/docker_audit_hf_model_dataset.sh owner/model-or-hf-url [dataset_root] [revision]

Environment:
  MODELFP_DATASET_ROOT    Default dataset root (default: audit_datasets)
  MODELFP_AUDIT_ID        Override generated audit id
  MODELFP_PROMPT          Runtime prompt (default inherited by docker_run_local_model.sh)
  MODELFP_SKIP_RUNTIME    Set true to build a static-only dataset
  MODELFP_HF_TOKEN        Optional token for gated/private download stage only

Each run creates:
  <dataset_root>/<repo_slug>/<audit_id>/
    dataset_manifest.json
    orchestrator.log
    metadata/hf_repo_metadata.json
    metadata/model_sha256.txt
    model/
    outputs_static/
    outputs_runtime/        omitted when MODELFP_SKIP_RUNTIME=true
EOF
}

if [ "${1:-}" = "" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 2
fi

INPUT_REF="$1"
DATASET_ROOT="${2:-${MODELFP_DATASET_ROOT:-audit_datasets}}"
REVISION_ARG="${3:-${MODELFP_REVISION:-}}"

repo_from_ref() {
  local ref="$1"
  ref="${ref#https://huggingface.co/}"
  ref="${ref#http://huggingface.co/}"
  ref="${ref%%/tree/*}"
  ref="${ref%%/blob/*}"
  ref="${ref%%\?*}"
  ref="${ref%/}"
  printf '%s' "$ref"
}

revision_from_ref() {
  local ref="$1"
  if [[ "$ref" == *"/tree/"* ]]; then
    ref="${ref#*/tree/}"
    ref="${ref%%/*}"
    ref="${ref%%\?*}"
    printf '%s' "$ref"
  fi
}

slugify() {
  printf '%s' "$1" \
    | tr '/:@ ' '____' \
    | tr -c 'A-Za-z0-9._-' '-' \
    | sed -E 's/^-+//; s/-+$//; s/-+/-/g'
}

REPO_ID="$(repo_from_ref "$INPUT_REF")"
URL_REVISION="$(revision_from_ref "$INPUT_REF")"
REVISION="${REVISION_ARG:-${URL_REVISION:-main}}"
REPO_SLUG="$(slugify "$REPO_ID")"
REVISION_SLUG="$(slugify "$REVISION")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
AUDIT_ID="${MODELFP_AUDIT_ID:-${STAMP}_${REPO_SLUG}_${REVISION_SLUG}}"
AUDIT_DIR="$DATASET_ROOT/$REPO_SLUG/$AUDIT_ID"
MODEL_DIR="$AUDIT_DIR/model"
STATIC_DIR="$AUDIT_DIR/outputs_static"
RUNTIME_DIR="$AUDIT_DIR/outputs_runtime"
METADATA_DIR="$AUDIT_DIR/metadata"
SKIP_RUNTIME="${MODELFP_SKIP_RUNTIME:-false}"

if [ -e "$AUDIT_DIR" ]; then
  echo "Audit dataset already exists: $AUDIT_DIR" >&2
  exit 2
fi

mkdir -p "$MODEL_DIR" "$STATIC_DIR" "$METADATA_DIR"
exec > >(tee "$AUDIT_DIR/orchestrator.log") 2>&1

write_manifest() {
  local download_status="$1"
  local hash_status="$2"
  local metadata_status="$3"
  local static_status="$4"
  local runtime_status="$5"
  local final_status="$6"
  python3 - "$AUDIT_DIR" "$REPO_ID" "$REVISION" "$INPUT_REF" "$AUDIT_ID" "$download_status" "$hash_status" "$metadata_status" "$static_status" "$runtime_status" "$final_status" "$SKIP_RUNTIME" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

audit_dir = Path(sys.argv[1]).resolve()
repo_id, revision, input_ref, audit_id = sys.argv[2:6]
download_status, hash_status, metadata_status, static_status, runtime_status, final_status = sys.argv[6:12]
skip_runtime = sys.argv[12].lower() == "true"


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(audit_dir))
    except Exception:
        return str(path)


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def graph_summary(path: Path):
    graph = load_json(path)
    if not graph:
        return None
    evidence = graph.get("evidence", [])
    by_type = {}
    high = 0
    for node in evidence:
        by_type[node.get("type", "unknown")] = by_type.get(node.get("type", "unknown"), 0) + 1
        if node.get("severity") == "high":
            high += 1
    return {
        "path": rel(path),
        "sha256": sha256_file(path),
        "evidence_count": graph.get("evidence_count", len(evidence)),
        "runtime_event_count": graph.get("runtime_event_count"),
        "by_type": by_type,
        "high_severity_count": high,
    }


def cert_summary(path: Path):
    certs = load_json(path)
    if not certs:
        return None
    return {
        "path": rel(path),
        "sha256": sha256_file(path),
        "count": certs.get("count"),
        "verified_count": certs.get("verified_count"),
        "certificate_ids": [c.get("certificate_id") for c in certs.get("certificates", [])],
    }


def run_manifest(path: Path):
    manifest = load_json(path)
    if not manifest:
        return None
    return {
        "path": rel(path),
        "run_id": manifest.get("run_id"),
        "target_returncode": manifest.get("target_returncode"),
        "containerized": manifest.get("containerized"),
        "skip_runtime": manifest.get("skip_runtime"),
    }


def docker_image(image: str):
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", "-f", "{{.Id}}", image],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        return None
    return proc.stdout.strip() or None


static_dir = audit_dir / "outputs_static"
runtime_dir = audit_dir / "outputs_runtime"
metadata_dir = audit_dir / "metadata"

manifest = {
    "schema": "modelfp.audit_dataset.v1",
    "audit_id": audit_id,
    "created_at_unix": time.time(),
    "repo_id": repo_id,
    "revision": revision,
    "input_ref": input_ref,
    "final_status": final_status,
    "phases": {
        "download_exit": int(download_status),
        "hash_exit": int(hash_status),
        "remote_metadata_exit": int(metadata_status),
        "static_exit": int(static_status),
        "runtime_exit": None if skip_runtime else int(runtime_status),
        "runtime_skipped": skip_runtime,
    },
    "docker_images": {
        "modelfp_latest": docker_image("modelfp:latest"),
        "modelfp_ml": docker_image("modelfp:ml"),
    },
    "paths": {
        "audit_dir": str(audit_dir),
        "orchestrator_log": "orchestrator.log",
        "model_dir": "model",
        "metadata_dir": "metadata",
        "static_dir": "outputs_static",
        "runtime_dir": None if skip_runtime else "outputs_runtime",
    },
    "artifacts": {
        "model_sha256": {
            "path": rel(metadata_dir / "model_sha256.txt"),
            "sha256": sha256_file(metadata_dir / "model_sha256.txt"),
        },
        "remote_metadata": {
            "path": rel(metadata_dir / "hf_repo_metadata.json"),
            "sha256": sha256_file(metadata_dir / "hf_repo_metadata.json"),
        },
        "static_graph": graph_summary(static_dir / "evidence_graph.json"),
        "static_certificates": cert_summary(static_dir / "harm_certificates.json"),
        "static_run_manifest": run_manifest(static_dir / "run_manifest.json"),
        "runtime_graph": None if skip_runtime else graph_summary(runtime_dir / "evidence_graph.json"),
        "runtime_certificates": None if skip_runtime else cert_summary(runtime_dir / "harm_certificates.json"),
        "runtime_run_manifest": None if skip_runtime else run_manifest(runtime_dir / "run_manifest.json"),
        "runtime_stdout": None if skip_runtime else rel(runtime_dir / "traces" / "target_stdout.log"),
        "runtime_stderr": None if skip_runtime else rel(runtime_dir / "traces" / "target_stderr.log"),
    },
}

(audit_dir / "dataset_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

echo "[ModelFP dataset] repo=$REPO_ID revision=$REVISION"
echo "[ModelFP dataset] audit_dir=$AUDIT_DIR"

download_status=0
hash_status=0
metadata_status=0
static_status=0
runtime_status=0

MODELFP_MODEL_NAME="$REPO_ID" MODELFP_REVISION="$REVISION" \
  ./scripts/docker_download_hf_model.sh "$REPO_ID" "$MODEL_DIR" "$REVISION"
download_status=$?

if [ "$download_status" -eq 0 ]; then
  docker run --rm --network none \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:size=64m,mode=1777 \
    -v "$(cd "$MODEL_DIR" && pwd):/workspace/models/model:ro" \
    -v "$(cd "$METADATA_DIR" && pwd):/workspace/out:rw" \
    --entrypoint sh \
    "${MODELFP_HASH_IMAGE:-modelfp:latest}" \
    -c 'cd /workspace/models/model && find . -type f ! -path "./.cache/*" -print0 | sort -z | xargs -0 sha256sum > /workspace/out/model_sha256.txt'
  hash_status=$?
else
  hash_status=1
fi

if [ "$download_status" -eq 0 ]; then
  metadata_env_args=(-e PYTHONDONTWRITEBYTECODE=1 -e HF_HOME=/workspace/tmp/hf_home -e HUGGINGFACE_HUB_CACHE=/workspace/tmp/hf_cache)
  if [ -n "${MODELFP_HF_TOKEN:-${HF_TOKEN:-}}" ]; then
    metadata_env_args+=(-e HF_TOKEN="${MODELFP_HF_TOKEN:-${HF_TOKEN:-}}")
  fi
  docker run --rm \
    --network bridge \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:size=512m,mode=1777 \
    --tmpfs /workspace/tmp:size=512m,mode=1777 \
    "${metadata_env_args[@]}" \
    -v "$(cd "$METADATA_DIR" && pwd):/workspace/metadata:rw" \
    --entrypoint python \
    "${MODELFP_METADATA_IMAGE:-modelfp:latest}" \
    /workspace/ModelFP_skill/scripts/collect_hf_repo_metadata.py \
      --repo-id "$REPO_ID" \
      --revision "$REVISION" \
      --out /workspace/metadata/hf_repo_metadata.json
  metadata_status=$?
else
  metadata_status=1
fi

if [ -f "$METADATA_DIR/hf_repo_metadata.json" ]; then
  export MODELFP_REMOTE_METADATA="$METADATA_DIR/hf_repo_metadata.json"
else
  unset MODELFP_REMOTE_METADATA
fi

if [ "$download_status" -eq 0 ]; then
  MODELFP_MODEL_NAME="$REPO_ID" MODELFP_REVISION="$REVISION" \
    ./scripts/docker_run_static_audit.sh "$MODEL_DIR" "$STATIC_DIR"
  static_status=$?
else
  static_status=1
fi

if [ "$SKIP_RUNTIME" = "true" ]; then
  echo "[ModelFP dataset] runtime skipped by MODELFP_SKIP_RUNTIME=true"
  runtime_status=0
elif [ "$download_status" -eq 0 ]; then
  MODELFP_MODEL_NAME="$REPO_ID" MODELFP_REVISION="$REVISION" \
    ./scripts/docker_run_local_model.sh "$MODEL_DIR" "$RUNTIME_DIR"
  runtime_status=$?
else
  runtime_status=1
fi

final_status="ok"
if [ "$download_status" -ne 0 ] || [ "$hash_status" -ne 0 ] || [ "$metadata_status" -ne 0 ] || [ "$static_status" -ne 0 ] || { [ "$SKIP_RUNTIME" != "true" ] && [ "$runtime_status" -ne 0 ]; }; then
  final_status="failed"
fi

write_manifest "$download_status" "$hash_status" "$metadata_status" "$static_status" "$runtime_status" "$final_status"

echo "[ModelFP dataset] manifest=$AUDIT_DIR/dataset_manifest.json"
echo "[ModelFP dataset] status=$final_status"

if [ "$final_status" = "ok" ]; then
  exit 0
fi
exit 1
