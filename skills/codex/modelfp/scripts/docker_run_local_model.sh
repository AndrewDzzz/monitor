#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

MODEL_DIR="${1:-${MODELFP_MODEL_DIR:-workspace/models/model}}"
OUT_DIR="${2:-${MODELFP_OUT_DIR:-outputs}}"
IMAGE="${MODELFP_IMAGE:-modelfp:ml}"
PROMPT="${MODELFP_PROMPT:-hello}"
TIMEOUT="${MODELFP_TIMEOUT:-300}"
MODEL_NAME="${MODELFP_MODEL_NAME:-local/model}"
REVISION="${MODELFP_REVISION:-local}"
TRUST_REMOTE_CODE="${MODELFP_TRUST_REMOTE_CODE:-false}"
REMOTE_METADATA="${MODELFP_REMOTE_METADATA:-}"

if [ ! -d "$MODEL_DIR" ]; then
  echo "Model directory not found: $MODEL_DIR" >&2
  echo "Usage: $0 /path/to/local_hf_snapshot [output_dir]" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

target_args=(--model-dir /workspace/models/model --prompt "$PROMPT")
if [ "$TRUST_REMOTE_CODE" = "true" ]; then
  target_args+=(--trust-remote-code)
fi

metadata_mount=()
runner_args=()
if [ -n "$REMOTE_METADATA" ]; then
  if [ ! -f "$REMOTE_METADATA" ]; then
    echo "Remote metadata file not found: $REMOTE_METADATA" >&2
    exit 2
  fi
  metadata_dir="$(cd "$(dirname "$REMOTE_METADATA")" && pwd)"
  metadata_name="$(basename "$REMOTE_METADATA")"
  metadata_mount=(-v "$metadata_dir:/workspace/metadata:ro")
  runner_args+=(--remote-metadata "/workspace/metadata/$metadata_name")
fi

docker run --rm --network none \
  --cap-add SYS_PTRACE \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=unconfined \
  --read-only \
  --tmpfs /tmp:size=512m,mode=1777 \
  --tmpfs /workspace/tmp:size=512m,mode=1777 \
  --pids-limit 256 \
  --memory 8g \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$(cd "$MODEL_DIR" && pwd):/workspace/models/model:ro" \
  "${metadata_mount[@]}" \
  -v "$PWD/examples/targets:/workspace/target:ro" \
  -v "$(mkdir -p "$OUT_DIR" && cd "$OUT_DIR" && pwd):/workspace/out:rw" \
  "$IMAGE" \
    --model-repo /workspace/models/model \
    --target-script /workspace/target/run_hf_local_model.py \
    --out /workspace/out \
    --model "$MODEL_NAME" \
    --revision "$REVISION" \
    --timeout "$TIMEOUT" \
    "${runner_args[@]}" \
    -- \
    "${target_args[@]}"

echo "Evidence graph: $OUT_DIR/evidence_graph.json"
echo "Certificates:    $OUT_DIR/harm_certificates.json"
echo "LLM payload:     $OUT_DIR/llm_payload.json"
