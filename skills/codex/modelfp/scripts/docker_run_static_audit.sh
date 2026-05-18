#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

MODEL_DIR="${1:-${MODELFP_MODEL_DIR:-workspace/models/model}}"
OUT_DIR="${2:-${MODELFP_OUT_DIR:-outputs_static}}"
IMAGE="${MODELFP_IMAGE:-modelfp:latest}"
TIMEOUT="${MODELFP_TIMEOUT:-180}"
MODEL_NAME="${MODELFP_MODEL_NAME:-local/model}"
REVISION="${MODELFP_REVISION:-local}"
REMOTE_METADATA="${MODELFP_REMOTE_METADATA:-}"

if [ ! -d "$MODEL_DIR" ]; then
  echo "Model directory not found: $MODEL_DIR" >&2
  echo "Usage: $0 /path/to/local_hf_snapshot [output_dir]" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

docker_cmd=(
  docker run --rm --network none
  --security-opt no-new-privileges:true
  --read-only
  --tmpfs /tmp:size=512m,mode=1777
  --tmpfs /workspace/tmp:size=512m,mode=1777
  -e PYTHONDONTWRITEBYTECODE=1
  -v "$(cd "$MODEL_DIR" && pwd):/workspace/models/model:ro"
)
runner_args=()
if [ -n "$REMOTE_METADATA" ]; then
  if [ ! -f "$REMOTE_METADATA" ]; then
    echo "Remote metadata file not found: $REMOTE_METADATA" >&2
    exit 2
  fi
  metadata_dir="$(cd "$(dirname "$REMOTE_METADATA")" && pwd)"
  metadata_name="$(basename "$REMOTE_METADATA")"
  docker_cmd+=(-v "$metadata_dir:/workspace/metadata:ro")
  runner_args+=(--remote-metadata "/workspace/metadata/$metadata_name")
fi

docker_cmd+=(
  -v "$(mkdir -p "$OUT_DIR" && cd "$OUT_DIR" && pwd):/workspace/out:rw"
  "$IMAGE"
  --model-repo /workspace/models/model
  --out /workspace/out
  --model "$MODEL_NAME"
  --revision "$REVISION"
  --timeout "$TIMEOUT"
)
if [ "${#runner_args[@]}" -gt 0 ]; then
  docker_cmd+=("${runner_args[@]}")
fi
docker_cmd+=(--skip-runtime)

"${docker_cmd[@]}"

echo "Evidence graph: $OUT_DIR/evidence_graph.json"
echo "Certificates:    $OUT_DIR/harm_certificates.json"
echo "LLM payload:     $OUT_DIR/llm_payload.json"
