#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "${1:-}" = "" ]; then
  echo "Usage: $0 owner/model [local_model_dir] [revision]" >&2
  echo "Example: $0 sshleifer/tiny-gpt2 workspace/models/model main" >&2
  exit 2
fi

REPO_ID="$1"
MODEL_DIR="${2:-${MODELFP_MODEL_DIR:-workspace/models/model}}"
REVISION="${3:-${MODELFP_REVISION:-}}"
IMAGE="${MODELFP_IMAGE:-modelfp:latest}"

mkdir -p "$MODEL_DIR"

args=(/workspace/ModelFP_skill/scripts/prefetch_hf_snapshot.py --repo-id "$REPO_ID" --out /workspace/models/model)
if [ -n "$REVISION" ]; then
  args+=(--revision "$REVISION")
fi

env_args=(-e PYTHONDONTWRITEBYTECODE=1 -e HF_HOME=/workspace/tmp/hf_home -e HUGGINGFACE_HUB_CACHE=/workspace/tmp/hf_cache)
if [ -n "${MODELFP_HF_TOKEN:-${HF_TOKEN:-}}" ]; then
  env_args+=(-e HF_TOKEN="${MODELFP_HF_TOKEN:-${HF_TOKEN:-}}")
fi

docker run --rm \
  --network bridge \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=512m,mode=1777 \
  --tmpfs /workspace/tmp:size=2g,mode=1777 \
  "${env_args[@]}" \
  -v "$(cd "$MODEL_DIR" && pwd):/workspace/models/model:rw" \
  --entrypoint python \
  "$IMAGE" \
  "${args[@]}"

echo "Downloaded snapshot: $MODEL_DIR"
echo "Next static audit:    ./scripts/docker_run_static_audit.sh $MODEL_DIR outputs_static"
echo "Next runtime audit:   ./scripts/docker_run_local_model.sh $MODEL_DIR outputs"
