#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

DATASET_ROOT="${1:-${MODELFP_DATASET_ROOT:-audit_datasets}}"
OUT_DIR="${2:-${MODELFP_FIGURE_OUT_DIR:-figures}}"
IMAGE="${MODELFP_IMAGE:-modelfp:latest}"

if [ ! -d "$DATASET_ROOT" ]; then
  echo "Dataset root not found: $DATASET_ROOT" >&2
  echo "Usage: $0 [dataset_root] [figure_out_dir]" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"

docker run --rm --network none \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$(cd "$DATASET_ROOT" && pwd):/workspace/audit_datasets:ro" \
  -v "$(cd "$OUT_DIR" && pwd):/workspace/figures:rw" \
  --entrypoint python \
  "$IMAGE" \
    /workspace/ModelFP_skill/code/experiment_figure_builder.py \
    --dataset-root /workspace/audit_datasets \
    --out /workspace/figures

echo "Experiment figures: $OUT_DIR"
