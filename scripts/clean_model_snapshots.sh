#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATASET_ROOT="${1:-$ROOT/audit_datasets}"

if [ ! -d "$DATASET_ROOT" ]; then
  echo "Dataset root not found: $DATASET_ROOT" >&2
  exit 2
fi

docker run --rm --network none \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  -v "$(cd "$DATASET_ROOT" && pwd):/workspace/audit_datasets:rw" \
  --entrypoint sh \
  "${MODELFP_IMAGE:-modelfp:latest}" \
  -c 'find /workspace/audit_datasets -type d -name model -prune -exec rm -rf {} +'

echo "Removed model snapshot folders under: $DATASET_ROOT"
