#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL_DIR="$ROOT/skills/codex/modelfp"

INPUT_REF="${1:-}"
DATASET_ROOT="${2:-$ROOT/audit_datasets}"
REVISION_ARG="${3:-}"

if [ -z "$INPUT_REF" ]; then
  echo "Usage: $0 owner/model-or-hf-url [dataset_root] [revision]" >&2
  exit 2
fi

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
  printf '%s' "$1" | tr '/:@ ' '____' | tr -c 'A-Za-z0-9._-' '-' | sed -E 's/^-+//; s/-+$//; s/-+/-/g'
}

REPO_ID="$(repo_from_ref "$INPUT_REF")"
URL_REVISION="$(revision_from_ref "$INPUT_REF")"
REVISION="${REVISION_ARG:-${URL_REVISION:-main}}"
REPO_SLUG="$(slugify "$REPO_ID")"
REVISION_SLUG="$(slugify "$REVISION")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
export MODELFP_AUDIT_ID="${MODELFP_AUDIT_ID:-${STAMP}_${REPO_SLUG}_${REVISION_SLUG}}"
export MODELFP_SKIP_RUNTIME="${MODELFP_SKIP_RUNTIME:-true}"

mkdir -p "$DATASET_ROOT"
"$SKILL_DIR/scripts/docker_audit_hf_model_dataset.sh" "$INPUT_REF" "$DATASET_ROOT" "$REVISION"

AUDIT_DIR="$DATASET_ROOT/$REPO_SLUG/$MODELFP_AUDIT_ID"
if [ "${MODELFP_DELETE_MODEL_AFTER:-true}" = "true" ] && [ -d "$AUDIT_DIR/model" ]; then
  rm -rf "$AUDIT_DIR/model"
  python3 - "$AUDIT_DIR/dataset_manifest.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if path.exists():
    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("paths", {})["model_dir"] = None
    data["model_removed_after_audit"] = True
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
fi

echo "Audit dataset: $AUDIT_DIR"
