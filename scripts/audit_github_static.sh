#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL_DIR="$ROOT/skills/codex/modelfp"

REPO_URL="${1:-}"
DATASET_ROOT="${2:-$ROOT/audit_datasets}"
REVISION="${3:-main}"

if [ -z "$REPO_URL" ]; then
  echo "Usage: $0 https://github.com/owner/repo [dataset_root] [revision]" >&2
  exit 2
fi

repo_slug() {
  local ref="$1"
  ref="${ref#https://github.com/}"
  ref="${ref#http://github.com/}"
  ref="${ref%.git}"
  printf 'github_%s' "$ref" | tr '/:@ ' '____' | tr -c 'A-Za-z0-9._-' '-' | sed -E 's/^-+//; s/-+$//; s/-+/-/g'
}

slugify() {
  printf '%s' "$1" | tr '/:@ ' '____' | tr -c 'A-Za-z0-9._-' '-' | sed -E 's/^-+//; s/-+$//; s/-+/-/g'
}

REPO_SLUG="$(repo_slug "$REPO_URL")"
REVISION_SLUG="$(slugify "$REVISION")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
export MODELFP_AUDIT_ID="${MODELFP_AUDIT_ID:-${STAMP}_${REPO_SLUG}_${REVISION_SLUG}}"

mkdir -p "$DATASET_ROOT"
"$SKILL_DIR/scripts/docker_audit_github_repo_static_dataset.sh" "$REPO_URL" "$DATASET_ROOT" "$REVISION"

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
