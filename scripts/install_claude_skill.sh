#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/skills/codex/modelfp"
ADAPTER="$ROOT/skills/claude/ModelFP/SKILL.md"
DEST_ROOT="${1:-}"

if [ -z "$DEST_ROOT" ]; then
  echo "Usage: $0 /path/to/claude/skills" >&2
  exit 2
fi

DEST="$DEST_ROOT/ModelFP"
mkdir -p "$DEST_ROOT"
rsync -a --delete \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '*.pyo' \
  --exclude 'audit_datasets/' \
  --exclude 'latest_hf_runs/' \
  --exclude 'outputs/' \
  --exclude 'outputs_*/' \
  --exclude 'workspace/models/' \
  --exclude 'workspace/out/' \
  "$SRC/" "$DEST/"
cp "$ADAPTER" "$DEST/SKILL.md"

echo "Installed Claude skill: $DEST"
