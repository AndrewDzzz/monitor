#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/skills/codex/modelfp"
DEST="${1:-${CODEX_HOME:-$HOME/.codex}/skills/modelfp}"

mkdir -p "$(dirname "$DEST")"
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

echo "Installed Codex skill: $DEST"
