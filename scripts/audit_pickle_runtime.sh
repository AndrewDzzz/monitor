#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILL_DIR="$ROOT/skills/codex/modelfp"

MODEL_DIR="${1:-}"
OUT_DIR="${2:-$ROOT/outputs_pickle_runtime}"

if [ -z "$MODEL_DIR" ]; then
  echo "Usage: $0 /path/to/local_repo_or_snapshot [output_dir]" >&2
  exit 2
fi

"$SKILL_DIR/scripts/docker_run_pickle_runtime.sh" "$MODEL_DIR" "$OUT_DIR"
