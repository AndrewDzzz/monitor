#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

MODEL_DIR="${1:-${MODELFP_MODEL_DIR:-workspace/models/model}}"
OUT_DIR="${2:-${MODELFP_OUT_DIR:-outputs_pickle_runtime}}"
IMAGE="${MODELFP_IMAGE:-modelfp:latest}"
TIMEOUT="${MODELFP_PICKLE_TIMEOUT:-30}"
MODEL_NAME="${MODELFP_MODEL_NAME:-local/model}"
REVISION="${MODELFP_REVISION:-local}"

if [ ! -d "$MODEL_DIR" ]; then
  echo "Model/repo directory not found: $MODEL_DIR" >&2
  echo "Usage: $0 /path/to/repo_or_snapshot [output_dir]" >&2
  exit 2
fi

mkdir -p "$OUT_DIR/artifacts"
MODEL_ABS="$(cd "$MODEL_DIR" && pwd)"
OUT_ABS="$(mkdir -p "$OUT_DIR" && cd "$OUT_DIR" && pwd)"

docker run --rm --network none \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  -v "$MODEL_ABS:/workspace/repo:ro" \
  -v "$OUT_ABS:/workspace/out:rw" \
  --entrypoint sh \
  "$IMAGE" \
  -c 'cd /workspace/repo && find . -type f \( -name "*.pickle" -o -name "*.pkl" \) ! -path "./.git/*" -print | sort > /workspace/out/pickle_artifacts.txt'

if [ ! -s "$OUT_ABS/pickle_artifacts.txt" ]; then
  echo "No .pickle/.pkl artifacts found under $MODEL_DIR" >&2
  exit 3
fi

overall_status=0
while IFS= read -r rel; do
  rel="${rel#./}"
  slug="$(printf '%s' "$rel" | tr '/:@ ' '____' | tr -c 'A-Za-z0-9._-' '-' | sed -E 's/^-+//; s/-+$//; s/-+/-/g')"
  artifact_out="$OUT_ABS/artifacts/$slug"
  mkdir -p "$artifact_out/traces"
  echo "[ModelFP pickle runtime] artifact=$rel out=$artifact_out"

  set +e
  docker run --rm --network none \
    --cap-add SYS_PTRACE \
    --security-opt no-new-privileges:true \
    --security-opt seccomp=unconfined \
    --read-only \
    --tmpfs /tmp:size=128m,mode=1777 \
    --pids-limit 128 \
    --memory "${MODELFP_PICKLE_MEMORY:-512m}" \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -e PYTHONUNBUFFERED=1 \
    -e MODELFP_PICKLE_TIMEOUT="$TIMEOUT" \
    -v "$MODEL_ABS:/workspace/repo:ro" \
    -v "$artifact_out:/workspace/out:rw" \
    --entrypoint sh \
    "$IMAGE" \
    -c 'set -eu
      timeout "${MODELFP_PICKLE_TIMEOUT:-30}" \
        strace -ff -tt -T -yy -s 4096 -o /workspace/out/traces/strace \
          python /workspace/ModelFP_skill/code/audit_runner.py \
            --script /workspace/ModelFP_skill/code/pickle_runtime_target.py \
            --audit-log /workspace/out/traces/python_audit.jsonl \
            --phase PICKLE_RUNTIME \
            -- --artifact "/workspace/repo/$1" --out /workspace/out/pickle_runtime_observations.json \
        > /workspace/out/traces/target_stdout.log \
        2> /workspace/out/traces/target_stderr.log' sh "$rel"
  rc=$?
  set -e
  printf '%s\n' "$rc" > "$artifact_out/container_exit.txt"
  if [ "$rc" -ne 0 ]; then
    overall_status=10
  fi

  docker run --rm --network none \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:size=64m,mode=1777 \
    -v "$artifact_out:/workspace/out:rw" \
    --entrypoint python \
    "$IMAGE" \
    /workspace/ModelFP_skill/code/trace_normalizer.py \
      --out-dir /workspace/out \
      --output /workspace/out/evidence_graph.json \
      --model "$MODEL_NAME" \
      --revision "$REVISION" \
      --run-id "pickle-runtime-$slug"

  docker run --rm --network none \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:size=64m,mode=1777 \
    -v "$artifact_out:/workspace/out:rw" \
    --entrypoint python \
    "$IMAGE" \
    /workspace/ModelFP_skill/code/simple_rulecheck_runner.py \
      --evidence-graph /workspace/out/evidence_graph.json \
      --policy /workspace/ModelFP_skill/rules/policy_minimal.yaml \
      --out /workspace/out/harm_certificates.json \
      --model "$MODEL_NAME" \
      --revision "$REVISION" \
      --run-id "pickle-runtime-$slug"
done < "$OUT_ABS/pickle_artifacts.txt"

docker run --rm --network none \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=64m,mode=1777 \
  -v "$OUT_ABS:/workspace/out:rw" \
  --entrypoint python \
  "$IMAGE" \
  /workspace/ModelFP_skill/code/pickle_runtime_aggregate.py \
    --out-root /workspace/out \
    --out /workspace/out/pickle_runtime_summary.json

echo "Pickle runtime summary: $OUT_DIR/pickle_runtime_summary.json"
exit "$overall_status"
