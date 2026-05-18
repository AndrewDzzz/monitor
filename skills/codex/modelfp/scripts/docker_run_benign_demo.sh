#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p outputs

docker run --rm \
  --cap-add SYS_PTRACE \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=unconfined \
  --network none \
  --read-only \
  --tmpfs /tmp:size=512m,mode=1777 \
  --tmpfs /workspace/tmp:size=512m,mode=1777 \
  --pids-limit 256 \
  --memory 4g \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD/examples/dummy_hf_model:/workspace/models/model:ro" \
  -v "$PWD/examples/targets:/workspace/target:ro" \
  -v "$PWD/outputs:/workspace/out:rw" \
  modelfp:latest \
    --model-repo /workspace/models/model \
    --target-script /workspace/target/benign_model.py \
    --out /workspace/out \
    --timeout 120

echo "LLM payload: outputs/llm_payload.json"
echo "LLM prompt:  outputs/llm_prompt.md"
