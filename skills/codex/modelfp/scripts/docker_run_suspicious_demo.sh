#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p outputs sandbox/canary_home/.ssh
printf 'MODELFP_FAKE_CANARY_PRIVATE_KEY_DO_NOT_USE\n' > sandbox/canary_home/.ssh/id_rsa
chmod 600 sandbox/canary_home/.ssh/id_rsa

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
  -v "$PWD/sandbox/canary_home/.ssh:/home/modelrunner/.ssh:ro" \
  -v "$PWD/outputs:/workspace/out:rw" \
  modelfp:latest \
    --model-repo /workspace/models/model \
    --target-script /workspace/target/suspicious_demo.py \
    --out /workspace/out \
    --timeout 120

echo "LLM payload: outputs/llm_payload.json"
echo "LLM prompt:  outputs/llm_prompt.md"
