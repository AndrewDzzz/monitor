#!/usr/bin/env bash
set -euo pipefail

MODELFP_HOME="${MODELFP_HOME:-/workspace/ModelFP_skill}"
RUNNER="$MODELFP_HOME/code/modelfp_docker_runner.py"
TRACE_NORMALIZER="$MODELFP_HOME/code/trace_normalizer.py"
RULECHECK="$MODELFP_HOME/code/simple_rulecheck_runner.py"
LLM_BUILDER="$MODELFP_HOME/code/llm_payload_builder.py"

cmd="${1:-help}"
shift || true

case "$cmd" in
  help)
    cat <<'EOF'
ModelFP Docker commands:

  scan-static      Static scan only: repo/config/artifact/ModelScan/env evidence.
  run-runtime      Runtime trace only: strace + Python audit hook in container.
  normalize        Normalize collected logs into evidence_graph.json.
  rulecheck        Run deterministic rulecheck and produce certificates.
  build-llm        Build llm_payload.json and llm_prompt.md for GPT/LLM review.
  pipeline         Run static scan -> runtime trace -> normalize -> rulecheck -> LLM payload.

Examples:
  modelfp pipeline --model-id sshleifer/tiny-gpt2 --output-dir /outputs/tiny
  modelfp scan-static --model-path /workspace/model --output-dir /outputs/static
  modelfp run-runtime --model-path /workspace/model --output-dir /outputs/runtime --prompt "hello"

Security notes:
  - For runtime testing, run this container without real secrets.
  - Prefer --network none once the model has already been downloaded/mounted.
  - Do not mount /var/run/docker.sock, ~/.ssh, ~/.aws, or cloud credentials.
EOF
    ;;
  scan-static)
    exec python "$RUNNER" --skip-runtime "$@"
    ;;
  run-runtime)
    exec python "$RUNNER" --skip-modelscan "$@"
    ;;
  normalize)
    exec python "$TRACE_NORMALIZER" "$@"
    ;;
  rulecheck)
    exec python "$RULECHECK" "$@"
    ;;
  build-llm)
    exec python "$LLM_BUILDER" "$@"
    ;;
  pipeline)
    exec python "$RUNNER" "$@"
    ;;
  *)
    exec "$cmd" "$@"
    ;;
esac
