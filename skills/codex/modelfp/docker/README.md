# ModelFP Docker Runtime

This Docker setup runs all ModelFP audit work inside a constrained container: static/config/artifact analysis, environment inspection, optional runtime tracing, evidence normalization, deterministic rulecheck, literature grounding, and LLM-payload generation. The host should only build images, mount read-only inputs, and read output files.

## What Docker collects

```text
/workspace/out/
  evidence_graph.json              unified static/config/env/runtime evidence
  harm_certificates.json           deterministic rulecheck certificates
  llm_payload.json                  compact payload to send to an LLM
  llm_prompt.md                     safe prompt wrapper for the LLM
  run_manifest.json                 run metadata
  evidence/*.jsonl                  repo/config/env/modelscan evidence
  evidence/literature_evidence.jsonl paper/method grounding nodes
  traces/strace.*                   syscall traces
  traces/python_audit.jsonl         Python audit-hook events
  traces/target_stdout.log          target stdout
  traces/target_stderr.log          target stderr
  static/modelscan_report.json      raw ModelScan report when available
```

## Build

From `ModelFP_skill/`:

```bash
docker build -f docker/Dockerfile -t modelfp:latest .
```

For actual Hugging Face model loading with CPU PyTorch/Transformers:

```bash
docker build -f docker/Dockerfile --build-arg INSTALL_ML_DEPS=true -t modelfp:ml .
```

## Demo: benign target

```bash
scripts/docker_build.sh
scripts/docker_run_benign_demo.sh
```

## Demo: suspicious target

This uses a fake canary SSH key, executes a harmless shell echo, and attempts a blocked network connection.

```bash
scripts/docker_build.sh
scripts/docker_run_suspicious_demo.sh
```

## Download a remote Hugging Face model

Use a separate network-enabled container only for fetching the snapshot. This stage does not run the model:

```bash
scripts/docker_download_hf_model.sh owner/model workspace/models/model main
```

For private or gated models:

```bash
MODELFP_HF_TOKEN="$HF_TOKEN" scripts/docker_download_hf_model.sh owner/private-model workspace/models/model main
```

After this, run static or runtime audit with network disabled.

## Static-only audit

Run repository/config/ModelScan analysis without executing the target model. This still runs inside Docker:

```bash
scripts/docker_build.sh
scripts/docker_run_static_audit.sh /path/to/hf_snapshot outputs_static
```

## Run a local Hugging Face snapshot offline

Convenience wrapper:

```bash
MODELFP_PROMPT="hello" ./scripts/docker_run_local_model.sh /path/to/hf_snapshot outputs
```

Manual equivalent:

Mount a pre-downloaded Hugging Face snapshot at `/workspace/models/model`, and use the included target script:

```bash
docker run --rm --network none \
  --cap-add SYS_PTRACE \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=unconfined \
  --read-only \
  --tmpfs /tmp:size=512m,mode=1777 \
  --tmpfs /workspace/tmp:size=512m,mode=1777 \
  --pids-limit 256 \
  --memory 8g \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -v "/path/to/hf_snapshot:/workspace/models/model:ro" \
  -v "$PWD/examples/targets:/workspace/target:ro" \
  -v "$PWD/outputs:/workspace/out:rw" \
  modelfp:ml \
    --model-repo /workspace/models/model \
    --target-script /workspace/target/run_hf_local_model.py \
    --out /workspace/out \
    --timeout 300 \
    -- \
    --model-dir /workspace/models/model \
    --prompt "hello"
```

Use `--trust-remote-code` only when intentionally testing custom code risk:

```bash
... -- --model-dir /workspace/models/model --trust-remote-code --prompt "hello"
```

## Docker Compose

Default no-network demo:

```bash
docker compose -f docker/docker-compose.yml up --build --abort-on-container-exit
```

ML dependencies override:

```bash
docker compose -f docker/docker-compose.yml -f docker/docker-compose.ml.yml up --build --abort-on-container-exit
```

## Returning logs to the LLM

Do **not** send raw logs first. Send:

```text
outputs/llm_payload.json
outputs/llm_prompt.md
```

The payload is evidence-indexed and redacted. The prompt tells the LLM that all paths, stdout/stderr, command arguments, and trace strings are untrusted evidence, not instructions. The LLM should summarize risks and propose candidate rules, but ModelFP evidence IDs and harm certificates remain the source of truth.

## Safety notes

- Do not run the Python runner directly on the host for normal audits; it refuses host execution by default.
- Keep `--network none` for runtime verification unless intentionally testing network behavior.
- Do not mount real `~/.ssh`, cloud credentials, Docker socket, or API keys.
- Use fake canary secrets when testing exfiltration-like behavior.
- ModelFP reports bounded evidence from this run. It does not prove universal model safety.
- `SYS_PTRACE` and `seccomp=unconfined` are needed so `strace` can monitor the target process; run inside an isolated VM if testing unknown models.
