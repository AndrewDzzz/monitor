# ModelFP Skill Package

This package turns ModelFP into a reusable Codex skill for Dockerized model repository forensics.

It includes:

- `SKILL.md`: Codex skill entry point.
- `agents/openai.yaml`: UI metadata.
- `schemas/evidence.schema.json`: evidence node schema.
- `schemas/rule.schema.json`: rule DSL schema.
- `schemas/harm_certificate.schema.json`: harm certificate schema.
- `examples/model_fp_policy.yaml`: sample policy and rules.
- `examples/harm_certificate.example.json`: sample certificate.
- `examples/model_fp_report.example.json`: sample final report.
- `prompts/gpt_trace_auditor_prompt.md`: GPT evidence-review prompt.
- `prompts/gpt_rule_generator_prompt.md`: GPT candidate-rule prompt.
- `docs/formalization_notes.md`: formalization notes.
- `docs/literature_grounding.md`: mapping from published methods to evidence-chain nodes.

The primary audit entry points are the Docker scripts. `code/modelfp_docker_runner.py` should run inside the container; by default it refuses host execution to avoid mixing host paths, credentials, or environment state into the evidence chain.
Remote model download, Hub metadata collection, static audit, and runtime audit are all performed through Docker. Each full audit is written to an isolated dataset folder.

## Docker sandbox add-on

This package includes a Docker sandbox for running target model scripts and producing LLM-ready evidence payloads.

Build:

```bash
./scripts/docker_build.sh
```

Run benign demo:

```bash
./scripts/docker_run_benign_demo.sh
```

Run suspicious demo:

```bash
./scripts/docker_run_suspicious_demo.sh
```

Download remote Hugging Face model into a local Docker-managed snapshot directory:

```bash
./scripts/docker_download_hf_model.sh owner/model workspace/models/model main
```

Run a full audit as a reusable dataset item:

```bash
./scripts/docker_audit_hf_model_dataset.sh owner/model audit_datasets main
```

This also saves `metadata/hf_repo_metadata.json` for commit-frequency, repeated-commit, model-card, and sibling-file evidence.

Run a GitHub repository static dataset item:

```bash
./scripts/docker_audit_github_repo_static_dataset.sh https://github.com/owner/repo audit_datasets main
```

Add controlled pickle detonation, one Docker container per `.pickle`/`.pkl` artifact:

```bash
MODELFP_RUN_PICKLE_RUNTIME=true ./scripts/docker_audit_github_repo_static_dataset.sh https://github.com/owner/repo audit_datasets main
./scripts/docker_run_pickle_runtime.sh /path/to/local_repo outputs_pickle_runtime
```

Generate report-ready experiment figures from accumulated datasets:

```bash
./scripts/docker_build_experiment_figures.sh audit_datasets figures
```

Run static-only audit inside Docker:

```bash
./scripts/docker_run_static_audit.sh /path/to/local_hf_snapshot outputs_static
```

Run a local Hugging Face snapshot inside Docker:

```bash
docker build -f docker/Dockerfile --build-arg INSTALL_ML_DEPS=true -t modelfp:ml .
./scripts/docker_run_local_model.sh /path/to/local_hf_snapshot outputs
```

After a run, inspect:

```text
outputs/evidence_graph.json
outputs/harm_certificates.json
outputs/llm_payload.json
outputs/llm_prompt.md
outputs/run_manifest.json
outputs/evidence/literature_evidence.jsonl
```

Send `outputs/llm_prompt.md` or `outputs/llm_payload.json` to the LLM for semantic auditing. Raw logs are kept in `outputs/` but should not be sent directly before normalization/redaction.


## Docker runtime extension

This package now includes `docker/`, which can run ModelFP inside a container:

- static scan inside Docker: all-file inventory, Python/Lambda AST, repo/config/repo-hygiene/HDF5 metadata/pickle opcodes/ModelScan/environment evidence;
- malware-style static triage: executable magic, shell download cradles, PowerShell stagers, reverse-shell snippets, persistence hooks, credential-harvesting strings, miner strings, and obfuscation patterns;
- static fusion: combines malware triage, config risks, pickle/ModelScan, AST sinks, all-file payload evidence, and repo hygiene into repo-level static judgments;
- repo hygiene checks: APK/EXE/BAT/PS1/DLL/ZIP/JAR payloads, README app/script instructions, abnormal or repeated commits, model-card task mismatch, and malware-hosting-like file trees;
- controlled pickle runtime: per-artifact Docker detonation with network disabled, read-only repo mount, tmpfs `/tmp`, `strace`, and Python audit hooks;
- experiment figures: repo-level workflow, pickle evidence chain, and dataset experiment matrix generated from `audit_datasets/`;
- runtime trace: `strace` + Python audit hook + stdout/stderr;
- normalized evidence graph;
- deterministic rulecheck;
- `llm_payload.json` and `llm_prompt.md` for GPT/LLM review.

Environment exposure findings are sandbox hygiene signals, not target repo findings. The experiment figures report target-side risk and keep environment checks out of the repo-risk matrix.
Fused static findings are derived evidence; reports should still cite the raw probe IDs behind the fused node.

Start with:

```bash
docker build -f docker/Dockerfile -t modelfp:latest .
./scripts/docker_run_benign_demo.sh
```

See `docker/README_DOCKER.md` for the safer two-stage network/no-network workflow.
