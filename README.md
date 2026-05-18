# ModelFP

## About

ModelFP is a Docker-first forensic audit suite for model repositories. It treats a model repo as a supply-chain object and builds an evidence chain from repository metadata, static artifact analysis, optional runtime traces, deterministic rules, and literature-grounded method notes.

The project is packaged for local CLI use and as agent skills:

- Codex skill: `skills/codex/modelfp`
- Claude skill adapter: `skills/claude/ModelFP`
- Local wrappers: `scripts/`

ModelFP audits a bounded context: repository, revision, files, config, metadata, container, command, inputs, and trace coverage. It does not prove universal model safety.

The dynamic-audit lineage comes from the March 2025 `monitor` prototype in this repository, which used `strace` and Python audit hooks to observe ML model execution. ModelFP turns that idea into a Docker-first, repo-level workflow and adds static fusion plus AI-assisted evidence review.

Use two citation targets:

- cite `monitor` for the original March 2025 dynamic audit prototype;
- cite `ModelFP` for the current Dockerized repo-level forensic audit workflow.

## Quick Start

Build the Docker images:

```bash
./scripts/build_images.sh
```

Audit a Hugging Face repo in static-only mode. The fingerprint and evidence stay under `audit_datasets/`; the downloaded model snapshot is deleted after the run by default.

```bash
./scripts/audit_hf_static.sh Helsinki-NLP/opus-mt-es-yua ./audit_datasets main
```

Audit a GitHub repo as a repo-level dataset:

```bash
./scripts/audit_github_static.sh https://github.com/AndrewDzzz/malicious_model_test ./audit_datasets main
```

Run static analysis on a local model snapshot or repo:

```bash
./scripts/audit_local_static.sh /path/to/local/repo ./outputs_static
```

Run controlled pickle detonation for `.pickle` and `.pkl` artifacts:

```bash
./scripts/audit_pickle_runtime.sh /path/to/local/repo ./outputs_pickle_runtime
```

## Install As Skills

Install or update the Codex skill:

```bash
./scripts/install_codex_skill.sh
```

Install a self-contained Claude skill folder into a chosen destination:

```bash
./scripts/install_claude_skill.sh /path/to/claude/skills
```

The Codex frontmatter name remains `modelfp` because Codex skill names are lowercase identifiers. The public project, UI display name, and Claude skill are named `ModelFP`.

## Docker Companion

ModelFP ships with Docker as the default execution boundary:

- `modelfp:latest` for static analysis, metadata collection, evidence normalization, rule checking, and pickle detonation helpers;
- `modelfp:ml` for controlled local model execution with CPU ML dependencies.

Remote fetch and metadata stages may use network access. Static analysis, normal runtime checks, and pickle detonation run offline with read-only target mounts. See `docs/DOCKER_WORKFLOW.md`.

## What It Checks

Static modules run inside Docker and include:

- file inventory, SHA256, file type, risky extensions, archives, command and URL text patterns;
- repository hygiene: non-model payloads, repeated commits, README script or external app instructions, task mismatch, malware-hosting-like file trees;
- malware-style static triage: executable magic, download cradles, PowerShell stagers, reverse-shell snippets, persistence hooks, credential harvesting strings, miner strings, and obfuscation patterns;
- Python and Lambda AST checks for dangerous calls, `subprocess(shell=True)`, unsafe deserialization, event logging, Flask debug mode, and private package indexes;
- config checks for `auto_map`, `trust_remote_code`, URLs, missing `model_type`, and custom-code loading;
- HDF5/Keras probing, pickle opcode probing, ModelScan integration, and fused static repo-level judgment.

Dynamic modules are optional and also run inside Docker:

- `strace` syscall capture;
- Python audit hook capture;
- per-artifact pickle runtime detonation with network disabled;
- normalized evidence graph and deterministic harm certificates.

## Output Contract

Dataset runs write one folder per audit:

```text
audit_datasets/<repo_slug>/<audit_id>/
dataset_manifest.json
orchestrator.log
metadata/
outputs_static/
outputs_runtime/          optional
outputs_pickle_runtime/   optional
```

Primary facts are `evidence_graph.json` and verified `harm_certificates.json`. LLM payloads are secondary interpretation and must cite evidence IDs.

## Data Hygiene

The published repository excludes local audit outputs, model snapshots, sandbox canaries, logs, archives, and generated figures. Runtime wrappers keep outputs on the host but remove downloaded or cloned model snapshots by default. See `docs/SANITIZATION.md`.

## Method

See `docs/METHODOLOGY.md` for the audit route and evidence-chain design.

## Citation

If you use the original dynamic audit idea, cite `monitor`. If you use the current Dockerized workflow, static fusion, evidence graph, harm certificates, or agent skill package, cite `ModelFP`. See `CITATION.cff` and `docs/RELATED_WORK.md`.
