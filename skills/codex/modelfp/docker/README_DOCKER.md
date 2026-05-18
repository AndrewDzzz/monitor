# ModelFP Docker Workflow

Use a two-stage Docker workflow:

1. Download the Hugging Face snapshot in a network-enabled container.
2. Collect Hub model-card, sibling-file, and commit metadata in the same network-enabled phase.
3. Audit the downloaded snapshot offline with `--network none`.

The host builds images, mounts model inputs read-only, and reads output files. Static probes, runtime tracing, rule checking, certificate generation, literature mapping, and LLM payload generation all run inside Docker.

## Build

```bash
docker build -f docker/Dockerfile -t modelfp:latest .
docker build -f docker/Dockerfile --build-arg INSTALL_ML_DEPS=true -t modelfp:ml .
```

## Download Stage

```bash
./scripts/docker_download_hf_model.sh owner/model workspace/models/model main
```

This stage may use network access. Do not execute the model here.

The dataset orchestrator also writes:

```text
metadata/hf_repo_metadata.json
```

That file is then mounted read-only into offline static/runtime audit containers for abnormal commit-frequency, repeated-commit, model-card consistency, and file-list cross-checks.

## Dataset-Oriented Full Audit

For repeatable audit datasets, prefer the orchestrator:

```bash
./scripts/docker_audit_hf_model_dataset.sh owner/model audit_datasets main
```

It creates one immutable directory per audit:

```text
audit_datasets/<repo_slug>/<audit_id>/
  dataset_manifest.json
  orchestrator.log
  metadata/hf_repo_metadata.json
  metadata/model_sha256.txt
  model/
  outputs_static/
  outputs_runtime/
```

## Static Audit Stage

```bash
./scripts/docker_run_static_audit.sh workspace/models/model outputs_static
```

Static audit runs repository/config/environment probes, repo-hygiene checks for non-model payloads and README execution guidance, HDF5/Keras metadata probing, pickle opcode probing without unpickling, ModelScan, evidence normalization, deterministic checks, certificate verification, literature mapping, and LLM payload generation.

Static audit also runs:

- all-file inventory and text-pattern scanning;
- malware-style static triage for executable magic, shell download cradles, PowerShell stagers, reverse shells, persistence hooks, credential-harvesting strings, miner indicators, and obfuscation patterns;
- Python/Lambda AST scanning without importing repository code.
- static fusion that combines malware, config, pickle/ModelScan, AST, payload, and repo-hygiene signals into repo-level judgments.

## GitHub Static Dataset

```bash
./scripts/docker_audit_github_repo_static_dataset.sh https://github.com/owner/repo audit_datasets main
```

To add controlled pickle detonation after static scanning:

```bash
MODELFP_RUN_PICKLE_RUNTIME=true ./scripts/docker_audit_github_repo_static_dataset.sh https://github.com/owner/repo audit_datasets main
```

Pickle runtime launches one fresh container per `.pickle`/`.pkl` artifact, with network disabled and `/tmp` backed by tmpfs.

## Experiment Figures

```bash
./scripts/docker_build_experiment_figures.sh audit_datasets figures
```

The figure builder runs with network disabled, reads audit datasets read-only, and writes:

```text
figures/figure_01_repo_level_workflow.svg
figures/figure_02_pickle_evidence_chain.svg
figures/figure_03_experiment_matrix.svg
figures/experiment_figure_metrics.json
```

## Runtime Audit Stage

```bash
MODELFP_PROMPT="hello" \
MODELFP_MODEL_NAME="owner/model" \
MODELFP_REVISION="main" \
./scripts/docker_run_local_model.sh workspace/models/model outputs
```

Runtime audit runs with network disabled, read-only model and target mounts, `strace`, Python audit hooks, stdout/stderr capture, and the same evidence/certificate/payload pipeline.
