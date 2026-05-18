# Docker Workflow

ModelFP is designed to ship with Docker as the default execution boundary.

## Images

Build both images from the repository root:

```bash
./scripts/build_images.sh
```

This creates:

- `modelfp:latest`: static analysis, metadata collection, ModelScan, evidence normalization, rule checking, and pickle detonation helpers.
- `modelfp:ml`: everything in `modelfp:latest` plus CPU ML dependencies for controlled local model execution.

## Stages

1. Download or clone stage: network enabled only when fetching a remote Hugging Face or GitHub repository.
2. Metadata stage: network enabled only when collecting Hub metadata.
3. Static stage: network disabled; target mounted read-only.
4. Runtime stage: network disabled by default; target mounted read-only; output folder mounted writable.
5. Pickle detonation stage: one fresh container per `.pickle` or `.pkl` artifact.

## Host Persistence

The host keeps evidence and fingerprints:

```text
audit_datasets/<repo_slug>/<audit_id>/
outputs_static/
outputs_pickle_runtime/
dataset_manifest.json
```

Downloaded or cloned model snapshots are removed after dataset runs unless:

```bash
MODELFP_DELETE_MODEL_AFTER=false
```

## Security Posture

Docker is an evidence boundary and reproducibility aid. It is not a perfect sandbox. Do not mount real SSH keys, cloud credentials, API keys, `/var/run/docker.sock`, or broad host directories into the runtime container.

Use `--cap-add SYS_PTRACE --security-opt seccomp=unconfined` only for the containers that need syscall tracing.
