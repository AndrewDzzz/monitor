# ModelFP Methodology

ModelFP is repo-level first. It treats a model repository as a supply-chain object, not just as one serialized model file.

The dynamic route descends from the March 2025 `monitor` prototype in this repository. That prototype used `strace` plus Python audit hooks to observe ML model execution at runtime. ModelFP keeps that core idea but packages it as a Docker-first, repo-level audit workflow with static fusion, evidence graphs, and AI-assisted review.

## Audit Boundary

Each audit records:

- repository or local path;
- revision;
- file tree and hashes;
- model card and remote metadata when available;
- Docker image identity;
- command and environment used for collection;
- raw evidence and derived certificates.

The claim is always bounded to that context.

## Static Route

Static analysis runs in Docker with no network unless a dedicated metadata or download stage needs it.

1. Build a full file inventory with hashes, sizes, extensions, magic/type signals, archives, URL-like strings, and command-like strings.
2. Inspect repo structure for non-model payloads, malware-hosting patterns, model-card/task mismatch, README instructions to run scripts or install external apps, abnormal commit cadence, and duplicate commits.
3. Run malware-style static triage over all files for executable magic, shell download cradles, PowerShell stagers, reverse-shell fragments, persistence hooks, credential-harvesting strings, miner strings, and obfuscation markers.
4. Parse Python/Lambda code with AST checks for dangerous imports/calls, `eval`/`exec`, subprocess sinks, unsafe deserialization, handler event logging, Flask debug mode, and private package indexes.
5. Inspect model config for `auto_map`, `trust_remote_code`, custom-code loading, URLs, missing `model_type`, and unexpected task hints.
6. Probe `.h5`/Keras artifacts without loading models.
7. Probe pickle-like artifacts with opcode inspection without unpickling.
8. Run ModelScan when available.
9. Fuse signals into repo-level findings. Fused findings are derived evidence and must point back to raw evidence IDs.

## Dynamic Route

Runtime analysis is optional and only runs in Docker.

1. Mount target inputs read-only.
2. Disable network for runtime unless the test is explicitly about network behavior.
3. Capture syscalls with `strace`.
4. Capture Python-level operations with audit hooks.
5. Capture stdout/stderr as supporting logs, not primary facts.
6. Normalize traces and static outputs into one evidence graph.
7. Run deterministic rules to produce harm certificates.

For pickle detonation, each `.pickle` or `.pkl` artifact runs in its own fresh container with network disabled, tmpfs temporary storage, resource limits, and read-only repo mounts.

## AI-Assisted Review

The 2025 prototype assumed the auditor would manually inspect logs. The current workflow lets an AI coding agent help with the repetitive audit work:

- run Dockerized collectors and preserve manifests;
- check that claims cite evidence IDs;
- compare static and runtime signals;
- summarize risk without treating LLM output as primary evidence;
- propose extra rules or follow-up experiments for human approval.

The evidence graph and deterministic certificates remain the source of truth.

## Evidence Chain

ModelFP separates evidence into layers:

- raw collector reports: static JSON/JSONL, strace logs, audit hook logs, metadata;
- normalized graph: stable evidence IDs and run context;
- certificates: deterministic claims supported by evidence IDs;
- literature nodes: method support from prior work, not direct facts about the target;
- LLM payload: sanitized semantic review material that must cite graph IDs.

## Static vs Dynamic

Static evidence can identify repo-level risk without executing code. Dynamic evidence can confirm runtime behavior for controlled executions, but absence of dynamic events is not proof of safety.

## Docker Model

The host builds Docker images, mounts inputs, and reads outputs. All audit collection and analysis should run inside containers. Network is allowed only for download or metadata stages, then disabled for offline static and runtime stages.

See `DOCKER_WORKFLOW.md` for the image and stage layout.

## Citation Position

Use two citation targets. When describing the original dynamic audit idea, cite the March 2025 `monitor` prototype from this repository. When using the current Dockerized repo-level workflow, static fusion, evidence graph, harm certificates, dataset layout, or Codex/Claude skill package, cite `ModelFP`.

DynaHug, "Malicious ML Model Detection by Learning Dynamic Behaviors" (arXiv:2604.19438, submitted 2026-04-21), is third-party work that uses a similar dynamic-behavior detection direction for malicious PTMs; cite it as comparison/context, not as a ModelFP or AndrewDzzz work. For broader supply-chain dynamic analysis, DySec (arXiv:2503.00324, submitted 2025-03-01) is relevant context.

Do not claim that DynaHug used or cited `AndrewDzzz/monitor` unless a concrete citation, acknowledgement, repository dependency, or author statement is available.
