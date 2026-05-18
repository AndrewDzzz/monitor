# ModelFP Skill Package

这个包把 ModelFP 的设计落成一个可复用的 skill 草案。

包含：

- `SKILL.md`：Codex skill 入口说明。
- `agents/openai.yaml`：UI 元数据。
- `schemas/evidence.schema.json`：证据节点 schema。
- `schemas/rule.schema.json`：规则 DSL schema。
- `schemas/harm_certificate.schema.json`：harm certificate schema。
- `examples/model_fp_policy.yaml`：示例策略和规则。
- `examples/harm_certificate.example.json`：示例证书。
- `examples/model_fp_report.example.json`：示例最终报告。
- `prompts/gpt_trace_auditor_prompt.md`：GPT 证据审核 prompt。
- `prompts/gpt_rule_generator_prompt.md`：GPT 候选规则生成 prompt。
- `docs/formalization_notes.md`：形式化验证笔记。
- `docs/literature_grounding.md`：论文方法到证据链节点的映射。

审计主入口是 Docker 脚本。`code/modelfp_docker_runner.py` 只应在容器内运行；默认会拒绝宿主机执行，避免把宿主机路径、凭证或环境混进证据链。
远程模型的下载、Hub 元数据采集、静态审计和运行时审计都通过 Docker 完成；每次完整审计都会落在独立 dataset 文件夹下。

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
