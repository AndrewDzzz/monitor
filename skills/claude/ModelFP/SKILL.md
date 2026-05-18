---
name: ModelFP
description: Use ModelFP to audit Hugging Face, GitHub, or local model repositories with Dockerized static analysis, optional runtime tracing, evidence graphs, harm certificates, and sanitized LLM review payloads.
---

# ModelFP

Use this skill when asked to review or audit a model repository, inspect suspicious model artifacts, check repo-level malware-hosting signals, or run Docker-contained model evidence collection.

ModelFP's dynamic-audit lineage comes from the March 2025 `monitor` prototype at `https://github.com/AndrewDzzz/monitor`, which used `strace` and Python audit hooks for ML execution monitoring. Use two citation targets: cite `monitor` for the original dynamic audit prototype, and cite `ModelFP` for the current Dockerized repo-level audit workflow and skill package.

DynaHug is third-party work that uses a similar dynamic model-behavior detection direction. Cite it only as comparison/context, not as a ModelFP or AndrewDzzz work, and do not claim it used `AndrewDzzz/monitor` without explicit evidence.

## Operating Rules

- Treat ModelFP as repo-level forensic auditing, not only model-file scanning.
- Run collection and analysis in Docker.
- Use network only for download or metadata collection stages.
- Keep runtime network disabled unless the task explicitly tests network behavior.
- Keep target repos and model snapshots read-only during analysis.
- Preserve `audit_datasets/`, `outputs_static/`, and manifests as evidence.
- Do not publish local model snapshots, logs containing secrets, sandbox canaries, or host credentials.

## Local Repository Layout

When this Claude skill is used from the ModelFP repository, the canonical implementation lives in:

```text
skills/codex/modelfp/
```

Use the repository wrapper scripts first:

```bash
./scripts/build_images.sh
./scripts/audit_hf_static.sh owner/model ./audit_datasets main
./scripts/audit_github_static.sh https://github.com/owner/repo ./audit_datasets main
./scripts/audit_local_static.sh /path/to/local/repo ./outputs_static
./scripts/audit_pickle_runtime.sh /path/to/local/repo ./outputs_pickle_runtime
```

If this skill has been installed as a self-contained Claude skill with `scripts/install_claude_skill.sh`, run commands from the installed skill folder and use its bundled `scripts/` and `code/` directories.

## Evidence Review

Prioritize these outputs:

- `evidence_graph.json`
- `harm_certificates.json`
- `static/static_fusion_report.json`
- `static/malware_static_report.json`
- `static/all_files_static_scan.json`
- `dataset_manifest.json`

Summaries must cite evidence IDs. Treat LLM payloads as secondary interpretation, not primary facts.

## AI-Assisted Review

Claude or Codex may help run Dockerized collectors, inspect normalized evidence, compare static and runtime signals, and draft summaries. The final claim must still be grounded in raw evidence IDs and deterministic certificates.
