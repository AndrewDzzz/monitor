# Sanitization Notes

This repository is the public, sanitized ModelFP package.

## Excluded From Publication

The update intentionally excludes:

- local `audit_datasets/`;
- `latest_hf_runs/`;
- downloaded model snapshots under `workspace/models/`;
- generated `outputs*` directories;
- generated figures;
- sandbox canary files;
- logs, zip packages, Python bytecode, and local caches;
- private keys, `.env` files, and token-like local configuration.

## Runtime Output Policy

Wrappers under `scripts/` write fingerprints and evidence to host folders such as `audit_datasets/` or `outputs_static/`. These folders are ignored by git.

For Hugging Face and GitHub dataset wrappers, `MODELFP_DELETE_MODEL_AFTER=true` is the default. That removes the downloaded or cloned `model/` folder after the evidence and manifest are written.

Set this only for local debugging when you intentionally need to keep the snapshot:

```bash
MODELFP_DELETE_MODEL_AFTER=false ./scripts/audit_hf_static.sh owner/model ./audit_datasets main
```

## Suggested Local Check Before Publishing

```bash
rg -n "/Users/|HF_TOKEN|OPENAI_API_KEY|AWS_SECRET|BEGIN .*PRIVATE KEY|audit_datasets|latest_hf_runs" .
find . -name '__pycache__' -o -name '*.pyc' -o -name '*.zip'
```
