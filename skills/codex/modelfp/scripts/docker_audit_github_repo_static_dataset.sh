#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/docker_audit_github_repo_static_dataset.sh https://github.com/owner/repo [dataset_root] [revision]

Environment:
  MODELFP_DATASET_ROOT          Default dataset root (default: audit_datasets)
  MODELFP_AUDIT_ID             Override generated audit id
  MODELFP_RUN_PICKLE_RUNTIME   Set true to detonate .pickle/.pkl artifacts after static scan

Each run creates:
  <dataset_root>/github_owner_repo/<audit_id>/
    dataset_manifest.json
    orchestrator.log
    metadata/file_sha256.txt
    metadata/github_repo_metadata.json
    model/
    outputs_static/
    outputs_pickle_runtime/     only when MODELFP_RUN_PICKLE_RUNTIME=true
EOF
}

if [ "${1:-}" = "" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 2
fi

REPO_URL="$1"
DATASET_ROOT="${2:-${MODELFP_DATASET_ROOT:-audit_datasets}}"
REVISION="${3:-${MODELFP_REVISION:-main}}"
RUN_PICKLE_RUNTIME="${MODELFP_RUN_PICKLE_RUNTIME:-false}"

repo_slug() {
  local ref="$1"
  ref="${ref#https://github.com/}"
  ref="${ref#http://github.com/}"
  ref="${ref%.git}"
  printf 'github_%s' "$ref" \
    | tr '/:@ ' '____' \
    | tr -c 'A-Za-z0-9._-' '-' \
    | sed -E 's/^-+//; s/-+$//; s/-+/-/g'
}

REPO_SLUG="$(repo_slug "$REPO_URL")"
REVISION_SLUG="$(printf '%s' "$REVISION" | tr '/:@ ' '____' | tr -c 'A-Za-z0-9._-' '-' | sed -E 's/^-+//; s/-+$//; s/-+/-/g')"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
AUDIT_ID="${MODELFP_AUDIT_ID:-${STAMP}_${REPO_SLUG}_${REVISION_SLUG}}"
AUDIT_DIR="$DATASET_ROOT/$REPO_SLUG/$AUDIT_ID"
MODEL_DIR="$AUDIT_DIR/model"
STATIC_DIR="$AUDIT_DIR/outputs_static"
METADATA_DIR="$AUDIT_DIR/metadata"
PICKLE_RUNTIME_DIR="$AUDIT_DIR/outputs_pickle_runtime"

if [ -e "$AUDIT_DIR" ]; then
  echo "Audit dataset already exists: $AUDIT_DIR" >&2
  exit 2
fi

mkdir -p "$MODEL_DIR" "$STATIC_DIR" "$METADATA_DIR"
exec > >(tee "$AUDIT_DIR/orchestrator.log") 2>&1

write_manifest() {
  local clone_status="$1"
  local hash_status="$2"
  local metadata_status="$3"
  local static_status="$4"
  local pickle_runtime_status="$5"
  local final_status="$6"
  python3 - "$AUDIT_DIR" "$REPO_URL" "$REVISION" "$AUDIT_ID" "$clone_status" "$hash_status" "$metadata_status" "$static_status" "$pickle_runtime_status" "$final_status" "$RUN_PICKLE_RUNTIME" <<'PY'
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

audit_dir = Path(sys.argv[1]).resolve()
repo_url, revision, audit_id = sys.argv[2:5]
clone_status, hash_status, metadata_status, static_status, pickle_runtime_status, final_status = sys.argv[5:11]
run_pickle_runtime = sys.argv[11].lower() == "true"

def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(audit_dir))
    except Exception:
        return str(path)

def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def docker_image(image: str):
    proc = subprocess.run(["docker", "image", "inspect", "-f", "{{.Id}}", image], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return proc.stdout.strip() or None

def graph_summary(path: Path):
    graph = load_json(path)
    if not graph:
        return None
    evidence = graph.get("evidence", [])
    return {
        "path": rel(path),
        "sha256": sha256_file(path),
        "evidence_count": graph.get("evidence_count", len(evidence)),
        "runtime_event_count": graph.get("runtime_event_count"),
        "high_or_critical_count": sum(1 for ev in evidence if ev.get("severity") in {"high", "critical"}),
    }

def cert_summary(path: Path):
    certs = load_json(path)
    if not certs:
        return None
    return {
        "path": rel(path),
        "sha256": sha256_file(path),
        "count": certs.get("count"),
        "verified_count": certs.get("verified_count"),
        "certificate_ids": [c.get("certificate_id") for c in certs.get("certificates", [])],
    }

manifest = {
    "schema": "modelfp.github_static_dataset.v1",
    "audit_id": audit_id,
    "created_at_unix": time.time(),
    "repo_url": repo_url,
    "revision": revision,
    "final_status": final_status,
    "phases": {
        "clone_exit": int(clone_status),
        "hash_exit": int(hash_status),
        "metadata_exit": int(metadata_status),
        "static_exit": int(static_status),
        "pickle_runtime_exit": None if not run_pickle_runtime else int(pickle_runtime_status),
        "pickle_runtime_requested": run_pickle_runtime,
    },
    "docker_images": {
        "modelfp_latest": docker_image("modelfp:latest"),
        "modelfp_ml": docker_image("modelfp:ml"),
    },
    "paths": {
        "audit_dir": str(audit_dir),
        "orchestrator_log": "orchestrator.log",
        "model_dir": "model",
        "metadata_dir": "metadata",
        "static_dir": "outputs_static",
        "pickle_runtime_dir": "outputs_pickle_runtime" if run_pickle_runtime else None,
    },
    "artifacts": {
        "file_sha256": {"path": rel(audit_dir / "metadata/file_sha256.txt"), "sha256": sha256_file(audit_dir / "metadata/file_sha256.txt")},
        "github_metadata": {"path": rel(audit_dir / "metadata/github_repo_metadata.json"), "sha256": sha256_file(audit_dir / "metadata/github_repo_metadata.json")},
        "static_graph": graph_summary(audit_dir / "outputs_static/evidence_graph.json"),
        "static_certificates": cert_summary(audit_dir / "outputs_static/harm_certificates.json"),
        "all_files_static_scan": {"path": rel(audit_dir / "outputs_static/static/all_files_static_scan.json"), "sha256": sha256_file(audit_dir / "outputs_static/static/all_files_static_scan.json")},
        "python_ast_report": {"path": rel(audit_dir / "outputs_static/static/python_ast_report.json"), "sha256": sha256_file(audit_dir / "outputs_static/static/python_ast_report.json")},
        "pickle_runtime_summary": None if not run_pickle_runtime else {"path": rel(audit_dir / "outputs_pickle_runtime/pickle_runtime_summary.json"), "sha256": sha256_file(audit_dir / "outputs_pickle_runtime/pickle_runtime_summary.json")},
    },
}
(audit_dir / "dataset_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

echo "[ModelFP GitHub dataset] repo=$REPO_URL revision=$REVISION"
echo "[ModelFP GitHub dataset] audit_dir=$AUDIT_DIR"

clone_status=0
hash_status=0
metadata_status=0
static_status=0
pickle_runtime_status=0

docker run --rm --network bridge \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=256m,mode=1777 \
  --tmpfs /workspace/tmp:size=1g,mode=1777 \
  -v "$(cd "$MODEL_DIR" && pwd):/workspace/repo:rw" \
  --entrypoint sh \
  "${MODELFP_GITHUB_IMAGE:-modelfp:latest}" \
  -c 'set -eu
    git clone --depth 1 --no-tags --branch "$1" "$0" /workspace/tmp/src 2>/workspace/tmp/clone.err || git clone --depth 1 --no-tags "$0" /workspace/tmp/src
    cp -a /workspace/tmp/src/. /workspace/repo/
    rm -rf /workspace/repo/.git' "$REPO_URL" "$REVISION"
clone_status=$?

if [ "$clone_status" -eq 0 ]; then
  docker run --rm --network none \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:size=64m,mode=1777 \
    -v "$(cd "$MODEL_DIR" && pwd):/workspace/repo:ro" \
    -v "$(cd "$METADATA_DIR" && pwd):/workspace/metadata:rw" \
    --entrypoint sh \
    "${MODELFP_HASH_IMAGE:-modelfp:latest}" \
    -c 'cd /workspace/repo && find . -type f ! -path "./.git/*" -print0 | sort -z | xargs -0 sha256sum > /workspace/metadata/file_sha256.txt && find . -type f ! -path "./.git/*" -print | sort > /workspace/metadata/file_list.txt'
  hash_status=$?
else
  hash_status=1
fi

if [ "$clone_status" -eq 0 ]; then
  docker run -i --rm --network bridge \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /tmp:size=256m,mode=1777 \
    --tmpfs /workspace/tmp:size=1g,mode=1777 \
    -v "$(cd "$METADATA_DIR" && pwd):/workspace/metadata:rw" \
    --entrypoint sh \
    "${MODELFP_METADATA_IMAGE:-modelfp:latest}" <<SH
set -eu
git clone --no-tags "$REPO_URL" /workspace/tmp/src >/dev/null 2>&1
cd /workspace/tmp/src
python - <<'PY'
import json, subprocess, time
from pathlib import Path
repo_url = "$REPO_URL"
revision = "$REVISION"
log = subprocess.check_output(["git", "log", "--date=iso-strict", "--pretty=format:%H%x1f%an%x1f%ad%x1f%s%x1f%b%x1e"], text=True)
commits = []
for rec in log.strip("\x1e").split("\x1e"):
    if not rec.strip():
        continue
    parts = rec.strip("\n").split("\x1f")
    while len(parts) < 5:
        parts.append("")
    commits.append({"commit_id": parts[0], "authors": [parts[1]], "created_at": parts[2], "title": parts[3], "message": parts[4]})
files = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
out = {
    "schema": "modelfp.github_repo_metadata.v1",
    "repo_url": repo_url,
    "repo_id": repo_url.rstrip("/").removesuffix(".git").split("github.com/")[-1],
    "revision": revision,
    "generated_at_unix": time.time(),
    "model_info": {"siblings": [{"rfilename": f} for f in files], "pipeline_tag": None, "tags": []},
    "commits": commits,
    "errors": [],
}
Path("/workspace/metadata/github_repo_metadata.json").write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
SH
  metadata_status=$?
else
  metadata_status=1
fi

if [ "$clone_status" -eq 0 ]; then
  MODELFP_MODEL_NAME="$REPO_URL" MODELFP_REVISION="$REVISION" MODELFP_REMOTE_METADATA="$METADATA_DIR/github_repo_metadata.json" \
    ./scripts/docker_run_static_audit.sh "$MODEL_DIR" "$STATIC_DIR"
  static_status=$?
else
  static_status=1
fi

if [ "$RUN_PICKLE_RUNTIME" = "true" ] && [ "$clone_status" -eq 0 ]; then
  MODELFP_MODEL_NAME="$REPO_URL" MODELFP_REVISION="$REVISION" \
    ./scripts/docker_run_pickle_runtime.sh "$MODEL_DIR" "$PICKLE_RUNTIME_DIR"
  pickle_runtime_status=$?
else
  pickle_runtime_status=0
fi

final_status="ok"
if [ "$clone_status" -ne 0 ] || [ "$hash_status" -ne 0 ] || [ "$metadata_status" -ne 0 ] || [ "$static_status" -ne 0 ] || { [ "$RUN_PICKLE_RUNTIME" = "true" ] && [ "$pickle_runtime_status" -ne 0 ]; }; then
  final_status="failed"
fi

write_manifest "$clone_status" "$hash_status" "$metadata_status" "$static_status" "$pickle_runtime_status" "$final_status"

echo "[ModelFP GitHub dataset] manifest=$AUDIT_DIR/dataset_manifest.json"
echo "[ModelFP GitHub dataset] status=$final_status"

if [ "$final_status" = "ok" ]; then
  exit 0
fi
exit 1
