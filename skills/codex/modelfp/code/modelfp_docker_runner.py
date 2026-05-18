"""ModelFP Docker runner.

Runs static/config/environment/runtime collection inside a Docker container,
normalizes evidence, generates harm certificates, and emits an LLM payload.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import List, Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def running_inside_container() -> bool:
    if Path("/.dockerenv").exists():
        return True
    cgroup = Path("/proc/1/cgroup")
    if cgroup.exists():
        try:
            text = cgroup.read_text(errors="ignore")
        except Exception:
            return False
        markers = ("docker", "containerd", "kubepods", "podman", "libpod")
        return any(marker in text for marker in markers)
    return False


def run(cmd: List[str], *, cwd: Optional[Path] = None, env: Optional[dict] = None, stdout_path: Optional[Path] = None, stderr_path: Optional[Path] = None, timeout: Optional[int] = None) -> int:
    print("[ModelFP] $ " + " ".join(shlex.quote(x) for x in cmd), flush=True)
    stdout = stdout_path.open("w", encoding="utf-8") if stdout_path else subprocess.PIPE
    stderr = stderr_path.open("w", encoding="utf-8") if stderr_path else subprocess.PIPE
    try:
        proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, stdout=stdout, stderr=stderr, text=True, timeout=timeout)
        if stdout_path is None and proc.stdout:
            print(proc.stdout[-4000:])
        if stderr_path is None and proc.stderr:
            print(proc.stderr[-4000:], file=sys.stderr)
        return proc.returncode
    except subprocess.TimeoutExpired:
        print(f"[ModelFP] command timed out after {timeout}s", file=sys.stderr)
        return 124
    finally:
        if stdout_path and hasattr(stdout, "close"):
            stdout.close()
        if stderr_path and hasattr(stderr, "close"):
            stderr.close()


def write_manifest(out_dir: Path, args: argparse.Namespace, target_rc: Optional[int]) -> None:
    manifest = {
        "schema": "modelfp.run_manifest.v1",
        "generated_at": time.time(),
        "model": args.model,
        "revision": args.revision,
        "run_id": args.run_id,
        "model_repo": args.model_repo,
        "target_script": args.target_script,
        "policy": args.policy,
        "remote_metadata": args.remote_metadata,
        "skip_runtime": args.skip_runtime,
        "skip_modelscan": args.skip_modelscan,
        "target_returncode": target_rc,
        "runtime_timeout_seconds": args.timeout,
        "containerized": running_inside_container(),
        "host_execution_allowed": args.allow_host,
        "network_note": "Runtime container should normally be launched with --network none unless explicitly testing network behavior.",
    }
    (out_dir / "run_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="ModelFP Docker evidence collector and LLM payload builder")
    parser.add_argument("--model-repo", default="/workspace/models/model", help="Local Hugging Face repo/model snapshot path mounted read-only")
    parser.add_argument("--target-script", default="/workspace/target/run_model.py", help="Target Python script to execute under strace/audit")
    parser.add_argument("--out", default="/workspace/out", help="Output directory")
    parser.add_argument("--policy", default="/workspace/ModelFP_skill/rules/policy_minimal.yaml")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("MODELFP_TIMEOUT", "180")))
    parser.add_argument("--model", default=os.environ.get("MODELFP_MODEL", "local/model"))
    parser.add_argument("--revision", default=os.environ.get("MODELFP_REVISION", "local"))
    parser.add_argument("--run-id", default=os.environ.get("MODELFP_RUN_ID"))
    parser.add_argument("--remote-metadata", default=os.environ.get("MODELFP_REMOTE_METADATA"), help="Optional hf_repo_metadata.json collected in the network download stage")
    parser.add_argument("--skip-runtime", action="store_true")
    parser.add_argument("--skip-modelscan", action="store_true")
    parser.add_argument("--max-llm-events", type=int, default=250)
    parser.add_argument("--allow-host", action="store_true", help="Development escape hatch: allow running outside Docker. Do not use for normal audits.")
    parser.add_argument("target_args", nargs=argparse.REMAINDER, help="Args after -- are passed to target script")
    args = parser.parse_args()
    if not running_inside_container() and not args.allow_host:
        print(
            "[ModelFP] Refusing to run audit outside Docker. "
            "Use scripts/docker_run_local_model.sh or scripts/docker_run_static_audit.sh. "
            "For development-only host tests, pass --allow-host.",
            file=sys.stderr,
        )
        return 2
    if not args.run_id:
        args.run_id = f"run-{int(time.time())}-{uuid.uuid4().hex[:8]}"

    out_dir = Path(args.out)
    for sub in ["evidence", "traces", "static", "reports"]:
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    model_repo = Path(args.model_repo)
    target_script = Path(args.target_script)

    # Environment, repo, config, static artifact evidence.
    run([sys.executable, str(HERE / "env_probe.py")], env={**os.environ, "MODELFP_ENV_EVIDENCE": str(out_dir / "evidence/env_evidence.jsonl")})

    if model_repo.exists():
        run([sys.executable, str(HERE / "all_files_static_probe.py"), "--repo", str(model_repo), "--out", str(out_dir / "evidence/all_files_static_evidence.jsonl"), "--raw-report", str(out_dir / "static/all_files_static_scan.json")])
        run([sys.executable, str(HERE / "repo_probe.py"), "--repo", str(model_repo), "--out", str(out_dir / "evidence/repo_evidence.jsonl")])
        hygiene_cmd = [sys.executable, str(HERE / "repo_hygiene_probe.py"), "--repo", str(model_repo), "--out", str(out_dir / "evidence/repo_hygiene_evidence.jsonl")]
        if args.remote_metadata and Path(args.remote_metadata).exists():
            hygiene_cmd.extend(["--metadata", str(Path(args.remote_metadata))])
        run(hygiene_cmd)
        run([sys.executable, str(HERE / "malware_static_probe.py"), "--repo", str(model_repo), "--out", str(out_dir / "evidence/malware_static_evidence.jsonl"), "--raw-report", str(out_dir / "static/malware_static_report.json")])
        run([sys.executable, str(HERE / "python_ast_probe.py"), "--repo", str(model_repo), "--out", str(out_dir / "evidence/python_ast_evidence.jsonl"), "--raw-report", str(out_dir / "static/python_ast_report.json")])
        run([sys.executable, str(HERE / "config_probe.py"), "--repo", str(model_repo), "--out", str(out_dir / "evidence/config_evidence.jsonl"), "--raw-report", str(out_dir / "static/config_static_report.json")])
        run([sys.executable, str(HERE / "h5_static_probe.py"), "--repo", str(model_repo), "--out", str(out_dir / "evidence/h5_static_evidence.jsonl")])
        run([sys.executable, str(HERE / "pickle_static_probe.py"), "--repo", str(model_repo), "--out", str(out_dir / "evidence/pickle_static_evidence.jsonl")])
        if not args.skip_modelscan:
            run([sys.executable, str(HERE / "modelscan_adapter.py"), "--path", str(model_repo), "--out", str(out_dir / "evidence/modelscan_evidence.jsonl"), "--raw-report", str(out_dir / "static/modelscan_report.json")])
        run([sys.executable, str(HERE / "static_fusion_probe.py"), "--evidence-dir", str(out_dir / "evidence"), "--out", str(out_dir / "evidence/static_fusion_evidence.jsonl"), "--raw-report", str(out_dir / "static/static_fusion_report.json")])
    else:
        print(f"[ModelFP] model repo not found: {model_repo}; static scanning skipped", file=sys.stderr)

    # Runtime evidence. Use strace inside the container; Docker must grant SYS_PTRACE/seccomp unconfined.
    target_rc: Optional[int] = None
    if not args.skip_runtime:
        if not target_script.exists():
            print(f"[ModelFP] target script not found: {target_script}; runtime skipped", file=sys.stderr)
        else:
            audit_log = out_dir / "traces/python_audit.jsonl"
            stdout_log = out_dir / "traces/target_stdout.log"
            stderr_log = out_dir / "traces/target_stderr.log"
            strace_prefix = out_dir / "traces/strace"
            passthrough = [x for x in args.target_args if x != "--"]
            cmd = [
                "strace", "-ff", "-tt", "-T", "-yy", "-s", "4096", "-o", str(strace_prefix),
                sys.executable, str(HERE / "audit_runner.py"),
                "--script", str(target_script),
                "--audit-log", str(audit_log),
                "--phase", "LOAD_AND_INFERENCE",
                "--",
            ] + passthrough
            env = dict(os.environ)
            env.update({
                "MODELFP_AUDIT_LOG": str(audit_log),
                "MODELFP_PHASE": "LOAD_AND_INFERENCE",
                "PYTHONUNBUFFERED": "1",
                # Canary values help detect exfiltration attempts without exposing real secrets.
                "MODELFP_CANARY_TOKEN": os.environ.get("MODELFP_CANARY_TOKEN", "MODELFP_CANARY_DO_NOT_USE"),
            })
            target_rc = run(cmd, env=env, stdout_path=stdout_log, stderr_path=stderr_log, timeout=args.timeout)

    # Normalize, run deterministic checks, build LLM payload.
    run([
        sys.executable, str(HERE / "trace_normalizer.py"),
        "--out-dir", str(out_dir),
        "--output", str(out_dir / "evidence_graph.json"),
        "--model", args.model,
        "--revision", args.revision,
        "--run-id", args.run_id,
    ])
    run([
        sys.executable, str(HERE / "simple_rulecheck_runner.py"),
        "--evidence-graph", str(out_dir / "evidence_graph.json"),
        "--policy", args.policy,
        "--out", str(out_dir / "harm_certificates.json"),
        "--model", args.model,
        "--revision", args.revision,
        "--run-id", args.run_id,
    ])
    run([
        sys.executable, str(HERE / "literature_mapper.py"),
        "--graph", str(out_dir / "evidence_graph.json"),
        "--certificates", str(out_dir / "harm_certificates.json"),
        "--out", str(out_dir / "evidence/literature_evidence.jsonl"),
        "--augment-graph",
    ])
    run([sys.executable, str(HERE / "llm_payload_builder.py"), "--graph", str(out_dir / "evidence_graph.json"), "--certificates", str(out_dir / "harm_certificates.json"), "--out", str(out_dir / "llm_payload.json"), "--max-events", str(args.max_llm_events)])
    write_manifest(out_dir, args, target_rc)

    print("\n[ModelFP] Done.")
    print(f"[ModelFP] Evidence graph: {out_dir / 'evidence_graph.json'}")
    print(f"[ModelFP] Harm certificates: {out_dir / 'harm_certificates.json'}")
    print(f"[ModelFP] LLM payload: {out_dir / 'llm_payload.json'}")
    return 0 if target_rc in (None, 0) else 10


if __name__ == "__main__":
    raise SystemExit(main())
