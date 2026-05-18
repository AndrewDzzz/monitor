"""Map ModelFP evidence nodes to literature-grounded methodology nodes.

These nodes are not primary evidence about the target model. They explain which
published detection ideas support the way ModelFP links static, environment,
runtime, and certificate evidence.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

Evidence = Dict[str, Any]

BIBLIOGRAPHY: Dict[str, Dict[str, Any]] = {
    "andrewdzzz_2025_monitor": {
        "title": "monitor: strace and Python audit hook monitoring for ML model execution",
        "year": 2025,
        "url": "https://github.com/AndrewDzzz/monitor",
        "method": "March 2025 repository prototype that used OS-level strace and Python audit hooks to observe sensitive behavior during ML model execution.",
    },
    "mehedi_2025_dysec": {
        "title": "DySec: A Machine Learning-based Dynamic Analysis for Detecting Malicious Packages in PyPI Ecosystem",
        "year": 2025,
        "url": "https://arxiv.org/abs/2503.00324",
        "method": "Controlled dynamic supply-chain analysis using kernel/user-level probes and real-time behavior features.",
    },
    "zhao_2024_malhug": {
        "title": "Models Are Codes: Towards Measuring Malicious Code Poisoning Attacks on Pre-trained Model Hubs",
        "year": 2024,
        "url": "https://arxiv.org/abs/2409.09368",
        "method": "MalHug combines loading-script extraction, model deserialization, taint analysis, and heuristic pattern matching for model-hub malware detection.",
    },
    "casey_2024_hf_exploit": {
        "title": "A Large-Scale Exploit Instrumentation Study of AI/ML Supply Chain Attacks in Hugging Face Models",
        "year": 2024,
        "url": "https://arxiv.org/abs/2410.04490",
        "method": "Exploit instrumentation for unsafe serialization in Hugging Face model files.",
    },
    "siddiq_2026_rce": {
        "title": "An Empirical Study on Remote Code Execution in Machine Learning Model Hosting Ecosystems",
        "year": 2026,
        "url": "https://arxiv.org/abs/2601.14163",
        "method": "Large-scale study of custom model loading and RCE risk via trust_remote_code/trust_repo, using static analyzers and malicious-pattern signatures.",
    },
    "nambiar_2026_dynahug": {
        "title": "Malicious ML Model Detection by Learning Dynamic Behaviors",
        "year": 2026,
        "url": "https://arxiv.org/abs/2604.19438",
        "method": "Third-party dynamic behavior analysis of pretrained models; use as comparison/context, not as a ModelFP or AndrewDzzz work.",
    },
    "safepickle_2026": {
        "title": "SafePickle: Robust and Generic ML Detection of Malicious Pickle-based ML Models",
        "year": 2026,
        "url": "https://arxiv.org/abs/2602.19818",
        "method": "Static structural and semantic feature extraction from Pickle bytecode for malicious model detection.",
    },
    "torres_arias_2019_intoto": {
        "title": "in-toto: Providing farm-to-table guarantees for bits and bytes",
        "year": 2019,
        "url": "https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias",
        "method": "Supply-chain integrity is represented as verifiable step metadata and a continuous chain of evidence.",
    },
    "huggingface_pickle_scanning": {
        "title": "Hugging Face Hub: Pickle Scanning",
        "year": 2026,
        "url": "https://huggingface.co/docs/hub/security-pickle",
        "method": "Hub practice: inspect pickle imports/opcodes without executing the model file, and treat signed origin as provenance rather than proof of safety.",
    },
}

UNSAFE_SERIALIZATION_FINDINGS = {
    "high_risk_model_artifact_format",
    "pickle_dangerous_global_ref",
    "modelscan_reported_issue",
    "modelscan_no_normalized_findings",
}

CUSTOM_CODE_FINDINGS = {
    "auto_map_present",
    "trust_remote_code_reference",
    "trust_remote_code_true",
    "custom_huggingface_python_code",
    "custom_python_files_present",
    "suspicious_repository_file",
    "dangerous_python_call",
    "subprocess_shell_true",
    "static_shell_command_literal",
    "sensitive_python_import",
}

REPO_HYGIENE_FINDINGS = {
    "non_model_payload_extension",
    "archive_file_present",
    "suspicious_text_pattern",
    "non_model_payload_present",
    "archive_or_native_payload_present",
    "readme_runs_external_script_or_app",
    "abnormal_high_frequency_commits",
    "large_repeated_commit_messages",
    "model_card_task_mismatch",
    "malware_hosting_like_file_tree",
}

MALWARE_STATIC_FINDINGS = {
    "embedded_executable_magic",
    "archive_or_package_container",
    "download_cradle_pipe_shell",
    "powershell_encoded_or_iex",
    "windows_lolbin_download_or_execute",
    "reverse_shell_shell",
    "reverse_shell_python",
    "credential_harvesting_path",
    "persistence_hook",
    "crypto_miner_indicator",
    "python_exec_obfuscation",
    "javascript_eval_obfuscation",
    "chmod_then_execute",
    "large_high_entropy_base64_blob",
    "suspicious_payload_url_context",
}

STATIC_FUSION_FINDINGS = {
    "malware_static_plus_custom_code_config",
    "malware_static_plus_network_config",
    "unsafe_serialization_correlated",
    "non_model_payload_repo_level_concern",
    "malware_static_plus_python_execution_sink",
    "static_target_risk_summary",
}

RUNTIME_RISK_OPS = {"execve", "connect", "open", "write"}
RUNTIME_RISK_PATH_CLASSES = {"secret", "docker_socket", "shell", "system_sensitive", "tmp_executable"}


def _run_context(graph: Mapping[str, Any]) -> Dict[str, str]:
    return {
        "model": str(graph.get("model", "local/model")),
        "revision": str(graph.get("revision", "local")),
        "run_id": str(graph.get("run_id", "local-run")),
    }


def _paper_summaries(paper_ids: Sequence[str]) -> List[Dict[str, Any]]:
    return [{"paper_id": pid, **BIBLIOGRAPHY[pid]} for pid in paper_ids]


def _node(idx: int, finding: str, meaning: str, evidence_ids: Sequence[str], paper_ids: Sequence[str], context: Mapping[str, str], *, severity: str = "medium", tags: Sequence[str] = ()) -> Evidence:
    return {
        "id": f"LIT{idx:04d}",
        "type": "literature_grounding",
        "evidence_type": "literature_grounding",
        "source": "literature_mapper",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "supports_evidence": list(evidence_ids),
        "paper_ids": list(paper_ids),
        "papers": _paper_summaries(paper_ids),
        "method_tags": list(tags),
        "not_primary_evidence": True,
        "time": time.time(),
        "model": context["model"],
        "revision": context["revision"],
        "run_id": context["run_id"],
        "run_context": dict(context),
    }


def _ids(nodes: Iterable[Evidence]) -> List[str]:
    return [str(ev["id"]) for ev in nodes if ev.get("id")]


def build_literature_nodes(graph: Mapping[str, Any], cert_bundle: Mapping[str, Any] | None = None) -> List[Evidence]:
    evidence = list(graph.get("evidence", []))
    certificates = list((cert_bundle or {}).get("certificates", []))
    context = _run_context(graph)
    out: List[Evidence] = []
    idx = 1

    unsafe_serialization = [
        ev for ev in evidence
        if ev.get("finding") in UNSAFE_SERIALIZATION_FINDINGS
        or str(ev.get("suffix", "")).lower() in {".pkl", ".pickle", ".joblib", ".dill", ".pt", ".pth", ".ckpt", ".bin"}
    ]
    if unsafe_serialization:
        out.append(_node(
            idx,
            "unsafe_serialization_methodology_match",
            "Repository/static evidence matches literature on unsafe serialized model artifacts and non-executing pickle/import inspection.",
            _ids(unsafe_serialization[:25]),
            ["casey_2024_hf_exploit", "safepickle_2026", "huggingface_pickle_scanning"],
            context,
            tags=["unsafe_serialization", "pickle_bytecode", "static_model_scan"],
        ))
        idx += 1

    custom_code = [ev for ev in evidence if ev.get("finding") in CUSTOM_CODE_FINDINGS]
    if custom_code:
        out.append(_node(
            idx,
            "custom_code_loading_methodology_match",
            "Config/repository evidence matches model-hub RCE work that treats model loading code paths as executable supply-chain surface.",
            _ids(custom_code[:25]),
            ["zhao_2024_malhug", "siddiq_2026_rce"],
            context,
            tags=["custom_code_loading", "trust_remote_code", "model_hub_rce"],
        ))
        idx += 1

    repo_hygiene = [ev for ev in evidence if ev.get("finding") in REPO_HYGIENE_FINDINGS]
    if repo_hygiene:
        out.append(_node(
            idx,
            "repo_hygiene_methodology_match",
            "Repository hygiene evidence matches model-hub abuse work that combines payload-format checks, README/script heuristics, commit-pattern review, and model-card consistency checks.",
            _ids(repo_hygiene[:50]),
            ["zhao_2024_malhug", "casey_2024_hf_exploit", "siddiq_2026_rce"],
            context,
            tags=["repo_hygiene", "payload_hosting", "model_hub_abuse", "metadata_consistency"],
        ))
        idx += 1

    malware_static = [ev for ev in evidence if ev.get("finding") in MALWARE_STATIC_FINDINGS]
    if malware_static:
        out.append(_node(
            idx,
            "malware_static_methodology_match",
            "Static evidence matches malware-triage methodology using executable signatures, shell/download stagers, persistence, credential-harvesting, miner, and obfuscation patterns.",
            _ids(malware_static[:50]),
            ["zhao_2024_malhug", "siddiq_2026_rce"],
            context,
            tags=["malware_static_triage", "signature_heuristics", "model_hub_abuse"],
        ))
        idx += 1

    static_fusion = [ev for ev in evidence if ev.get("finding") in STATIC_FUSION_FINDINGS]
    if static_fusion:
        out.append(_node(
            idx,
            "static_fusion_methodology_match",
            "Fused static evidence follows model-hub malware work that combines file, config, serialization, custom-code, and repo-hygiene signals rather than relying on one indicator.",
            _ids(static_fusion[:25]),
            ["zhao_2024_malhug", "casey_2024_hf_exploit", "siddiq_2026_rce", "safepickle_2026"],
            context,
            tags=["static_fusion", "cross_signal_triage", "repo_level_detection"],
        ))
        idx += 1

    runtime_risky = [
        ev for ev in evidence
        if ev.get("type") == "runtime_event" and (
            ev.get("op") in RUNTIME_RISK_OPS
            and (
                ev.get("path_class") in RUNTIME_RISK_PATH_CLASSES
                or ev.get("dst_type") == "external"
                or ev.get("risk_hints")
            )
        )
    ]
    if runtime_risky:
        out.append(_node(
            idx,
            "dynamic_behavior_methodology_match",
            "Runtime evidence follows this repository's March 2025 dynamic-monitoring lineage and is comparable to third-party dynamic-analysis work that catches behaviors static scanners can miss.",
            _ids(runtime_risky[:50]),
            ["andrewdzzz_2025_monitor", "nambiar_2026_dynahug", "mehedi_2025_dysec", "zhao_2024_malhug"],
            context,
            tags=["dynamic_analysis", "syscall_trace", "runtime_behavior"],
        ))
        idx += 1

    verified = [c for c in certificates if c.get("checker_status") == "verified"]
    if verified:
        cert_ids = [str(c.get("certificate_id")) for c in verified[:25] if c.get("certificate_id")]
        evidence_ids: List[str] = []
        for cert in verified:
            evidence_ids.extend(str(x) for x in cert.get("evidence", []) if x)
        out.append(_node(
            idx,
            "verified_chain_provenance_methodology_match",
            "Verified harm certificates are represented as a bounded chain of evidence, following supply-chain provenance ideas from in-toto-style step metadata.",
            sorted(set(evidence_ids))[:50],
            ["torres_arias_2019_intoto"],
            context,
            severity="info",
            tags=["provenance", "certificate_chain", "verifiable_steps"],
        ))
        out[-1]["supports_certificates"] = cert_ids
        idx += 1

    if unsafe_serialization and runtime_risky:
        out.append(_node(
            idx,
            "static_runtime_correlation_methodology_match",
            "Static artifact risk and runtime behavior both appear in this run, matching the ModelFP/monitor lineage and third-party literature that combine static scanning with dynamic behavior to reduce blind spots.",
            sorted(set(_ids(unsafe_serialization[:25] + runtime_risky[:50]))),
            ["andrewdzzz_2025_monitor", "zhao_2024_malhug", "nambiar_2026_dynahug", "safepickle_2026"],
            context,
            tags=["cross_layer_correlation", "static_dynamic_fusion"],
        ))

    return out


def write_jsonl(path: Path, nodes: Sequence[Evidence]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")


def augment_graph(graph_path: Path, nodes: Sequence[Evidence]) -> None:
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    existing_ids = {ev.get("id") for ev in graph.get("evidence", [])}
    additions = [node for node in nodes if node.get("id") not in existing_ids]
    graph.setdefault("evidence", []).extend(additions)
    graph["evidence_count"] = len(graph.get("evidence", []))
    graph["literature_grounding_count"] = sum(1 for ev in graph.get("evidence", []) if ev.get("type") == "literature_grounding")
    graph_path.write_text(json.dumps(graph, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Add literature-grounding nodes to a ModelFP evidence graph")
    parser.add_argument("--graph", required=True)
    parser.add_argument("--certificates", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--augment-graph", action="store_true")
    args = parser.parse_args()

    graph_path = Path(args.graph)
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    cert_bundle = None
    if args.certificates and Path(args.certificates).exists():
        cert_bundle = json.loads(Path(args.certificates).read_text(encoding="utf-8"))

    nodes = build_literature_nodes(graph, cert_bundle)
    if args.out:
        write_jsonl(Path(args.out), nodes)
        print(args.out)
    if args.augment_graph:
        augment_graph(graph_path, nodes)
        print(str(graph_path))
    if not args.out and not args.augment_graph:
        print(json.dumps({"count": len(nodes), "literature_grounding": nodes}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
