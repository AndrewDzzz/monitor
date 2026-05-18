"""Fuse static ModelFP signals into repo-level static judgments.

This module reads already-collected static evidence JSONL files and emits
derived evidence nodes. It does not rescan files and does not execute target
code. The goal is to make repo-level conclusions explicit instead of forcing a
reviewer to mentally combine malware triage, config, pickle, ModelScan, and
repo-hygiene signals.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterable, Mapping


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _node(idx: int, finding: str, severity: str, meaning: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": f"FUS{idx:04d}",
        "source": "static_fusion_probe",
        "evidence_type": "static_fusion",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    if not path.exists():
        return nodes
    for line in path.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            nodes.append(json.loads(line))
        except Exception:
            continue
    return nodes


def load_evidence(evidence_dir: Path) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for name in [
        "all_files_static_evidence.jsonl",
        "repo_evidence.jsonl",
        "repo_hygiene_evidence.jsonl",
        "malware_static_evidence.jsonl",
        "python_ast_evidence.jsonl",
        "config_evidence.jsonl",
        "h5_static_evidence.jsonl",
        "pickle_static_evidence.jsonl",
        "modelscan_evidence.jsonl",
    ]:
        evidence.extend(read_jsonl(evidence_dir / name))
    return evidence


def sev_at_least(node: Mapping[str, Any], severity: str) -> bool:
    return SEVERITY_ORDER.get(str(node.get("severity", "info")), -1) >= SEVERITY_ORDER[severity]


def ids(nodes: Iterable[Mapping[str, Any]]) -> list[str]:
    return [str(node.get("id")) for node in nodes if node.get("id")]


def has_model_content(evidence: list[dict[str, Any]]) -> bool:
    return any(
        node.get("source") in {"all_files_static_probe", "repo_probe"}
        and node.get("finding") in {"model_artifact_or_metadata_present", "high_risk_model_artifact_format"}
        for node in evidence
    )


def risk_score(evidence: list[dict[str, Any]]) -> tuple[int, dict[str, int]]:
    weights = {
        "malware_static_probe": {"critical": 7, "high": 5, "medium": 2, "low": 1},
        "modelscan": {"critical": 6, "high": 4, "medium": 2, "low": 1},
        "pickle_static_probe": {"critical": 6, "high": 5, "medium": 2, "low": 1},
        "config_probe": {"critical": 5, "high": 4, "medium": 2, "low": 1},
        "python_ast_probe": {"critical": 5, "high": 4, "medium": 2, "low": 1},
        "all_files_static_probe": {"critical": 5, "high": 4, "medium": 2, "low": 1},
        "repo_hygiene_probe": {"critical": 4, "high": 3, "medium": 1, "low": 0},
    }
    by_source: dict[str, int] = {}
    total = 0
    for node in evidence:
        source = str(node.get("source"))
        severity = str(node.get("severity", "info"))
        points = weights.get(source, {}).get(severity, 0)
        if points:
            by_source[source] = by_source.get(source, 0) + points
            total += points
    return total, by_source


def score_to_severity(score: int) -> str:
    if score >= 15:
        return "critical"
    if score >= 8:
        return "high"
    if score >= 3:
        return "medium"
    return "info"


def fuse(evidence_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    evidence = load_evidence(evidence_dir)
    nodes: list[dict[str, Any]] = []
    idx = 1

    malware_high = [node for node in evidence if node.get("source") == "malware_static_probe" and sev_at_least(node, "high")]
    malware_medium = [node for node in evidence if node.get("source") == "malware_static_probe" and node.get("severity") == "medium"]
    config_custom = [
        node for node in evidence
        if node.get("source") == "config_probe"
        and node.get("finding") in {"auto_map_present", "trust_remote_code_reference"}
    ]
    config_network = [
        node for node in evidence
        if node.get("source") == "config_probe"
        and node.get("finding") == "external_url_reference"
    ]
    pickle_danger = [
        node for node in evidence
        if node.get("source") == "pickle_static_probe"
        and node.get("finding") == "pickle_dangerous_global_ref"
    ]
    modelscan_critical = [
        node for node in evidence
        if node.get("source") == "modelscan"
        and sev_at_least(node, "critical")
    ]
    non_model_payload = [
        node for node in evidence
        if node.get("source") == "all_files_static_probe"
        and node.get("finding") == "non_model_payload_extension"
    ]
    hygiene_hosting = [
        node for node in evidence
        if node.get("source") == "repo_hygiene_probe"
        and node.get("finding") == "malware_hosting_like_file_tree"
    ]
    python_high = [
        node for node in evidence
        if node.get("source") == "python_ast_probe"
        and sev_at_least(node, "high")
    ]

    if malware_high and config_custom:
        merged_ids = ids(malware_high[:5] + config_custom[:5])
        nodes.append(_node(idx, "malware_static_plus_custom_code_config", "critical", "Malware-style static indicators coexist with config that can route loading to custom code.", evidence_ids=merged_ids))
        idx += 1
    if malware_high and config_network:
        merged_ids = ids(malware_high[:5] + config_network[:5])
        nodes.append(_node(idx, "malware_static_plus_network_config", "high", "Malware-style static indicators coexist with external URL references in config.", evidence_ids=merged_ids))
        idx += 1
    if pickle_danger and modelscan_critical:
        merged_ids = ids(pickle_danger[:5] + modelscan_critical[:5])
        nodes.append(_node(idx, "unsafe_serialization_correlated", "critical", "Pickle opcode risk is corroborated by ModelScan critical findings.", evidence_ids=merged_ids))
        idx += 1
    if non_model_payload and (hygiene_hosting or not has_model_content(evidence)):
        merged_ids = ids(non_model_payload[:5] + hygiene_hosting[:5])
        nodes.append(_node(idx, "non_model_payload_repo_level_concern", "high", "Non-model payload files align with malware-hosting-like repo structure or lack of model content.", evidence_ids=merged_ids))
        idx += 1
    if malware_high and python_high:
        merged_ids = ids(malware_high[:5] + python_high[:5])
        nodes.append(_node(idx, "malware_static_plus_python_execution_sink", "critical", "Malware-style indicators coexist with high-risk Python execution sinks.", evidence_ids=merged_ids))
        idx += 1

    score, by_source = risk_score(evidence)
    severity = score_to_severity(score)
    high_or_critical_ids = ids(node for node in evidence if node.get("source") != "env_probe" and sev_at_least(node, "high"))
    nodes.append(_node(
        idx,
        "static_target_risk_summary",
        severity,
        "Repo-level static target risk summary fused from malware, config, artifact, and hygiene signals.",
        static_score=score,
        score_by_source=by_source,
        high_or_critical_evidence_ids=high_or_critical_ids[:50],
        malware_high_count=len(malware_high),
        malware_medium_count=len(malware_medium),
        config_custom_code_count=len(config_custom),
        config_network_reference_count=len(config_network),
        pickle_danger_count=len(pickle_danger),
        modelscan_critical_count=len(modelscan_critical),
        non_model_payload_count=len(non_model_payload),
    ))

    report = {
        "schema": "modelfp.static_fusion_report.v1",
        "generated_at_unix": time.time(),
        "evidence_dir": str(evidence_dir),
        "input_evidence_count": len(evidence),
        "fusion_evidence": nodes,
    }
    return nodes, report


def write_jsonl(path: Path, nodes: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Fuse ModelFP static evidence into repo-level judgments")
    parser.add_argument("--evidence-dir", default="/workspace/out/evidence")
    parser.add_argument("--out", default="/workspace/out/evidence/static_fusion_evidence.jsonl")
    parser.add_argument("--raw-report", default=None)
    args = parser.parse_args()
    nodes, report = fuse(Path(args.evidence_dir))
    write_jsonl(Path(args.out), nodes)
    if args.raw_report:
        raw = Path(args.raw_report)
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
