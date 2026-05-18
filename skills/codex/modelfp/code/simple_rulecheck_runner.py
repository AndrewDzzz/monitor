"""Minimal deterministic ModelFP rulecheck for Docker runs.

This is deliberately small and transparent. GPT can summarize the output, but
certificates are generated only from concrete evidence nodes.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

import yaml

from certificate_checker import verify_certificate
from rulecheck_engine import flatten_policy

Evidence = Dict[str, Any]
Rule = Dict[str, Any]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_at_least(actual: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(str(actual).lower(), -1) >= SEVERITY_ORDER.get(str(minimum).lower(), -1)


def matches(ev: Evidence, cond: Mapping[str, Any]) -> bool:
    for key, expected in cond.items():
        if key in {"var", "after", "fd_from"}:
            continue
        if key == "min_severity":
            if not severity_at_least(str(ev.get("severity", "info")), str(expected)):
                return False
        elif key == "finding_any":
            if ev.get("finding") not in set(expected):
                return False
        else:
            if ev.get(key) != expected:
                return False
    return True


def simple_certificate(rule: Rule, ev: Evidence, context: Mapping[str, str]) -> Dict[str, Any]:
    return {
        "certificate_id": f"ModelFP-HC-{rule['id']}-{ev['id']}",
        "model": context["model"],
        "revision": context["revision"],
        "run_id": context["run_id"],
        "rule_id": rule["id"],
        "verdict": rule["verdict"],
        "severity": rule["severity"],
        "harm_type": rule.get("harm_type", rule.get("verdict", "risk")),
        "harm_subtype": rule.get("harm_subtype", rule["id"].lower()),
        "witness": {"event": ev["id"]},
        "evidence": [ev["id"]],
        "checker_status": "generated_by_simple_rulecheck",
        "generated_at": time.time(),
    }


def run_simple_rules(policy: Mapping[str, Any], evidence: List[Evidence], context: Mapping[str, str]) -> List[Dict[str, Any]]:
    certs: List[Dict[str, Any]] = []
    for section in ["environment_rules", "static_rules", "config_rules", "runtime_rules"]:
        for rule in policy.get(section, []):
            cond = rule.get("if", {})
            for ev in evidence:
                if matches(ev, cond):
                    certs.append(simple_certificate(rule, ev, context))
    return certs


def _event_order(evidence: List[Evidence]) -> Dict[str, int]:
    return {ev.get("id"): idx for idx, ev in enumerate(evidence)}


def _same_pid(events: Iterable[Evidence]) -> bool:
    pids = [ev.get("pid") for ev in events if ev.get("pid") is not None]
    return bool(pids) and len(set(pids)) == 1


def _fd_matches(ev: Evidence, source: Evidence) -> bool:
    if ev.get("fd") is not None and source.get("fd") is not None:
        return ev.get("fd") == source.get("fd")
    # Fallback: parser may annotate fd_path/fd_path_class on read/write events.
    if source.get("path") and ev.get("fd_path"):
        return ev.get("fd_path") == source.get("path")
    if source.get("path_class") and ev.get("fd_path_class"):
        return ev.get("fd_path_class") == source.get("path_class")
    return False


def run_temporal_rules(policy: Mapping[str, Any], evidence: List[Evidence], context: Mapping[str, str]) -> List[Dict[str, Any]]:
    certs: List[Dict[str, Any]] = []
    runtime = [ev for ev in evidence if ev.get("evidence_type") == "runtime_event"]
    order = _event_order(runtime)

    for rule in policy.get("temporal_rules", []):
        if rule.get("id") != "SECRET_ACCESS_FOLLOWED_BY_EXTERNAL_WRITE":
            continue
        opens = [e for e in runtime if matches(e, {"op": "open", "path_class": "secret", "result": "success"})]
        for a in opens:
            reads = [e for e in runtime if order.get(e.get("id"), -1) > order.get(a.get("id"), -1) and matches(e, {"op": "read", "result": "success"}) and _fd_matches(e, a)]
            for b in reads:
                connects = [e for e in runtime if order.get(e.get("id"), -1) > order.get(b.get("id"), -1) and matches(e, {"op": "connect", "dst_type": "external", "result": "success"})]
                for c in connects:
                    writes = [e for e in runtime if order.get(e.get("id"), -1) > order.get(c.get("id"), -1) and matches(e, {"op": "write", "result": "success"}) and _fd_matches(e, c)]
                    for d in writes:
                        chain = [a, b, c, d]
                        if rule.get("constraints", {}).get("same_process") and not _same_pid(chain):
                            continue
                        certs.append({
                            "certificate_id": f"ModelFP-HC-{rule['id']}-{a['id']}-{d['id']}",
                            "model": context["model"],
                            "revision": context["revision"],
                            "run_id": context["run_id"],
                            "rule_id": rule["id"],
                            "verdict": rule["verdict"],
                            "severity": rule["severity"],
                            "harm_type": rule.get("harm_type", "confidentiality"),
                            "harm_subtype": rule.get("harm_subtype", "possible_secret_exfiltration"),
                            "witness": {"a": a["id"], "b": b["id"], "c": c["id"], "d": d["id"]},
                            "evidence": [a["id"], b["id"], c["id"], d["id"]],
                            "checker_status": "generated_by_simple_rulecheck",
                            "generated_at": time.time(),
                        })
                        break
    return certs


def run_cross_layer_rules(policy: Mapping[str, Any], evidence: List[Evidence], context: Mapping[str, str]) -> List[Dict[str, Any]]:
    certs: List[Dict[str, Any]] = []
    for rule in policy.get("cross_layer_rules", []):
        conds = rule.get("conditions", {})
        static_matches = [e for e in evidence if matches(e, conds.get("static", {}))]
        runtime_matches = [e for e in evidence if matches(e, conds.get("runtime", {}))]
        for s in static_matches:
            for r in runtime_matches:
                certs.append({
                    "certificate_id": f"ModelFP-HC-{rule['id']}-{s['id']}-{r['id']}",
                    "model": context["model"],
                    "revision": context["revision"],
                    "run_id": context["run_id"],
                    "rule_id": rule["id"],
                    "verdict": rule["verdict"],
                    "severity": rule["severity"],
                    "harm_type": rule.get("harm_type", "cross_layer"),
                    "harm_subtype": rule.get("harm_subtype", rule["id"].lower()),
                    "witness": {"static": s["id"], "runtime": r["id"]},
                    "evidence": [s["id"], r["id"]],
                    "checker_status": "generated_by_simple_rulecheck",
                    "generated_at": time.time(),
                })
    return certs


def run_rulecheck(policy: Mapping[str, Any], evidence: List[Evidence], context: Mapping[str, str] | None = None) -> List[Dict[str, Any]]:
    context = context or {"model": "local/model", "revision": "local", "run_id": "local-run"}
    certs: List[Dict[str, Any]] = []
    certs.extend(run_simple_rules(policy, evidence, context))
    certs.extend(run_temporal_rules(policy, evidence, context))
    certs.extend(run_cross_layer_rules(policy, evidence, context))
    # Deduplicate by rule + evidence tuple.
    seen = set(); unique = []
    for c in certs:
        key = (c.get("rule_id"), tuple(c.get("evidence", [])))
        if key not in seen:
            seen.add(key); unique.append(c)
    return unique


def verify_certificates(policy: Mapping[str, Any], evidence: List[Evidence], certs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rule_map = {rule["id"]: rule for rule in flatten_policy(policy)}
    verified: List[Dict[str, Any]] = []
    for cert in certs:
        result = verify_certificate(cert, rule_map, evidence)
        checked = dict(cert)
        checked["checker_status"] = "verified" if result.ok else "rejected"
        checked["checker_reason"] = result.reason
        verified.append(checked)
    return verified


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-graph", default="/workspace/out/evidence_graph.json")
    parser.add_argument("--policy", default="/workspace/ModelFP_skill/rules/policy_minimal.yaml")
    parser.add_argument("--out", default="/workspace/out/harm_certificates.json")
    parser.add_argument("--model", default=None)
    parser.add_argument("--revision", default=None)
    parser.add_argument("--run-id", default=None)
    args = parser.parse_args()
    graph = json.loads(Path(args.evidence_graph).read_text(encoding="utf-8"))
    policy = yaml.safe_load(Path(args.policy).read_text(encoding="utf-8"))
    context = {
        "model": args.model or graph.get("model", "local/model"),
        "revision": args.revision or graph.get("revision", "local"),
        "run_id": args.run_id or graph.get("run_id", "local-run"),
    }
    certs = verify_certificates(policy, graph.get("evidence", []), run_rulecheck(policy, graph.get("evidence", []), context))
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "schema": "modelfp.harm_certificates.v1",
        "model": context["model"],
        "revision": context["revision"],
        "run_id": context["run_id"],
        "count": len(certs),
        "verified_count": sum(1 for c in certs if c.get("checker_status") == "verified"),
        "certificates": certs,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
