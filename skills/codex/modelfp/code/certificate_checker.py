"""
Minimal ModelFP harm certificate checker.

This is intentionally small: the certificate checker should be the trusted core.
Rulecheck may be complex, GPT may propose candidate rules, but a certificate is only
accepted if this checker can verify that its evidence exists and satisfies the rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional


Evidence = Dict[str, Any]
Rule = Dict[str, Any]
Certificate = Dict[str, Any]


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    reason: str


def index_evidence(nodes: List[Evidence]) -> Dict[str, Evidence]:
    return {node["id"]: node for node in nodes if "id" in node}


def severity_at_least(actual: str, minimum: str) -> bool:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(actual, -1) >= order.get(minimum, -1)


def path_class_matches(ev: Evidence, required: str) -> bool:
    return ev.get("path_class") == required


def simple_condition_matches(ev: Evidence, condition: Mapping[str, Any]) -> bool:
    """Check common event/evidence predicates.

    This is not a full DSL implementation. It is a starter trusted-core checker
    for evidence predicates that appear in the minimal examples.
    """
    for key, expected in condition.items():
        if key in {"id", "var", "after", "fd_from"}:
            continue
        if key == "min_severity":
            if not severity_at_least(str(ev.get("severity", "info")), str(expected)):
                return False
        elif key == "finding_any":
            if ev.get("finding") not in expected:
                return False
        elif key == "path_class":
            if not path_class_matches(ev, str(expected)):
                return False
        elif key == "source":
            if ev.get("source") != expected:
                return False
        else:
            if ev.get(key) != expected:
                return False
    return True


def before(a: Evidence, b: Evidence) -> bool:
    return float(a.get("time", -1)) < float(b.get("time", -1))


def same_process(events: List[Evidence]) -> bool:
    pids = {ev.get("pid") for ev in events}
    return len(pids) == 1


def verify_runtime_rule(cert: Certificate, rule: Rule, evidence_index: Mapping[str, Evidence]) -> CheckResult:
    witness = cert.get("witness", {})
    runtime_id = witness.get("runtime") or witness.get("e") or witness.get("event")
    if not runtime_id:
        return CheckResult(False, "missing runtime witness")
    ev = evidence_index.get(runtime_id)
    if not ev:
        return CheckResult(False, f"missing evidence node {runtime_id}")
    cond = rule.get("if") or rule.get("conditions") or {}
    if not simple_condition_matches(ev, cond):
        return CheckResult(False, f"runtime witness {runtime_id} does not match rule predicates")
    return CheckResult(True, "runtime rule certificate verified")


def verify_cross_layer_rule(cert: Certificate, rule: Rule, evidence_index: Mapping[str, Evidence]) -> CheckResult:
    witness = cert.get("witness", {})
    static_id = witness.get("static")
    runtime_id = witness.get("runtime")
    if not static_id or not runtime_id:
        return CheckResult(False, "missing static/runtime witness")

    s = evidence_index.get(static_id)
    r = evidence_index.get(runtime_id)
    if not s:
        return CheckResult(False, f"missing evidence node {static_id}")
    if not r:
        return CheckResult(False, f"missing evidence node {runtime_id}")

    conds = rule.get("conditions", {})
    static_cond = conds.get("static", {})
    runtime_cond = conds.get("runtime", {})

    if not simple_condition_matches(s, static_cond):
        return CheckResult(False, f"static witness {static_id} does not match rule predicates")
    if not simple_condition_matches(r, runtime_cond):
        return CheckResult(False, f"runtime witness {runtime_id} does not match rule predicates")

    if rule.get("constraints", {}).get("same_model_revision"):
        if s.get("model") != r.get("model") or s.get("revision") != r.get("revision"):
            return CheckResult(False, "static/runtime evidence do not belong to same model revision")

    return CheckResult(True, "cross-layer certificate verified")


def verify_temporal_dataflow_rule(cert: Certificate, rule: Rule, evidence_index: Mapping[str, Evidence]) -> CheckResult:
    witness = cert.get("witness", {})
    sequence = rule.get("sequence", [])
    if not sequence:
        return CheckResult(False, "temporal rule has no sequence")

    resolved: Dict[str, Evidence] = {}
    for step in sequence:
        var = step.get("var")
        ev_id = witness.get(var)
        if not var or not ev_id:
            return CheckResult(False, f"missing witness for step {var}")
        ev = evidence_index.get(ev_id)
        if not ev:
            return CheckResult(False, f"missing evidence node {ev_id}")
        if not simple_condition_matches(ev, step):
            return CheckResult(False, f"witness {ev_id} does not match step {var}")
        resolved[var] = ev

    # Check ordering and fd/dataflow constraints encoded in step fields.
    for step in sequence:
        var = step.get("var")
        after_var = step.get("after")
        if after_var and not before(resolved[after_var], resolved[var]):
            return CheckResult(False, f"ordering violation: {after_var} is not before {var}")
        fd_from = step.get("fd_from")
        if fd_from:
            current = resolved[var]
            previous = resolved[fd_from]
            same_fd = current.get("fd") is not None and previous.get("fd") is not None and current.get("fd") == previous.get("fd")
            same_path_class = previous.get("path_class") is not None and current.get("path_class") == previous.get("path_class")
            same_dst_type = previous.get("dst_type") is not None and current.get("dst_type") == previous.get("dst_type")
            if not (same_fd or same_path_class or same_dst_type):
                return CheckResult(False, f"fd/dataflow constraint failed: {var} is not related to {fd_from}")

    constraints = rule.get("constraints", {})
    if "same_process" in constraints:
        events = [resolved[v] for v in constraints["same_process"]]
        if not same_process(events):
            return CheckResult(False, "same_process constraint failed")

    if "within_seconds" in constraints:
        times = [float(ev.get("time", 0)) for ev in resolved.values()]
        if max(times) - min(times) > float(constraints["within_seconds"]):
            return CheckResult(False, "within_seconds constraint failed")

    return CheckResult(True, "temporal dataflow certificate verified")


def verify_certificate(cert: Certificate, rules: Mapping[str, Rule], evidence_nodes: List[Evidence]) -> CheckResult:
    rule_id = cert.get("rule_id")
    if not rule_id or rule_id not in rules:
        return CheckResult(False, "certificate references unknown rule")

    rule = rules[rule_id]
    evidence_index = index_evidence(evidence_nodes)

    for ev_id in cert.get("evidence", []):
        if ev_id not in evidence_index:
            return CheckResult(False, f"certificate references missing evidence {ev_id}")

    if cert.get("verdict") != rule.get("verdict"):
        return CheckResult(False, "certificate verdict does not match rule verdict")
    if cert.get("severity") != rule.get("severity"):
        return CheckResult(False, "certificate severity does not match rule severity")

    rule_type = rule.get("type")
    if rule_type == "cross_layer_correlation":
        return verify_cross_layer_rule(cert, rule, evidence_index)
    if rule_type == "temporal_dataflow":
        return verify_temporal_dataflow_rule(cert, rule, evidence_index)
    if rule_type in {"runtime", "static", "config", "environment"}:
        return verify_runtime_rule(cert, rule, evidence_index)

    return CheckResult(False, f"unsupported rule type {rule_type}")
