"""ModelFP deterministic rulecheck engine.

This starter engine supports:
- single-evidence static/config/environment/runtime rules;
- cross-layer correlation rules;
- simple temporal dataflow rules over normalized runtime events.

GPT must not write to active rules directly. GPT may generate candidate YAML rules,
which are validated separately before promotion.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Sequence

Evidence = Dict[str, Any]
Rule = Dict[str, Any]
Certificate = Dict[str, Any]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_at_least(actual: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(str(actual).lower(), -1) >= SEVERITY_ORDER.get(str(minimum).lower(), -1)


def matches(ev: Evidence, cond: Mapping[str, Any]) -> bool:
    for key, expected in cond.items():
        if key in {"id", "var", "after", "fd_from"}:
            continue
        if key == "min_severity":
            if not severity_at_least(str(ev.get("severity", "info")), str(expected)):
                return False
        elif key == "finding_any":
            if ev.get("finding") not in expected:
                return False
        elif key == "path_class":
            if ev.get("path_class") != expected:
                return False
        elif ev.get(key) != expected:
            return False
    return True


def flatten_policy(policy: Mapping[str, Any]) -> List[Rule]:
    rules: List[Rule] = []
    for section, default_type in [
        ("static_rules", "static"),
        ("config_rules", "config"),
        ("environment_rules", "environment"),
        ("runtime_rules", "runtime"),
    ]:
        for rule in policy.get(section, []) or []:
            r = dict(rule)
            r.setdefault("type", default_type)
            rules.append(r)
    for rule in policy.get("temporal_rules", []) or []:
        r = dict(rule)
        r.setdefault("type", "temporal_dataflow")
        rules.append(r)
    for rule in policy.get("cross_layer_rules", []) or []:
        r = dict(rule)
        r.setdefault("type", "cross_layer_correlation")
        rules.append(r)
    return rules


def _single_condition(rule: Rule) -> Mapping[str, Any]:
    return rule.get("if") or rule.get("conditions") or {}


def find_single_evidence_certificates(model: str, revision: str, run_id: str, rule: Rule, evidence_nodes: List[Evidence]) -> List[Certificate]:
    cond = _single_condition(rule)
    certs: List[Certificate] = []
    for ev in evidence_nodes:
        if matches(ev, cond):
            certs.append({
                "certificate_id": f"ModelFP-HC-{rule['id']}-{ev['id']}",
                "model": model,
                "revision": revision,
                "run_id": run_id,
                "rule_id": rule["id"],
                "verdict": rule["verdict"],
                "severity": rule["severity"],
                "harm_type": rule.get("harm_type", rule.get("type", "risk")),
                "harm_subtype": rule.get("harm_subtype", rule["id"].lower()),
                "witness": {"event": ev["id"]},
                "evidence": [ev["id"]],
                "checker_status": "unverified",
            })
    return certs


def find_cross_layer_certificates(model: str, revision: str, run_id: str, rule: Rule, evidence_nodes: List[Evidence]) -> List[Certificate]:
    conds = rule.get("conditions", {})
    static_cond = conds.get("static", {})
    runtime_cond = conds.get("runtime", {})

    static_matches = [ev for ev in evidence_nodes if matches(ev, static_cond)]
    runtime_matches = [ev for ev in evidence_nodes if matches(ev, runtime_cond)]

    certs: List[Certificate] = []
    for s in static_matches:
        for r in runtime_matches:
            if rule.get("constraints", {}).get("same_model_revision"):
                if s.get("model") != r.get("model") or s.get("revision") != r.get("revision"):
                    continue
            if rule.get("constraints", {}).get("same_run_context"):
                if r.get("run_id") != run_id:
                    continue
            certs.append({
                "certificate_id": f"ModelFP-HC-{rule['id']}-{s['id']}-{r['id']}",
                "model": model,
                "revision": revision,
                "run_id": run_id,
                "rule_id": rule["id"],
                "verdict": rule["verdict"],
                "severity": rule["severity"],
                "harm_type": rule.get("harm_type", "cross_layer"),
                "harm_subtype": rule.get("harm_subtype", rule["id"].lower()),
                "witness": {"static": s["id"], "runtime": r["id"]},
                "evidence": [s["id"], r["id"]],
                "checker_status": "unverified",
            })
    return certs


def _before(a: Evidence, b: Evidence) -> bool:
    return float(a.get("time", -1)) < float(b.get("time", -1))


def _fd_related(current: Evidence, previous: Evidence) -> bool:
    # Primary fd equality when both events have an fd.
    if current.get("fd") is not None and previous.get("fd") is not None and current.get("fd") == previous.get("fd"):
        return True
    # Semantic relation: read/write event inherited source/sink labels from strace_parser.
    if previous.get("path_class") and current.get("path_class") == previous.get("path_class"):
        return True
    if previous.get("dst_type") and current.get("dst_type") == previous.get("dst_type"):
        return True
    return False


def _candidate_events(events: Sequence[Evidence], step: Mapping[str, Any]) -> List[Evidence]:
    return [ev for ev in events if matches(ev, step)]


def find_temporal_certificates(model: str, revision: str, run_id: str, rule: Rule, evidence_nodes: List[Evidence]) -> List[Certificate]:
    sequence = rule.get("sequence", []) or []
    if not sequence:
        return []
    events = [ev for ev in evidence_nodes if ev.get("evidence_type") == "runtime_event"]
    events.sort(key=lambda ev: float(ev.get("time", 0)))

    matches_by_var: Dict[str, List[Evidence]] = {}
    for step in sequence:
        var = step.get("var")
        if not var:
            return []
        matches_by_var[var] = _candidate_events(events, step)

    certs: List[Certificate] = []

    def backtrack(i: int, chosen: Dict[str, Evidence]) -> None:
        if i == len(sequence):
            constraints = rule.get("constraints", {}) or {}
            if "same_process" in constraints:
                pids = {chosen[v].get("pid") for v in constraints["same_process"] if v in chosen}
                if len(pids) != 1:
                    return
            if "within_seconds" in constraints:
                times = [float(ev.get("time", 0)) for ev in chosen.values()]
                if times and max(times) - min(times) > float(constraints["within_seconds"]):
                    return
            witness = {var: chosen[var]["id"] for var in chosen}
            evidence = [witness[step["var"]] for step in sequence]
            certs.append({
                "certificate_id": f"ModelFP-HC-{rule['id']}-" + "-".join(evidence),
                "model": model,
                "revision": revision,
                "run_id": run_id,
                "rule_id": rule["id"],
                "verdict": rule["verdict"],
                "severity": rule["severity"],
                "harm_type": rule.get("harm_type", "runtime"),
                "harm_subtype": rule.get("harm_subtype", rule["id"].lower()),
                "witness": witness,
                "evidence": evidence,
                "checker_status": "unverified",
            })
            return

        step = sequence[i]
        var = step["var"]
        after_var = step.get("after")
        fd_from = step.get("fd_from")
        for ev in matches_by_var.get(var, []):
            if after_var and after_var in chosen and not _before(chosen[after_var], ev):
                continue
            if fd_from and fd_from in chosen and not _fd_related(ev, chosen[fd_from]):
                continue
            chosen[var] = ev
            backtrack(i + 1, chosen)
            chosen.pop(var, None)

    backtrack(0, {})
    return certs[:50]  # avoid certificate explosion in MVP


def run_rulecheck(model: str, revision: str, run_id: str, rules: Iterable[Rule], evidence_nodes: List[Evidence]) -> List[Certificate]:
    certificates: List[Certificate] = []
    for rule in rules:
        rule_type = rule.get("type")
        if rule_type in {"static", "config", "environment", "runtime"}:
            certificates.extend(find_single_evidence_certificates(model, revision, run_id, rule, evidence_nodes))
        elif rule_type == "cross_layer_correlation":
            certificates.extend(find_cross_layer_certificates(model, revision, run_id, rule, evidence_nodes))
        elif rule_type == "temporal_dataflow":
            certificates.extend(find_temporal_certificates(model, revision, run_id, rule, evidence_nodes))
    return certificates
