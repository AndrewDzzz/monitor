"""Build publication-oriented ModelFP experiment figures from audit datasets.

The builder is intentionally dependency-light: it reads dataset manifests and
evidence graphs, then writes SVG figures plus a compact metrics JSON. It does
not execute target code or contact the network.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PALETTE = {
    "ink": "#17202a",
    "muted": "#5b677a",
    "line": "#bdc7d3",
    "paper": "#ffffff",
    "band": "#f5f7fb",
    "blue": "#2b6cb0",
    "cyan": "#0f8b8d",
    "green": "#2f855a",
    "amber": "#b7791f",
    "red": "#c53030",
    "purple": "#6b46c1",
    "slate": "#334155",
}


@dataclass
class CaseMetrics:
    label: str
    audit_id: str
    graph_path: Path
    certificate_path: Path | None
    evidence_count: int
    runtime_event_count: int
    high_or_critical_count: int
    target_high_or_critical_count: int
    environment_high_or_critical_count: int
    verified_certificate_count: int
    target_verified_certificate_count: int
    environment_verified_certificate_count: int
    source_counts: dict[str, int]
    severity_counts: dict[str, int]
    key_findings: list[dict[str, Any]]
    pickle_runtime_artifacts: int = 0
    pickle_runtime_verified_certificates: int = 0
    pickle_runtime_marker_hits: int = 0


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_label(value: str, limit: int = 42) -> str:
    value = value.strip() or "unknown"
    value = re.sub(r"^https?://(huggingface.co|github.com)/", "", value)
    value = value.removesuffix(".git")
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "..."


def wrap_svg_text(text: str, width: int) -> list[str]:
    return textwrap.wrap(text, width=width, break_long_words=False, break_on_hyphens=False) or [""]


def text_element(x: float, y: float, text: str, *, size: int = 14, weight: str = "400", fill: str | None = None, anchor: str = "start") -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-family="Inter, Arial, sans-serif" '
        f'font-size="{size}" font-weight="{weight}" fill="{fill or PALETTE["ink"]}" '
        f'text-anchor="{anchor}">{html.escape(text)}</text>'
    )


def rect(x: float, y: float, w: float, h: float, *, fill: str, stroke: str | None = None, radius: int = 8, opacity: float = 1.0) -> str:
    stroke_attr = f' stroke="{stroke}"' if stroke else ""
    opacity_attr = f' opacity="{opacity:.3f}"' if opacity < 1 else ""
    return f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{radius}" fill="{fill}"{stroke_attr}{opacity_attr}/>'


def line(x1: float, y1: float, x2: float, y2: float, *, stroke: str | None = None, width: float = 1.5, dash: str | None = None, arrow: bool = False) -> str:
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    arrow_attr = ' marker-end="url(#arrow)"' if arrow else ""
    return f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{stroke or PALETTE["line"]}" stroke-width="{width:.1f}"{dash_attr}{arrow_attr}/>'


def svg_doc(width: int, height: int, body: Iterable[str]) -> str:
    return "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
            "<defs>",
            '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
            f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{PALETTE["line"]}"/>',
            "</marker>",
            "</defs>",
            rect(0, 0, width, height, fill=PALETTE["paper"], radius=0),
            *body,
            "</svg>",
        ]
    )


def graph_from_manifest(audit_dir: Path, manifest: dict[str, Any]) -> Path | None:
    preferred = audit_dir / "outputs_static_v2/evidence_graph.json"
    if preferred.exists():
        return preferred
    artifact = manifest.get("artifacts", {}).get("static_graph") or {}
    rel = artifact.get("path")
    if rel:
        candidate = audit_dir / rel
        if candidate.exists():
            return candidate
    candidate = audit_dir / "outputs_static/evidence_graph.json"
    if candidate.exists():
        return candidate
    return None


def certificate_for_graph(graph_path: Path) -> Path | None:
    candidate = graph_path.parent / "harm_certificates.json"
    return candidate if candidate.exists() else None


def pickle_summary_for_audit(audit_dir: Path) -> Path | None:
    candidate = audit_dir / "outputs_pickle_runtime/pickle_runtime_summary.json"
    return candidate if candidate.exists() else None


def discover_manifests(dataset_root: Path) -> list[Path]:
    if not dataset_root.exists():
        return []
    return sorted(dataset_root.rglob("dataset_manifest.json"))


def latest_manifest_by_label(manifests: list[Path]) -> list[Path]:
    chosen: dict[str, tuple[float, Path]] = {}
    for path in manifests:
        try:
            manifest = load_json(path)
        except Exception:
            continue
        label = safe_label(manifest.get("repo_id") or manifest.get("repo_url") or manifest.get("input_ref") or path.parent.name)
        timestamp = float(manifest.get("created_at_unix") or path.stat().st_mtime)
        previous = chosen.get(label)
        if previous is None or timestamp > previous[0]:
            chosen[label] = (timestamp, path)
    return [item[1] for item in sorted(chosen.values(), key=lambda x: safe_label(x[1].parent.name))]


def summarize_case(label: str, audit_id: str, graph_path: Path, cert_path: Path | None, pickle_summary: Path | None) -> CaseMetrics:
    graph = load_json(graph_path)
    evidence = graph.get("evidence", [])
    source_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    key_findings: list[dict[str, Any]] = []
    target_high_or_critical = 0
    environment_high_or_critical = 0
    for node in evidence:
        source = str(node.get("source", "unknown"))
        severity = str(node.get("severity", "unknown"))
        source_counts[source] = source_counts.get(source, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if severity in {"high", "critical"}:
            if source == "env_probe":
                environment_high_or_critical += 1
            else:
                target_high_or_critical += 1
        if source != "env_probe" and (
            severity in {"high", "critical"}
            or source in {"python_ast_probe", "all_files_static_probe", "pickle_static_probe", "repo_hygiene_probe"}
        ):
            key_findings.append(
                {
                    "id": node.get("id"),
                    "source": source,
                    "finding": node.get("finding"),
                    "severity": severity,
                    "path": node.get("path"),
                }
            )
    key_findings.sort(key=lambda item: (-SEVERITY_ORDER.get(str(item.get("severity")), -1), str(item.get("id"))))

    verified = 0
    target_verified = 0
    environment_verified = 0
    if cert_path and cert_path.exists():
        certs = load_json(cert_path)
        verified = int(certs.get("verified_count") or 0)
        for cert in certs.get("certificates", []):
            if cert.get("checker_status") != "verified":
                continue
            rule_id = str(cert.get("rule_id") or "")
            if rule_id.startswith("ENV_"):
                environment_verified += 1
            else:
                target_verified += 1

    pickle_artifacts = 0
    pickle_verified = 0
    pickle_marker_hits = 0
    if pickle_summary and pickle_summary.exists():
        summary = load_json(pickle_summary)
        artifacts = summary.get("artifacts", [])
        pickle_artifacts = int(summary.get("artifact_count") or len(artifacts))
        for artifact in artifacts:
            pickle_verified += int(artifact.get("verified_certificate_count") or 0)
            observation = artifact.get("observation") or {}
            if observation.get("after_marker_exists"):
                pickle_marker_hits += 1

    return CaseMetrics(
        label=label,
        audit_id=audit_id,
        graph_path=graph_path,
        certificate_path=cert_path,
        evidence_count=int(graph.get("evidence_count") or len(evidence)),
        runtime_event_count=int(graph.get("runtime_event_count") or 0),
        high_or_critical_count=sum(1 for node in evidence if node.get("severity") in {"high", "critical"}),
        target_high_or_critical_count=target_high_or_critical,
        environment_high_or_critical_count=environment_high_or_critical,
        verified_certificate_count=verified,
        target_verified_certificate_count=target_verified,
        environment_verified_certificate_count=environment_verified,
        source_counts=source_counts,
        severity_counts=severity_counts,
        key_findings=key_findings[:12],
        pickle_runtime_artifacts=pickle_artifacts,
        pickle_runtime_verified_certificates=pickle_verified,
        pickle_runtime_marker_hits=pickle_marker_hits,
    )


def load_cases(args: argparse.Namespace) -> list[CaseMetrics]:
    cases: list[CaseMetrics] = []
    explicit = args.case or []
    for label, graph in explicit:
        graph_path = Path(graph).resolve()
        cert_path = Path(args.certificate).resolve() if args.certificate else certificate_for_graph(graph_path)
        cases.append(summarize_case(label, graph_path.parent.parent.name, graph_path, cert_path, None))
    if cases:
        if args.pickle_summary:
            summary_path = Path(args.pickle_summary).resolve()
            if cases:
                first = cases[-1]
                cases[-1] = summarize_case(first.label, first.audit_id, first.graph_path, first.certificate_path, summary_path)
        return cases

    manifests = latest_manifest_by_label(discover_manifests(Path(args.dataset_root).resolve()))
    for manifest_path in manifests:
        try:
            manifest = load_json(manifest_path)
        except Exception:
            continue
        audit_dir = manifest_path.parent
        graph_path = graph_from_manifest(audit_dir, manifest)
        if not graph_path:
            continue
        label = safe_label(manifest.get("repo_id") or manifest.get("repo_url") or manifest.get("input_ref") or audit_dir.name)
        cases.append(
            summarize_case(
                label=label,
                audit_id=str(manifest.get("audit_id") or audit_dir.name),
                graph_path=graph_path,
                cert_path=certificate_for_graph(graph_path),
                pickle_summary=pickle_summary_for_audit(audit_dir),
            )
        )
    return cases


def draw_workflow(out: Path) -> None:
    width, height = 1480, 610
    body: list[str] = [
        text_element(60, 60, "ModelFP repo-level audit workflow", size=28, weight="700"),
        text_element(60, 88, "Network is limited to acquisition. Static, runtime, evidence normalization, and rulechecking run inside Docker.", size=15, fill=PALETTE["muted"]),
    ]
    steps = [
        ("Remote repo", "HF model or GitHub repository\\nURL + revision", PALETTE["blue"]),
        ("Docker acquisition", "Download/clone + metadata\\nnetwork enabled only here", PALETTE["cyan"]),
        ("Static modules", "All files, repo hygiene,\\nPython AST, config, H5, pickle, ModelScan", PALETTE["green"]),
        ("Optional runtime", "strace + Python audit hooks\\nnetwork none, read-only inputs", PALETTE["amber"]),
        ("Evidence graph", "Normalized evidence IDs\\nwith literature nodes", PALETTE["purple"]),
        ("Rulechecker", "Deterministic policy\\nverified certificates", PALETTE["red"]),
        ("Dataset folder", "manifest, hashes, raw reports,\\ncertificates, LLM payload", PALETTE["slate"]),
    ]
    x, y, w, h, gap = 55, 150, 175, 154, 28
    for idx, (title, detail, color) in enumerate(steps):
        xx = x + idx * (w + gap)
        body.append(rect(xx, y, w, h, fill="#ffffff", stroke=PALETTE["line"], radius=8))
        body.append(rect(xx, y, w, 10, fill=color, radius=8))
        body.append(text_element(xx + 18, y + 42, title, size=17, weight="700", fill=PALETTE["ink"]))
        detail_lines: list[str] = []
        for raw_line in detail.split("\\n"):
            detail_lines.extend(wrap_svg_text(raw_line, 24))
        for line_no, line_text in enumerate(detail_lines[:4]):
            body.append(text_element(xx + 18, y + 74 + line_no * 22, line_text, size=13, fill=PALETTE["muted"]))
        if idx < len(steps) - 1:
            body.append(line(xx + w + 4, y + h / 2, xx + w + gap - 8, y + h / 2, arrow=True))

    lanes = [
        (60, 375, 400, "Network stage", "remote metadata, model snapshot, git history"),
        (490, 375, 450, "Offline Docker evidence stage", "static probes and optional execution boundary"),
        (970, 375, 430, "Portable audit dataset", "manifested evidence for review and reproducibility"),
    ]
    for xx, yy, ww, title, detail in lanes:
        body.append(rect(xx, yy, ww, 120, fill=PALETTE["band"], stroke="#d8dee9", radius=8))
        body.append(text_element(xx + 22, yy + 38, title, size=18, weight="700", fill=PALETTE["ink"]))
        body.append(text_element(xx + 22, yy + 68, detail, size=14, fill=PALETTE["muted"]))
    body.append(text_element(60, 555, "Output contract: evidence_graph.json + harm_certificates.json + raw probe reports + dataset_manifest.json", size=15, weight="600", fill=PALETTE["slate"]))
    out.write_text(svg_doc(width, height, body), encoding="utf-8")


def draw_evidence_chain(out: Path, cases: list[CaseMetrics]) -> None:
    width, height = 1480, 720
    target = next((case for case in cases if "malicious_model_test" in case.label), cases[-1] if cases else None)
    body: list[str] = [
        text_element(60, 58, "Evidence chain: malicious pickle repository", size=28, weight="700"),
        text_element(60, 86, "Static findings establish pre-execution risk; isolated pickle runtime confirms observed shell execution.", size=15, fill=PALETTE["muted"]),
    ]
    chain = [
        ("AF0001/AF0002", "Repository inventory", "Two .pickle artifacts detected", PALETTE["blue"]),
        ("P0001", "Pickle static probe", "Dangerous global reference: posix.system", PALETTE["amber"]),
        ("S0001/S0002", "ModelScan", "Critical unsafe operators", PALETTE["red"]),
        ("Docker runtime", "Controlled detonation", "network none, read-only repo, tmpfs /tmp", PALETTE["purple"]),
        ("E001537", "Runtime trace", "shell execution observed", PALETTE["red"]),
        ("Certificate", "Rulechecker", "RUNTIME_SHELL_EXECUTION verified", PALETTE["green"]),
    ]
    x, y, w, h, gap = 75, 145, 190, 132, 42
    for idx, (eid, title, detail, color) in enumerate(chain):
        xx = x + idx * (w + gap)
        body.append(rect(xx, y, w, h, fill="#ffffff", stroke=PALETTE["line"], radius=8))
        body.append(text_element(xx + 16, y + 34, eid, size=15, weight="700", fill=color))
        body.append(text_element(xx + 16, y + 64, title, size=16, weight="700"))
        for line_no, line_text in enumerate(wrap_svg_text(detail, 24)[:2]):
            body.append(text_element(xx + 16, y + 92 + line_no * 20, line_text, size=12, fill=PALETTE["muted"]))
        if idx < len(chain) - 1:
            body.append(line(xx + w + 5, y + h / 2, xx + w + gap - 8, y + h / 2, arrow=True))

    static_box = (90, 365, 600, 180)
    runtime_box = (790, 365, 600, 180)
    body.append(rect(*static_box, fill="#fff8e8", stroke="#f0d59b", radius=8))
    body.append(text_element(static_box[0] + 26, static_box[1] + 42, "Static conclusion", size=20, weight="700", fill=PALETTE["amber"]))
    static_lines = [
        "pre_execution_risk before loading the artifact",
        "pickle opcode evidence is primary; literature nodes only ground methodology",
        "ModelScan corroborates unsafe deserialization surface",
    ]
    for i, item in enumerate(static_lines):
        body.append(text_element(static_box[0] + 26, static_box[1] + 78 + i * 29, item, size=14, fill=PALETTE["ink"]))

    body.append(rect(*runtime_box, fill="#fff0f0", stroke="#efb4b4", radius=8))
    body.append(text_element(runtime_box[0] + 26, runtime_box[1] + 42, "Runtime conclusion", size=20, weight="700", fill=PALETTE["red"]))
    if target:
        runtime_lines = [
            f"pickle artifacts detonated: {target.pickle_runtime_artifacts}",
            f"runtime verified certificates: {target.pickle_runtime_verified_certificates}",
            f"marker-hit artifacts: {target.pickle_runtime_marker_hits}",
        ]
    else:
        runtime_lines = ["runtime summary unavailable"]
    for i, item in enumerate(runtime_lines):
        body.append(text_element(runtime_box[0] + 26, runtime_box[1] + 78 + i * 29, item, size=14, fill=PALETTE["ink"]))

    body.append(line(static_box[0] + static_box[2], static_box[1] + 90, runtime_box[0], runtime_box[1] + 90, stroke=PALETTE["line"], width=2, dash="6 6", arrow=True))
    body.append(text_element(60, 645, "Verdict boundary: static risk is not claimed as realized harm until runtime evidence supports a certificate.", size=15, weight="600", fill=PALETTE["slate"]))
    out.write_text(svg_doc(width, height, body), encoding="utf-8")


def draw_experiment_matrix(out: Path, cases: list[CaseMetrics]) -> None:
    width = 1480
    row_h = 78
    height = 210 + max(1, len(cases)) * row_h + 120
    body: list[str] = [
        text_element(60, 58, "Experiment matrix from ModelFP audit datasets", size=28, weight="700"),
        text_element(60, 86, "Each row is one repository-level audit dataset. Counts come from evidence_graph.json and harm_certificates.json.", size=15, fill=PALETTE["muted"]),
    ]
    headers = [
        ("Repository", 60, 310),
        ("Evidence", 390, 115),
        ("Target High/Crit", 515, 145),
        ("Static modules hit", 675, 330),
        ("Target certs", 1030, 120),
        ("Pickle runtime", 1160, 230),
    ]
    y0 = 145
    body.append(rect(45, y0 - 38, 1390, 58, fill=PALETTE["band"], stroke="#d8dee9", radius=8))
    for title, x, w in headers:
        body.append(text_element(x + 8, y0, title, size=14, weight="700", fill=PALETTE["slate"]))
    source_order = [
        ("AF", "all_files_static_probe", PALETTE["blue"]),
        ("RH", "repo_hygiene_probe", PALETTE["cyan"]),
        ("MW", "malware_static_probe", PALETTE["purple"]),
        ("AST", "python_ast_probe", PALETTE["green"]),
        ("PKL", "pickle_static_probe", PALETTE["amber"]),
        ("MS", "modelscan", PALETTE["red"]),
        ("FUS", "static_fusion_probe", PALETTE["slate"]),
    ]
    for idx, case in enumerate(cases):
        yy = y0 + 38 + idx * row_h
        fill = "#ffffff" if idx % 2 == 0 else "#fbfcff"
        body.append(rect(45, yy - 26, 1390, row_h - 10, fill=fill, stroke="#e1e7ef", radius=8))
        for line_no, line_text in enumerate(wrap_svg_text(case.label, 35)[:2]):
            body.append(text_element(68, yy + line_no * 18, line_text, size=14 if line_no == 0 else 12, weight="700" if line_no == 0 else "400"))
        body.append(text_element(398, yy, str(case.evidence_count), size=18, weight="700", fill=PALETTE["blue"]))
        severity_fill = PALETTE["red"] if case.target_high_or_critical_count else PALETTE["muted"]
        body.append(text_element(555, yy, str(case.target_high_or_critical_count), size=18, weight="700", fill=severity_fill))
        sx = 665
        for tag, source, color in source_order:
            active = source in case.source_counts
            body.append(rect(sx, yy - 24, 42, 34, fill=color if active else "#eef2f7", stroke="#d8dee9", radius=6, opacity=1 if active else 0.85))
            body.append(text_element(sx + 21, yy - 2, tag, size=11, weight="700", fill="#ffffff" if active else PALETTE["muted"], anchor="middle"))
            sx += 48
        cert_fill = PALETTE["green"] if case.target_verified_certificate_count else PALETTE["muted"]
        body.append(text_element(1065, yy, str(case.target_verified_certificate_count), size=18, weight="700", fill=cert_fill))
        runtime_text = f"{case.pickle_runtime_artifacts} art / {case.pickle_runtime_verified_certificates} cert / {case.pickle_runtime_marker_hits} hit"
        body.append(text_element(1172, yy, runtime_text, size=12, fill=PALETTE["ink"]))

    legend_y = height - 95
    body.append(text_element(60, legend_y, "Static module legend", size=14, weight="700", fill=PALETTE["slate"]))
    for legend_idx, (tag, source, color) in enumerate(source_order):
        row = legend_idx // 4
        col = legend_idx % 4
        lx = 220 + col * 300
        ly = legend_y + row * 34
        body.append(rect(lx, ly - 20, 46, 28, fill=color, radius=6))
        body.append(text_element(lx + 23, ly - 2, tag, size=11, weight="700", fill="#ffffff", anchor="middle"))
        body.append(text_element(lx + 54, ly - 2, source, size=12, fill=PALETTE["muted"]))
    out.write_text(svg_doc(width, height, body), encoding="utf-8")


def write_metrics(out: Path, cases: list[CaseMetrics]) -> None:
    payload = {
        "schema": "modelfp.experiment_figures.v1",
        "generated_at_unix": time.time(),
        "case_count": len(cases),
        "cases": [
            {
                "label": case.label,
                "audit_id": case.audit_id,
                "graph_path": str(case.graph_path),
                "certificate_path": str(case.certificate_path) if case.certificate_path else None,
                "evidence_count": case.evidence_count,
                "runtime_event_count": case.runtime_event_count,
                "high_or_critical_count": case.target_high_or_critical_count,
                "total_high_or_critical_count_including_environment": case.high_or_critical_count,
                "target_high_or_critical_count": case.target_high_or_critical_count,
                "environment_high_or_critical_count": case.environment_high_or_critical_count,
                "verified_certificate_count": case.verified_certificate_count,
                "target_verified_certificate_count": case.target_verified_certificate_count,
                "environment_verified_certificate_count": case.environment_verified_certificate_count,
                "source_counts": case.source_counts,
                "severity_counts": case.severity_counts,
                "pickle_runtime_artifacts": case.pickle_runtime_artifacts,
                "pickle_runtime_verified_certificates": case.pickle_runtime_verified_certificates,
                "pickle_runtime_marker_hits": case.pickle_runtime_marker_hits,
                "key_findings": case.key_findings,
            }
            for case in cases
        ],
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build ModelFP experiment SVG figures from audit datasets")
    parser.add_argument("--dataset-root", default="/workspace/audit_datasets", help="Root containing ModelFP audit dataset folders")
    parser.add_argument("--out", default="/workspace/figures", help="Figure output directory")
    parser.add_argument("--case", nargs=2, action="append", metavar=("LABEL", "EVIDENCE_GRAPH"), help="Explicit case label and evidence_graph.json path")
    parser.add_argument("--certificate", help="Optional certificate path for explicit --case mode")
    parser.add_argument("--pickle-summary", help="Optional pickle_runtime_summary.json for explicit --case mode")
    args = parser.parse_args()

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = load_cases(args)
    if not cases:
        raise SystemExit(f"No usable evidence graphs found under {args.dataset_root}")
    draw_workflow(out_dir / "figure_01_repo_level_workflow.svg")
    draw_evidence_chain(out_dir / "figure_02_pickle_evidence_chain.svg", cases)
    draw_experiment_matrix(out_dir / "figure_03_experiment_matrix.svg", cases)
    write_metrics(out_dir / "experiment_figure_metrics.json", cases)
    print(f"Wrote {out_dir / 'figure_01_repo_level_workflow.svg'}")
    print(f"Wrote {out_dir / 'figure_02_pickle_evidence_chain.svg'}")
    print(f"Wrote {out_dir / 'figure_03_experiment_matrix.svg'}")
    print(f"Wrote {out_dir / 'experiment_figure_metrics.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
