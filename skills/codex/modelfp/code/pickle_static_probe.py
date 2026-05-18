"""Static pickle opcode probe for ModelFP.

This inspects pickle opcode streams without importing or unpickling objects.
It is intended to complement ModelScan by recording GLOBAL/STACK_GLOBAL
references and clearly dangerous callable references when present.
"""

from __future__ import annotations

import argparse
import io
import json
import pickletools
import re
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

PICKLE_SUFFIXES = {".bin", ".pt", ".pth", ".pkl", ".pickle"}
DANGEROUS_RE = re.compile(
    r"(?ix)"
    r"(^|[.\s])("
    r"os\.system|posix\.system|nt\.system|subprocess\.Popen|subprocess\.call|"
    r"builtins\.eval|builtins\.exec|__builtin__\.eval|__builtin__\.exec|"
    r"socket\.socket|requests\.|urllib\.request|httpx\.|"
    r"shutil\.rmtree|pathlib\.Path|open"
    r")($|[.\s])"
)


def _node(idx: int, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": f"P{idx:04d}",
        "source": "pickle_static_probe",
        "evidence_type": "static_artifact",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def _pickle_members(path: Path) -> Iterable[Tuple[str, bytes]]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            for name in sorted(zf.namelist()):
                if name.endswith(".pkl"):
                    yield name, zf.read(name)
        return
    yield path.name, path.read_bytes()


def _scan_pickle_bytes(data: bytes) -> Dict[str, Any]:
    globals_seen: List[str] = []
    dangerous: List[str] = []
    op_counts: Dict[str, int] = {}
    stack: List[str] = []
    reduce_count = 0

    for op, arg, _pos in pickletools.genops(io.BytesIO(data)):
        op_counts[op.name] = op_counts.get(op.name, 0) + 1
        if op.name in {"UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINBYTES", "SHORT_BINBYTES"}:
            if isinstance(arg, bytes):
                stack.append(arg.decode("utf-8", errors="replace"))
            elif isinstance(arg, str):
                stack.append(arg)
            continue
        if op.name == "GLOBAL":
            ref = str(arg).replace(" ", ".")
            globals_seen.append(ref)
            if DANGEROUS_RE.search(ref):
                dangerous.append(ref)
            continue
        if op.name == "STACK_GLOBAL":
            if len(stack) >= 2:
                name = stack.pop()
                module = stack.pop()
                ref = f"{module}.{name}"
            else:
                ref = "<unresolved STACK_GLOBAL>"
            globals_seen.append(ref)
            if DANGEROUS_RE.search(ref):
                dangerous.append(ref)
            continue
        if op.name == "REDUCE":
            reduce_count += 1

    return {
        "global_refs": sorted(set(globals_seen)),
        "dangerous_refs": sorted(set(dangerous)),
        "opcode_counts": op_counts,
        "reduce_count": reduce_count,
    }


def scan_repo(repo: Path) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    idx = 1
    for path in sorted(p for p in repo.rglob("*") if p.is_file() and p.suffix.lower() in PICKLE_SUFFIXES):
        rel = str(path.relative_to(repo))
        member_results = []
        dangerous_refs: List[str] = []
        try:
            for member, data in _pickle_members(path):
                result = _scan_pickle_bytes(data)
                dangerous_refs.extend(result["dangerous_refs"])
                member_results.append({
                    "member": member,
                    "global_refs": result["global_refs"][:200],
                    "dangerous_refs": result["dangerous_refs"],
                    "reduce_count": result["reduce_count"],
                    "opcode_counts": result["opcode_counts"],
                })
        except Exception as exc:
            nodes.append(
                _node(
                    idx,
                    "pickle_static_probe_error",
                    "medium",
                    "Pickle static probe could not parse this artifact.",
                    path=rel,
                    error=repr(exc),
                )
            )
            idx += 1
            continue

        if dangerous_refs:
            nodes.append(
                _node(
                    idx,
                    "pickle_dangerous_global_ref",
                    "high",
                    "Pickle opcode stream references callable names associated with execution, network, or destructive filesystem behavior.",
                    path=rel,
                    dangerous_refs=sorted(set(dangerous_refs)),
                    members=member_results,
                )
            )
        else:
            nodes.append(
                _node(
                    idx,
                    "pickle_global_refs_observed",
                    "info",
                    "Pickle opcode stream was inspected without execution; no configured dangerous global references were found.",
                    path=rel,
                    members=member_results,
                )
            )
        idx += 1
    return nodes


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect pickle opcodes without loading the artifact")
    parser.add_argument("--repo", default="/workspace/models/model")
    parser.add_argument("--out", default="/workspace/out/evidence/pickle_static_evidence.jsonl")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    nodes = scan_repo(Path(args.repo))
    with out.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
