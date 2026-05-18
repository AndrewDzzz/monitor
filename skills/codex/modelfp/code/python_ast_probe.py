"""Static Python/Lambda AST probe for model-hub repositories.

This probe parses Python source without importing or executing repository code.
It is intentionally conservative: imports are treated as context, while calls
to process, shell, network, dynamic execution, unsafe deserialization, and
destructive filesystem APIs become evidence nodes.
"""

from __future__ import annotations

import ast
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence
from urllib.parse import urlparse

DANGEROUS_CALLS = {
    "os.system": "critical",
    "os.popen": "high",
    "subprocess.Popen": "high",
    "subprocess.run": "high",
    "subprocess.call": "high",
    "subprocess.check_call": "high",
    "subprocess.check_output": "high",
    "socket.socket": "medium",
    "requests.get": "medium",
    "requests.post": "medium",
    "urllib.request.urlopen": "medium",
    "pickle.load": "high",
    "pickle.loads": "high",
    "marshal.loads": "high",
    "shutil.rmtree": "high",
    "eval": "high",
    "exec": "high",
    "compile": "medium",
    "__import__": "medium",
}

SENSITIVE_IMPORT_ROOTS = {
    "base64", "ctypes", "marshal", "os", "pickle", "requests", "shutil",
    "socket", "subprocess", "urllib",
}

HANDLER_NAMES = {"execute", "handler", "lambda_handler"}
LOG_EVENT_RE = re.compile(r"logger\.(?:debug|info|warning|error|exception)\([^\n]*\bevent\b", re.I)
PUBLIC_PYPI_HOSTS = {"pypi.org", "files.pythonhosted.org", "pypi.python.org"}


def _node(idx: int, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": f"PYAST{idx:04d}",
        "source": "python_ast_probe",
        "evidence_type": "static_code",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def _rel(repo: Path, path: Path) -> str:
    return path.relative_to(repo).as_posix()


def _iter_python_files(repo: Path, max_files: int) -> tuple[List[Path], bool]:
    files: List[Path] = []
    truncated = False
    for path in sorted(repo.rglob("*.py")):
        if any(part in {".git", ".cache", "__pycache__"} for part in path.relative_to(repo).parts):
            continue
        if len(files) >= max_files:
            truncated = True
            break
        files.append(path)
    return files, truncated


def _import_aliases(tree: ast.AST) -> tuple[Dict[str, str], List[str]]:
    aliases: Dict[str, str] = {}
    imports: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
                aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.append(module)
            for alias in node.names:
                if alias.name == "*":
                    continue
                full = f"{module}.{alias.name}" if module else alias.name
                aliases[alias.asname or alias.name] = full
    return aliases, sorted(set(x for x in imports if x))


def _call_name(func: ast.AST, aliases: Mapping[str, str]) -> str | None:
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute):
        parts: List[str] = []
        cur: ast.AST = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            root = aliases.get(cur.id, cur.id)
            parts.append(root)
            return ".".join(reversed(parts))
    return None


def _literal_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _string_arg(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _scan_python_file(repo: Path, path: Path, idx: int) -> tuple[List[Dict[str, Any]], int, Dict[str, Any]]:
    rel = _rel(repo, path)
    text = path.read_text(errors="ignore")
    nodes: List[Dict[str, Any]] = []
    report: Dict[str, Any] = {"path": rel, "imports": [], "calls": []}

    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        nodes.append(_node(idx, "python_syntax_error", "medium", "Python source could not be parsed by ast.parse.", path=rel, line_no=exc.lineno, detail=str(exc)))
        return nodes, idx + 1, report

    aliases, imports = _import_aliases(tree)
    report["imports"] = imports
    for imp in imports:
        root = imp.split(".", 1)[0]
        if root in SENSITIVE_IMPORT_ROOTS:
            nodes.append(_node(idx, "sensitive_python_import", "info", f"Python file imports security-sensitive module {imp}.", path=rel, import_name=imp))
            idx += 1

    calls: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call = _call_name(node.func, aliases)
            if not call:
                continue
            calls.append(call)
            severity = DANGEROUS_CALLS.get(call)
            if severity:
                nodes.append(_node(idx, "dangerous_python_call", severity, f"Python AST contains call to {call}.", path=rel, line_no=getattr(node, "lineno", None), call=call))
                idx += 1
            if call.startswith("subprocess."):
                for kw in node.keywords:
                    if kw.arg == "shell" and _literal_true(kw.value):
                        nodes.append(_node(idx, "subprocess_shell_true", "critical", "subprocess call uses shell=True.", path=rel, line_no=getattr(node, "lineno", None), call=call))
                        idx += 1
            if call in {"os.system", "os.popen"}:
                command = _string_arg(node.args[0]) if node.args else None
                if command:
                    nodes.append(_node(idx, "static_shell_command_literal", "high", "Python AST contains a literal shell command argument.", path=rel, line_no=getattr(node, "lineno", None), call=call, command=command[:500]))
                    idx += 1
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "config" and isinstance(node.value, ast.Dict):
                    cfg: Dict[str, Any] = {}
                    for key, value in zip(node.value.keys, node.value.values):
                        if isinstance(key, ast.Constant):
                            cfg[str(key.value)] = value.value if isinstance(value, ast.Constant) else ast.unparse(value)
                    if cfg.get("DEBUG") is True:
                        nodes.append(_node(idx, "flask_debug_enabled", "low", "Flask-style config dictionary sets DEBUG=True.", path=rel, line_no=getattr(node, "lineno", None)))
                        idx += 1
        elif isinstance(node, ast.FunctionDef) and node.name in HANDLER_NAMES:
            body = "\n".join(ast.get_source_segment(text, child) or "" for child in node.body)
            if LOG_EVENT_RE.search(body):
                nodes.append(_node(idx, "logs_lambda_event", "low", "Lambda-style handler logs the event object.", path=rel, line_no=getattr(node, "lineno", None), function=node.name))
                idx += 1

    report["calls"] = calls[:200]
    return nodes, idx, report


def _scan_package_indexes(repo: Path, idx: int) -> tuple[List[Dict[str, Any]], int]:
    nodes: List[Dict[str, Any]] = []
    for name in ("pyproject.toml", "poetry.toml", "pip.conf", "requirements.txt"):
        path = repo / name
        if not path.exists() or not path.is_file():
            continue
        text = path.read_text(errors="ignore")
        urls = sorted(set(re.findall(r"https?://[^\s\"')]+", text)))
        for url in urls:
            host = urlparse(url).hostname or ""
            if host and host not in PUBLIC_PYPI_HOSTS:
                nodes.append(_node(idx, "private_or_external_package_index_configured", "medium", "Dependency configuration references a non-default package/index URL.", path=name, url=url[:500], host=host))
                idx += 1
    return nodes, idx


def scan_repo(repo: Path, max_files: int = 5000) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    files, truncated = _iter_python_files(repo, max_files)
    nodes: List[Dict[str, Any]] = []
    idx = 1
    reports: List[Dict[str, Any]] = []
    for path in files:
        found, idx, report = _scan_python_file(repo, path, idx)
        nodes.extend(found)
        reports.append(report)
    package_nodes, idx = _scan_package_indexes(repo, idx)
    nodes.extend(package_nodes)
    nodes.append(_node(idx, "python_ast_summary", "info", "Python AST static scan completed without executing repository code.", python_file_count=len(files), truncated=truncated, files=[_rel(repo, p) for p in files[:500]]))
    report = {
        "schema": "modelfp.python_ast_report.v1",
        "generated_at_unix": time.time(),
        "repo": str(repo),
        "python_file_count": len(files),
        "truncated": truncated,
        "reports": reports,
        "finding_count": len(nodes),
    }
    return nodes, report


def write_jsonl(path: Path, nodes: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Run static Python/Lambda AST checks without importing repository code")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out", default="/workspace/out/evidence/python_ast_evidence.jsonl")
    parser.add_argument("--raw-report", default=None)
    parser.add_argument("--max-files", type=int, default=5000)
    args = parser.parse_args()

    nodes, report = scan_repo(Path(args.repo), max_files=args.max_files)
    write_jsonl(Path(args.out), nodes)
    if args.raw_report:
        raw = Path(args.raw_report)
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
