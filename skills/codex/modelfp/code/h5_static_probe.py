"""Static HDF5/Keras artifact probe for ModelFP.

This complements ModelScan by recording whether .h5 artifacts expose a Keras
model_config and whether that config contains Lambda layers. It does not load
or execute the model.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _node(idx: int, finding: str, severity: str, meaning: str, **extra: Any) -> Dict[str, Any]:
    return {
        "id": f"H5{idx:04d}",
        "source": "h5_static_probe",
        "evidence_type": "static_artifact",
        "finding": finding,
        "severity": severity,
        "meaning": meaning,
        "time": time.time(),
        **extra,
    }


def _json_loads_maybe(value: Any) -> Any:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if not isinstance(value, str):
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _walk_json(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def _has_lambda_layer(config: Any) -> bool:
    for item in _walk_json(config):
        if isinstance(item, dict) and item.get("class_name") == "Lambda":
            return True
    return False


def scan_h5(repo: Path) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    idx = 1
    try:
        import h5py  # type: ignore
    except Exception as exc:
        return [
            _node(
                idx,
                "h5_probe_dependency_missing",
                "medium",
                "h5py is unavailable, so HDF5/Keras static probing could not run.",
                error=repr(exc),
            )
        ]

    for path in sorted(repo.rglob("*.h5")):
        rel = str(path.relative_to(repo))
        try:
            with h5py.File(path, "r") as h5:
                attr_names = sorted(str(k) for k in h5.attrs.keys())
                model_config = _json_loads_maybe(h5.attrs.get("model_config"))
                if model_config is None:
                    nodes.append(
                        _node(
                            idx,
                            "h5_model_config_missing",
                            "info",
                            "HDF5 artifact does not expose a Keras model_config attribute for Lambda-layer inspection.",
                            path=rel,
                            attrs=attr_names,
                        )
                    )
                    idx += 1
                    continue
                if _has_lambda_layer(model_config):
                    nodes.append(
                        _node(
                            idx,
                            "h5_lambda_layer_present",
                            "high",
                            "HDF5/Keras model_config contains a Lambda layer, which can embed executable Python semantics.",
                            path=rel,
                            attrs=attr_names,
                        )
                    )
                else:
                    nodes.append(
                        _node(
                            idx,
                            "h5_model_config_no_lambda",
                            "info",
                            "HDF5/Keras model_config was parsed and no Lambda layer was found.",
                            path=rel,
                            attrs=attr_names,
                        )
                    )
                idx += 1
        except Exception as exc:
            nodes.append(
                _node(
                    idx,
                    "h5_static_probe_error",
                    "medium",
                    "HDF5 static probe could not inspect this file.",
                    path=rel,
                    error=repr(exc),
                )
            )
            idx += 1
    return nodes


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe HDF5/Keras model artifacts without loading them")
    parser.add_argument("--repo", default="/workspace/models/model")
    parser.add_argument("--out", default="/workspace/out/evidence/h5_static_evidence.jsonl")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    nodes = scan_h5(Path(args.repo))
    with out.open("w", encoding="utf-8") as fp:
        for node in nodes:
            fp.write(json.dumps(node, ensure_ascii=False) + "\n")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
