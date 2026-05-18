"""Controlled single-artifact pickle runtime target.

This script intentionally unpickles exactly one artifact. It must only be run
inside the Docker runtime wrapper with network disabled, read-only repository
mounts, tmpfs /tmp, and strace/Python audit hooks enabled.
"""

from __future__ import annotations

import argparse
import json
import pickle
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Controlled runtime detonation for one pickle artifact")
    parser.add_argument("--artifact", required=True, help="Pickle artifact path inside the container")
    parser.add_argument("--out", default="/workspace/out/pickle_runtime_observations.json")
    parser.add_argument("--marker", default="/tmp/hack", help="Marker path to observe common PoC payloads")
    args = parser.parse_args()

    artifact = Path(args.artifact)
    marker = Path(args.marker)
    rec = {
        "schema": "modelfp.pickle_runtime_observation.v1",
        "artifact": str(artifact),
        "artifact_name": artifact.name,
        "marker": str(marker),
        "before_marker_exists": marker.exists(),
        "started_at_unix": time.time(),
    }
    print(f"[ModelFP pickle runtime] loading {artifact}", flush=True)
    print(f"[ModelFP pickle runtime] marker_before={rec['before_marker_exists']} marker={marker}", flush=True)
    try:
        with artifact.open("rb") as fp:
            value = pickle.load(fp)
        rec["status"] = "ok"
        rec["result_type"] = type(value).__name__
        rec["result_repr"] = repr(value)[:1000]
        print(f"[ModelFP pickle runtime] result_type={rec['result_type']} result={rec['result_repr']}", flush=True)
    except BaseException as exc:
        rec["status"] = "error"
        rec["error_type"] = type(exc).__name__
        rec["error"] = repr(exc)
        print(f"[ModelFP pickle runtime] error_type={type(exc).__name__} error={exc!r}", flush=True)
    finally:
        rec["after_marker_exists"] = marker.exists()
        rec["finished_at_unix"] = time.time()
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[ModelFP pickle runtime] marker_after={rec['after_marker_exists']}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
