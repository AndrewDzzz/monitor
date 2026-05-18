"""Benign ModelFP demo target.
This simulates a harmless model load/inference run without shell/network/secret access.
"""
import json
import pathlib

print("[demo] loading benign model metadata")
model_dir = pathlib.Path("/workspace/model")
config = model_dir / "config.json"
if config.exists():
    print("[demo] config keys:", sorted(json.loads(config.read_text()).keys()))
print("[demo] inference result: ok")
