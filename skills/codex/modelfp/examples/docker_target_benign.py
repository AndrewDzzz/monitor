"""Benign demo target for ModelFP testing."""
from __future__ import annotations

from pathlib import Path
print('Files in model repo:', [p.name for p in Path('/workspace/models/model').glob('*')][:20])
