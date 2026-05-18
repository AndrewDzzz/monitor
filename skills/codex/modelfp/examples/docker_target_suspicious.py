"""Suspicious demo target for ModelFP testing.

This does not exfiltrate real data. It demonstrates events that ModelFP should
flag: shell execution and canary environment access.
"""
from __future__ import annotations

import os
import subprocess

print('Canary present:', 'MODELFP_CANARY_TOKEN' in os.environ)
subprocess.run(['/bin/sh', '-c', 'true'], check=False)
try:
    open('/root/.ssh/id_rsa', 'rb').read(1)
except Exception:
    pass
