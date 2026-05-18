"""Compatibility wrapper for the current ModelFP Docker runner.

The original package had an older experimental pipeline in this file. Keep this
entrypoint importable and executable, but delegate all supported behavior to the
maintained runner so documentation and scripts have one source of truth.
"""

from __future__ import annotations

from modelfp_docker_runner import main


if __name__ == "__main__":
    raise SystemExit(main())
