# monitor/audit.py
"""
Enhanced Python Audit Hook Module (Consolidated Version)

- Monitors sensitive operations such as dynamic code execution, file I/O, network calls,
  process injection, and unsafe global usage.
- Consolidates similar events into aggregated rules using regex to reduce redundancy.
- Also checks for unsafe global usage based on a configuration dictionary.
"""

import sys
import re
from typing import Tuple, List, Dict, Any

# ---------------------------
# Consolidated Audit Rules
# ---------------------------
# Dynamic code execution: catches exec, eval, compile, and __import__ usage.
DYNAMIC_CODE_PATTERN = r'^(exec|eval|compile|__import__)$'
DYNAMIC_CODE_DESC = "Dynamic code execution detected"

# Subprocess execution: catches os.system and subprocess.Popen calls.
SUBPROCESS_PATTERN = r'^(os\.system|subprocess\.Popen)$'
SUBPROCESS_DESC = "Subprocess execution detected"

# Sensitive file access: catches calls to open or os.open that target critical paths.
FILE_ACCESS_PATTERN = r'^(open|os\.open)$'
FILE_ACCESS_ARGS_PATTERN = r'path=.*?(/etc/(passwd|shadow|sudoers)|/root/|\.ssh/)'
FILE_ACCESS_DESC = "Sensitive file access detected"

# Network connection: monitor common network connection calls.
NETWORK_PATTERN = r'^(socket\.connect|socket\.create_connection)$'
NETWORK_DESC = "Network connection operation detected"

# Define the consolidated audit rules.
# Each rule is a tuple: (event regex, argument regex, risk level, description)
AUDIT_RULES: List[Tuple[str, str, str, str]] = [
    (DYNAMIC_CODE_PATTERN, r'.*', 'CRITICAL', DYNAMIC_CODE_DESC),
    (SUBPROCESS_PATTERN, r'.*', 'CRITICAL', SUBPROCESS_DESC),
    (FILE_ACCESS_PATTERN, FILE_ACCESS_ARGS_PATTERN, 'CRITICAL', FILE_ACCESS_DESC),
    (NETWORK_PATTERN, r'.*', 'CRITICAL', NETWORK_DESC),
]

# ---------------------------
# Unsafe Globals Configuration
# ---------------------------
# The keys represent risk levels; each maps to a dictionary of module names.
# For each module, either a list of function names or "*" indicates that any usage
# of that module's function is considered unsafe.
UNSAFE_GLOBALS: Dict[str, Dict[str, Any]] = {
    "CRITICAL": {
        "builtins": ["exec", "eval", "compile", "__import__", "open", "breakpoint"],
        "os": "*",
        "socket": "*",
        "subprocess": "*",
        "pickle": "*",
    },
    "HIGH": {
        "webbrowser": "*",
        "requests.api": "*",
    },
    "MEDIUM": {},
    "LOW": {},
}

def check_unsafe_globals(event: str, args: Tuple) -> None:
    """
    Check if the event and its arguments indicate unsafe global usage.
    If a match is found, print a warning message.
    """
    arg_str = ", ".join(str(a) for a in args)
    for level, modules in UNSAFE_GLOBALS.items():
        for mod, funcs in modules.items():
            if mod in event:
                if funcs == "*" or any(func in event for func in (funcs if isinstance(funcs, list) else [funcs])):
                    print(f"[AUDIT {level.upper()}] Unsafe global usage detected: Module '{mod}' in event '{event}', Args: {args}")

def audit_hook(event: str, args: Tuple):
    """
    Consolidated audit hook function that monitors sensitive internal events.
    It checks against both static audit rules and unsafe global usage.
    """
    # Check against audit rules
    for event_pattern, arg_pattern, risk, desc in AUDIT_RULES:
        if re.match(event_pattern, event):
            arg_str = ", ".join(str(a) for a in args)
            if re.search(arg_pattern, arg_str, re.IGNORECASE):
                print(f"[AUDIT {risk.upper()}] {desc} => Event: {event}, Args: {args}")
    # Check for unsafe globals usage
    check_unsafe_globals(event, args)

def register_audit_hook():
    """
    Register the audit hook and add a guard to prevent unauthorized modifications.
    """
    sys.addaudithook(audit_hook)
    
    def guard_audit_hook(event: str, args: Tuple):
        if event == 'sys.addaudithook' and 'monitor/audit.py' not in str(args):
            print("[AUDIT CRITICAL] Unauthorized audit hook modification detected!")
            raise RuntimeError("Security policy violation: Audit hook modification blocked")
    
    sys.addaudithook(guard_audit_hook)

if __name__ == '__main__':
    register_audit_hook()
    print("Enhanced Python audit hook activated!")
