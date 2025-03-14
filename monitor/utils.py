# monitor/utils.py
"""
Utility functions for running strace, parsing logs, detecting risk behaviors,
and optionally registering a Python internal audit hook.
"""

import argparse
import subprocess
import re
import glob
import os
import signal
import sys
from .rules import RISK_RULES, MAX_SUBPROCESS_COUNT

def run_strace(script_path, log_file, terminate_on_high_risk, mode="once"):
    """
    Run strace to monitor the target Python script.
    In "once" mode, the script is run once and the log is parsed afterwards.
    In "realtime" mode, the script is monitored live.
    """
    strace_args = [
        "strace", "-ff", "-e", "trace:file,process,network",
        "-s", "1024", "-o", log_file, "python", script_path
    ]
    print(f"Monitoring: {script_path}, log file: {log_file}")
    
    if mode == "once":
        subprocess.run(strace_args)
        risks = parse_log(log_file, terminate_on_high_risk)
        print_results(risks)
    else:
        monitor_realtime(strace_args, log_file, terminate_on_high_risk)

def parse_log(log_file, terminate_on_high_risk):
    """
    Parse all strace log files and detect potential risks.
    """
    risks = {"high": [], "medium": [], "low": []}
    counters = {"file_ops": 0, "net_ops": 0, "subprocess_count": 0}

    log_files = glob.glob(log_file + "*")
    for f in log_files:
        with open(f) as fp:
            for line in fp:
                detect_risks(line.strip(), risks, counters, terminate_on_high_risk)

    if counters["subprocess_count"] > MAX_SUBPROCESS_COUNT:
        risks["high"].append(f"⚠️ Too many subprocesses detected: {counters['subprocess_count']}, monitoring terminated")
    return risks

def detect_risks(line, risks, counters, terminate_on_high_risk):
    """
    Check the given log line against each risk rule.
    If a match is found for a high risk and termination is enabled, exit immediately.
    """
    for level, rules in RISK_RULES.items():
        for rule in rules:
            if len(rule) == 3:
                pattern, message, threshold = rule
                if re.search(pattern, line):
                    risks[level].append(f"{message}: {line}")
                    if level == "high" and terminate_on_high_risk:
                        print(f"\n🚨 High-risk behavior detected: {message}")
                        print("⚠️ Terminating monitoring!")
                        sys.exit(1)
            else:
                pattern, message = rule
                if re.search(pattern, line):
                    risks[level].append(f"{message}: {line}")
                    if level == "high" and terminate_on_high_risk:
                        print(f"\n🚨 High-risk behavior detected: {message}")
                        print("⚠️ Terminating monitoring!")
                        sys.exit(1)
    if "execve(" in line:
        counters["subprocess_count"] += 1
        if counters["subprocess_count"] > MAX_SUBPROCESS_COUNT:
            print(f"⚠️ Subprocess count exceeds {MAX_SUBPROCESS_COUNT}, terminating monitoring!")
            sys.exit(1)

def monitor_realtime(strace_args, log_file, terminate_on_high_risk):
    """
    Run strace in realtime monitoring mode.
    """
    f_log = open(log_file, "w") if log_file else None
    print("Realtime monitoring...")
    process = subprocess.Popen(strace_args, stderr=subprocess.PIPE, text=True)
    counters = {"file_ops": 0, "net_ops": 0, "subprocess_count": 0}

    for line in process.stderr:
        line = line.strip()
        if f_log:
            f_log.write(line + "\n")
        detect_risks(line, {"high": [], "medium": [], "low": []}, counters, terminate_on_high_risk)
        if counters["subprocess_count"] > MAX_SUBPROCESS_COUNT:
            print(f"⚠️ Subprocess count exceeds {counters['subprocess_count']}, terminating process {process.pid}!")
            process.terminate()
            break

    process.wait()
    if f_log:
        f_log.close()

def print_results(risks):
    """
    Print the detected risks in a formatted manner.
    """
    for level, label in [("high", "🚨 High Risk"), ("medium", "⚠️ Medium Risk"), ("low", "ℹ️ Low Risk")]:
        print(f"\n=== {label} ===")
        if risks[level]:
            for event in risks[level]:
                print(event)
        else:
            print("None")
