# monitor
A lightweight monitoring tool that leverages OS-level strace alongside Python audit hooks to detect sensitive operations during ML model execution.

## Features

- **Sensitive File Access Detection:**  
  Monitors access to critical system configuration files and user credential files.

- **Network Monitoring:**  
  Flags any network-related system calls as high risk.

- **Dynamic Code Execution Detection:**  
  Detects dangerous internal operations such as exec, eval, pickle.load, and more.

- **Realtime & One‑time Monitoring:**  
  Run the tool continuously (realtime) or just once to analyze a script’s execution.

- **Immediate Termination Option:**  
  Automatically terminates the monitored process when high‑risk behavior is detected (configurable via a command‑line flag).

- **Python Internal Audit Hook (Optional):**  
  When enabled, registers an audit hook to catch sensitive Python operations at the interpreter level.

## Directory Structure

- **monitor/__init__.py:** Marks the directory as a Python package.
- **monitor/rules.py:** Contains risk rules and constants.
- **monitor/audit.py:** Implements the internal audit hook for Python-level monitoring.
- **monitor/utils.py:** Provides utility functions for running strace, parsing logs, and detecting risk events.
- **monitor/main.py:** The main entry point for the tool.
- **README.md:** This file.

## Requirements

- **Operating System:** Linux (the tool uses `strace`)
- **Python Version:** 3.8 or later
- **Dependencies:**  
  - `strace` must be installed on your system.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/your-ml-runtime-monitoring-tool.git
    cd your-ml-runtime-monitoring-tool
    ```

2. (Optional) Create and activate a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

## Usage

### One-time Monitoring

Run your ML script once and then parse the log:
```bash
python -m monitor.main --script /path/to/your_ml_script.py --logfile /path/to/trace.log --mode once
```

### Realtime Monitoring

Continuously monitor your ML script:
```bash
python -m monitor.main --script /path/to/your_ml_script.py --logfile /path/to/trace.log --mode realtime
```

### Immediate Termination on High Risk

To immediately terminate monitoring upon detecting a high‑risk event:
```bash
python -m monitor.main --script /path/to/your_ml_script.py --logfile /path/to/trace.log --terminate-on-high-risk
```

### Enable Python Internal Audit Hook

To monitor internal Python operations (e.g., dynamic code execution) with the audit hook:
```bash
python -m monitor.main --script /path/to/your_ml_script.py --logfile /path/to/trace.log --audit
```

## Disclaimer

This tool is a basic, rule-based monitoring solution for ML runtimes and is intended for demonstration and educational purposes only. It should not replace a comprehensive security audit or intrusion detection system. Please customize the risk rules as needed for your environment and adhere to best security practices.

**[IMPORTANT]** It is still under contrustion




