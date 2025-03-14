# monitor/main.py
import argparse
from .utils import run_strace

def main():
    parser = argparse.ArgumentParser(description="Strace-based Python Monitoring Tool")
    parser.add_argument("--script", type=str, required=True, help="Path to the target Python script")
    parser.add_argument("--logfile", type=str, default="trace.log", help="Path to save the log file")
    parser.add_argument("--terminate-on-high-risk", action="store_true",
                        help="Terminate immediately on detecting high-risk behavior")
    parser.add_argument("--mode", type=str, choices=["once", "realtime"], default="once",
                        help="Monitoring mode: 'once' for one-time monitoring or 'realtime' for realtime monitoring")
    parser.add_argument("--audit", action="store_true",
                        help="Enable Python internal audit hook to monitor internal operations")
    args = parser.parse_args()

    if args.audit:
        from .audit import register_audit_hook
        register_audit_hook()
        print("Python audit hook registered.")

    run_strace(args.script, args.logfile, args.terminate_on_high_risk, args.mode)

if __name__ == "__main__":
    main()
