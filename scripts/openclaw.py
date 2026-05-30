#!/usr/bin/env python3
"""
OpenClaw - Threat Hunting Agent CLI
"""
import argparse
import sys
import json
import os
from pathlib import Path

# Ensure the scripts directory is in sys.path so we can import openclaw_agent
sys.path.insert(0, str(Path(__file__).parent))
from openclaw_agent.agent import OpenClawAgent

def main():
    parser = argparse.ArgumentParser(description="OpenClaw Threat Hunting Agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    investigate_parser = subparsers.add_parser("investigate")
    investigate_parser.add_argument("--cve", required=True)
    investigate_parser.add_argument("--workload-id", required=True)
    investigate_parser.add_argument("--tier1-results", required=True)
    investigate_parser.add_argument("--exploit-signals", required=True)
    investigate_parser.add_argument("--raw-telemetry", required=True)
    investigate_parser.add_argument("--output-json", action="store_true")
    investigate_parser.add_argument("--output-file", required=True)
    
    args = parser.parse_args()
    
    if args.command == "investigate":
        agent = OpenClawAgent()
        verdict_data = agent.run_investigation(
            cve_id=args.cve,
            workload_id=args.workload_id,
            tier1_path=args.tier1_results,
            signals_path=args.exploit_signals,
            telemetry_source=args.raw_telemetry
        )
        
        with open(args.output_file, 'w') as f:
            json.dump(verdict_data, f, indent=2)

if __name__ == "__main__":
    sys.exit(main())
