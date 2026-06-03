#!/usr/bin/env python3
"""
OpenClaw - Threat Hunting Agent CLI

Dispatches to one of two framework implementations of the Tier 2 agent loop:
  - litellm-direct (default): scripts/openclaw_agent/        (raw LiteLLM loop)
  - strands:                  scripts/openclaw_agent_strands/ (Strands SDK)

Select via OPENCLAW_FRAMEWORK env var, or --framework CLI flag.

Both implementations satisfy the same contract: take a tier1.json + signals YAML
and return a verdict dict {verdict, confidence, reasoning_trace, recommended_action}.
The bench's `framework` axis in models.yaml flips this seam per run.
"""
import argparse
import sys
import json
import os
from pathlib import Path

# Ensure scripts/ is on sys.path so we can import either agent variant.
sys.path.insert(0, str(Path(__file__).parent))


def _load_agent(framework: str):
    """Import + instantiate the requested framework's agent class."""
    if framework == "litellm-direct":
        from openclaw_agent.agent import OpenClawAgent
        return OpenClawAgent()
    if framework == "strands":
        from openclaw_agent_strands.agent import OpenClawStrandsAgent
        return OpenClawStrandsAgent()
    raise ValueError(
        f"Unknown OPENCLAW_FRAMEWORK '{framework}'. "
        f"Supported: 'litellm-direct', 'strands'."
    )


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
    investigate_parser.add_argument(
        "--framework",
        default=os.getenv("OPENCLAW_FRAMEWORK", "litellm-direct"),
        choices=("litellm-direct", "strands"),
        help="Agent framework to use (default: env OPENCLAW_FRAMEWORK or litellm-direct).",
    )

    args = parser.parse_args()

    if args.command == "investigate":
        agent = _load_agent(args.framework)
        verdict_data = agent.run_investigation(
            cve_id=args.cve,
            workload_id=args.workload_id,
            tier1_path=args.tier1_results,
            signals_path=args.exploit_signals,
            telemetry_source=args.raw_telemetry,
        )

        with open(args.output_file, "w") as f:
            json.dump(verdict_data, f, indent=2)


if __name__ == "__main__":
    sys.exit(main())
