#!/usr/bin/env python3
"""
ThIOClaw — Threat Hunting Agent CLI

Dispatches to one of two framework implementations of the Tier 2 agent loop:
  - litellm-direct (default): scripts/thioclaw_agent/        (raw LiteLLM loop)
  - strands:                  scripts/thioclaw_agent_strands/ (Strands SDK)

Select via THIOCLAW_FRAMEWORK env var, or --framework CLI flag.
Legacy OPENCLAW_FRAMEWORK is honored with a one-release deprecation warning.

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


def _framework_from_env() -> str:
    """Read THIOCLAW_FRAMEWORK with one-release fallback to OPENCLAW_FRAMEWORK."""
    val = os.getenv("THIOCLAW_FRAMEWORK")
    if val:
        return val
    legacy = os.getenv("OPENCLAW_FRAMEWORK")
    if legacy:
        print(
            "[ThIOClaw] DEPRECATED: env var OPENCLAW_FRAMEWORK is deprecated; "
            "use THIOCLAW_FRAMEWORK. Falling back for this release.",
            file=sys.stderr,
        )
        return legacy
    return "litellm-direct"


def _load_agent(framework: str):
    """Import + instantiate the requested framework's agent class."""
    if framework == "litellm-direct":
        from thioclaw_agent.agent import ThIOClawAgent
        return ThIOClawAgent()
    if framework == "strands":
        from thioclaw_agent_strands.agent import ThIOClawStrandsAgent
        return ThIOClawStrandsAgent()
    raise ValueError(
        f"Unknown THIOCLAW_FRAMEWORK '{framework}'. "
        f"Supported: 'litellm-direct', 'strands'."
    )


def main():
    parser = argparse.ArgumentParser(description="ThIOClaw Threat Hunting Agent")
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
        default=_framework_from_env(),
        choices=("litellm-direct", "strands"),
        help="Agent framework to use (default: env THIOCLAW_FRAMEWORK or litellm-direct).",
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
