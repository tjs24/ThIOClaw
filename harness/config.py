"""
harness/config.py
-----------------
Load and validate harness.yaml and targets.yaml.
Provides a typed Config dataclass accessible throughout the harness.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


@dataclass
class TelemetryConfig:
    local_json_path: str = "./data/events.json"
    local_auditd_path: str = "./data/sample_auditd.log"
    s3_manifest_path: str = "./data/s3_manifest.json"
    lookback_hours: int = 24
    lookback_anchor: str = "latest_event"  # "latest_event" (anchor window to data) | "now" (wall-clock)
    default_source: str = "local"  # "local" | "s3"
    event_source: str = "osquery"  # "osquery" | "auditd" | "both"


@dataclass
class InventoryConfig:
    csv_path: str = "./data/inventory.csv"
    refresh_interval_seconds: int = 60


@dataclass
class AWSConfig:
    profile_name: str = "default"


@dataclass
class AgentConfig:
    thioclaw_bin: str = "./scripts/thioclaw.py"
    timeout_seconds: int = 120


@dataclass
class OrchestratorConfig:
    run_interval_seconds: int = 300
    max_concurrent_runs: int = 4


@dataclass
class OutputConfig:
    findings_dir: str = "./findings"
    docs_dir: str = "./docs"
    yaml: bool = True
    markdown: bool = True


@dataclass
class ObservabilityConfig:
    log_path: str = "./logs/agent_runs.jsonl"
    metrics_port: int = 9090
    trace_endpoint: Optional[str] = None
    service_name: str = "thioclaw-harness"


@dataclass
class CVETarget:
    cve_id: str
    description: str
    script: str
    signals_file: str
    priority: str = "high"
    enabled: bool = True
    trigger_assessments: List[str] = field(default_factory=lambda: [
        "vulnerable_or_not_confirmed_fixed",
        "running_kernel_pkg_not_matched",
    ])
    skip_assessments: List[str] = field(default_factory=lambda: [
        "not_affected_ubuntu_26_04",
        "patched_kernel_pkg_exact_match",
    ])


@dataclass
class HarnessConfig:
    inventory: InventoryConfig = field(default_factory=InventoryConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    aws: AWSConfig = field(default_factory=AWSConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    observability: ObservabilityConfig = field(default_factory=ObservabilityConfig)
    targets: List[CVETarget] = field(default_factory=list)


def load_config(
    harness_yaml: str = "harness.yaml",
    targets_yaml: str = "targets.yaml",
) -> HarnessConfig:
    """Load and merge harness.yaml + targets.yaml into a HarnessConfig."""
    base_path = Path(harness_yaml)
    if not base_path.exists():
        raise FileNotFoundError(f"harness.yaml not found: {harness_yaml}")

    with open(harness_yaml) as f:
        raw = yaml.safe_load(f)

    cfg = HarnessConfig(
        inventory=InventoryConfig(**raw.get("inventory", {})),
        telemetry=TelemetryConfig(**raw.get("telemetry", {})),
        aws=AWSConfig(**raw.get("aws", {})),
        agent=AgentConfig(**raw.get("agent", {})),
        orchestrator=OrchestratorConfig(**raw.get("orchestrator", {})),
        output=OutputConfig(**raw.get("output", {})),
        observability=ObservabilityConfig(**raw.get("observability", {})),
    )

    targets_path = Path(targets_yaml)
    if targets_path.exists():
        with open(targets_yaml) as f:
            traw = yaml.safe_load(f)
        for t in traw.get("targets", []):
            cfg.targets.append(CVETarget(**t))

    return cfg


def resolve_telemetry_source(cfg: HarnessConfig, cli_override: Optional[str] = None) -> str:
    """
    Determine telemetry source:
      1. CLI --raw-telemetry flag (highest priority)
      2. harness.yaml telemetry.default_source
    Returns 'local' or 's3'.
    """
    src = cli_override or cfg.telemetry.default_source
    if src not in ("local", "s3"):
        raise ValueError(f"Invalid raw-telemetry source: {src!r}. Must be 'local' or 's3'.")
    return src
