"""
harness/orchestrator.py
-----------------------
Main harness entry point.

Usage:
    python -m harness.orchestrator [--raw-telemetry local|s3] [--once] [--cve CVE-ID]

Flags:
    --raw-telemetry  Override telemetry source (local | s3). Default: from harness.yaml.
    --once           Run a single cycle then exit (useful for CI / testing).
    --cve            Only investigate this specific CVE (default: all enabled targets).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from harness.config import HarnessConfig, CVETarget, load_config, resolve_telemetry_source
from harness.ingester import InventoryIngester
from observability.logger import get_structured_logger
from observability.metrics import HarnessMetrics

# ------------------------------------------------------------------
# Logging setup
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("openclaw.orchestrator")


# ------------------------------------------------------------------
# Single CVE investigation cycle
# ------------------------------------------------------------------
def investigate_target(
    target: CVETarget,
    cfg: HarnessConfig,
    raw_telemetry: str,
    ingester: InventoryIngester,
    structured_log,
    metrics: HarnessMetrics,
) -> None:
    if not target.enabled:
        logger.info("Target %s is disabled, skipping.", target.cve_id)
        return

    logger.info("=== Starting investigation: %s ===", target.cve_id)
    structured_log.info(
        "run_start",
        cve_id=target.cve_id,
        raw_telemetry=raw_telemetry,
    )

    # 1. Query inventory for vulnerable workloads
    workloads_df = ingester.get_vulnerable_workloads(target.trigger_assessments)
    n_workloads = len(workloads_df)
    logger.info("Found %d workload(s) to investigate for %s", n_workloads, target.cve_id)
    metrics.record_workloads_matched(target.cve_id, n_workloads)

    if n_workloads == 0:
        logger.info("No vulnerable workloads found for %s. Skipping.", target.cve_id)
        return

    # 2. Dispatch Python script
    import importlib
    try:
        dp = importlib.import_module(target.script)
    except ModuleNotFoundError:
        logger.error("Data plane script %s not found.", target.script)
        return

    result = dp.run_investigation(
        cve_id=target.cve_id,
        workload_id="ALL",
        raw_telemetry=raw_telemetry,
        output_dir=cfg.output.findings_dir,
        local_events_path=cfg.telemetry.local_json_path,
        local_inventory_path=cfg.inventory.csv_path,
        s3_manifest_path=cfg.telemetry.s3_manifest_path,
        lookback_hours=cfg.telemetry.lookback_hours,
        openclaw_bin=cfg.agent.openclaw_bin,
        signals_file=target.signals_file,
    )

    status = result.get("status", "error")
    elapsed_ms = result.get("elapsed_ms", 0)
    metrics.record_run(target.cve_id, status, elapsed_ms)

    structured_log.info(
        "run_complete",
        cve_id=target.cve_id,
        status=status,
        elapsed_ms=elapsed_ms,
        run_id=result.get("run_id"),
        output_notebook=result.get("output_notebook"),
    )

    if status == "error":
        logger.error("Investigation FAILED for %s: %s", target.cve_id, result.get("error"))
    else:
        logger.info(
            "Investigation complete for %s | run_id=%s elapsed=%dms",
            target.cve_id, result.get("run_id"), elapsed_ms,
        )


# ------------------------------------------------------------------
# Run cycle: iterate all enabled targets
# ------------------------------------------------------------------
def run_cycle(
    cfg: HarnessConfig,
    raw_telemetry: str,
    ingester: InventoryIngester,
    structured_log,
    metrics: HarnessMetrics,
    cve_filter: Optional[str] = None,
) -> None:
    targets = [
        t for t in cfg.targets
        if t.enabled and (cve_filter is None or t.cve_id == cve_filter)
    ]
    if not targets:
        logger.warning("No enabled targets found (cve_filter=%s).", cve_filter)
        return

    max_workers = min(cfg.orchestrator.max_concurrent_runs, len(targets))
    if max_workers <= 1:
        for target in targets:
            investigate_target(target, cfg, raw_telemetry, ingester, structured_log, metrics)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(
                    investigate_target,
                    target, cfg, raw_telemetry, ingester, structured_log, metrics,
                ): target.cve_id
                for target in targets
            }
            for future in concurrent.futures.as_completed(futures):
                cve = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    logger.error("Unhandled error in investigation of %s: %s", cve, exc)


# ------------------------------------------------------------------
# CLI entrypoint
# ------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenClaw Vulnerability Investigation Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--raw-telemetry",
        choices=["local", "s3"],
        default=None,
        help="Telemetry source: 'local' (events.json) or 's3' (boto3 download via named profile). "
             "Overrides harness.yaml setting.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single investigation cycle then exit.",
    )
    parser.add_argument(
        "--cve",
        default=None,
        help="Investigate only this specific CVE (e.g. CVE-2026-31431).",
    )
    parser.add_argument(
        "--config",
        default="harness.yaml",
        help="Path to harness.yaml (default: ./harness.yaml).",
    )
    args = parser.parse_args()

    cfg = load_config(harness_yaml=args.config)
    raw_telemetry = resolve_telemetry_source(cfg, args.raw_telemetry)

    # Ensure output directories exist
    Path(cfg.output.findings_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.output.docs_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.observability.log_path).parent.mkdir(parents=True, exist_ok=True)
    Path("logs").mkdir(exist_ok=True)

    structured_log = get_structured_logger(cfg.observability.log_path)
    metrics = HarnessMetrics(port=cfg.observability.metrics_port)
    ingester = InventoryIngester(csv_path=cfg.inventory.csv_path)
    ingester.ingest()

    logger.info(
        "OpenClaw Harness starting | telemetry=%s interval=%ds",
        raw_telemetry, cfg.orchestrator.run_interval_seconds,
    )

    if args.once:
        run_cycle(cfg, raw_telemetry, ingester, structured_log, metrics, cve_filter=args.cve)
        return

    # Continuous loop
    while True:
        cycle_start = time.monotonic()
        try:
            run_cycle(cfg, raw_telemetry, ingester, structured_log, metrics, cve_filter=args.cve)
        except KeyboardInterrupt:
            logger.info("Interrupted. Shutting down.")
            break
        except Exception as exc:
            logger.error("Cycle error (continuing): %s", exc)

        elapsed = time.monotonic() - cycle_start
        sleep_for = max(0, cfg.orchestrator.run_interval_seconds - elapsed)
        logger.info("Cycle done in %.1fs. Next run in %.0fs.", elapsed, sleep_for)
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
