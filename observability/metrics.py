"""
observability/metrics.py
------------------------
OpenTelemetry metrics for the OpenClaw harness.
Exposes a Prometheus scrape endpoint on the configured port.

Metrics exported:
  openclaw_run_total              (counter)   cve_id, status
  openclaw_run_duration_ms        (histogram)  cve_id
  openclaw_workloads_matched      (gauge)      cve_id
  openclaw_findings_total         (counter)    cve_id, verdict
  openclaw_notebook_duration_ms   (histogram)  cve_id
  openclaw_notebook_errors_total  (counter)    cve_id
  openclaw_tier1_signals_matched  (counter)    cve_id, rule_id
  openclaw_telemetry_rows_loaded  (gauge)      source
  openclaw_docs_pages_generated   (counter)    cve_id
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)


class HarnessMetrics:
    """
    Wrapper around OpenTelemetry metrics instruments.
    Falls back gracefully if opentelemetry packages are not installed.
    """

    def __init__(self, port: int = 9090, service_name: str = "openclaw-harness"):
        self.port = port
        self.service_name = service_name
        self._enabled = False
        self._init_otel()

    def _init_otel(self) -> None:
        try:
            from opentelemetry import metrics as otel_metrics
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.resources import Resource, SERVICE_NAME
            from opentelemetry.exporter.prometheus import PrometheusMetricExporter
            from prometheus_client import start_http_server

            resource = Resource(attributes={SERVICE_NAME: self.service_name})
            exporter = PrometheusMetricExporter()
            reader = PeriodicExportingMetricReader(exporter, export_interval_millis=15_000)
            provider = MeterProvider(resource=resource, metric_readers=[reader])
            otel_metrics.set_meter_provider(provider)

            meter = otel_metrics.get_meter("openclaw.harness", "1.0.0")

            self._run_counter = meter.create_counter(
                "openclaw_run_total",
                description="Total agent investigation runs",
            )
            self._run_duration = meter.create_histogram(
                "openclaw_run_duration_ms",
                description="Investigation run duration in milliseconds",
                unit="ms",
            )
            self._workloads_gauge = meter.create_up_down_counter(
                "openclaw_workloads_matched",
                description="Workloads matched per CVE investigation",
            )
            self._findings_counter = meter.create_counter(
                "openclaw_findings_total",
                description="Total findings by verdict",
            )
            self._notebook_duration = meter.create_histogram(
                "openclaw_notebook_duration_ms",
                description="Notebook execution duration",
                unit="ms",
            )
            self._notebook_errors = meter.create_counter(
                "openclaw_notebook_errors_total",
                description="Notebook execution errors",
            )
            self._signals_counter = meter.create_counter(
                "openclaw_tier1_signals_matched",
                description="Tier 1 signal rule matches",
            )
            self._telemetry_rows = meter.create_up_down_counter(
                "openclaw_telemetry_rows_loaded",
                description="Telemetry event rows loaded",
            )
            self._docs_counter = meter.create_counter(
                "openclaw_docs_pages_generated",
                description="Documentation pages generated",
            )

            # Start Prometheus scrape endpoint
            start_http_server(self.port)
            logger.info("Prometheus metrics available at http://localhost:%d/metrics", self.port)
            self._enabled = True

        except ImportError:
            logger.warning(
                "opentelemetry/prometheus packages not found. Metrics disabled. "
                "Install: pip install opentelemetry-api opentelemetry-sdk "
                "opentelemetry-exporter-prometheus prometheus-client"
            )
        except Exception as exc:
            logger.warning("Failed to initialise OTel metrics (non-fatal): %s", exc)

    # ------------------------------------------------------------------
    # Public recording methods — all no-op if OTel is unavailable
    # ------------------------------------------------------------------

    def record_run(self, cve_id: str, status: str, elapsed_ms: int) -> None:
        if not self._enabled:
            return
        attrs = {"cve_id": cve_id, "status": status}
        self._run_counter.add(1, attrs)
        self._run_duration.record(elapsed_ms, {"cve_id": cve_id})

    def record_workloads_matched(self, cve_id: str, count: int) -> None:
        if not self._enabled:
            return
        self._workloads_gauge.add(count, {"cve_id": cve_id})

    def record_finding(self, cve_id: str, verdict: str) -> None:
        if not self._enabled:
            return
        self._findings_counter.add(1, {"cve_id": cve_id, "verdict": verdict})

    def record_notebook(self, cve_id: str, elapsed_ms: int, error: bool = False) -> None:
        if not self._enabled:
            return
        self._notebook_duration.record(elapsed_ms, {"cve_id": cve_id})
        if error:
            self._notebook_errors.add(1, {"cve_id": cve_id})

    def record_signal_match(self, cve_id: str, rule_id: str) -> None:
        if not self._enabled:
            return
        self._signals_counter.add(1, {"cve_id": cve_id, "rule_id": rule_id})

    def record_telemetry_rows(self, source: str, count: int) -> None:
        if not self._enabled:
            return
        self._telemetry_rows.add(count, {"source": source})

    def record_docs_page(self, cve_id: str) -> None:
        if not self._enabled:
            return
        self._docs_counter.add(1, {"cve_id": cve_id})
