"""
observability/traces.py
-----------------------
OpenTelemetry trace context helpers for the ThIOClaw harness.

Provides a context manager `investigation_span` that creates a root span
for each investigation run, with child spans for telemetry fetch,
notebook execution, and output writing.

Falls back gracefully if opentelemetry is not installed.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Dict, Generator, Optional

logger = logging.getLogger(__name__)

_tracer = None
_enabled = False


def init_tracing(
    service_name: str = "thioclaw-harness",
    endpoint: Optional[str] = None,
) -> None:
    """
    Initialise OTel tracing.
    If endpoint is None, traces are exported to stdout (console exporter).
    If endpoint is set (e.g. 'http://localhost:4317'), uses OTLP gRPC exporter.
    """
    global _tracer, _enabled
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource(attributes={SERVICE_NAME: service_name})
        provider = TracerProvider(resource=resource)

        if endpoint:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            exporter = OTLPSpanExporter(endpoint=endpoint)
        else:
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter
            exporter = ConsoleSpanExporter()

        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("thioclaw.harness", "1.0.0")
        _enabled = True
        logger.info("OTel tracing initialised (endpoint=%s)", endpoint or "console")

    except ImportError:
        logger.warning(
            "opentelemetry packages not found. Tracing disabled. "
            "Install: pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp"
        )
    except Exception as exc:
        logger.warning("Failed to initialise OTel tracing (non-fatal): %s", exc)


@contextmanager
def investigation_span(
    cve_id: str,
    run_id: str,
    raw_telemetry: str,
) -> Generator[Any, None, None]:
    """Root span for a full CVE investigation run."""
    if not _enabled or _tracer is None:
        yield None
        return

    from opentelemetry import trace

    with _tracer.start_as_current_span("thioclaw.run") as span:
        span.set_attribute("cve_id", cve_id)
        span.set_attribute("run_id", run_id)
        span.set_attribute("raw_telemetry", raw_telemetry)
        yield span


@contextmanager
def child_span(name: str, attributes: Optional[Dict[str, Any]] = None) -> Generator[Any, None, None]:
    """Generic child span — use inside an investigation_span context."""
    if not _enabled or _tracer is None:
        yield None
        return

    with _tracer.start_as_current_span(name) as span:
        for k, v in (attributes or {}).items():
            span.set_attribute(k, str(v))
        yield span
