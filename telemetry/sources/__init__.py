"""
telemetry/sources/
------------------
TelemetrySource adapters — one per collector format. Each turns a raw
collector artifact into the canonical NormalizedEvent frame (telemetry/schema.py)
so Tier 1 scoring never sees a collector-specific shape.

Two adapters (osquery + auditd) make the source seam real rather than asserted.
"""
from telemetry.sources.base import TelemetrySource, IngestResult
from telemetry.sources.osquery import OsquerySource
from telemetry.sources.auditd import AuditdSource

# Registry keyed by the name used in harness.yaml telemetry.event_source.
SOURCE_REGISTRY: dict[str, type[TelemetrySource]] = {
    OsquerySource.name: OsquerySource,
    AuditdSource.name: AuditdSource,
}

__all__ = [
    "TelemetrySource",
    "IngestResult",
    "OsquerySource",
    "AuditdSource",
    "SOURCE_REGISTRY",
]
