"""
telemetry/schema.py
-------------------
The canonical NormalizedEvent schema — the contract every TelemetrySource
adapter must produce, and the only event shape Tier 1 scoring depends on.

Defined once here (not re-derived per CVE). Tier 1 validates + coerces a
normalized frame through this module *before* scoring, which is what lets it
distinguish "behaviour absent" from "source blind" (CONTEXT.md).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

# Canonical columns the scoring layer reads. The mapping value is the logical
# dtype used for coercion ("int" columns are nullable floats in pandas because
# telemetry rows legitimately carry null pid/uid for non-process events).
NORMALIZED_COLUMNS: dict[str, str] = {
    "workload_id": "str",
    "ts": "int",
    "event_type": "str",
    "pid": "int",
    "ppid": "int",
    "uid": "int",
    "euid": "int",
    "socket_family": "int",
    "socket_protocol": "int",
    "process_name": "str",
    "cmdline": "str",
    "module_name": "str",
    "file_path": "str",
}

# A frame is unusable for scoring without these. Others may be absent (a source
# that never emits sockets simply has nulls there).
REQUIRED_COLUMNS: tuple[str, ...] = ("workload_id", "ts", "event_type")

# event_type values the signal queries branch on.
EVENT_TYPES = frozenset({"process", "socket", "file", "kernel_module"})

_NUMERIC_COLUMNS = tuple(c for c, t in NORMALIZED_COLUMNS.items() if t == "int")


@dataclass
class ValidationReport:
    """Outcome of validating a normalized frame.

    ok=False is the degrade-and-flag signal (decision 2.b): the caller drops
    the source and records `reason` in SourceCoverage.failed.
    """
    ok: bool
    source: str = ""
    missing_columns: list[str] = field(default_factory=list)
    reason: str | None = None


def validate(df: pd.DataFrame, source: str = "") -> ValidationReport:
    """Check a normalized frame against the schema's required columns."""
    if df is None:
        return ValidationReport(ok=False, source=source, reason="frame is None")
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        return ValidationReport(
            ok=False, source=source, missing_columns=missing,
            reason=f"missing required columns: {missing}",
        )
    return ValidationReport(ok=True, source=source)


def coerce_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce the integer-semantic columns to numeric (nulls -> NaN).

    Lifted out of data_plane/cve_2026_31431.py so every adapter normalizes
    numbers the same way before scoring."""
    out = df.copy()
    for col in _NUMERIC_COLUMNS:
        if col in out.columns:
            out[col] = pd.to_numeric(out[col], errors="coerce")
    return out
