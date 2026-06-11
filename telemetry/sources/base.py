"""
telemetry/sources/base.py
-------------------------
The TelemetrySource seam: load a raw collector artifact, normalize it into the
NormalizedEvent schema, scope it to the workload + lookback window, coerce
numerics, and validate.

ingest() never raises — a load/parse failure becomes an ok=False IngestResult
(decision 2.b: degrade-and-flag). Tier 1 records the failure in
SourceCoverage.failed and continues on the remaining sources.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pandas as pd

from telemetry import schema
from telemetry.schema import ValidationReport


@dataclass
class IngestResult:
    """What one source produced this run."""
    source: str
    frame: pd.DataFrame
    report: ValidationReport

    @property
    def ok(self) -> bool:
        # Schema-valid. An empty frame after scoping is fine (the workload
        # simply had no events) — load/parse failures are caught upstream and
        # surface as report.ok == False.
        return self.report.ok


def scope_frame(
    df: pd.DataFrame,
    workload_id: str,
    cutoff_ts: Optional[float],
) -> pd.DataFrame:
    """Filter to one workload (unless 'ALL') and to events at/after cutoff_ts."""
    if df.empty:
        return df
    if workload_id and workload_id != "ALL" and "workload_id" in df.columns:
        df = df[df["workload_id"] == workload_id]
    if cutoff_ts is not None and "ts" in df.columns:
        df = df[pd.to_numeric(df["ts"], errors="coerce") >= cutoff_ts]
    return df


class TelemetrySource:
    """Base adapter. Subclasses implement load() + normalize(); the ingest()
    template handles scoping, coercion, validation, and failure capture."""

    name: str = "base"

    def __init__(self, workload_id_default: str = "") -> None:
        # Used by sources whose raw format carries no workload_id (auditd
        # snapshots are per-host); stamped onto every row at normalize time.
        self.workload_id_default = workload_id_default

    # --- subclass hooks ---------------------------------------------------
    def load(self, path: str):
        raise NotImplementedError

    def normalize(self, raw) -> pd.DataFrame:
        raise NotImplementedError

    # --- template ---------------------------------------------------------
    def ingest(
        self,
        path: str,
        workload_id: str = "ALL",
        cutoff_ts: Optional[float] = None,
    ) -> IngestResult:
        try:
            raw = self.load(path)
            df = self.normalize(raw)
        except FileNotFoundError as exc:
            return IngestResult(self.name, pd.DataFrame(),
                                ValidationReport(False, self.name, reason=f"not found: {exc}"))
        except Exception as exc:  # parse / shape failure -> degrade-and-flag
            return IngestResult(self.name, pd.DataFrame(),
                                ValidationReport(False, self.name, reason=f"{type(exc).__name__}: {exc}"))

        if df is None or df.empty:
            return IngestResult(self.name, pd.DataFrame(),
                                ValidationReport(False, self.name, reason="no events after normalize"))

        df = scope_frame(df, workload_id, cutoff_ts)
        df = schema.coerce_numeric(df)
        report = schema.validate(df, self.name)
        return IngestResult(self.name, df, report)
