"""
telemetry/sources/osquery.py
----------------------------
osquery adapter. The sample telemetry (data/sample_events.json) is already in
the NormalizedEvent shape, so normalize() is close to a pass-through — but
keeping it behind the seam means a future osquery schema drift is one adapter
edit, not a change scattered through the data plane.
"""
from __future__ import annotations

import json

import pandas as pd

from telemetry.sources.base import TelemetrySource


class OsquerySource(TelemetrySource):
    name = "osquery"

    def load(self, path: str):
        with open(path) as f:
            return json.load(f)

    def normalize(self, raw) -> pd.DataFrame:
        # osquery export is already row-per-event in canonical column names.
        return pd.DataFrame(raw)
