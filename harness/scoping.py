"""
harness/scoping.py
------------------
Resolve which workloads are in scope for an investigation.

Grounded mode (today): trigger_assessments from the CVE target's YAML
selects rows from the inventory whose `assessment` column matches.

Hypothesis mode (designed; not yet implemented): an inline
vulnerability_context derives the equivalent criteria from inventory
attributes (kernel range, distro, config) without a pre-existing
assessment list.

Extracted from harness/orchestrator.py so the hypothesis-mode resolver
can land in one named place instead of being scattered.
"""
from __future__ import annotations

import pandas as pd

from harness.ingester import InventoryIngester


def determine_affected_workloads(
    *,
    ingester: InventoryIngester,
    trigger_assessments: list[str],
    skip_assessments: list[str] | None = None,
    vulnerability_context: dict | None = None,
) -> pd.DataFrame:
    """Return the inventory rows in scope for this investigation.

    Grounded mode honors trigger_assessments directly; skip_assessments is
    reserved for a future filter step (the ingester does not yet consume
    it). Hypothesis-mode scoping via vulnerability_context is designed but
    not yet implemented.
    """
    if vulnerability_context is not None and not trigger_assessments:
        raise NotImplementedError(
            "Hypothesis-mode scoping (vulnerability_context without "
            "trigger_assessments) is designed but not yet implemented."
        )
    return ingester.get_vulnerable_workloads(trigger_assessments)
