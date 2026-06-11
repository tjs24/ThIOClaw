"""
harness/finding.py
------------------
The typed Tier 1 -> Tier 2 contract object (the "Finding").

Replaces the ad-hoc dict written inline by report_writer.write_tier1. One
module owns the whole seam between the deterministic Data Plane and the LLM
Control Plane: verdict, per-signal evidence + provenance, telemetry source
coverage, and the deterministic response plan.

The serialized form (Finding.to_dict -> findings/<run>_tier1.json) is the
cross-process contract the Tier 2 agent reads. See CONTEXT.md for vocabulary
(NormalizedEvent, SignalHit, detected_by/blind_sources, ResponsePlan).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 1

# Verdict vocabulary — shared with signals/<cve>.yaml verdict_logic and the
# Tier 2 submit_verdict enum.
VERDICT_EXPLOITED = "exploited"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_BENIGN = "benign"
VERDICT_INCONCLUSIVE = "inconclusive"

TIER_EXPLOITED = "exploited"
TIER_SUSPICIOUS = "suspicious"


# ---------------------------------------------------------------------------
# Per-signal record
# ---------------------------------------------------------------------------
@dataclass
class SignalHit:
    """One signal's outcome inside a Finding.

    detected_by / blind_sources come from per-source scoring (decision 1.a):
      - detected_by:   sources whose rows actually fired this signal.
      - blind_sources: sources in the signal's supported_sources that were not
                       loaded this run. Non-empty on a *non-fired* signal means
                       "we could not have seen it," not "it did not happen."
    """
    id: str
    weight: float
    tier: str
    fired: bool
    query: str = ""                                   # e.g. "Q3"; kept for traceability
    detected_by: list[str] = field(default_factory=list)
    blind_sources: list[str] = field(default_factory=list)
    evidence_rows: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "weight": self.weight,
            "tier": self.tier,
            "fired": self.fired,
            "query": self.query,
            "detected_by": self.detected_by,
            "blind_sources": self.blind_sources,
            "evidence_rows": self.evidence_rows,
        }


# ---------------------------------------------------------------------------
# Telemetry source coverage (filled by Tier 1 *before* scoring)
# ---------------------------------------------------------------------------
@dataclass
class SourceCoverage:
    """What Tier 1 could and could not see this run.

    failed entries (decision 2.b: degrade-and-flag) record a configured source
    that did not load, so a blind spot can never masquerade as a clean negative.
    """
    configured: list[str] = field(default_factory=list)
    loaded: list[str] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)          # [{"source","reason"}]
    visible_signals: dict[str, list[str]] = field(default_factory=dict)  # source -> [signal_id]

    def visible_anywhere(self) -> set[str]:
        """Signal ids visible to at least one loaded source."""
        seen: set[str] = set()
        for sigs in self.visible_signals.values():
            seen.update(sigs)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "loaded": self.loaded,
            "failed": self.failed,
            "visible_signals": self.visible_signals,
        }


# ---------------------------------------------------------------------------
# Response plan (B) — placeholder taxonomy, to be defined further. See CONTEXT.md.
# ---------------------------------------------------------------------------
BLAST_NONE, BLAST_LOW, BLAST_HIGH = "none", "low", "high"
REVERSIBLE, IRREVERSIBLE = "reversible", "irreversible"
APPROVAL_AUTO, APPROVAL_ANALYST, APPROVAL_TWO_PERSON = "auto", "analyst", "two_person"


@dataclass
class ResponseAction:
    """A candidate response action. Tier 2 selects + justifies; HITL gates the
    irreversible ones. The action *set* below is a placeholder — the real
    taxonomy is deferred (CONTEXT.md: ResponsePlan)."""
    id: str
    rank: int
    blast_radius: str
    reversibility: str
    required_approval: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rank": self.rank,
            "blast_radius": self.blast_radius,
            "reversibility": self.reversibility,
            "required_approval": self.required_approval,
        }


# Placeholder, deterministic mapping from verdict tier to candidate actions.
# Ordered = ranked. Replace with the real taxonomy in a later pass.
_PLACEHOLDER_PLANS: dict[str, list[tuple[str, str, str, str]]] = {
    VERDICT_EXPLOITED: [
        ("capture_forensic_bundle", BLAST_LOW, REVERSIBLE, APPROVAL_ANALYST),
        ("isolate_host", BLAST_HIGH, IRREVERSIBLE, APPROVAL_TWO_PERSON),
        ("rotate_credentials", BLAST_HIGH, IRREVERSIBLE, APPROVAL_TWO_PERSON),
        ("open_incident_ticket", BLAST_NONE, REVERSIBLE, APPROVAL_AUTO),
    ],
    VERDICT_SUSPICIOUS: [
        ("capture_forensic_bundle", BLAST_LOW, REVERSIBLE, APPROVAL_ANALYST),
        ("increase_monitoring", BLAST_LOW, REVERSIBLE, APPROVAL_ANALYST),
        ("open_incident_ticket", BLAST_NONE, REVERSIBLE, APPROVAL_AUTO),
    ],
    VERDICT_INCONCLUSIVE: [
        ("capture_forensic_bundle", BLAST_LOW, REVERSIBLE, APPROVAL_ANALYST),
        ("open_triage_ticket", BLAST_NONE, REVERSIBLE, APPROVAL_AUTO),
    ],
    VERDICT_BENIGN: [
        ("no_action", BLAST_NONE, REVERSIBLE, APPROVAL_AUTO),
    ],
}


def build_response_plan(verdict: str) -> list[ResponseAction]:
    """Deterministic, bounded, ranked candidate actions for a verdict.

    Keyed off verdict tier only for now; scoped-workload-aware ranking lands
    with the real taxonomy."""
    spec = _PLACEHOLDER_PLANS.get(verdict, _PLACEHOLDER_PLANS[VERDICT_INCONCLUSIVE])
    return [
        ResponseAction(id=name, rank=i, blast_radius=blast,
                       reversibility=rev, required_approval=appr)
        for i, (name, blast, rev, appr) in enumerate(spec)
    ]


# ---------------------------------------------------------------------------
# Verdict computation — with the blind cap (decision 3)
# ---------------------------------------------------------------------------
def compute_verdict(
    signals: list[SignalHit],
    coverage: SourceCoverage,
) -> tuple[str, float]:
    """Deterministic verdict + total weight.

    Decision 3 (blind cap): a *non-fired* exploited-tier signal that no loaded
    source could see can never resolve to `benign`; it floors the verdict at
    `inconclusive`. A signal that actually fired, or a score that already
    reaches `suspicious`, takes precedence over the cap.
    """
    total = sum(s.weight for s in signals if s.fired)
    exploited_fired = any(s.fired and s.tier == TIER_EXPLOITED for s in signals)

    visible = coverage.visible_anywhere()
    exploited_blind = any(
        (not s.fired) and s.tier == TIER_EXPLOITED and s.id not in visible
        for s in signals
    )

    if exploited_fired and total >= 1.0:
        return VERDICT_EXPLOITED, total
    if total >= 0.5:
        return VERDICT_SUSPICIOUS, total
    if exploited_blind:                       # would-be benign/low, but blind
        return VERDICT_INCONCLUSIVE, total
    if total == 0.0:
        return VERDICT_BENIGN, total
    return VERDICT_INCONCLUSIVE, total


# ---------------------------------------------------------------------------
# The Finding itself
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """Typed Tier 1 -> Tier 2 contract. The single test surface for what the
    agent sees."""
    run_id: str
    cve_id: str
    verdict: str
    score: float
    scoped_workloads: list[str]
    signals: list[SignalHit]
    source_coverage: SourceCoverage
    response_plan: list[ResponseAction]
    schema_version: int = SCHEMA_VERSION

    def signals_fired(self) -> list[str]:
        return [s.id for s in self.signals if s.fired]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "cve_id": self.cve_id,
            "verdict": self.verdict,
            "score": self.score,
            "scoped_workloads": self.scoped_workloads,
            "signals_fired": self.signals_fired(),
            "signals": [s.to_dict() for s in self.signals],
            "source_coverage": self.source_coverage.to_dict(),
            "response_plan": [a.to_dict() for a in self.response_plan],
        }
