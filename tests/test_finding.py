"""
tests/test_finding.py
Phase 1 foundation: the typed Finding contract, verdict computation with the
blind cap (decision 3), and schema validation / coercion.
"""
import pandas as pd

from harness.finding import (
    Finding,
    SignalHit,
    SourceCoverage,
    ResponseAction,
    build_response_plan,
    compute_verdict,
    VERDICT_EXPLOITED,
    VERDICT_SUSPICIOUS,
    VERDICT_BENIGN,
    VERDICT_INCONCLUSIVE,
)
from telemetry import schema


# --- helpers ---------------------------------------------------------------
def hit(id, weight, tier, fired):
    return SignalHit(id=id, weight=weight, tier=tier, fired=fired)


def cov(visible):
    """SourceCoverage where the given {source: [signal_ids]} are visible."""
    loaded = list(visible.keys())
    return SourceCoverage(configured=loaded, loaded=loaded, visible_signals=visible)


# --- verdict: the ordinary ladder -----------------------------------------
def test_benign_when_nothing_fires_and_nothing_blind():
    signals = [hit("UID_ESC", 1.0, "exploited", False)]
    coverage = cov({"osquery": ["UID_ESC"]})  # exploited signal WAS visible, just didn't fire
    verdict, total = compute_verdict(signals, coverage)
    assert verdict == VERDICT_BENIGN
    assert total == 0.0


def test_suspicious_on_weight():
    signals = [hit("AF_ALG", 0.5, "suspicious", True)]
    coverage = cov({"osquery": ["AF_ALG"]})
    verdict, total = compute_verdict(signals, coverage)
    assert verdict == VERDICT_SUSPICIOUS
    assert total == 0.5


def test_exploited_on_fired_exploited_signal():
    signals = [hit("UID_ESC", 1.0, "exploited", True)]
    coverage = cov({"osquery": ["UID_ESC"]})
    verdict, _ = compute_verdict(signals, coverage)
    assert verdict == VERDICT_EXPLOITED


# --- verdict: the blind cap (decision 3) ----------------------------------
def test_blind_exploited_signal_floors_at_inconclusive_not_benign():
    """An exploited-tier signal no loaded source can see must NOT read benign."""
    signals = [hit("UID_ESC", 1.0, "exploited", False)]
    # auditd loaded, but it cannot see UID_ESC (osquery-only signal).
    coverage = cov({"auditd": ["AF_ALG", "ROOT_SHELL"]})
    verdict, total = compute_verdict(signals, coverage)
    assert verdict == VERDICT_INCONCLUSIVE
    assert total == 0.0


def test_blind_cap_does_not_downgrade_a_real_suspicious():
    """Suspicious evidence present + an exploited signal blind -> stays suspicious."""
    signals = [
        hit("AF_ALG", 0.5, "suspicious", True),     # real suspicious evidence
        hit("UID_ESC", 1.0, "exploited", False),    # blind exploited
    ]
    coverage = cov({"auditd": ["AF_ALG"]})          # UID_ESC not visible
    verdict, _ = compute_verdict(signals, coverage)
    assert verdict == VERDICT_SUSPICIOUS


def test_visible_exploited_signal_that_didnt_fire_is_truly_benign():
    """If a loaded source COULD see the exploited signal and it didn't fire,
    that is a real negative, not a blind spot."""
    signals = [hit("UID_ESC", 1.0, "exploited", False)]
    coverage = cov({"osquery": ["UID_ESC", "AF_ALG"]})
    verdict, _ = compute_verdict(signals, coverage)
    assert verdict == VERDICT_BENIGN


# --- response plan (placeholder) ------------------------------------------
def test_response_plan_is_ranked_and_nonempty():
    plan = build_response_plan(VERDICT_EXPLOITED)
    assert plan, "exploited verdict must yield candidate actions"
    assert [a.rank for a in plan] == list(range(len(plan)))
    assert any(a.id == "capture_forensic_bundle" for a in plan)


def test_exploited_plan_has_two_person_gate_on_irreversible():
    plan = build_response_plan(VERDICT_EXPLOITED)
    irreversible = [a for a in plan if a.reversibility == "irreversible"]
    assert irreversible, "exploited plan should contain irreversible actions"
    assert all(a.required_approval == "two_person" for a in irreversible)


def test_benign_plan_is_no_action():
    plan = build_response_plan(VERDICT_BENIGN)
    assert [a.id for a in plan] == ["no_action"]


# --- Finding serialization ------------------------------------------------
def test_finding_to_dict_roundtrips_key_fields():
    signals = [hit("AF_ALG", 0.5, "suspicious", True)]
    coverage = cov({"osquery": ["AF_ALG"]})
    verdict, score = compute_verdict(signals, coverage)
    finding = Finding(
        run_id="r1", cve_id="CVE-2026-31431", verdict=verdict, score=score,
        scoped_workloads=["wl_a3f9b1c2"], signals=signals,
        source_coverage=coverage, response_plan=build_response_plan(verdict),
    )
    d = finding.to_dict()
    assert d["schema_version"] == 1
    assert d["verdict"] == VERDICT_SUSPICIOUS
    assert d["signals_fired"] == ["AF_ALG"]
    assert d["signals"][0]["evidence_rows"] == []
    assert d["source_coverage"]["loaded"] == ["osquery"]
    assert d["response_plan"][0]["rank"] == 0


# --- schema validation / coercion -----------------------------------------
def test_validate_flags_missing_required_columns():
    df = pd.DataFrame([{"event_type": "socket"}])  # no workload_id / ts
    report = schema.validate(df, source="osquery")
    assert report.ok is False
    assert "workload_id" in report.missing_columns
    assert report.source == "osquery"


def test_validate_passes_on_well_formed_frame():
    df = pd.DataFrame([{"workload_id": "wl", "ts": 1, "event_type": "socket"}])
    assert schema.validate(df).ok is True


def test_coerce_numeric_turns_strings_into_numbers():
    df = pd.DataFrame([{"workload_id": "wl", "ts": "1748448000", "event_type": "socket",
                        "uid": "1001", "socket_family": "38"}])
    out = schema.coerce_numeric(df)
    assert out["uid"].iloc[0] == 1001
    assert out["socket_family"].iloc[0] == 38
