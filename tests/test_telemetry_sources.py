"""
tests/test_telemetry_sources.py
Phase 2: the TelemetrySource seam. Two adapters (osquery + auditd) normalize
their respective raw shapes into the same NormalizedEvent frame, and the auditd
adapter faithfully reproduces its documented blind spot (no Q3).
"""
import pandas as pd

from telemetry import schema
from telemetry.sources import OsquerySource, AuditdSource, SOURCE_REGISTRY

OSQUERY_PATH = "data/sample_events.json"
AUDITD_PATH = "data/sample_auditd.log"
WL = "wl_a3f9b1c2"


# --- registry -------------------------------------------------------------
def test_registry_exposes_both_adapters():
    assert set(SOURCE_REGISTRY) == {"osquery", "auditd"}


# --- osquery --------------------------------------------------------------
def test_osquery_ingests_and_validates():
    res = OsquerySource().ingest(OSQUERY_PATH, workload_id="ALL")
    assert res.ok
    assert res.report.ok
    for col in schema.REQUIRED_COLUMNS:
        assert col in res.frame.columns


def test_osquery_scopes_to_workload():
    res = OsquerySource().ingest(OSQUERY_PATH, workload_id=WL)
    assert (res.frame["workload_id"] == WL).all()
    assert len(res.frame) >= 1


# --- auditd: normalization ------------------------------------------------
def test_auditd_normalizes_into_canonical_schema():
    res = AuditdSource(workload_id_default=WL).ingest(AUDITD_PATH, workload_id="ALL")
    assert res.ok, res.report.reason
    df = res.frame
    # workload_id stamped from scope (auditd carries none of its own)
    assert (df["workload_id"] == WL).all()
    # event types present after mapping
    assert set(df["event_type"]) >= {"socket", "kernel_module", "process", "file"}


def test_auditd_af_alg_socket_row():
    df = AuditdSource(workload_id_default=WL).ingest(AUDITD_PATH).frame
    sock = df[df["event_type"] == "socket"].iloc[0]
    assert sock["socket_family"] == 38        # 0x26 -> 38
    assert sock["uid"] == 1001


def test_auditd_module_load_normalized_to_kernel_module():
    df = AuditdSource(workload_id_default=WL).ingest(AUDITD_PATH).frame
    km = df[df["event_type"] == "kernel_module"]
    assert len(km) == 1
    assert km.iloc[0]["module_name"] == "algif_aead"


def test_auditd_staging_file_row():
    df = AuditdSource(workload_id_default=WL).ingest(AUDITD_PATH).frame
    files = df[df["event_type"] == "file"]
    assert files.iloc[0]["file_path"].startswith("/tmp/")


def test_auditd_root_shell_has_parent_for_q4_join():
    """The root bash row and its non-root parent must both be present so the
    Q4 (root shell from unpriv parent) join can resolve."""
    df = AuditdSource(workload_id_default=WL).ingest(AUDITD_PATH).frame
    proc = df[df["event_type"] == "process"]
    bash = proc[proc["process_name"] == "bash"].iloc[0]
    assert bash["euid"] == 0
    parent = proc[proc["pid"] == bash["ppid"]]
    assert not parent.empty and parent.iloc[0]["uid"] != 0


def test_auditd_cannot_see_uid_escalation_q3():
    """Appendix C blind spot: no normalized row carries the same-PID
    uid!=0 + euid==0 shape Q3 keys on."""
    df = AuditdSource(workload_id_default=WL).ingest(AUDITD_PATH).frame
    q3 = df[(df["socket_family"] == 38) & (df["uid"] != 0) & (df["euid"] == 0)]
    assert q3.empty


# --- degrade-and-flag (decision 2.b) --------------------------------------
def test_missing_file_degrades_not_raises():
    res = AuditdSource().ingest("data/does_not_exist.log")
    assert res.ok is False
    assert "not found" in (res.report.reason or "")
    assert res.frame.empty
