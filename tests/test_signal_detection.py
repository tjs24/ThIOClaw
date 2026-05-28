"""
tests/test_signal_detection.py
Test the Tier 1 signal scoring logic as implemented in the notebook
(extracted here as pure Python for fast unit testing).
"""
import pandas as pd
import pytest


# ---- Signal scoring logic (mirrors notebook Cell 10) -----------

def score_signals(events_df: pd.DataFrame, algif_loaded: bool) -> dict:
    """
    Run Q2–Q6 signal checks against an events DataFrame.
    Returns the signals dict and computed verdict.
    """
    # Q2
    q2 = events_df[
        (events_df.get("socket_family", pd.Series(dtype=float)) == 38) &
        (events_df.get("uid", pd.Series(dtype=float)) > 0)
    ]
    # Q3
    q3 = events_df[
        (events_df.get("socket_family", pd.Series(dtype=float)) == 38) &
        (events_df.get("uid", pd.Series(dtype=float)) != 0) &
        (events_df.get("euid", pd.Series(dtype=float)) == 0)
    ]
    # Q4
    SHELL_NAMES = frozenset(["bash","sh","dash","su","sudo","id","whoami","passwd"])
    proc = events_df[events_df.get("event_type", pd.Series(dtype=str)) == "process"]
    root_shells = proc[
        proc.get("process_name", pd.Series(dtype=str)).isin(SHELL_NAMES) &
        (proc.get("euid", pd.Series(dtype=float)) == 0)
    ] if not proc.empty else pd.DataFrame()
    parent_map = proc.set_index("pid")[["uid"]].rename(columns={"uid":"parent_uid"}) \
        if not proc.empty and "pid" in proc.columns else pd.DataFrame()
    if not root_shells.empty and not parent_map.empty and "ppid" in root_shells.columns:
        q4 = root_shells.join(parent_map, on="ppid", how="left")
        q4 = q4[q4.get("parent_uid", pd.Series(dtype=float)).notna() & (q4.get("parent_uid", pd.Series(dtype=float)) != 0)]
    else:
        q4 = pd.DataFrame()
    # Q5
    q5 = events_df[
        (events_df.get("event_type", pd.Series(dtype=str)) == "kernel_module") &
        (events_df.get("module_name", pd.Series(dtype=str)) == "algif_aead")
    ]
    # Q6
    STAGING = ("/tmp/", "/dev/shm/", "/proc/")
    file_ev = events_df[events_df.get("event_type", pd.Series(dtype=str)) == "file"]
    if not file_ev.empty and "file_path" in file_ev.columns:
        q6 = file_ev[
            file_ev["file_path"].str.startswith(STAGING, na=False) |
            file_ev.get("cmdline", pd.Series(dtype=str)).str.contains("memfd", na=False)
        ]
    else:
        q6 = pd.DataFrame()

    signals = {
        "ALGIF_LOADED":               {"fired": algif_loaded, "weight": 0.3, "tier": "suspicious"},
        "AF_ALG_SOCKET_OPEN_UNPRIV":  {"fired": len(q2) > 0,  "weight": 0.5, "tier": "suspicious"},
        "UID_ESCALATION_AFTER_AFALG": {"fired": len(q3) > 0,  "weight": 1.0, "tier": "exploited"},
        "ROOT_SHELL_FROM_UNPRIV":     {"fired": len(q4) > 0,  "weight": 0.9, "tier": "exploited"},
        "MODULE_LOAD_EVENT":          {"fired": len(q5) > 0,  "weight": 0.4, "tier": "suspicious"},
        "EXPLOIT_STAGING_ARTIFACTS":  {"fired": len(q6) > 0,  "weight": 0.6, "tier": "suspicious"},
    }
    total_weight    = sum(v["weight"] for v in signals.values() if v["fired"])
    exploited_fired = any(v["fired"] and v["tier"] == "exploited" for v in signals.values())

    if exploited_fired and total_weight >= 1.0:
        verdict = "exploited"
    elif total_weight >= 0.5:
        verdict = "suspicious"
    elif total_weight == 0.0:
        verdict = "benign"
    else:
        verdict = "inconclusive"

    return {"signals": signals, "verdict": verdict, "total_weight": total_weight}


# ---- Fixtures --------------------------------------------------

def make_event(**kwargs):
    defaults = {
        "event_id": "evt_x", "workload_id": "wl_001", "hostname": "host-a",
        "ts": 1748448000, "event_type": "socket",
        "pid": 1234, "ppid": 1000, "uid": 1001, "euid": 1001,
        "process_name": "test", "cmdline": "test",
        "syscall": None, "socket_family": None, "socket_type": None,
        "socket_protocol": None, "module_name": None, "file_path": None,
    }
    defaults.update(kwargs)
    return defaults


# ---- Tests -----------------------------------------------------

def test_benign_no_events():
    df = pd.DataFrame([make_event(socket_family=None, uid=0)])
    result = score_signals(df, algif_loaded=False)
    assert result["verdict"] == "benign"
    assert result["total_weight"] == 0.0


def test_suspicious_af_alg_open():
    df = pd.DataFrame([make_event(socket_family=38, uid=1001, euid=1001)])
    result = score_signals(df, algif_loaded=False)
    assert result["signals"]["AF_ALG_SOCKET_OPEN_UNPRIV"]["fired"] is True
    assert result["verdict"] == "suspicious"


def test_exploited_uid_escalation():
    df = pd.DataFrame([
        make_event(socket_family=38, uid=1001, euid=0)  # Q3 signal
    ])
    result = score_signals(df, algif_loaded=True)
    assert result["signals"]["UID_ESCALATION_AFTER_AFALG"]["fired"] is True
    assert result["verdict"] == "exploited"


def test_exploited_root_shell():
    df = pd.DataFrame([
        make_event(event_type="process", pid=200, ppid=100, uid=0, euid=0, process_name="bash"),
        make_event(event_type="process", pid=100, ppid=1,   uid=1001, euid=1001, process_name="app"),
    ])
    result = score_signals(df, algif_loaded=False)
    assert result["signals"]["ROOT_SHELL_FROM_UNPRIV"]["fired"] is True
    assert result["verdict"] in ("exploited", "suspicious")


def test_suspicious_module_load():
    df = pd.DataFrame([
        make_event(event_type="kernel_module", module_name="algif_aead")
    ])
    result = score_signals(df, algif_loaded=True)
    assert result["signals"]["MODULE_LOAD_EVENT"]["fired"] is True
    assert result["signals"]["ALGIF_LOADED"]["fired"] is True


def test_suspicious_staging_artifact():
    df = pd.DataFrame([
        make_event(event_type="file", file_path="/tmp/.x9a3b/payload", euid=1001)
    ])
    result = score_signals(df, algif_loaded=False)
    assert result["signals"]["EXPLOIT_STAGING_ARTIFACTS"]["fired"] is True


def test_full_exploit_scenario():
    """Simulate a complete exploit chain — should yield 'exploited' verdict."""
    df = pd.DataFrame([
        make_event(event_type="kernel_module", module_name="algif_aead"),
        make_event(socket_family=38, uid=1001, euid=0),  # Q3
        make_event(event_type="file", file_path="/tmp/.x/exploit"),
    ])
    result = score_signals(df, algif_loaded=True)
    assert result["verdict"] == "exploited"
    assert result["total_weight"] >= 1.0
