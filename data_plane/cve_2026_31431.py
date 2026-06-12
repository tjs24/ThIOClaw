"""
data_plane/cve_2026_31431.py
----------------------------
Tier 1 for CVE-2026-31431 (CopyFail). Ingests every configured telemetry
source through the TelemetrySource seam, scores each independently, then
reconciles into one typed Finding (provenance preserved — decision 1.a) before
handing off to the Tier 2 agent.

The signal scoring math (Q1-Q6) is unchanged from the original single-source
implementation; what's new is that it runs per source and the results carry
detected_by / blind_sources / evidence_rows.
"""
import datetime
import json
import pathlib
import subprocess
import uuid

import pandas as pd
import yaml

from harness.finding import (
    Finding,
    SignalHit,
    SourceCoverage,
    build_response_plan,
    compute_verdict,
)
from harness.report_writer import write_tier1, write_final_report
from telemetry.sources import SOURCE_REGISTRY

# Signal weight / tier / query id. Source support is read from the signal YAML.
SIGNAL_META: dict[str, tuple[float, str, str]] = {
    "ALGIF_LOADED":                  (0.3, "suspicious", "Q1"),
    "AF_ALG_SOCKET_OPEN_UNPRIV":     (0.5, "suspicious", "Q2"),
    "UID_ESCALATION_AFTER_AFALG":    (1.0, "exploited",  "Q3"),
    "ROOT_SHELL_FROM_UNPRIV_PARENT": (0.9, "exploited",  "Q4"),
    "MODULE_LOAD_EVENT":             (0.4, "suspicious", "Q5"),
    "EXPLOIT_STAGING_ARTIFACTS":     (0.6, "suspicious", "Q6"),
}
_EVENT_SIGNALS = [k for k in SIGNAL_META if k != "ALGIF_LOADED"]  # Q2-Q6

SHELL_NAMES = frozenset(["bash", "sh", "dash", "su", "sudo", "id", "whoami",
                         "passwd", "useradd", "newgrp"])
STAGING_PREFIXES = ("/tmp/", "/dev/shm/", "/proc/")

_CONFIGURED_SOURCES = {
    "osquery": ["osquery"],
    "auditd": ["auditd"],
    "both": ["osquery", "auditd"],
}


# ---------------------------------------------------------------------------
# Scoring (runs per source; returns the matching rows so they can be evidence)
# ---------------------------------------------------------------------------
def score_events(events_df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Q2-Q6 against one normalized frame. Returns sig_id -> matching rows."""
    hits = {k: pd.DataFrame() for k in _EVENT_SIGNALS}
    if events_df is None or events_df.empty:
        return hits

    df = events_df
    hits["AF_ALG_SOCKET_OPEN_UNPRIV"] = df[
        (df.get("socket_family") == 38) & (df.get("uid") > 0)
    ]
    hits["UID_ESCALATION_AFTER_AFALG"] = df[
        (df.get("socket_family") == 38) & (df.get("uid") != 0) & (df.get("euid") == 0)
    ]

    if "event_type" in df.columns:
        proc = df[df["event_type"] == "process"].copy()
        if not proc.empty and "process_name" in proc.columns:
            root_shells = proc[
                proc["process_name"].isin(SHELL_NAMES) &
                (proc.get("euid", pd.Series(dtype=float)) == 0)
            ].copy()
            if not root_shells.empty and "ppid" in root_shells.columns and "pid" in proc.columns:
                parent_map = proc.set_index("pid")[["uid"]].rename(columns={"uid": "parent_uid"})
                q4 = root_shells.join(parent_map, on="ppid", how="left")
                hits["ROOT_SHELL_FROM_UNPRIV_PARENT"] = q4[
                    q4["parent_uid"].notna() & (q4["parent_uid"] != 0)
                ]

    hits["MODULE_LOAD_EVENT"] = df[
        (df.get("event_type") == "kernel_module") & (df.get("module_name") == "algif_aead")
    ]

    if "event_type" in df.columns:
        file_events = df[df["event_type"] == "file"].copy()
        if not file_events.empty and "file_path" in file_events.columns:
            hits["EXPLOIT_STAGING_ARTIFACTS"] = file_events[
                file_events["file_path"].str.startswith(STAGING_PREFIXES, na=False) |
                file_events.get("cmdline", pd.Series(dtype=str)).str.contains("memfd", na=False)
            ]
    return hits


def score_inventory(inventory_df: pd.DataFrame) -> bool:
    """Q1 — is algif_aead loaded per the inventory snapshot?"""
    if inventory_df is not None and "algif_aead" in inventory_df.columns:
        return len(inventory_df[inventory_df["algif_aead"] == "loaded"]) > 0
    return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _supported_sources(signals_file: str) -> dict[str, list[str]]:
    """Read each rule's supported_sources from the signal YAML."""
    out: dict[str, list[str]] = {}
    try:
        with open(signals_file) as f:
            data = yaml.safe_load(f)
        for rule in data.get("rules", []):
            out[rule["id"]] = rule.get("supported_sources", ["osquery"])
    except Exception:
        pass
    return out


def _evidence(df: pd.DataFrame, n: int = 3) -> list[dict]:
    """Top-n matching rows as JSON-safe dicts (to_json handles NaN + numpy)."""
    if df is None or df.empty:
        return []
    return json.loads(df.head(n).to_json(orient="records"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run_investigation(
    cve_id: str,
    workload_id: str,
    raw_telemetry: str,
    output_dir: str,
    local_events_path: str,
    local_inventory_path: str,
    s3_manifest_path: str,
    lookback_hours: int = 24,
    thioclaw_bin: str = "./scripts/thioclaw.py",
    signals_file: str = "",
    run_id: str = "",
    event_source: str = "osquery",
    local_auditd_path: str = "",
    lookback_anchor: str = "latest_event",
    extra_params: dict = None,
) -> dict:
    run_id = run_id or str(uuid.uuid4())
    output_path = pathlib.Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    now_ts = datetime.datetime.utcnow().timestamp()

    configured = _CONFIGURED_SOURCES.get(event_source, ["osquery"])
    source_paths = {"osquery": local_events_path, "auditd": local_auditd_path}

    # --- ingest every configured source through the seam (decision 2.b) ----
    results = []
    inventory_df = pd.DataFrame()
    if raw_telemetry == "local":
        for name in configured:
            adapter = SOURCE_REGISTRY[name](
                workload_id_default=(workload_id if workload_id != "ALL" else "ALL")
            )
            results.append(adapter.ingest(
                source_paths.get(name, ""), workload_id=workload_id,
                lookback_hours=lookback_hours, anchor=lookback_anchor, now_ts=now_ts,
            ))
        try:
            inventory_df = pd.read_csv(local_inventory_path, dtype=str)
        except Exception:
            inventory_df = pd.DataFrame()

    loaded = [r for r in results if r.ok]
    loaded_names = [r.source for r in loaded]
    per_source_hits = {r.source: score_events(r.frame) for r in loaded}
    algif_loaded = score_inventory(inventory_df)

    supported = _supported_sources(signals_file)

    # --- reconcile per-source results into one Finding (decision 1.a) ------
    signal_hits: list[SignalHit] = []
    for sig_id, (weight, tier, q) in SIGNAL_META.items():
        sup = supported.get(sig_id) or loaded_names          # fallback: no blind if YAML silent
        blind = [s for s in sup if s not in loaded_names]

        if sig_id == "ALGIF_LOADED":
            fired = bool(algif_loaded)
            detected_by = ["osquery"] if (fired and "osquery" in loaded_names) else []
            rows: list[dict] = []
        else:
            detected_by = [n for n in loaded_names if not per_source_hits[n][sig_id].empty]
            fired = bool(detected_by)
            rows = []
            for n in detected_by:
                rows.extend(_evidence(per_source_hits[n][sig_id]))

        signal_hits.append(SignalHit(
            id=sig_id, weight=weight, tier=tier, fired=fired, query=q,
            detected_by=detected_by, blind_sources=blind, evidence_rows=rows,
        ))

    coverage = SourceCoverage(
        configured=configured,
        loaded=loaded_names,
        failed=[{"source": r.source, "reason": r.report.reason} for r in results if not r.ok],
        visible_signals={
            n: [sid for sid in SIGNAL_META if n in (supported.get(sid) or loaded_names)]
            for n in loaded_names
        },
    )

    verdict, score = compute_verdict(signal_hits, coverage)

    scoped = set()
    for r in loaded:
        if "workload_id" in r.frame.columns:
            scoped.update(
                w for w in r.frame["workload_id"].dropna().unique().tolist()
                if w and w != "ALL"
            )
    scoped_workloads = sorted(scoped) or ([workload_id] if workload_id and workload_id != "ALL" else [])

    finding = Finding(
        run_id=run_id, cve_id=cve_id, verdict=verdict, score=score,
        scoped_workloads=scoped_workloads, signals=signal_hits,
        source_coverage=coverage, response_plan=build_response_plan(verdict),
    )

    tier1_path = write_tier1(finding, output_path)

    # --- invoke Tier 2 agent -----------------------------------------------
    tier2_finding: dict = {}
    if pathlib.Path(thioclaw_bin).exists():
        res = subprocess.run([
            thioclaw_bin, "investigate",
            "--cve", cve_id, "--workload-id", workload_id,
            "--tier1-results", str(tier1_path),
            "--exploit-signals", signals_file,
            "--raw-telemetry", raw_telemetry,
            "--output-json", "--output-file", str(output_path / f"{run_id}_tier2.json"),
        ], capture_output=True, text=True)
        try:
            tier2_path = output_path / f"{run_id}_tier2.json"
            if tier2_path.exists():
                tier2_finding = json.loads(tier2_path.read_text())
            elif res.stdout:
                tier2_finding = json.loads(res.stdout)
        except json.JSONDecodeError:
            pass

    paths = write_final_report(
        finding=finding, tier2_finding=tier2_finding,
        findings_dir=output_path, docs_dir=pathlib.Path("docs"),
    )

    return {
        "run_id": run_id,
        "status": "success",
        "elapsed_ms": 0,
        "verdict": verdict,
        "finding_yaml": str(paths.finding_yaml),
        "finding_md": str(paths.report_md),
        "finding_html": str(paths.report_html),
    }
