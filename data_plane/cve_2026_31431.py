import json
import subprocess
import uuid
import pathlib
import datetime
import pandas as pd
import yaml
import markdown

def run_investigation(
    cve_id: str,
    workload_id: str,
    raw_telemetry: str,
    output_dir: str,
    local_events_path: str,
    local_inventory_path: str,
    s3_manifest_path: str,
    lookback_hours: int = 24,
    openclaw_bin: str = "./scripts/openclaw.py",
    signals_file: str = "",
    run_id: str = "",
    extra_params: dict = None,
) -> dict:
    run_id = run_id or str(uuid.uuid4())
    output_path = pathlib.Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    cutoff_ts = (datetime.datetime.utcnow() - datetime.timedelta(hours=lookback_hours)).timestamp()

    # Load Data
    if raw_telemetry == "local":
        with open(local_events_path, "r") as f:
            events_raw = json.load(f)
        events_df = pd.DataFrame(events_raw)
        inventory_df = pd.read_csv(local_inventory_path, dtype=str)
    else:
        events_df = pd.DataFrame()
        inventory_df = pd.DataFrame()

    if workload_id != "ALL" and "workload_id" in events_df.columns:
        events_df = events_df[events_df["workload_id"] == workload_id]
    if "ts" in events_df.columns:
        events_df = events_df[events_df["ts"] >= cutoff_ts]

    for col in ["uid", "euid", "socket_family", "socket_protocol", "pid", "ppid"]:
        if col in events_df.columns:
            events_df[col] = pd.to_numeric(events_df[col], errors="coerce")

    # Q1: Inventory
    algif_loaded_signal = False
    if "algif_aead" in inventory_df.columns:
        algif_loaded_signal = len(inventory_df[inventory_df["algif_aead"] == "loaded"]) > 0

    # Q2: AF_ALG
    q2_signal = False
    if not events_df.empty:
        q2 = events_df[(events_df.get("socket_family") == 38) & (events_df.get("uid") > 0)]
        q2_signal = len(q2) > 0

    # Q3: UID Esc
    q3_signal = False
    if not events_df.empty:
        q3 = events_df[(events_df.get("socket_family") == 38) & (events_df.get("uid") != 0) & (events_df.get("euid") == 0)]
        q3_signal = len(q3) > 0

    # Q4: Root Shell from Unprivileged Parent
    q4_signal = False
    SHELL_NAMES = frozenset(["bash", "sh", "dash", "su", "sudo", "id", "whoami", "passwd", "useradd", "newgrp"])
    if not events_df.empty and "event_type" in events_df.columns:
        proc_events = events_df[events_df["event_type"] == "process"].copy()
        if not proc_events.empty and "process_name" in proc_events.columns:
            root_shells = proc_events[
                (proc_events["process_name"].isin(SHELL_NAMES)) &
                (proc_events.get("euid", pd.Series(dtype=float)) == 0)
            ].copy()
            if not root_shells.empty and "ppid" in root_shells.columns and "pid" in proc_events.columns:
                parent_map = proc_events.set_index("pid")[["uid"]].rename(columns={"uid": "parent_uid"})
                q4 = root_shells.join(parent_map, on="ppid", how="left")
                q4 = q4[q4["parent_uid"].notna() & (q4["parent_uid"] != 0)]
                q4_signal = len(q4) > 0

    # Q5: Module Load
    q5_signal = False
    if not events_df.empty:
        q5 = events_df[(events_df.get("event_type") == "kernel_module") & (events_df.get("module_name") == "algif_aead")]
        q5_signal = len(q5) > 0

    # Q6: Exploit Staging Artifacts
    q6_signal = False
    STAGING_PREFIXES = ("/tmp/", "/dev/shm/", "/proc/")
    if not events_df.empty and "event_type" in events_df.columns:
        file_events = events_df[events_df["event_type"] == "file"].copy()
        if not file_events.empty and "file_path" in file_events.columns:
            q6 = file_events[
                file_events["file_path"].str.startswith(STAGING_PREFIXES, na=False) |
                file_events.get("cmdline", pd.Series(dtype=str)).str.contains("memfd", na=False)
            ]
            q6_signal = len(q6) > 0

    signals = {
        "ALGIF_LOADED": {"fired": algif_loaded_signal, "weight": 0.3, "tier": "suspicious", "q": "Q1"},
        "AF_ALG_SOCKET_OPEN_UNPRIV": {"fired": q2_signal, "weight": 0.5, "tier": "suspicious", "q": "Q2"},
        "UID_ESCALATION_AFTER_AFALG": {"fired": q3_signal, "weight": 1.0, "tier": "exploited", "q": "Q3"},
        "ROOT_SHELL_FROM_UNPRIV_PARENT": {"fired": q4_signal, "weight": 0.9, "tier": "exploited", "q": "Q4"},
        "MODULE_LOAD_EVENT": {"fired": q5_signal, "weight": 0.4, "tier": "suspicious", "q": "Q5"},
        "EXPLOIT_STAGING_ARTIFACTS": {"fired": q6_signal, "weight": 0.6, "tier": "suspicious", "q": "Q6"},
    }

    total_weight = sum(v["weight"] for v in signals.values() if v["fired"])
    signals_fired = [k for k, v in signals.items() if v["fired"]]
    exploited_fired = any(v["fired"] and v["tier"] == "exploited" for v in signals.values())

    if exploited_fired and total_weight >= 1.0: tier1_verdict = "exploited"
    elif total_weight >= 0.5: tier1_verdict = "suspicious"
    elif total_weight == 0.0: tier1_verdict = "benign"
    else: tier1_verdict = "inconclusive"

    tier1_results = {
        "run_id": run_id,
        "cve_id": cve_id,
        "tier1_verdict": tier1_verdict,
        "total_weight": total_weight,
        "signals_fired": signals_fired,
        "signals": signals
    }
    tier1_path = output_path / f"{run_id}_tier1.json"
    tier1_path.write_text(json.dumps(tier1_results, indent=2))

    # Invoke OpenClaw
    openclaw_finding = {}
    if pathlib.Path(openclaw_bin).exists():
        res = subprocess.run([
            openclaw_bin, "investigate",
            "--cve", cve_id, "--workload-id", workload_id,
            "--tier1-results", str(tier1_path),
            "--exploit-signals", signals_file,
            "--raw-telemetry", raw_telemetry,
            "--output-json", "--output-file", str(output_path / f"{run_id}_openclaw.json")
        ], capture_output=True, text=True)
        try:
            if (output_path / f"{run_id}_openclaw.json").exists():
                openclaw_finding = json.loads((output_path / f"{run_id}_openclaw.json").read_text())
            elif res.stdout:
                openclaw_finding = json.loads(res.stdout)
        except json.JSONDecodeError: pass

    # Reports
    signals_bullet_list = "\n".join([f"- **{k}** (Weight: {signals[k]['weight']}, Tier: {signals[k]['tier']})" for k in signals_fired]) if signals_fired else "- None"
    md_content = f"""# {cve_id} Investigation Report
**Verdict:** {tier1_verdict}

**Total Weight:** {total_weight}

## Deterministic Signals Fired
{signals_bullet_list}

## OpenClaw Agent Reasoning
{openclaw_finding.get('reasoning_trace', 'N/A')}

## Recommended Action
> {openclaw_finding.get('recommended_action', 'N/A')}
"""
    docs_dir = pathlib.Path("docs")
    docs_dir.mkdir(parents=True, exist_ok=True)
    md_path = docs_dir / f"{cve_id}_{run_id[:8]}.md"
    md_path.write_text(md_content)
    
    html_content = markdown.markdown(md_content)
    html_path = docs_dir / f"{cve_id}_{run_id[:8]}.html"
    html_path.write_text(f"<html><body>{html_content}</body></html>")

    finding = {
        "run_id": run_id, "cve_id": cve_id, "tier1_verdict": tier1_verdict, "tier2": openclaw_finding
    }
    yaml_path = output_path / f"{run_id}_finding.yaml"
    yaml_path.write_text(yaml.dump(finding))

    return {
        "run_id": run_id,
        "status": "success",
        "elapsed_ms": 0,
        "finding_yaml": str(yaml_path),
        "finding_md": str(md_path),
        "finding_html": str(html_path)
    }
