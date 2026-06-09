"""
harness/report_writer.py
------------------------
Persist Tier 1 + Tier 2 investigation results to findings/ and docs/.

Extracted from data_plane/cve_2026_31431.py so the rendering layer is one
named module instead of inline f-strings. Today writes one report per
(CVE, run); the signatures are stable enough to extend for fleet +
per-workload reports without rewriting callers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import markdown
import yaml


@dataclass
class ReportPaths:
    tier1_json: Path
    finding_yaml: Path
    report_md: Path
    report_html: Path


def write_tier1(
    *,
    run_id: str,
    cve_id: str,
    tier1_verdict: str,
    total_weight: float,
    signals_fired: list[str],
    signals: dict[str, Any],
    findings_dir: Path,
) -> Path:
    """Persist Tier 1 deterministic results. Returns the path written."""
    findings_dir.mkdir(parents=True, exist_ok=True)
    tier1_path = findings_dir / f"{run_id}_tier1.json"
    tier1_path.write_text(json.dumps({
        "run_id": run_id,
        "cve_id": cve_id,
        "tier1_verdict": tier1_verdict,
        "total_weight": total_weight,
        "signals_fired": signals_fired,
        "signals": signals,
    }, indent=2))
    return tier1_path


def write_final_report(
    *,
    run_id: str,
    cve_id: str,
    tier1_verdict: str,
    total_weight: float,
    signals_fired: list[str],
    signals: dict[str, Any],
    tier2_finding: dict[str, Any],
    findings_dir: Path,
    docs_dir: Path,
) -> ReportPaths:
    """Render and persist the human + machine reports for an investigation.

    Assumes write_tier1 has already produced tier1.json under findings_dir;
    the path is included in the returned ReportPaths for caller convenience.
    """
    findings_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)

    signals_bullet_list = "\n".join(
        f"- **{k}** (Weight: {signals[k]['weight']}, Tier: {signals[k]['tier']})"
        for k in signals_fired
    ) or "- None"

    md_content = (
        f"# {cve_id} Investigation Report\n"
        f"**Verdict:** {tier1_verdict}\n\n"
        f"**Total Weight:** {total_weight}\n\n"
        f"## Deterministic Signals Fired\n"
        f"{signals_bullet_list}\n\n"
        f"## ThIOClaw Agent Reasoning\n"
        f"{tier2_finding.get('reasoning_trace', 'N/A')}\n\n"
        f"## Recommended Action\n"
        f"> {tier2_finding.get('recommended_action', 'N/A')}\n"
    )
    md_path = docs_dir / f"{cve_id}_{run_id[:8]}.md"
    md_path.write_text(md_content)

    html_path = docs_dir / f"{cve_id}_{run_id[:8]}.html"
    html_path.write_text(
        f"<html><body>{markdown.markdown(md_content)}</body></html>"
    )

    finding = {
        "run_id": run_id,
        "cve_id": cve_id,
        "tier1_verdict": tier1_verdict,
        "tier2": tier2_finding,
    }
    finding_yaml = findings_dir / f"{run_id}_finding.yaml"
    finding_yaml.write_text(yaml.dump(finding))

    return ReportPaths(
        tier1_json=findings_dir / f"{run_id}_tier1.json",
        finding_yaml=finding_yaml,
        report_md=md_path,
        report_html=html_path,
    )
