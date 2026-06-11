"""
harness/report_writer.py
------------------------
Persist a Finding (the typed Tier 1 -> Tier 2 contract) to findings/ and docs/.

Consumes harness.finding.Finding directly — the rendering layer no longer
reaches into loose dicts. The human-readable report now surfaces telemetry
source coverage (which source detected each signal, which signals were blind)
and the deterministic Tier 1 response plan, alongside the Tier 2 reasoning.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import markdown
import yaml

from harness.finding import Finding


@dataclass
class ReportPaths:
    tier1_json: Path
    finding_yaml: Path
    report_md: Path
    report_html: Path


def write_tier1(finding: Finding, findings_dir: Path) -> Path:
    """Persist the deterministic Tier 1 Finding as JSON. Returns the path."""
    findings_dir.mkdir(parents=True, exist_ok=True)
    tier1_path = findings_dir / f"{finding.run_id}_tier1.json"
    tier1_path.write_text(json.dumps(finding.to_dict(), indent=2))
    return tier1_path


def _signals_section(finding: Finding) -> str:
    lines = []
    for s in finding.signals:
        if not s.fired:
            continue
        src = ", ".join(s.detected_by) or "—"
        blind = f" · _blind to: {', '.join(s.blind_sources)}_" if s.blind_sources else ""
        lines.append(
            f"- **{s.id}** (weight {s.weight}, {s.tier}) — detected by: {src}"
            f" · {len(s.evidence_rows)} evidence row(s){blind}"
        )
    return "\n".join(lines) or "- None"


def _coverage_section(finding: Finding) -> str:
    c = finding.source_coverage
    parts = [
        f"- **Configured sources:** {', '.join(c.configured) or '—'}",
        f"- **Loaded:** {', '.join(c.loaded) or '—'}",
    ]
    if c.failed:
        parts.append("- **Failed (degraded):** " +
                     "; ".join(f"{f['source']} ({f['reason']})" for f in c.failed))
    # Blind exploited signals are the response engineer's headline risk.
    blind_exploited = [
        s.id for s in finding.signals
        if s.tier == "exploited" and s.id not in c.visible_anywhere()
    ]
    if blind_exploited:
        parts.append(f"- **⚠ Blind exploited signals (no loaded source can see):** "
                     f"{', '.join(blind_exploited)}")
    return "\n".join(parts)


def _response_plan_section(finding: Finding) -> str:
    if not finding.response_plan:
        return "- None"
    return "\n".join(
        f"{a.rank + 1}. **{a.id}** — blast: {a.blast_radius}, {a.reversibility}, "
        f"approval: {a.required_approval}"
        for a in finding.response_plan
    )


def write_final_report(
    *,
    finding: Finding,
    tier2_finding: dict[str, Any],
    findings_dir: Path,
    docs_dir: Path,
) -> ReportPaths:
    """Render + persist the human and machine reports for an investigation."""
    findings_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)

    md_content = (
        f"# {finding.cve_id} Investigation Report\n"
        f"**Verdict:** {finding.verdict}  ·  **Score:** {finding.score}\n\n"
        f"**Scoped workloads:** {', '.join(finding.scoped_workloads) or '—'}\n\n"
        f"## Telemetry Source Coverage\n"
        f"{_coverage_section(finding)}\n\n"
        f"## Deterministic Signals Fired\n"
        f"{_signals_section(finding)}\n\n"
        f"## Tier 1 Response Plan (candidate actions)\n"
        f"{_response_plan_section(finding)}\n\n"
        f"## ThIOClaw Agent Reasoning\n"
        f"{tier2_finding.get('reasoning_trace', 'N/A')}\n\n"
        f"## Recommended Action\n"
        f"> {tier2_finding.get('recommended_action', 'N/A')}\n"
    )
    md_path = docs_dir / f"{finding.cve_id}_{finding.run_id[:8]}.md"
    md_path.write_text(md_content)

    html_path = docs_dir / f"{finding.cve_id}_{finding.run_id[:8]}.html"
    html_path.write_text(f"<html><body>{markdown.markdown(md_content)}</body></html>")

    finding_doc = {
        "run_id": finding.run_id,
        "cve_id": finding.cve_id,
        "tier1_verdict": finding.verdict,
        "tier1": finding.to_dict(),
        "tier2": tier2_finding,
    }
    finding_yaml = findings_dir / f"{finding.run_id}_finding.yaml"
    finding_yaml.write_text(yaml.dump(finding_doc, sort_keys=False))

    return ReportPaths(
        tier1_json=findings_dir / f"{finding.run_id}_tier1.json",
        finding_yaml=finding_yaml,
        report_md=md_path,
        report_html=html_path,
    )
