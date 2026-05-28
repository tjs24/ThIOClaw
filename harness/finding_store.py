"""
harness/finding_store.py
------------------------
Persists investigation findings as:
  - YAML (machine-readable, in findings/)
  - Markdown with Jekyll front-matter (in docs/, for GitHub Pages)
  - Append-only JSONL log (findings/findings.jsonl)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import yaml

logger = logging.getLogger(__name__)


class FindingStore:
    """Write and index investigation findings."""

    def __init__(self, findings_dir: str = "./findings", docs_dir: str = "./docs"):
        self.findings_dir = Path(findings_dir)
        self.docs_dir = Path(docs_dir)
        self.jsonl_path = self.findings_dir / "findings.jsonl"

        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.docs_dir.mkdir(parents=True, exist_ok=True)
        (self.docs_dir / "_data").mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # YAML output
    # ------------------------------------------------------------------
    def write_yaml(self, finding: Dict[str, Any]) -> Path:
        run_id = finding.get("run_id", "unknown")
        path = self.findings_dir / f"{run_id}_finding.yaml"
        with open(path, "w") as f:
            yaml.dump(finding, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        logger.info("YAML finding written: %s", path)
        return path

    # ------------------------------------------------------------------
    # Markdown output (Jekyll front-matter for GitHub Pages)
    # ------------------------------------------------------------------
    def write_markdown(self, finding: Dict[str, Any]) -> Path:
        run_id = finding.get("run_id", "unknown")
        cve_id = finding.get("cve_id", "CVE-UNKNOWN")
        verdict = finding.get("tier1", {}).get("verdict", "inconclusive")
        investigated_at = finding.get("investigated_at", datetime.now(timezone.utc).isoformat())
        date_str = investigated_at[:10]

        workloads = finding.get("workloads_investigated", [])
        signals_fired = finding.get("tier1", {}).get("signals_fired", [])
        total_weight = finding.get("tier1", {}).get("total_weight", 0.0)
        tier2 = finding.get("tier2", {})
        reasoning = tier2.get("reasoning_trace", "_OpenClaw reasoning not available._")
        recommended_action = finding.get("recommended_action", "Manual review required.")
        raw_telemetry_source = finding.get("raw_telemetry_source", "unknown")

        verdict_badge = {
            "exploited": "🔴 EXPLOITED",
            "suspicious": "🟠 SUSPICIOUS",
            "benign": "✅ BENIGN",
            "inconclusive": "⚪ INCONCLUSIVE",
        }.get(verdict, verdict.upper())

        lines = [
            "---",
            f'title: "{cve_id} Investigation — {run_id[:8]}"',
            f"date: {date_str}",
            f"cve: {cve_id}",
            f"verdict: {verdict}",
            f"run_id: {run_id}",
            "layout: finding",
            "---",
            "",
            f"# {cve_id} — Exploitation Investigation Report",
            "",
            f"| Field | Value |",
            f"|---|---|",
            f"| **Run ID** | `{run_id}` |",
            f"| **Investigated at** | {investigated_at} |",
            f"| **Telemetry source** | `{raw_telemetry_source}` |",
            f"| **Verdict** | {verdict_badge} |",
            f"| **Total signal weight** | {total_weight} |",
            "",
            "---",
            "",
            "## Workloads Investigated",
            "",
        ]

        workload_rows = finding.get("_workload_rows", [])
        if workload_rows:
            lines += [
                "| Hostname | Distro | Kernel | Assessment |",
                "|---|---|---|---|",
            ]
            for row in workload_rows:
                lines.append(
                    f"| {row.get('hostname','?')} "
                    f"| {row.get('distro_family','?')} "
                    f"| `{row.get('running_kernel','?')}` "
                    f"| `{row.get('assessment','?')}` |"
                )
        else:
            for wl in workloads:
                lines.append(f"- `{wl}`")

        lines += [
            "",
            "---",
            "",
            "## Signal Analysis",
            "",
            "| Signal Rule | Fired | Weight | Tier |",
            "|---|---|---|---|",
        ]

        all_signals = finding.get("_all_signals", {})
        for sig_id, sig in all_signals.items():
            icon = "✅" if sig.get("fired") else "—"
            lines.append(
                f"| `{sig_id}` | {icon} | {sig.get('weight', 0)} | {sig.get('tier', '?')} |"
            )

        lines += [
            "",
            f"**Signals fired**: {', '.join(f'`{s}`' for s in signals_fired) or '_none_'}",
            f"**Total weight**: `{total_weight}`",
            "",
            "---",
            "",
            "## Evidence",
            "",
        ]

        # Embed Q evidence tables
        for q_key in ("q3_rows", "q2_rows", "q4_rows", "q5_rows", "q6_rows"):
            q_label = q_key.replace("_rows", "").upper()
            rows = finding.get("_evidence", {}).get(q_key, [])
            if rows:
                lines += [f"### {q_label} — {len(rows)} event(s)", ""]
                headers = list(rows[0].keys())
                lines.append("| " + " | ".join(headers) + " |")
                lines.append("|" + "|".join(["---"] * len(headers)) + "|")
                for row in rows:
                    lines.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
                lines.append("")

        lines += [
            "---",
            "",
            "## OpenClaw Reasoning (Tier 2)",
            "",
            reasoning,
            "",
            "---",
            "",
            "## Recommended Action",
            "",
            f"> ⚠️ {recommended_action}",
            "",
        ]

        slug = f"{cve_id}_{run_id[:8]}"
        path = self.docs_dir / f"{slug}.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("Markdown finding written: %s", path)
        return path

    # ------------------------------------------------------------------
    # Append-only JSONL log
    # ------------------------------------------------------------------
    def append_jsonl(self, finding: Dict[str, Any]) -> None:
        # Strip large evidence blobs from the log index entry
        index_entry = {
            k: v for k, v in finding.items()
            if not k.startswith("_")
        }
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(index_entry, default=str) + "\n")

    # ------------------------------------------------------------------
    # Convenience: write all formats
    # ------------------------------------------------------------------
    def save(self, finding: Dict[str, Any]) -> Dict[str, str]:
        yaml_path = self.write_yaml(finding)
        md_path = self.write_markdown(finding)
        self.append_jsonl(finding)
        return {
            "yaml": str(yaml_path),
            "markdown": str(md_path),
        }
