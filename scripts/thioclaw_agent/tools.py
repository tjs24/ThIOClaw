import json
import yaml

def get_tier1_summary(tier1_path: str) -> str:
    """Reads the Tier 1 summary: verdict, signals fired, and — critically —
    telemetry source coverage so the agent knows what it could NOT see."""
    try:
        with open(tier1_path) as f:
            data = json.load(f)
        coverage = data.get("source_coverage", {})
        # Surface exploited-tier signals no loaded source could see: these are
        # blind spots, not clean negatives.
        visible = set()
        for sigs in coverage.get("visible_signals", {}).values():
            visible.update(sigs)
        blind_exploited = [
            s["id"] for s in data.get("signals", [])
            if s.get("tier") == "exploited" and not s.get("fired")
            and s["id"] not in visible
        ]
        summary = {
            "cve_id": data.get("cve_id"),
            "verdict": data.get("verdict"),
            "score": data.get("score"),
            "signals_fired": data.get("signals_fired"),
            "source_coverage": {
                "loaded": coverage.get("loaded"),
                "failed": coverage.get("failed"),
            },
            "blind_exploited_signals": blind_exploited,
            "response_plan": [a.get("id") for a in data.get("response_plan", [])],
        }
        return json.dumps(summary, indent=2)
    except Exception as e:
        return f"Error reading Tier 1 summary: {e}"

def get_cve_theoretical_path(signals_path: str) -> str:
    """Reads the CVE signals YAML to understand the expected exploit chain."""
    try:
        with open(signals_path) as f:
            data = yaml.safe_load(f)
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error reading signals yaml: {e}"

def get_exploit_evidence(tier1_path: str, signal_name: str) -> str:
    """Fetches the raw telemetry rows that fired a specific signal, plus which
    source detected it. Reads SignalHit.evidence_rows from the Finding."""
    try:
        with open(tier1_path) as f:
            data = json.load(f)
        for sig in data.get("signals", []):   # signals is a list of SignalHit dicts
            if sig.get("id") == signal_name:
                return json.dumps({
                    "signal": signal_name,
                    "fired": sig.get("fired"),
                    "detected_by": sig.get("detected_by"),
                    "blind_sources": sig.get("blind_sources"),
                    "evidence_rows": sig.get("evidence_rows", [])[:5],
                }, indent=2)
        return f"No signal named {signal_name} in the Tier 1 finding."
    except Exception as e:
        return f"Error reading evidence: {e}"

AVAILABLE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_tier1_summary",
            "description": "Reads the summary of deterministic signals that fired on the workload."
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_cve_theoretical_path",
            "description": "Reads the theoretical exploit path and rules for the target CVE."
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_exploit_evidence",
            "description": "Fetches raw telemetry rows containing evidence for a specific signal.",
            "parameters": {
                "type": "object",
                "properties": {
                    "signal_name": {"type": "string", "description": "Name of the signal (e.g., UID_ESCALATION_AFTER_AFALG)"}
                },
                "required": ["signal_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "propose_query_execution",
            "description": "Proposes executing a modified or new query against the telemetry.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query_sql": {"type": "string", "description": "The exact SQL or Pandas code to execute."},
                    "rationale": {"type": "string", "description": "Why this execution is necessary."},
                    "performance_impact": {"type": "string", "description": "Estimated impact (e.g., 'Low - filters 100 rows')."},
                    "target_sql_file": {"type": "string", "description": "The file to update if successful (e.g. queries/CVE-2026-31431/q6.sql)"}
                },
                "required": ["query_sql", "rationale", "performance_impact", "target_sql_file"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit_verdict",
            "description": "Submits the final investigation verdict.",
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["exploited", "suspicious", "benign", "inconclusive"]},
                    "confidence": {"type": "number", "description": "Confidence score (0.0 - 1.0)"},
                    "reasoning_trace": {"type": "string", "description": "Markdown explanation."},
                    "recommended_action": {"type": "string", "description": "Immediate remediation steps."}
                },
                "required": ["verdict", "confidence", "reasoning_trace", "recommended_action"]
            }
        }
    }
]
