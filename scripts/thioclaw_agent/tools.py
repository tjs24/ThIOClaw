import json
import yaml

def get_tier1_summary(tier1_path: str) -> str:
    """Reads the Tier 1 summary data to see which signals fired."""
    try:
        with open(tier1_path) as f:
            data = json.load(f)
        summary = {
            "cve_id": data.get("cve_id"),
            "total_weight": data.get("total_weight"),
            "signals_fired": data.get("signals_fired")
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
    """Fetches the raw telemetry rows for deeper inspection of a specific signal."""
    try:
        with open(tier1_path) as f:
            data = json.load(f)
        signals_map = data.get("signals", {})
        if signal_name in signals_map:
            q_name = signals_map[signal_name].get("q")
            if q_name:
                rows_key = f"{q_name.lower()}_rows"
                rows = data.get(rows_key, [])
                return json.dumps(rows[:5], indent=2) # return top 5 rows for context limit
        return f"No specific evidence found for {signal_name}."
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
