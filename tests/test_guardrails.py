"""
Guardrails policy tests.

Covers the pre-tool-call safety policy shared by both framework paths.
A regression here would silently weaken the agent's safety floor on both
the LiteLLM-direct and Strands loops, so the assertions are explicit.
"""
from __future__ import annotations

import pytest

from observability.guardrails import (
    GuardrailPolicy,
    SAFETY_READ_ONLY,
    SAFETY_STATE_CHANGING,
    SAFETY_TERMINAL,
    classify,
)


# --- Tool classification ---------------------------------------------------
def test_classify_known_tools():
    assert classify("get_tier1_summary") == SAFETY_READ_ONLY
    assert classify("get_cve_theoretical_path") == SAFETY_READ_ONLY
    assert classify("get_exploit_evidence") == SAFETY_READ_ONLY
    assert classify("propose_query_execution") == SAFETY_STATE_CHANGING
    assert classify("submit_verdict") == SAFETY_TERMINAL


def test_classify_unknown_tool_is_state_changing():
    # Fail closed: an unfamiliar tool is never read-only by default.
    assert classify("fabricated_tool_xyz") == SAFETY_STATE_CHANGING


# --- Read-only tools should pass through ----------------------------------
def test_read_only_tools_allowed():
    policy = GuardrailPolicy()
    v = policy.evaluate("get_tier1_summary", {})
    assert v.allowed, v.reason
    v = policy.evaluate("get_cve_theoretical_path", {})
    assert v.allowed, v.reason


# --- get_exploit_evidence signal_name validation --------------------------
def test_signal_name_valid_passes():
    policy = GuardrailPolicy()
    v = policy.evaluate("get_exploit_evidence",
                        {"signal_name": "UID_ESCALATION_AFTER_AFALG"})
    assert v.allowed


def test_signal_name_empty_blocked():
    policy = GuardrailPolicy()
    v = policy.evaluate("get_exploit_evidence", {"signal_name": ""})
    assert not v.allowed
    assert v.rule_id == "EMPTY_SIGNAL_NAME"


@pytest.mark.parametrize("bad_name", [
    "../etc/passwd",
    "uid_escalation",          # lowercase — not a real signal id shape
    "UID;DROP TABLE",
    "/absolute/path",
    "UID ESCALATION",          # whitespace
])
def test_signal_name_injection_blocked(bad_name):
    policy = GuardrailPolicy()
    v = policy.evaluate("get_exploit_evidence", {"signal_name": bad_name})
    assert not v.allowed
    assert v.rule_id in {"INVALID_SIGNAL_NAME", "EMPTY_SIGNAL_NAME"}


# --- propose_query_execution: destructive SQL -----------------------------
@pytest.mark.parametrize("query", [
    "DELETE FROM events WHERE 1=1",
    "drop table workloads",                       # case-insensitive
    "SELECT * FROM e; TRUNCATE TABLE foo",        # piggybacked
    "UPDATE signals SET weight = 0",
    "INSERT INTO foo VALUES (1)",
    "ALTER TABLE x ADD COLUMN y INT",
    "GRANT ALL ON db.* TO 'agent'",
    "REVOKE SELECT ON db.* FROM 'analyst'",
])
def test_destructive_sql_blocked(query):
    policy = GuardrailPolicy()
    v = policy.evaluate(
        "propose_query_execution",
        {"query_sql": query, "rationale": "r", "performance_impact": "low",
         "target_sql_file": "queries/CVE-2026-31431/q6.sql"},
    )
    assert not v.allowed, f"Should have blocked: {query}"
    assert v.rule_id == "DESTRUCTIVE_SQL"


def test_select_query_allowed():
    policy = GuardrailPolicy()
    v = policy.evaluate(
        "propose_query_execution",
        {"query_sql": "SELECT * FROM events WHERE updated_at > now() - interval '1 day'",
         "rationale": "investigating staging artifacts",
         "performance_impact": "low — 100 rows",
         "target_sql_file": "queries/CVE-2026-31431/q6.sql"},
    )
    assert v.allowed, v.reason


# --- propose_query_execution: target_sql_file scope -----------------------
@pytest.mark.parametrize("path,rule", [
    ("/etc/passwd",                       "PATH_TRAVERSAL"),
    ("../../scripts/thioclaw_agent/prompts.py", "PATH_TRAVERSAL"),
    ("scripts/thioclaw.py",               "TARGET_OUT_OF_SCOPE"),
    ("README.md",                         "TARGET_OUT_OF_SCOPE"),
])
def test_target_sql_file_out_of_scope(path, rule):
    policy = GuardrailPolicy()
    v = policy.evaluate(
        "propose_query_execution",
        {"query_sql": "SELECT 1", "rationale": "r", "performance_impact": "low",
         "target_sql_file": path},
    )
    assert not v.allowed
    assert v.rule_id == rule


def test_target_sql_file_in_signals_allowed():
    policy = GuardrailPolicy()
    v = policy.evaluate(
        "propose_query_execution",
        {"query_sql": "SELECT 1", "rationale": "r", "performance_impact": "low",
         "target_sql_file": "signals/CVE-2026-31431.yaml"},
    )
    assert v.allowed, v.reason


# --- submit_verdict validation --------------------------------------------
def test_valid_verdict_allowed():
    policy = GuardrailPolicy()
    v = policy.evaluate("submit_verdict", {
        "verdict": "exploited", "confidence": 0.9,
        "reasoning_trace": "Q3 + Q4 fired together.",
        "recommended_action": "Isolate host.",
    })
    assert v.allowed, v.reason


def test_invalid_verdict_enum_blocked():
    policy = GuardrailPolicy()
    v = policy.evaluate("submit_verdict", {
        "verdict": "definitely_pwned", "confidence": 0.9,
        "reasoning_trace": "...", "recommended_action": "...",
    })
    assert not v.allowed
    assert v.rule_id == "INVALID_VERDICT"


@pytest.mark.parametrize("conf", [-0.1, 1.5, "high", None])
def test_invalid_confidence_blocked(conf):
    policy = GuardrailPolicy()
    v = policy.evaluate("submit_verdict", {
        "verdict": "suspicious", "confidence": conf,
        "reasoning_trace": "...", "recommended_action": "...",
    })
    assert not v.allowed
    assert v.rule_id == "INVALID_CONFIDENCE"


def test_empty_reasoning_blocked():
    policy = GuardrailPolicy()
    v = policy.evaluate("submit_verdict", {
        "verdict": "benign", "confidence": 0.5,
        "reasoning_trace": "   ", "recommended_action": "monitor",
    })
    assert not v.allowed
    assert v.rule_id == "EMPTY_REASONING"


# --- Call budgets ----------------------------------------------------------
def test_total_call_budget_enforced():
    policy = GuardrailPolicy(max_total_calls=3, max_per_tool_calls=10)
    for _ in range(3):
        assert policy.evaluate("get_tier1_summary", {}).allowed
    v = policy.evaluate("get_tier1_summary", {})
    assert not v.allowed
    assert v.rule_id == "TOTAL_CALL_BUDGET"


def test_per_tool_call_budget_enforced():
    policy = GuardrailPolicy(max_total_calls=100, max_per_tool_calls=2)
    assert policy.evaluate("get_tier1_summary", {}).allowed
    assert policy.evaluate("get_tier1_summary", {}).allowed
    v = policy.evaluate("get_tier1_summary", {})
    assert not v.allowed
    assert v.rule_id == "PER_TOOL_CALL_BUDGET"


def test_per_tool_budget_does_not_leak_across_tools():
    policy = GuardrailPolicy(max_total_calls=100, max_per_tool_calls=2)
    # Hit the per-tool cap on one tool, then verify another tool still works.
    for _ in range(2):
        assert policy.evaluate("get_tier1_summary", {}).allowed
    assert not policy.evaluate("get_tier1_summary", {}).allowed
    assert policy.evaluate("get_cve_theoretical_path", {}).allowed
