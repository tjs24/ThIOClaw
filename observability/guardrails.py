"""
observability/guardrails.py
---------------------------
Pre-tool-call safety policy for the ThIOClaw Tier 2 agent.

This module is the single source of truth for "what is this tool allowed to
do, and under what conditions?" Both framework paths (LiteLLM-direct and
Strands) call into the same `evaluate()` function before executing any tool,
so a policy change here propagates to both loops without touching framework
glue.

Design intent (matches PRD v0.3.1 hybrid HITL model):

    safety_class: read_only       | state_changing | terminal
    enforcement:  always allow    | guarded + HITL | validated + capped

Specifically what we block today:

  1. Destructive SQL in propose_query_execution.query_sql
     (DELETE / DROP / TRUNCATE / UPDATE / INSERT / ALTER / GRANT / REVOKE).
     Telemetry queries must be SELECT-shaped.

  2. Path traversal / absolute paths in signal_name or target_sql_file.
     Tools should reference repo-relative paths only.

  3. submit_verdict arg validation: verdict in the allowed enum,
     confidence in [0, 1], reasoning_trace non-empty.
     Defense-in-depth — the model can usually do this, but the policy
     refuses to record a clearly malformed verdict.

  4. Per-investigation tool-call budget (default 30 calls total) +
     per-tool budget (default 10). Bounds runaway loops even if the
     LLM gets stuck mid-investigation.

  5. target_sql_file write target must live under queries/ or signals/.
     Prevents the agent from proposing edits to source code, agent
     prompts, or anything outside the detection-logic surface.

Each rule has a stable `rule_id` so guardrail_block events are queryable
by which policy fired (e.g. "show me all DESTRUCTIVE_SQL hits this week").
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


# --- Safety classification ------------------------------------------------
SAFETY_READ_ONLY = "read_only"
SAFETY_STATE_CHANGING = "state_changing"
SAFETY_TERMINAL = "terminal"

TOOL_SAFETY_CLASS: dict[str, str] = {
    "get_tier1_summary":        SAFETY_READ_ONLY,
    "get_cve_theoretical_path": SAFETY_READ_ONLY,
    "get_exploit_evidence":     SAFETY_READ_ONLY,
    "propose_query_execution":  SAFETY_STATE_CHANGING,
    "submit_verdict":           SAFETY_TERMINAL,
}


def classify(tool_name: str) -> str:
    """Return the safety class of `tool_name`. Unknown tools are treated as
    state_changing — fail closed, not open."""
    return TOOL_SAFETY_CLASS.get(tool_name, SAFETY_STATE_CHANGING)


# --- Policy rules ---------------------------------------------------------
# SQL keywords we refuse to let the agent propose in query_sql. The match is
# word-boundary-bound and case-insensitive so 'updated_at' (a column name) is
# not mistaken for 'UPDATE'.
_DESTRUCTIVE_SQL_PATTERN = re.compile(
    r"\b(DELETE|DROP|TRUNCATE|UPDATE|INSERT|ALTER|GRANT|REVOKE|MERGE|REPLACE)\b",
    re.IGNORECASE,
)

# Paths the agent is allowed to nominate as targets for signature updates.
_ALLOWED_SIGNATURE_PREFIXES = ("queries/", "signals/")

_ALLOWED_VERDICTS = {"exploited", "suspicious", "benign", "inconclusive"}

# Default budgets. Overridable by passing a custom GuardrailPolicy.
DEFAULT_MAX_TOTAL_CALLS = 30
DEFAULT_MAX_PER_TOOL_CALLS = 10


@dataclass
class GuardrailVerdict:
    """Returned by `GuardrailPolicy.evaluate()`.

    allowed=True   → proceed.
    allowed=False  → block; `reason` is the analyst-readable message and
                     `rule_id` is the stable identifier for telemetry.
    """
    allowed: bool
    rule_id: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class GuardrailPolicy:
    """Stateful policy: tracks per-investigation call counts and enforces
    arg-level checks. One instance per agent invocation."""
    max_total_calls: int = DEFAULT_MAX_TOTAL_CALLS
    max_per_tool_calls: int = DEFAULT_MAX_PER_TOOL_CALLS
    _total_calls: int = 0
    _per_tool_calls: dict[str, int] = field(default_factory=dict)

    # --- public entry point ----------------------------------------------
    def evaluate(self, tool_name: str, args: dict[str, Any]) -> GuardrailVerdict:
        """Decide whether `tool_name(**args)` may proceed.

        Increments call counters *before* arg-level checks so a malformed
        call still counts toward the budget (otherwise an agent stuck in a
        loop emitting invalid args could spin forever)."""
        self._total_calls += 1
        self._per_tool_calls[tool_name] = self._per_tool_calls.get(tool_name, 0) + 1

        # 1. Call budgets.
        if self._total_calls > self.max_total_calls:
            return GuardrailVerdict(
                allowed=False,
                rule_id="TOTAL_CALL_BUDGET",
                reason=(
                    f"Investigation exceeded {self.max_total_calls} total tool "
                    f"calls. Aborting to prevent runaway."
                ),
            )
        if self._per_tool_calls[tool_name] > self.max_per_tool_calls:
            return GuardrailVerdict(
                allowed=False,
                rule_id="PER_TOOL_CALL_BUDGET",
                reason=(
                    f"Tool '{tool_name}' called more than {self.max_per_tool_calls} "
                    f"times in one investigation."
                ),
            )

        # 2. Arg-level checks per tool.
        if tool_name == "propose_query_execution":
            return self._check_propose_query(args)
        if tool_name == "submit_verdict":
            return self._check_submit_verdict(args)
        if tool_name == "get_exploit_evidence":
            return self._check_signal_name(args.get("signal_name", ""))

        return GuardrailVerdict(allowed=True)

    # --- per-tool argument validators ------------------------------------
    def _check_propose_query(self, args: dict[str, Any]) -> GuardrailVerdict:
        query = (args.get("query_sql") or "").strip()
        target = (args.get("target_sql_file") or "").strip()

        if not query:
            return GuardrailVerdict(False, "EMPTY_QUERY",
                                    "propose_query_execution called with empty query_sql.")

        m = _DESTRUCTIVE_SQL_PATTERN.search(query)
        if m:
            return GuardrailVerdict(
                False,
                "DESTRUCTIVE_SQL",
                f"Proposed query contains disallowed keyword '{m.group(0).upper()}'. "
                f"Telemetry queries must be SELECT-shaped.",
            )

        if target:
            if any(seg in target for seg in ("..", "\x00")) or target.startswith("/"):
                return GuardrailVerdict(
                    False, "PATH_TRAVERSAL",
                    f"target_sql_file '{target}' contains path traversal or is absolute.",
                )
            if not target.startswith(_ALLOWED_SIGNATURE_PREFIXES):
                return GuardrailVerdict(
                    False, "TARGET_OUT_OF_SCOPE",
                    f"target_sql_file '{target}' is outside the detection-logic "
                    f"surface (queries/ or signals/).",
                )
        return GuardrailVerdict(allowed=True)

    def _check_submit_verdict(self, args: dict[str, Any]) -> GuardrailVerdict:
        verdict = (args.get("verdict") or "").strip().lower()
        if verdict not in _ALLOWED_VERDICTS:
            return GuardrailVerdict(
                False, "INVALID_VERDICT",
                f"verdict '{verdict}' is not in {sorted(_ALLOWED_VERDICTS)}.",
            )

        confidence = args.get("confidence")
        try:
            c = float(confidence)
        except (TypeError, ValueError):
            return GuardrailVerdict(False, "INVALID_CONFIDENCE",
                                    f"confidence '{confidence}' is not a number.")
        if not (0.0 <= c <= 1.0):
            return GuardrailVerdict(False, "INVALID_CONFIDENCE",
                                    f"confidence {c} is outside [0, 1].")

        if not (args.get("reasoning_trace") or "").strip():
            return GuardrailVerdict(False, "EMPTY_REASONING",
                                    "submit_verdict requires a non-empty reasoning_trace.")
        return GuardrailVerdict(allowed=True)

    def _check_signal_name(self, signal_name: str) -> GuardrailVerdict:
        if not signal_name:
            return GuardrailVerdict(False, "EMPTY_SIGNAL_NAME",
                                    "get_exploit_evidence requires a signal_name.")
        # Signal IDs are uppercase tokens with underscores. Anything outside
        # that shape is almost certainly a path-traversal or injection attempt.
        if not re.fullmatch(r"[A-Z0-9_]+", signal_name):
            return GuardrailVerdict(
                False, "INVALID_SIGNAL_NAME",
                f"signal_name '{signal_name}' is not a valid signal id "
                f"(uppercase letters / digits / underscore only).",
            )
        return GuardrailVerdict(allowed=True)
