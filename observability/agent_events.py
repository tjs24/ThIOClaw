"""
observability/agent_events.py
-----------------------------
Shared structured-event taxonomy for the ThIOClaw Tier 2 agent.

Both the LiteLLM-direct loop (scripts/thioclaw_agent/agent.py) and the
Strands-driven loop (scripts/thioclaw_agent_strands/agent.py) emit the same
event names with the same field shape. That keeps downstream consumers —
logs/agent_runs.jsonl tailers, bench summary aggregators, CloudWatch Logs
Insights queries — framework-agnostic.

Event names are stable. New optional fields can be added without breaking
consumers; renames or removals are breaking changes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional

from observability.logger import StructuredLogger, get_structured_logger


# --- Event names (stable identifiers downstream tools can grep on) ----------
EVENT_INVOCATION_START = "agent_invocation_start"
EVENT_INVOCATION_END = "agent_invocation_end"
EVENT_TOOL_CALL_START = "tool_call_start"
EVENT_TOOL_CALL_END = "tool_call_end"
EVENT_GUARDRAIL_BLOCK = "guardrail_block"
EVENT_HITL_PROMPT = "hitl_prompt"
EVENT_HITL_DECISION = "hitl_decision"


def fingerprint_args(args: dict) -> str:
    """Stable, short fingerprint of tool args.

    Used in logs so we can correlate calls without writing potentially
    sensitive raw payloads. Sorted-key JSON makes the hash deterministic.
    """
    try:
        canonical = json.dumps(args, sort_keys=True, default=str)
    except Exception:
        canonical = str(args)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


@dataclass
class AgentSession:
    """Per-investigation context carried alongside every emitted event.

    Constructed once at the top of run_investigation() and passed to the
    event emitter / hook providers so each line in agent_runs.jsonl can be
    correlated back to a specific CVE / workload / model.
    """
    cve_id: str
    workload_id: str
    framework: str            # 'litellm-direct' | 'strands'
    provider: str             # 'ollama' | 'bedrock' | 'anthropic' | ...
    model: str
    run_id: Optional[str] = None

    def context(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "workload_id": self.workload_id,
            "framework": self.framework,
            "provider": self.provider,
            "model": self.model,
            "run_id": self.run_id,
        }


class AgentEventEmitter:
    """Thin convenience wrapper around StructuredLogger.

    Centralises the event name + field-shape contract so framework-specific
    hook code stays small and consistent.
    """

    def __init__(self, session: AgentSession, logger: Optional[StructuredLogger] = None):
        self.session = session
        self._log = logger or get_structured_logger()

    def _emit(self, event: str, level: str = "INFO", **fields: Any) -> None:
        payload = {**self.session.context(), **fields}
        if level == "WARNING":
            self._log.warning(event, **payload)
        elif level == "ERROR":
            self._log.error(event, **payload)
        else:
            self._log.info(event, **payload)

    # --- Invocation lifecycle ---------------------------------------------
    def invocation_start(self) -> None:
        self._emit(EVENT_INVOCATION_START)

    def invocation_end(self, verdict: Optional[dict], elapsed_ms: int, turns: int) -> None:
        v = verdict or {}
        self._emit(
            EVENT_INVOCATION_END,
            verdict=v.get("verdict"),
            confidence=v.get("confidence"),
            elapsed_ms=elapsed_ms,
            turns=turns,
        )

    # --- Per-tool lifecycle -----------------------------------------------
    def tool_call_start(self, tool: str, safety_class: str, args: dict, turn_idx: int) -> None:
        self._emit(
            EVENT_TOOL_CALL_START,
            tool=tool,
            safety_class=safety_class,
            args_fingerprint=fingerprint_args(args),
            turn_idx=turn_idx,
        )

    def tool_call_end(
        self,
        tool: str,
        safety_class: str,
        status: str,                 # 'ok' | 'error' | 'blocked'
        latency_ms: int,
        error: Optional[str] = None,
    ) -> None:
        level = "ERROR" if status == "error" else ("WARNING" if status == "blocked" else "INFO")
        self._emit(
            EVENT_TOOL_CALL_END,
            level=level,
            tool=tool,
            safety_class=safety_class,
            status=status,
            latency_ms=latency_ms,
            error=error,
        )

    # --- Guardrails / HITL ------------------------------------------------
    def guardrail_block(self, tool: str, rule: str, reason: str) -> None:
        self._emit(
            EVENT_GUARDRAIL_BLOCK,
            level="WARNING",
            tool=tool,
            rule=rule,
            reason=reason,
        )

    def hitl_prompt(self, tool: str, args: dict) -> None:
        self._emit(
            EVENT_HITL_PROMPT,
            tool=tool,
            args_fingerprint=fingerprint_args(args),
        )

    def hitl_decision(self, tool: str, decision: str, scope: str) -> None:
        self._emit(
            EVENT_HITL_DECISION,
            tool=tool,
            decision=decision,      # 'approved' | 'rejected'
            scope=scope,            # 'query_execution' | 'signature_update' | ...
        )
