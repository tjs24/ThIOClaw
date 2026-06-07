"""
scripts/thioclaw_agent_strands/hooks.py
---------------------------------------
Strands HookProvider implementations for ThIOClaw Tier 2 agents.

Two providers, kept separate so consumers can mix-and-match (e.g. enable
observability in staging but loosen guardrails for an exploratory run):

  ObservabilityHooks   →  emits structured events at every lifecycle point
  GuardrailHooks       →  evaluates the shared guardrails policy and uses
                          Strands' BeforeToolCallEvent.cancel_tool to block
                          unsafe calls before they execute

Both delegate to observability/agent_events.py and observability/guardrails.py
so a single policy change applies to both this Strands path and the
LiteLLM-direct path.
"""
from __future__ import annotations

import time
from typing import Any

from strands.hooks import (
    AfterInvocationEvent,
    AfterToolCallEvent,
    BeforeInvocationEvent,
    BeforeToolCallEvent,
    HookProvider,
    HookRegistry,
)

from observability.agent_events import AgentEventEmitter, AgentSession
from observability.guardrails import GuardrailPolicy, classify


def _tool_name(event: BeforeToolCallEvent | AfterToolCallEvent) -> str:
    return event.tool_use.get("name", "<unknown>")


def _tool_args(event: BeforeToolCallEvent | AfterToolCallEvent) -> dict:
    raw = event.tool_use.get("input", {})
    return raw if isinstance(raw, dict) else {}


class ObservabilityHooks(HookProvider):
    """Emits structured events for invocation start/end and every tool call.

    Tracks per-tool start times in an instance dict keyed by tool_use_id so
    latency measurements survive Strands' async/streaming tool dispatch.
    """

    def __init__(self, emitter: AgentEventEmitter):
        self.emitter = emitter
        self._tool_starts: dict[str, tuple[float, str, dict]] = {}
        self._invocation_start_ns: int = 0
        self._tool_call_count: int = 0

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeInvocationEvent, self._on_invocation_start)
        registry.add_callback(AfterInvocationEvent, self._on_invocation_end)
        registry.add_callback(BeforeToolCallEvent, self._on_tool_start)
        registry.add_callback(AfterToolCallEvent, self._on_tool_end)

    def _on_invocation_start(self, event: BeforeInvocationEvent) -> None:
        self._invocation_start_ns = time.monotonic_ns()
        self.emitter.invocation_start()

    def _on_invocation_end(self, event: AfterInvocationEvent) -> None:
        elapsed_ms = (time.monotonic_ns() - self._invocation_start_ns) // 1_000_000
        # The verdict is captured via VerdictCapture in tools.py; the emitter
        # just records that the invocation closed and how many turns we used.
        self.emitter.invocation_end(verdict=None, elapsed_ms=int(elapsed_ms),
                                    turns=self._tool_call_count)

    def _on_tool_start(self, event: BeforeToolCallEvent) -> None:
        tool = _tool_name(event)
        args = _tool_args(event)
        safety = classify(tool)
        self._tool_call_count += 1
        self._tool_starts[event.tool_use["toolUseId"]] = (
            time.monotonic_ns(), tool, args,
        )
        self.emitter.tool_call_start(
            tool=tool, safety_class=safety, args=args,
            turn_idx=self._tool_call_count,
        )

    def _on_tool_end(self, event: AfterToolCallEvent) -> None:
        tool = _tool_name(event)
        safety = classify(tool)
        start = self._tool_starts.pop(event.tool_use["toolUseId"], None)
        latency_ms = 0
        if start:
            latency_ms = (time.monotonic_ns() - start[0]) // 1_000_000

        # cancel_message set means an earlier hook blocked it.
        # exception set means the tool body raised.
        if event.cancel_message:
            status, err = "blocked", event.cancel_message
        elif event.exception is not None:
            status, err = "error", repr(event.exception)
        else:
            status, err = "ok", None

        self.emitter.tool_call_end(
            tool=tool, safety_class=safety, status=status,
            latency_ms=int(latency_ms), error=err,
        )


class GuardrailHooks(HookProvider):
    """Enforces the shared safety policy via BeforeToolCallEvent.cancel_tool.

    When evaluate() returns allowed=False, we set `cancel_tool` to the
    rule_id|reason string. Strands then short-circuits the tool dispatch and
    surfaces the cancel message as a tool result to the model — the agent
    sees the block and can adjust, but cannot execute the blocked call.
    """

    def __init__(self, policy: GuardrailPolicy, emitter: AgentEventEmitter):
        self.policy = policy
        self.emitter = emitter

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self._on_tool_start)

    def _on_tool_start(self, event: BeforeToolCallEvent) -> None:
        tool = _tool_name(event)
        args = _tool_args(event)
        verdict = self.policy.evaluate(tool, args)
        if verdict.allowed:
            return

        self.emitter.guardrail_block(
            tool=tool, rule=verdict.rule_id or "UNKNOWN",
            reason=verdict.reason or "blocked",
        )
        # The cancel_tool string becomes the tool's "result" for this turn.
        # Include the rule_id so the model sees structured feedback.
        event.cancel_tool = f"[GUARDRAIL_BLOCK:{verdict.rule_id}] {verdict.reason}"
