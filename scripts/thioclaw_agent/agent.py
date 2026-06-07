"""
scripts/thioclaw_agent/agent.py
-------------------------------
Raw LiteLLM tool-calling loop for the ThIOClaw Tier 2 agent.

Mirrors the Strands variant (scripts/thioclaw_agent_strands/agent.py) in
observability and guardrails: both paths emit the same structured event
taxonomy (observability/agent_events.py) and consult the same policy
(observability/guardrails.py) before executing any tool.

Selected via THIOCLAW_FRAMEWORK=litellm-direct (or by default).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import litellm

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
try:
    from observability.traces import get_tracer
except ImportError:
    class DummySpan:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def set_attribute(self, *args): pass
    class DummyTracer:
        def start_as_current_span(self, *args): return DummySpan()
    def get_tracer(): return DummyTracer()

from observability.agent_events import AgentEventEmitter, AgentSession
from observability.guardrails import GuardrailPolicy, classify
from thioclaw_agent.prompts import SYSTEM_PROMPT
from thioclaw_agent.tools import (
    AVAILABLE_TOOLS,
    get_tier1_summary,
    get_cve_theoretical_path,
    get_exploit_evidence,
)
from thioclaw_agent.providers import resolve_provider, check_required_env, completion_kwargs


MAX_TURNS = 15


class ThIOClawAgent:
    def __init__(self):
        self.tracer = get_tracer()

    def run_investigation(
        self,
        cve_id: str,
        workload_id: str,
        tier1_path: str,
        signals_path: str,
        telemetry_source: str,
    ) -> dict:
        with self.tracer.start_as_current_span("thioclaw.agent.investigate") as span:
            span.set_attribute("cve_id", cve_id)
            span.set_attribute("workload_id", workload_id)

            resolution = resolve_provider()
            span.set_attribute("llm_provider", resolution.provider)
            span.set_attribute("llm_model", resolution.model)

            missing = check_required_env(resolution)
            if missing:
                print(
                    f"[ThIOClaw Agent] Warning: required env vars not set for provider "
                    f"'{resolution.provider}': {missing}. LiteLLM may still succeed if "
                    f"creds come from another source (boto3 chain, gcloud ADC, etc)."
                )

            base_completion_kwargs = completion_kwargs(resolution)
            session = AgentSession(
                cve_id=cve_id,
                workload_id=workload_id,
                framework="litellm-direct",
                provider=resolution.provider,
                model=resolution.model,
            )
            emitter = AgentEventEmitter(session)
            policy = GuardrailPolicy()
            emitter.invocation_start()

            invocation_start_ns = time.monotonic_ns()
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            tool_call_count = 0
            final_verdict: dict | None = None

            for i in range(MAX_TURNS):
                response = litellm.completion(
                    messages=messages,
                    tools=AVAILABLE_TOOLS,
                    tool_choice="auto",
                    **base_completion_kwargs,
                )

                # --- Per-turn token/cost accounting (commented; fallback path) ----
                # When PurpleClaw runs through the llm-gateway, accounting comes from
                # the gateway's /v1/usage endpoint (single source of truth, all turns).
                # Without the gateway (direct provider mode), capture per-turn usage
                # here. `response.usage` is an attribute on the LiteLLM response object,
                # not a function call. Uncomment to enable:
                #
                # usage = getattr(response, "usage", None)
                # if usage:
                #     span.set_attribute("turn.prompt_tokens", usage.prompt_tokens)
                #     span.set_attribute("turn.completion_tokens", usage.completion_tokens)
                #     span.set_attribute("turn.total_tokens", usage.total_tokens)
                # try:
                #     cost_usd = litellm.completion_cost(completion_response=response)
                #     span.set_attribute("turn.cost_usd", cost_usd)
                # except Exception:
                #     pass
                # ------------------------------------------------------------------

                message = response.choices[0].message
                if not message.tool_calls:
                    # Model answered without a tool call - prompt it to submit the verdict
                    messages.append({"role": "assistant", "content": message.content or ""})
                    messages.append({"role": "user", "content": "Please submit your final verdict using the `submit_verdict` tool."})
                    continue

                messages.append(message)  # Append assistant's tool call

                for tool_call in message.tool_calls:
                    tool_call_count += 1
                    func_name = tool_call.function.name
                    try:
                        args = json.loads(tool_call.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {}

                    result, terminal_verdict = self._dispatch_tool(
                        func_name=func_name,
                        args=args,
                        emitter=emitter,
                        policy=policy,
                        turn_idx=tool_call_count,
                        tier1_path=tier1_path,
                        signals_path=signals_path,
                    )
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": str(result),
                    })
                    if terminal_verdict is not None:
                        final_verdict = terminal_verdict
                        break

                if final_verdict is not None:
                    break

            elapsed_ms = (time.monotonic_ns() - invocation_start_ns) // 1_000_000
            emitter.invocation_end(verdict=final_verdict, elapsed_ms=int(elapsed_ms),
                                   turns=tool_call_count)

            if final_verdict is not None:
                return final_verdict
            return {
                "verdict": "inconclusive",
                "reasoning_trace": "Agent exhausted maximum tool iterations without submitting a verdict.",
                "confidence": 0.0,
                "recommended_action": "Manual review required.",
            }

    # ------------------------------------------------------------------
    # Tool dispatch — single seam where observability + guardrails apply
    # ------------------------------------------------------------------
    def _dispatch_tool(
        self,
        func_name: str,
        args: dict,
        emitter: AgentEventEmitter,
        policy: GuardrailPolicy,
        turn_idx: int,
        tier1_path: str,
        signals_path: str,
    ) -> tuple[str, dict | None]:
        """Run one tool call with observability + guardrails.

        Returns (tool_result_string, terminal_verdict_or_None). When
        terminal_verdict is non-None, the agent loop should exit.
        """
        safety = classify(func_name)
        emitter.tool_call_start(tool=func_name, safety_class=safety,
                                args=args, turn_idx=turn_idx)

        # Guardrail gate.
        verdict = policy.evaluate(func_name, args)
        if not verdict.allowed:
            emitter.guardrail_block(tool=func_name,
                                    rule=verdict.rule_id or "UNKNOWN",
                                    reason=verdict.reason or "blocked")
            block_msg = f"[GUARDRAIL_BLOCK:{verdict.rule_id}] {verdict.reason}"
            emitter.tool_call_end(tool=func_name, safety_class=safety,
                                  status="blocked", latency_ms=0, error=block_msg)
            return block_msg, None

        started_ns = time.monotonic_ns()
        terminal: dict | None = None
        try:
            if func_name == "submit_verdict":
                terminal = args
                result = f"Verdict '{args.get('verdict')}' recorded."
            elif func_name == "get_tier1_summary":
                result = get_tier1_summary(tier1_path)
            elif func_name == "get_cve_theoretical_path":
                result = get_cve_theoretical_path(signals_path)
            elif func_name == "get_exploit_evidence":
                result = get_exploit_evidence(tier1_path, args.get("signal_name"))
            elif func_name == "propose_query_execution":
                result = self._run_hitl_query_proposal(args, emitter)
            else:
                # Unknown tool — guardrails fail closed, but route through
                # the same exit so the loop sees a sane error string.
                result = f"Unknown tool '{func_name}'."
                emitter.tool_call_end(tool=func_name, safety_class=safety,
                                      status="error", latency_ms=0,
                                      error="unknown_tool")
                return result, None
        except Exception as exc:
            elapsed_ms = (time.monotonic_ns() - started_ns) // 1_000_000
            emitter.tool_call_end(tool=func_name, safety_class=safety,
                                  status="error", latency_ms=int(elapsed_ms),
                                  error=repr(exc))
            return f"Tool '{func_name}' raised: {exc!r}", None

        elapsed_ms = (time.monotonic_ns() - started_ns) // 1_000_000
        emitter.tool_call_end(tool=func_name, safety_class=safety,
                              status="ok", latency_ms=int(elapsed_ms))
        return str(result), terminal

    def _run_hitl_query_proposal(self, args: dict, emitter: AgentEventEmitter) -> str:
        """Mock HITL flow with structured event capture.

        Real execution backend is not yet wired; the prompt + decision
        capture matches the Strands variant verbatim so audit trails are
        framework-independent."""
        emitter.hitl_prompt(tool="propose_query_execution", args=args)
        print("\n[ThIOClaw Agent] Proposing Query Execution:")
        print(f"Rationale: {args.get('rationale')}")
        print(f"Performance Impact: {args.get('performance_impact')}")
        print(f"Query:\n{args.get('query_sql')}\n")

        approval = input("Approve execution? (y/N): ")
        if not approval.lower().startswith("y"):
            emitter.hitl_decision("propose_query_execution", "rejected", "query_execution")
            return "Execution rejected by analyst."

        emitter.hitl_decision("propose_query_execution", "approved", "query_execution")
        print("\n... executing ...")
        # MOCK execution — same stub as the Strands variant.
        result = "Query executed successfully. Returned 4 suspicious rows."
        print(f"{result}\n")

        target = args.get("target_sql_file")
        update_approval = input(
            f"[ThIOClaw Agent] Do you approve updating the signature file {target} with this query? (y/N): "
        )
        if update_approval.lower().startswith("y"):
            emitter.hitl_decision("propose_query_execution", "approved", "signature_update")
            result += f" Target file {target} updated."
            print(f"-> Updated {target}")
        else:
            emitter.hitl_decision("propose_query_execution", "rejected", "signature_update")
            result += " Target file update rejected by analyst."
        return result
