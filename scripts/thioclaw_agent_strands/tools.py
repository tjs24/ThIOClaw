"""
Strands @tool-decorated wrappers around the existing ThIOClaw tool implementations.

We reuse thioclaw_agent/tools.py's helpers (get_tier1_summary, get_cve_theoretical_path,
get_exploit_evidence) and wrap them in Strands @tool decorators. Path arguments
(tier1_path, signals_path) are captured via a closure in build_tools() since they
are session-bound (one investigation = one Tier 1 file = one signals file) and
the model should not have to track them per call.

submit_verdict() captures the verdict into a session-scoped VerdictCapture object,
so the harness can extract it after the Strands agent loop returns.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from strands import tool

from observability.agent_events import AgentEventEmitter
# Reuse the existing implementations — Tier 1 reading is identical regardless
# of which framework drives Tier 2.
from thioclaw_agent.tools import (
    get_tier1_summary as _read_tier1_summary,
    get_cve_theoretical_path as _read_cve_theoretical_path,
    get_exploit_evidence as _read_exploit_evidence,
)


@dataclass
class VerdictCapture:
    """Session-scoped holder for the final verdict.

    submit_verdict() writes into this; the harness reads from it after the
    Strands agent loop returns. Avoids raising sentinel exceptions to break
    out of the loop.
    """
    verdict: Optional[dict] = field(default=None)


def build_tools(
    tier1_path: str,
    signals_path: str,
    capture: VerdictCapture,
    emitter: Optional[AgentEventEmitter] = None,
) -> list:
    """Return a list of Strands @tool-decorated callables bound to this session.

    The path args and capture object are closed over so the model sees clean,
    no-argument or signal-arg-only tools rather than tools that demand state
    paths the LLM cannot infer.

    If `emitter` is provided, HITL prompts and analyst decisions inside
    propose_query_execution are logged as structured events so the audit
    trail records *who decided what* on every state-changing call.
    """

    @tool
    def get_tier1_summary() -> str:
        """Read the deterministic Tier 1 summary for this investigation.

        Returns a JSON string containing the CVE ID, total signal weight, and
        the list of signal IDs that fired. Call this FIRST.
        """
        return _read_tier1_summary(tier1_path)

    @tool
    def get_cve_theoretical_path() -> str:
        """Read the theoretical exploit chain and rule definitions for the
        target CVE from its signals YAML.

        Returns a JSON-encoded representation of the CVE's signal rules,
        verdict logic, block describing the theoretical exploit chain. Use this to map fired signals to
        steps in the expected exploit chain.
        """
        return _read_cve_theoretical_path(signals_path)

    @tool
    def get_exploit_evidence(signal_name: str) -> str:
        """Fetch raw telemetry rows backing a specific Tier 1 signal.

        Args:
            signal_name: One of the signal IDs from get_tier1_summary()
                (e.g. UID_ESCALATION_AFTER_AFALG).

        Returns up to 5 raw event rows for inspection. Use this for any
        suspicious signal whose underlying evidence you need to verify
        before reaching a verdict.
        """
        return _read_exploit_evidence(tier1_path, signal_name)

    @tool
    def propose_query_execution(
        query_sql: str,
        rationale: str,
        performance_impact: str,
        target_sql_file: str,
    ) -> str:
        """Propose a new or modified query to the analyst for HITL approval.

        Use this when existing Tier 1 queries are insufficient to reach a
        confident verdict. The analyst will see the rationale, performance
        impact, and proposed query, and decide whether to execute. If
        executed and the result is useful, the analyst is also prompted to
        approve updating the signature SQL file.

        Args:
            query_sql: The exact SQL or pandas code to execute.
            rationale: Why this execution is necessary.
            performance_impact: Estimated cost (e.g. 'Low - filters 100 rows').
            target_sql_file: The signature file to update if approved
                (e.g. queries/CVE-2026-31431/q6.sql).
        """
        args = {
            "query_sql": query_sql, "rationale": rationale,
            "performance_impact": performance_impact, "target_sql_file": target_sql_file,
        }
        if emitter:
            emitter.hitl_prompt(tool="propose_query_execution", args=args)
        print("\n[ThIOClaw Agent / Strands] Proposing Query Execution:")
        print(f"Rationale: {rationale}")
        print(f"Performance Impact: {performance_impact}")
        print(f"Query:\n{query_sql}\n")

        approval = input("Approve execution? (y/N): ")
        if not approval.lower().startswith("y"):
            if emitter:
                emitter.hitl_decision("propose_query_execution", "rejected", "query_execution")
            return "Execution rejected by analyst."

        if emitter:
            emitter.hitl_decision("propose_query_execution", "approved", "query_execution")
        print("\n... executing ...")
        # MOCK execution — same stub as the litellm-direct variant.
        # Real backend wiring lives behind the contract's hitl_workflow seam.
        result = "Query executed successfully. Returned 4 suspicious rows."
        print(f"{result}\n")

        update_approval = input(
            f"[ThIOClaw Agent / Strands] Approve updating {target_sql_file}? (y/N): "
        )
        if update_approval.lower().startswith("y"):
            if emitter:
                emitter.hitl_decision("propose_query_execution", "approved", "signature_update")
            result += f" Target file {target_sql_file} updated."
            print(f"-> Updated {target_sql_file}")
        else:
            if emitter:
                emitter.hitl_decision("propose_query_execution", "rejected", "signature_update")
            result += " Target file update rejected by analyst."
        return result

    @tool
    def submit_verdict(
        verdict: str,
        confidence: float,
        reasoning_trace: str,
        recommended_action: str,
    ) -> str:
        """Submit the final investigation verdict. This is the TERMINAL action;
        after calling this, your investigation is complete.

        Args:
            verdict: One of: exploited, suspicious, benign, inconclusive.
            confidence: 0.0 to 1.0.
            reasoning_trace: Markdown explanation. MUST cite the Tier 1 signal
                IDs that fired and map them to the theoretical exploit chain.
            recommended_action: Immediate remediation step.
        """
        capture.verdict = {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning_trace": reasoning_trace,
            "recommended_action": recommended_action,
        }
        return f"Verdict '{verdict}' submitted. Investigation complete."

    return [
        get_tier1_summary,
        get_cve_theoretical_path,
        get_exploit_evidence,
        propose_query_execution,
        submit_verdict,
    ]
