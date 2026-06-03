"""
Strands-based OpenClaw agent (Tier 2 reasoning).

Parallel implementation to openclaw_agent/agent.py (the LiteLLM-direct path).
Both satisfy the same harness contract: given a tier1.json path and a signals
YAML path, run a tool-using agentic loop to produce a verdict dict with
keys: verdict, confidence, reasoning_trace, recommended_action.

Selected via OPENCLAW_FRAMEWORK=strands in scripts/openclaw.py.

Model routing reuses the existing openclaw_agent.providers module so the same
provider profiles (Ollama, Anthropic, OpenAI, Bedrock, Vertex, gateway) work
across both frameworks. Strands' LiteLLMModel adapter accepts any LiteLLM
model string.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
try:
    from observability.traces import get_tracer
except ImportError:
    class _DummySpan:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def set_attribute(self, *args): pass
    class _DummyTracer:
        def start_as_current_span(self, *args): return _DummySpan()
    def get_tracer(): return _DummyTracer()

from strands import Agent
from strands.models.litellm import LiteLLMModel

from openclaw_agent.providers import (
    resolve_provider,
    check_required_env,
    completion_kwargs,
)
from openclaw_agent_strands.prompts import SYSTEM_PROMPT
from openclaw_agent_strands.tools import build_tools, VerdictCapture


class OpenClawStrandsAgent:
    """Tier 2 agent loop driven by the Strands SDK."""

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
        with self.tracer.start_as_current_span("openclaw.agent.investigate") as span:
            span.set_attribute("cve_id", cve_id)
            span.set_attribute("workload_id", workload_id)
            span.set_attribute("agent.framework", "strands")

            resolution = resolve_provider()
            span.set_attribute("llm_provider", resolution.provider)
            span.set_attribute("llm_model", resolution.model)

            missing = check_required_env(resolution)
            if missing:
                print(
                    f"[OpenClaw Agent / Strands] Warning: required env vars not set "
                    f"for provider '{resolution.provider}': {missing}. LiteLLM may "
                    f"still succeed via boto3 chain / gcloud ADC."
                )

            kwargs = completion_kwargs(resolution)
            # Strands' LiteLLMModel takes model_id + client_args + params.
            # client_args -> args for the LiteLLM client (api_key, base_url).
            # params      -> LiteLLM completion params (provider-specific
            #                extras like aws_region_name, vertex_project, etc.).
            client_args: dict = {}
            if kwargs.get("base_url"):
                client_args["base_url"] = kwargs["base_url"]
            if kwargs.get("api_key"):
                client_args["api_key"] = kwargs["api_key"]
            params: dict = {k: v for k, v in kwargs.items()
                            if k not in ("model", "base_url", "api_key")}

            # Always pass a dict (even if empty) — Strands' format_request
            # spreads self.config.params and trips on None.
            model = LiteLLMModel(
                client_args=client_args or None,
                model_id=resolution.model,
                params=params,
            )

            capture = VerdictCapture()
            tools = build_tools(tier1_path, signals_path, capture)

            agent = Agent(
                model=model,
                tools=tools,
                system_prompt=SYSTEM_PROMPT,
            )

            # Single user turn kicks off the loop; the agent will tool-call
            # its way to a verdict and terminate when submit_verdict is called.
            agent(
                f"Investigate workload '{workload_id}' for {cve_id}. "
                f"Begin by reading the Tier 1 summary, then the theoretical exploit "
                f"path, then any signal-specific evidence you need. End by submitting "
                f"your verdict."
            )

            if capture.verdict is not None:
                return capture.verdict

            return {
                "verdict": "inconclusive",
                "confidence": 0.0,
                "reasoning_trace": (
                    "Strands agent loop returned without calling submit_verdict. "
                    "This may indicate a tool-call validity failure, model-side "
                    "refusal, or token / turn budget exhaustion. Manual review required."
                ),
                "recommended_action": "Manual review required.",
            }
