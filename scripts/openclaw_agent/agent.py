import json
import os
import sys
from pathlib import Path

# Add project root to sys.path to import observability
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
try:
    from observability.traces import get_tracer
except ImportError:
    # Fallback dummy tracer if observability module is missing
    class DummySpan:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def set_attribute(self, *args): pass
    class DummyTracer:
        def start_as_current_span(self, *args): return DummySpan()
    def get_tracer(): return DummyTracer()

from openclaw_agent.prompts import SYSTEM_PROMPT

class OpenClawAgent:
    def __init__(self):
        self.tracer = get_tracer()
        
    def run_investigation(self, cve_id: str, workload_id: str, tier1_path: str, signals_path: str, telemetry_source: str) -> dict:
        with self.tracer.start_as_current_span("openclaw.agent.investigate") as span:
            span.set_attribute("cve_id", cve_id)
            span.set_attribute("workload_id", workload_id)
            
            with open(tier1_path) as f:
                tier1_data = json.load(f)
                
            # TODO: Integrate actual LLM provider here using SYSTEM_PROMPT
            # For this scaffolding step, we mock the LLM reasoning to ensure the
            # Control Plane -> Data Plane hand-off and Observability tracing work end-to-end.
            total_weight = tier1_data.get("total_weight", 0.0)
            
            verdict = "suspicious"
            if total_weight >= 1.0:
                verdict = "exploited"
            elif total_weight == 0.0:
                verdict = "benign"
                
            return {
                "verdict": verdict,
                "confidence": min(total_weight, 1.0),
                "reasoning_trace": f"Analyzed {cve_id}. Data plane signal weight: {total_weight}. Simulated agent trace.",
                "recommended_action": "Isolate workload if exploited, otherwise monitor."
            }
