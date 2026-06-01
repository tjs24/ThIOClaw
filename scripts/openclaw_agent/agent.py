import json
import os
import sys
from pathlib import Path
from openai import OpenAI

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
try:
    from observability.traces import get_tracer
except ImportError:
    # Dummy tracer fallback
    class DummySpan:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def set_attribute(self, *args): pass
    class DummyTracer:
        def start_as_current_span(self, *args): return DummySpan()
    def get_tracer(): return DummyTracer()

from openclaw_agent.prompts import SYSTEM_PROMPT
from openclaw_agent.tools import AVAILABLE_TOOLS, get_tier1_summary, get_cve_theoretical_path, get_exploit_evidence

class OpenClawAgent:
    def __init__(self):
        self.tracer = get_tracer()
        self.client = OpenAI(
            base_url="http://localhost:11434/v1",
            api_key="ollama" # required but unused by Ollama
        )
        
    def run_investigation(self, cve_id: str, workload_id: str, tier1_path: str, signals_path: str, telemetry_source: str) -> dict:
        with self.tracer.start_as_current_span("openclaw.agent.investigate") as span:
            span.set_attribute("cve_id", cve_id)
            span.set_attribute("workload_id", workload_id)
            
            model = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
            span.set_attribute("llm_model", model)
            
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            
            # Start the LLM Loop
            for i in range(15): # Max 15 turns
                response = self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=AVAILABLE_TOOLS,
                    tool_choice="auto"
                )
                
                message = response.choices[0].message
                if message.tool_calls:
                    messages.append(message) # Append assistant's tool call
                    
                    for tool_call in message.tool_calls:
                        func_name = tool_call.function.name
                        
                        if func_name == "submit_verdict":
                            # We got our final verdict!
                            args = json.loads(tool_call.function.arguments)
                            return args
                        elif func_name == "get_tier1_summary":
                            result = get_tier1_summary(tier1_path)
                        elif func_name == "get_cve_theoretical_path":
                            result = get_cve_theoretical_path(signals_path)
                        elif func_name == "get_exploit_evidence":
                            args = json.loads(tool_call.function.arguments)
                            result = get_exploit_evidence(tier1_path, args.get("signal_name"))
                        elif func_name == "propose_query_execution":
                            args = json.loads(tool_call.function.arguments)
                            print(f"\n[OpenClaw Agent] Proposing Query Execution:")
                            print(f"Rationale: {args.get('rationale')}")
                            print(f"Performance Impact: {args.get('performance_impact')}")
                            print(f"Query:\n{args.get('query_sql')}\n")
                            
                            approval = input("Approve execution? (y/N): ")
                            if approval.lower().startswith('y'):
                                print("\n... executing ...")
                                # MOCK execution since we don't have a real SQL DB hooked up yet
                                result = "Query executed successfully. Returned 4 suspicious rows."
                                print(f"{result}\n")
                                
                                update_approval = input(f"[OpenClaw Agent] Do you approve updating the signature file {args.get('target_sql_file')} with this query? (y/N): ")
                                if update_approval.lower().startswith('y'):
                                    result += f" Target file {args.get('target_sql_file')} updated."
                                    print(f"-> Updated {args.get('target_sql_file')}")
                                else:
                                    result += " Target file update rejected by analyst."
                            else:
                                result = "Execution rejected by analyst."
                            
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": str(result)
                        })
                else:
                    # Model answered without a tool call - prompt it to submit the verdict
                    messages.append({"role": "assistant", "content": message.content or ""})
                    messages.append({"role": "user", "content": "Please submit your final verdict using the `submit_verdict` tool."})
                    
            return {"verdict": "inconclusive", "reasoning_trace": "Agent exhausted maximum tool iterations without submitting a verdict.", "confidence": 0.0, "recommended_action": "Manual review required."}
