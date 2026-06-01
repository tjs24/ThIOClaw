# CLAUDE.md — ThIOClaw Project Guide

## Why This Project Exists

Security operations is undergoing a fundamental shift. LLMs are being embedded into detection and response workflows at an accelerating pace — but the way most teams adopt them is **dangerously opaque**. Managed AI features ship as black boxes: you cannot inspect the reasoning, you cannot reproduce a verdict, you cannot version-control the logic, and you cannot evaluate whether the agent actually improved your security posture or just generated convincing-sounding text.

**ThIOClaw exists because engineering-first detection & response workflows demand:**

- **Transparency.** Every reasoning step the LLM takes — every tool call, every piece of evidence it examined, every verdict it reached — must be visible, logged, and auditable. Security teams cannot accept "the AI said so" as a justification for incident response actions. ThIOClaw logs the full agentic trace (tool calls, intermediate results, final verdicts) in structured JSONL and OpenTelemetry spans so that every investigation is fully reconstructable after the fact.

- **Repeatability.** Given the same telemetry input and the same signal rules, ThIOClaw's Tier 1 (deterministic pandas scoring) produces the exact same verdict every time. The LLM is confined to Tier 2 reasoning *on top of* deterministic foundations — it does not control the signal scoring math. This means investigations are reproducible and auditable even if the LLM's behavior varies between runs.

- **Configurability.** Signal rules, weights, verdict thresholds, exploit chain descriptions, and query logic are all defined in version-controlled YAML and Python files — not hidden in a vendor dashboard. Security engineers can tune weights, add new CVE targets, or redefine what "exploited" means by editing a YAML file and committing the change. The LLM's system prompt, available tools, and behavioral constraints are all source code.

- **Version Control.** Every component of the investigation pipeline — from the signal rules (`signals/CVE-*.yaml`) to the data plane analysis logic (`data_plane/cve_*.py`) to the agent's system prompt (`scripts/openclaw_agent/prompts.py`) — lives in Git. Changes to detection logic produce clean diffs. Teams can review, approve, and roll back changes to their threat-hunting workflows using the same engineering practices they use for production code.

- **Evaluability of Agentic Workflows.** This is the hardest problem and the core reason ThIOClaw exists. When you give an LLM agent tools and autonomy, how do you know it's actually making good decisions? ThIOClaw provides the scaffolding to answer this: deterministic Tier 1 scoring as a baseline, structured Tier 2 agent traces for comparison, Human-In-The-Loop (HITL) approval gates for high-impact actions, and Prometheus metrics tracking agent performance over time. Teams can run the same investigation with different models, different prompts, or different tool configurations and objectively compare outcomes.

**This project is for security teams who want engineering control and observability as they adopt LLM-powered SecOps.** It is not a product — it is a harness, a workbench, and an evaluation framework. It is designed to be forked, extended, and adapted to any vulnerability or threat-hunting workflow.

---

## Architecture Overview

ThIOClaw separates concerns into a **Control Plane** (LLM agent reasoning) and a **Data Plane** (deterministic telemetry analysis), connected by a typed interface (`tier1.json`).

```
┌──────────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATOR (harness/)                       │
│  harness.yaml + targets.yaml → config → run_cycle() → ThreadPool    │
└──────────────┬───────────────────────────────────────────────────────┘
               │ importlib.import_module(target.script)
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    DATA PLANE (data_plane/)                           │
│  cve_2026_31431.py                                                   │
│  ├── Load telemetry (events.json or S3)                              │
│  ├── Pandas signal scoring (Q1–Q6)                                   │
│  ├── Tier 1 deterministic verdict                                    │
│  ├── Write tier1.json                                                │
│  └── Invoke OpenClaw agent (subprocess)                              │
└──────────────┬───────────────────────────────────────────────────────┘
               │ scripts/openclaw.py investigate --tier1-results ...
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                 CONTROL PLANE (scripts/openclaw_agent/)               │
│  OpenClawAgent (agent.py)                                            │
│  ├── System prompt (prompts.py)                                      │
│  ├── Tool definitions (tools.py)                                     │
│  │   ├── get_tier1_summary        → reads tier1.json                 │
│  │   ├── get_cve_theoretical_path → reads signals YAML               │
│  │   ├── get_exploit_evidence     → fetches raw telemetry rows       │
│  │   ├── propose_query_execution  → HITL approval gate               │
│  │   └── submit_verdict           → final output                     │
│  └── Agentic loop (max 15 turns, Ollama local LLM)                   │
└──────────────┬───────────────────────────────────────────────────────┘
               │ verdict dict
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      OUTPUT & OBSERVABILITY                          │
│  ├── findings/{run_id}_finding.yaml    (machine-readable)            │
│  ├── findings/{run_id}_tier1.json      (deterministic signals)       │
│  ├── docs/{CVE}_{run_id}.md + .html    (human-readable reports)      │
│  ├── findings/findings.jsonl           (append-only log)             │
│  ├── logs/agent_runs.jsonl             (structured event log)        │
│  ├── Prometheus metrics (:9090)        (operational dashboards)      │
│  └── OpenTelemetry traces              (distributed tracing)         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Key Concepts

### Tier 1: Deterministic Signal Scoring
The Data Plane runs pandas queries (Q1–Q6) against raw telemetry and scores them using weighted rules defined in `signals/<CVE-ID>.yaml`. This produces a **deterministic** verdict that is reproducible and auditable. No LLM is involved.

### Tier 2: LLM Agentic Reasoning
The Control Plane (OpenClaw agent) receives the Tier 1 results and uses an LLM (via Ollama) to perform deeper reasoning. It can request additional evidence, correlate signals against the theoretical exploit chain, and propose new queries — but it must go through the analyst for approval.

### Human-In-The-Loop (HITL)
When the agent calls `propose_query_execution`, execution pauses and the analyst sees the rationale, performance impact, and proposed query in the terminal. The analyst must approve execution. After seeing results, they must approve any updates to the signature SQL files. The LLM cannot autonomously modify detection logic.

---

## Project Structure

```
ThIOClaw/
├── CLAUDE.md                          # This file
├── README.md                          # User-facing setup and usage guide
├── harness.yaml                       # Main harness configuration
├── targets.yaml                       # CVE investigation targets
├── requirements.txt                   # Python dependencies
│
├── harness/                           # Orchestrator (entry point)
│   ├── orchestrator.py                #   CLI + run loop + concurrent dispatch
│   ├── config.py                      #   Typed dataclasses from YAML
│   ├── ingester.py                    #   CSV → SQLite inventory ingestion
│   ├── docs_builder.py                #   GitHub Pages index regeneration
│   └── finding_store.py               #   YAML + Markdown + JSONL persistence
│
├── data_plane/                        # Modular Data Plane scripts
│   └── cve_2026_31431.py              #   CVE-2026-31431 investigation logic
│
├── scripts/                           # LLM Control Plane
│   ├── openclaw.py                    #   CLI wrapper for the agent
│   └── openclaw_agent/
│       ├── agent.py                   #   Agentic loop (Ollama + tool calling)
│       ├── prompts.py                 #   System prompt
│       └── tools.py                   #   Tool definitions + implementations
│
├── signals/                           # Signal rule definitions (YAML)
│   └── CVE-2026-31431.yaml            #   Rules, weights, exploit chain context
│
├── queries/                           # Reference OSQuery SQL
│   └── CVE-2026-31431/
│       ├── Q1_algif_loaded.sql
│       ├── Q2_af_alg_socket_open.sql
│       ├── Q3_uid_escalation.sql
│       ├── Q4_root_shell_from_unpriv.sql
│       ├── Q5_module_load_events.sql
│       └── Q6_exploit_staging.sql
│
├── observability/                     # OpenTelemetry + structured logging
│   ├── logger.py                      #   Thread-safe JSONL structured logger
│   ├── metrics.py                     #   Prometheus metrics via OTel
│   └── traces.py                      #   OTel trace context helpers
│
├── data/                              # Sample telemetry and inventory
│   ├── sample_events.json             #   9 events simulating a full exploit
│   ├── sample_inventory.csv           #   8 workloads with mixed statuses
│   └── s3_manifest.json               #   S3 bucket config (no secrets)
│
├── findings/                          # Output (gitignored except .gitkeep)
├── docs/                              # GitHub Pages output
│   ├── _config.yml                    #   Jekyll config (theme: minima)
│   ├── _layouts/finding.html          #   Finding page template
│   └── index.md                       #   Auto-rebuilt landing page
├── logs/                              # Structured logs (gitignored)
└── tests/                             # Unit tests
    ├── test_ingester.py               #   InventoryIngester tests
    ├── test_docs_builder.py           #   docs_builder tests
    └── test_signal_detection.py       #   Tier 1 signal scoring tests
```

---

## How to Add a New CVE Target

1. **Define the target** in `targets.yaml`:
   ```yaml
   - cve_id: CVE-YYYY-NNNNN
     description: "Short description"
     script: data_plane.cve_yyyy_nnnnn
     signals_file: signals/CVE-YYYY-NNNNN.yaml
     priority: high
     enabled: true
     trigger_assessments:
       - vulnerable_or_not_confirmed_fixed
   ```

2. **Create signal rules** at `signals/CVE-YYYY-NNNNN.yaml` with weighted rules and an `openclaw_context` block describing the exploit chain for the LLM.

3. **Write the data plane script** at `data_plane/cve_yyyy_nnnnn.py`. It must export a `run_investigation()` function matching the signature in `cve_2026_31431.py`. Implement pandas queries specific to the vulnerability's telemetry fingerprint.

4. **Add reference OSQuery SQL** to `queries/CVE-YYYY-NNNNN/` for documentation and HITL query proposals.

---

## Running the Harness

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start Ollama (separate terminal)
ollama serve && ollama pull llama3.1:8b

# Single investigation cycle
python -m harness.orchestrator --raw-telemetry local --once

# Investigate a specific CVE
python -m harness.orchestrator --cve CVE-2026-31431 --once

# Continuous monitoring loop (runs every 300s)
python -m harness.orchestrator --raw-telemetry local

# Run tests
pytest tests/ -v --cov=harness --cov=observability --cov-report=term-missing
```

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `OPENCLAW_MODEL` | `ollama/llama3.1:8b` | Which LLM the agent uses |
| `OPENCLAW_BASE_URL` | `http://localhost:11434` | The API endpoint for the LLM |

---

## Observability Stack

| Layer | Implementation | Location |
|---|---|---|
| Structured logs | Thread-safe JSONL writer | `logs/agent_runs.jsonl` |
| Metrics | OTel → Prometheus scrape endpoint | `http://localhost:9090/metrics` |
| Traces | OTel spans (stdout or OTLP gRPC) | Configured in `harness.yaml` |
| Findings log | Append-only JSONL | `findings/findings.jsonl` |

### Key Metrics Exported

- `openclaw_run_total` — investigation runs by CVE and status
- `openclaw_run_duration_ms` — investigation duration histogram
- `openclaw_workloads_matched` — vulnerable workloads found per CVE
- `openclaw_findings_total` — findings by CVE and verdict
- `openclaw_tier1_signals_matched` — individual signal fire counts

---

## Design Decisions

### Why modular Python scripts instead of Jupyter notebooks?
The data plane was originally implemented as Jupyter notebooks executed via Papermill. We migrated to pure Python scripts because: (1) clean git diffs for version-controlled detection logic, (2) standard `pytest` unit testing of individual query functions, (3) dramatically faster execution without kernel startup overhead, and (4) deployment flexibility (Docker, Lambda, stream processors).

### Why LiteLLM instead of raw SDKs?
The control plane uses the LiteLLM library because it provides a single, unified interface to 100+ LLM providers. Instead of writing separate code paths for Anthropic, OpenAI, and Ollama, we write one tool-calling loop. Teams can default to Ollama for complete privacy (telemetry never leaves the host), but easily swap to Claude 3.5 Sonnet or GPT-4o via the `OPENCLAW_MODEL` environment variable.

### Why separate Tier 1 and Tier 2?
Deterministic signal scoring (Tier 1) provides a reproducible, auditable baseline that works even if the LLM is unavailable or produces nonsense. The LLM (Tier 2) adds reasoning depth but cannot override the math. This layered architecture lets teams measure what the LLM actually contributes versus deterministic rules alone.

### Why HITL gates on query execution?
An LLM proposing to run arbitrary queries against production telemetry is a potential performance and security risk. The HITL approval flow forces the agent to articulate *why* it needs the query and *what the cost is*, giving the analyst veto power. If the query produces useful results, the analyst can approve updating the signature file — creating a human-supervised feedback loop that improves detection logic over time.

---

## Common Development Tasks

### Editing the agent's behavior
Modify `scripts/openclaw_agent/prompts.py` (system prompt) and `scripts/openclaw_agent/tools.py` (available tools). The agent's reasoning loop is in `agent.py`.

### Tuning signal weights
Edit `signals/<CVE-ID>.yaml`. Weights and verdict thresholds are defined there and consumed by the data plane script.

### Adding a new agent tool
1. Add the tool schema to `AVAILABLE_TOOLS` in `tools.py`
2. Implement the Python function in `tools.py`
3. Add the dispatch case in `agent.py`'s agentic loop
4. Update `prompts.py` to instruct the LLM on when to use it

### Swapping the LLM model
```bash
# Local Ollama
export OPENCLAW_MODEL="ollama/qwen2.5:7b"

# Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENCLAW_MODEL="claude-3-5-sonnet-20241022"
```

---

## Known Limitations

- The HITL `propose_query_execution` tool currently uses a mock execution backend. Real SQL/pandas execution against live telemetry is not yet wired up.
- Only one CVE target (CVE-2026-31431) is implemented as a reference. The framework is generic but requires new data plane scripts for each CVE.
- The agent's observability traces use a dummy fallback when the OTel package path mismatches. Full trace instrumentation of individual tool calls is planned.
