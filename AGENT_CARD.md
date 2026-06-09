# ThIOClaw — Agent Card

> Contract for invoking ThIOClaw from another agent or orchestrator. If you are a human, see `README.md` for the user-facing setup guide; this document is for callers, not operators.

---

## Greeting

I am **ThIOClaw**, a Tier-2 threat-hunting agent. I investigate a **vulnerability** against the telemetry from all affected workloads and return a structured verdict with a defended reasoning trace. I do not act on the verdict — containment, remediation, and rule changes are the caller's responsibility.

The unit of investigation is the vulnerability, not the CVE identifier. CVE is one convenient identifier convention; I also accept inline vulnerability context for 0-days, embargoed CVEs, internal findings, multi-CVE attack chains, and pre-attribution threat-hunting hypotheses.

I am deterministic at Tier 1 (weighted signal scoring in pandas) and probabilistic at Tier 2 (LLM tool-calling loop). Tier 1 always produces a reproducible verdict regardless of whether Tier 2 is available; my contribution as an agent is the Tier 2 reasoning on top.

I default to a local Ollama model so I can operate on sensitive telemetry without external egress. I can be reconfigured to use any LiteLLM-supported provider via `THIOCLAW_MODEL` and `THIOCLAW_BASE_URL`.

---

## Purpose

Given **vulnerability context** and a pointer to telemetry, decide whether the vulnerability was **exploited**, **suspicious**, **benign**, or **inconclusive** on the target workload. Defend the verdict with a reasoning trace that maps fired signals to the theoretical exploit chain and acknowledges the limits of what the active telemetry source can see.

---

## Operating modes

I resolve the caller's vulnerability context into one of two modes. The mode dictates how Tier 1 behaves and what the caller can expect from the verdict.

| Mode | When it applies | Tier 1 behavior | Tier 2 behavior | Output side effect |
|---|---|---|---|---|
| **Grounded** | A signal YAML for the vulnerability exists in `signals/` (resolved by CVE id, alias, or canonical-chain hash) | Runs weighted scoring against the rules in the YAML; produces a deterministic verdict | Reasons against the grounded exploit chain; calibrated against known weights | None — the grounded definition is unchanged |
| **Hypothesis** *(designed; not yet implemented end-to-end)* | No matching signal YAML; caller provides inline vulnerability context (narrative + technique IDs + IOCs) | Degenerates to behavior extraction — pulls events matching caller-provided IOCs without weighted scoring | Leads the investigation; reasons from first principles against the inline context | Emits a **candidate signal YAML** alongside the verdict for an analyst to promote into `signals/` |

The hypothesis-mode output is how the platform learns. Promoted candidate YAMLs become grounded knowledge for the next investigation of the same vulnerability. This is the feedback loop that ties the agent to the platform's knowledge-base compartment (see [`purple-team-platform-architecture/`](./purple-team-platform-architecture/)).

---

## Inputs

The primary input is a **vulnerability context**. The caller supplies it in one of three forms:

| Form | Resolves to mode | How |
|---|---|---|
| **CVE id** (e.g. `CVE-2026-31431`) | Grounded if `signals/<cve>.yaml` exists; otherwise hypothesis (with the CVE as a hint) | I look up the file by name |
| **Path to a signal YAML** | Grounded | Caller pins the exact definition |
| **Inline context block** (narrative + technique IDs + IOCs, no signal YAML) | Hypothesis | Caller is hunting an unnamed or unattributed vulnerability |

I accept these via three invocation shapes:

### 1. Run-from-config (recommended for orchestrators)

The caller writes a `harness.yaml` + `targets.yaml` and invokes the orchestrator. I select the target and run end-to-end (ingest → Tier 1 → Tier 2 → emit).

```bash
python -m harness.orchestrator --cve CVE-2026-31431 --once
```

| Field | Where | Required | Meaning |
|---|---|---|---|
| `cve_id` | `targets.yaml` | one of these three | CVE identifier; I resolve to a grounded YAML if one exists |
| `signals_file` | `targets.yaml` | one of these three | Direct path to a grounded signal YAML |
| `vulnerability_context` | `targets.yaml` | one of these three | Inline hypothesis context (designed; not yet implemented in `targets.yaml` loader) |
| `script` | `targets.yaml` | yes | Python module implementing the data plane (e.g. `data_plane.cve_2026_31431`) |
| `telemetry.source` | `harness.yaml` | yes | `local` (file path), `s3` (manifest), or `api` |
| `telemetry.event_source` | `harness.yaml` | no | `osquery` (default), `auditd`, or `both` |
| `model` | env `THIOCLAW_MODEL` | no | LiteLLM model id; defaults to `ollama/llama3.1:8b` |

### 2. Tier-2-only invocation (when caller already has Tier 1 results, or wants hypothesis mode)

Grounded:
```bash
python scripts/thioclaw.py investigate \
    --tier1-results findings/<run_id>_tier1.json \
    --signals signals/CVE-2026-31431.yaml \
    --workload-id <workload_id>
```

Hypothesis *(designed; not yet implemented)*:
```bash
python scripts/thioclaw.py investigate \
    --vulnerability-context path/to/context.yaml \
    --telemetry path/to/raw_events.json \
    --workload-id <workload_id>
```

The Tier-2-only entry point is what a red-plane / purple-eval orchestrator uses to compare verdicts across telemetry sources without re-running Tier 1.

### 3. Python API (in-process)

```python
from scripts.thioclaw_agent.agent import ThIOClawAgent

agent = ThIOClawAgent()

# Grounded
verdict = agent.run_investigation(
    cve_id="CVE-2026-31431",
    workload_id="i-0abc123",
    tier1_path="findings/<run_id>_tier1.json",
    signals_path="signals/CVE-2026-31431.yaml",
    telemetry_source="osquery",
)

# Hypothesis (designed; not yet implemented)
verdict = agent.run_investigation(
    vulnerability_context={
        "name": "suspected-af_alg-lpe",
        "exploit_chain": "Process opens AF_ALG SOCK_SEQPACKET socket, binds to aead, ...",
        "mitre_techniques": ["T1068"],
        "iocs": {"syscalls": ["socket", "splice"], "modules": ["algif_aead"]},
    },
    workload_id="i-0abc123",
    telemetry_path="path/to/raw_events.json",
    telemetry_source="auditd",
)
```

---

## Outputs

### Verdict object (the return value)

```json
{
  "mode": "grounded | hypothesis",
  "verdict": "exploited | suspicious | benign | inconclusive",
  "confidence": 0.0,
  "reasoning_trace": "markdown string — fired signals, mapping to exploit chain, source-coverage notes",
  "recommended_action": "concrete next step for a human",
  "candidate_signal_yaml": "..."
}
```

`verdict` in grounded mode follows the `verdict_logic:` block in the signal YAML. In hypothesis mode, the agent uses the same four-state vocabulary but cannot lean on pre-defined weights — the trace must justify the verdict from inline context alone. `confidence` is the agent's self-reported calibration in [0.0, 1.0]; callers should treat it as advisory in grounded mode and as *low-trust* in hypothesis mode, where it is uncalibrated by definition.

`candidate_signal_yaml` is emitted only in hypothesis mode. It is a draft signal definition the agent constructed during the investigation — rules it would have wanted to fire, weighted by what it observed. Promotion to a grounded definition in `signals/` is an analyst decision, not an agent decision.

### Files I write (caller can fetch these by `run_id`)

| Path | Format | Purpose |
|---|---|---|
| `findings/<run_id>_tier1.json` | JSON | Deterministic Tier 1 signal scoring. Stable input for re-invocation and eval. |
| `findings/<run_id>_finding.yaml` | YAML | Machine-readable verdict + reasoning trace + recommended action. |
| `docs/<cve>_<run_id>.md` | Markdown | Human-readable investigation report. |
| `docs/<cve>_<run_id>.html` | HTML | Same content, browser-renderable. |
| `logs/agent_runs.jsonl` | JSONL (append-only) | Structured event log: tool calls, tool results, guardrail decisions, HITL prompts and outcomes. |

The `run_id` is emitted on stdout at start of run and embedded in every event in `logs/agent_runs.jsonl` so the caller can correlate.

### Observability streams (in-process)

- **Prometheus metrics** at `:9090/metrics` — see `observability/metrics.py` for the full series list. Key counters: `thioclaw_run_total{cve,status}`, `thioclaw_findings_total{cve,verdict}`, `thioclaw_tier1_signals_matched{cve,signal_id}`.
- **OpenTelemetry spans** under the root span name `thioclaw.agent.investigate`. Per-tool-call child spans are partial (see Known Limitations in project README).

---

## HITL pause points the caller must expect

I am not fully autonomous. The caller's orchestration must account for these blocking interactions:

| Tool | Why it pauses | What happens |
|---|---|---|
| `propose_query_execution` | Agent proposes running a new/modified query against telemetry. Has performance and correctness implications. | Prints rationale + performance impact + query to stdout. Reads `y/N` from stdin. Logs the decision to `logs/agent_runs.jsonl` as a `hitl_decision` event. |
| `propose_query_execution` (post-execution) | Agent proposes updating the signature file with the validated query. | Second `y/N` prompt for the file update. Same logging. |

If you are invoking me from a non-interactive environment, you must either:
- Pre-set `THIOCLAW_HITL_MODE=deny` to auto-reject all HITL proposals (the run will complete with whatever verdict the agent reaches *without* the proposed query), or
- Wire a SOAR/approval system as the stdin/stdout transport and gate the `y/N` decision through your control plane.

Bypassing HITL is not supported. The Strands hooks policy (`observability/guardrails.py`) and the agent loop both enforce that `propose_query_execution` cannot self-approve.

---

## Things I will refuse to do

| Refusal | Rule | Reason |
|---|---|---|
| Execute a new query without HITL approval | `propose_query_execution` requires analyst input | Production telemetry queries have cost and security implications |
| Update signal YAML without explicit second approval | Two-step HITL on signature updates | The agent cannot modify detection logic unilaterally |
| Override Tier 1 verdict math | Architectural — Tier 1 is deterministic, Tier 2 reasons on top | Reproducibility is the platform's foundational guarantee |
| Call unknown tools | Guardrail `classify()` fails closed on unregistered tools | Tool surface is a fixed allowlist; new tools require code review |

If you need me to do any of the above, the answer is "no, propose a code change." This is by design.

---

## Failure modes

| Symptom | Cause | What the caller sees |
|---|---|---|
| Verdict `inconclusive` with reasoning trace mentioning exhausted turns | Agent hit `MAX_TURNS` (15) without calling `submit_verdict` | Verdict returned as `inconclusive`, `confidence: 0.0`, `recommended_action: "Manual review required."` |
| Tier 1 ran, Tier 2 errored | LLM provider unreachable or returned malformed tool calls | Run exits non-zero; `findings/<run_id>_tier1.json` exists; `findings/<run_id>_finding.yaml` absent. Tier 1 verdict is still valid as a fallback. |
| Signal not firing despite obvious exploit telemetry | `supported_sources` mismatch — the active collector cannot produce the event shape the rule expects | Tier 1 score lower than expected; Tier 2 reasoning trace should call this out if source-awareness instructions are in the prompt |
| Guardrail block message in tool result | Policy refused the tool call | Tool returns `[GUARDRAIL_BLOCK:<rule>] <reason>` as the tool result string; agent loop continues |
| Hypothesis mode requested but caller passed only a CVE id | I could not find a matching grounded YAML *and* no inline context was supplied | Run exits non-zero with an error pointing at the missing context; no findings file is written |
| Hypothesis mode verdict `exploited` with `confidence > 0.7` | Possible overconfidence — without a grounded YAML, calibration is not enforced | Caller should treat as a high-priority *lead*, not a confirmed verdict; verify by promoting the `candidate_signal_yaml` and re-running grounded |

---

## Provenance and version

| Field | Value |
|---|---|
| Agent name | ThIOClaw |
| Tier 2 framework | LiteLLM (direct) or Strands (selected via `THIOCLAW_FRAMEWORK`) |
| Default model | `ollama/llama3.1:8b` |
| System prompt | `scripts/thioclaw_agent/prompts.py` |
| Tool surface | `scripts/thioclaw_agent/tools.py` (`AVAILABLE_TOOLS`) |
| Guardrail policy | `observability/guardrails.py` |
| Source repository | this repo, branch `main` |
| Architecture context | [`purple-team-platform-architecture/`](./purple-team-platform-architecture/) |

The system prompt, tool schemas, and guardrail policy are all version-controlled in this repo. If you need to know exactly what I will and will not do under a given commit, read those three files at that commit's SHA — they are the contract.
