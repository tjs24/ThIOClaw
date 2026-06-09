# Guardrails and Observability for an Agentic Purple Platform

Companion to [`README.md`](./README.md). The README argues *what* the architecture is. This document is *how* the guardrails, observability, and evaluation work, what they look like in code, and what fails when they're missing.

Structure: three planes (blue, red, platform) of guardrails, then the same three planes of observability, then the evaluation methodology that scores both.

---

## Part 1 — Guardrails

### 1.1 Blue guardrails (what ThIOClaw has, what's still missing)

**What's in the repo today.**

- **HITL on query proposal** (`scripts/thioclaw_agent/tools.py`, `propose_query_execution`). The agent cannot autonomously execute new queries against telemetry. The proposal is rendered to the analyst with rationale + cost + the proposed query, and the analyst must approve before execution. The same pattern gates any subsequent update to the signal YAML.
- **Strands hooks shared guardrails policy** (commit `a0bcded`). A policy layer that intercepts tool calls before they reach the model loop and after they return. The pattern is right; the catalog of policies is incomplete.
- **Ollama-default LLM** (`THIOCLAW_MODEL=ollama/llama3.1:8b`). Telemetry never leaves the host. This isn't a guardrail in the policy-enforcement sense, it's a deployment guarantee — but it's the single most important property for handling sensitive customer telemetry, and it's enforced by absence of network egress rather than by code.
- **Tier 1 / Tier 2 separation.** The LLM cannot override the deterministic scoring math. If the agent goes off the rails, the Tier 1 verdict still stands and is auditable. This is the architectural guardrail that every other guardrail depends on.

**What's missing and worth adding.**

1. **Irreversible-action denylist.** A response/containment compartment will eventually wrap actions like "isolate host X" or "rotate credential Y." These cannot be approved by a single analyst at 3am. The tool schema must declare reversibility (`reversible: false`) and the gate must require named two-person approval — not role-based.
2. **Prompt-injection detection on telemetry fields.** Process command lines, file paths, and user-controlled fields land in the agent's context. An attacker who controls one of those fields controls part of the model's prompt. A pre-tool-call sanitizer that strips/escapes known injection patterns (and logs the attempt) is required before the response compartment exists. There's recent literature on indirect prompt injection that documents the attack class clearly; the guardrail belongs in the platform layer because both blue and red agents will face it.
3. **Max-blast-radius declaration on every tool.** Even read-only tools have cost (query latency, telemetry rows scanned, IAM events). The tool schema should declare a cost ceiling and the agent loop should refuse to call past it.
4. **Embargoed-CVE awareness.** When the agent reasons about a CVE under embargo, the audit log should mark the run with the embargo class — and the report writer should refuse to emit HTML/Markdown to a path outside the embargo compartment.

### 1.2 Red guardrails (entirely new surface)

Red guardrails are not blue guardrails with the word "attack" substituted. The threat model is different and the failure mode is different. Blue's worst failure is missing a detection; red's worst failure is causing the incident it was supposed to simulate.

**Required guardrails for a red agent:**

1. **Blast radius declaration on every offensive tool.** Each tool must declare:
   - `reversible: true | false`
   - `target_class: synthetic | lab | staging | production`
   - `persistence: ephemeral | session | persistent`
   - `attribution_risk: none | observable | linkable`

   The agent loop refuses to chain tools whose combined declaration exceeds the engagement's authorization. This is the offensive analogue of HITL: it doesn't ask the human, but it does refuse statically.

2. **Authorization scope as a hard input, not a prompt.** Every red run carries an `authorization.yaml` declaring target ASNs/hostnames/accounts, allowed techniques, time window, and named approvers. The orchestrator validates every tool call against this file *outside* the agent loop. Putting the authorization in the system prompt is insufficient — the agent will follow the most recent instruction it sees.

3. **Attribution control.** No offensive infrastructure may be linkable to corporate identity. [MITRE ATT&CK Resource Development (TA0042)](https://attack.mitre.org/tactics/TA0042/) catalogs the adversary techniques for acquiring infrastructure; an authorized red team has to mirror that discipline because the program's *integrity* depends on red looking like an external threat even when the engagement is internal. Concretely: separate cloud accounts billed to a non-attributable cost center, domains registered through a privacy-preserving registrar, no corporate SSO on any red-owned system, no reuse of red infrastructure across engagements.

4. **Production execution gate.** Any tool call against a `target_class: production` asset requires a named approver per call, not per session. Per-session approval drifts; per-call approval forces the operator to articulate intent at each escalation step.

5. **Embargo handling for dual-use research material.** When the red agent synthesizes an exploit chain for an embargoed CVE, the output is automatically routed to the embargo compartment and never to the shared knowledge base. The agent's `submit_findings` tool refuses to write to the shared path when the embargo flag is set on the run.

6. **Deception/honey-asset awareness.** The agent must not be told what's a honeypot (that defeats the test) — but it must be prevented from escalating *against* a honey asset in a way that breaks the engagement's legal scope. The platform layer's authorization gate handles this without leaking the deception.

### 1.3 Platform-layer guardrails (cross-cutting)

These are the guardrails neither team owns. They exist because both teams will, in good faith, optimize past their own guardrails over time.

1. **Audit log streaming to an external sink.** Every tool call, every model response, every HITL decision streams to a sink outside both teams' write access. Append-only, signed, retention measured in years. This is the only mechanism that lets a future incident review reconstruct what an agent actually did.
2. **Supply-chain provenance for the tool surface.** Every tool the agents can call is signed (sigstore/cosign), inventoried in an SBOM, and pinned by digest. The platform layer refuses to load an unsigned tool. This addresses the AI-specific attack of poisoning the agent's tool surface itself.
3. **Eval scorecard schema change requires arbitration.** The scorecard schema (what counts as detected, what the noise floor is, what the time-to-detect cutoff is) cannot be changed by either team in isolation. The change passes through a third party — typically a platform owner with CISO-office sign-off. This is the smallest, sharpest guardrail in the platform compartment, and the one most often missing.
4. **Air-gap network policy enforcement.** When the platform runs in air-gapped mode (the JD-relevant configuration), the network policy is enforced by the orchestrator runtime, not by the model: any outbound call from inside the agent sandbox fails closed. The model can ask to make an external request; the runtime denies it without prompting the analyst. Asking the analyst opens a social-engineering path.
5. **AI-RMF / ATLAS alignment per run.** Each run records which [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) functions (Govern, Map, Measure, Manage) and which [MITRE ATLAS](https://atlas.mitre.org/) tactics/techniques it intersects with. This is metadata, not enforcement — but it makes the program legible to risk and compliance functions, which is the difference between "we run a red team" and "we run a documented AI red teaming program."

---

## Part 2 — Observability

The principle: three observability planes, one cross-cutting correlation layer. Each plane is owned by its compartment. The correlation layer is the platform's responsibility.

### 2.1 Blue plane (largely implemented in this repo)

What's emitted today:

- **Structured JSONL** to `logs/agent_runs.jsonl` via `observability/logger.py`. Thread-safe, one event per line, schema includes `run_id`, `cve`, `phase`, `tool`, `tool_args`, `tool_result`, `verdict`, `latency_ms`.
- **Prometheus metrics** at `:9090/metrics` via `observability/metrics.py`. Key series:
  - `thioclaw_run_total{cve, status}`
  - `thioclaw_run_duration_ms` (histogram)
  - `thioclaw_workloads_matched{cve}`
  - `thioclaw_findings_total{cve, verdict}`
  - `thioclaw_tier1_signals_matched{cve, signal_id}`
- **OpenTelemetry traces** via `observability/traces.py` — span per investigation, child spans per tool call (the per-tool-call instrumentation is partial; see the "Known Limitations" section of the project README).

What a mature blue observability story needs that isn't there yet:

- **Time-to-verdict broken out by Tier.** "How long did Tier 1 take? How long did Tier 2 add? How many tool calls did Tier 2 require to reach the verdict?" These are the questions a program lead asks when deciding whether the LLM is earning its keep.
- **Signal-to-noise ratio per signal rule.** `tier1_signals_matched / tier1_signal_true_positives` over a rolling window. A signal with high match rate and low TP rate is detection-debt and should be re-weighted or retired.
- **Counterfactual logging.** When the agent decides not to escalate (Tier 2 says "benign"), the log should capture which signals it considered and dismissed. Otherwise you can't audit a missed detection after the fact.

### 2.2 Red plane (entirely new)

The red plane's observability is *not* "the agent's logs." It's the operational telemetry that lets a program owner trust an autonomous agent is doing what it claims.

Required series:

- **`redclaw_action_total{cve, action_class, target_class, reversible}`** — every offensive tool call, dimensioned by the blast-radius declaration. Lets you graph "production-targeted, irreversible actions per week" and alarm on outliers.
- **`redclaw_authorization_denials_total{cve, action_class, reason}`** — every time the authorization gate refused a tool call. A sudden spike means either the agent is wandering or the authorization scope is mis-specified. Both are worth knowing.
- **`redclaw_attribution_risk_emitted_total{cve, risk_level}`** — counts of actions that increased observable attribution. A red agent that's accumulating attribution debt over a campaign is one whose engagement is about to be burned.
- **`redclaw_campaign_progression_phase{campaign_id}`** — gauge of which phase the campaign is in (recon, weaponization, delivery, etc., mapping to MITRE ATT&CK kill-chain). Lets you compare planned vs. actual campaign trajectory.

Plus structured action logs, separately retained, signed, and streamed to the platform audit sink — same structural pattern as blue's JSONL but never written into blue-readable storage.

### 2.3 Platform plane (the part that makes the program a program)

This is the observability layer most "purple programs" never build, and it's the one that answers the JD's measurability question.

**The purple scorecard.** One row per red campaign × CVE × blue detection stack. Columns:

| Column | Meaning |
|---|---|
| `campaign_id` | red campaign ID |
| `cve` | target CVE |
| `attack_executed_at` | timestamp red agent fired the attack |
| `telemetry_captured` | did the collectors see the events? boolean |
| `sigma_fired` | did the external Sigma rules fire? boolean + rule IDs |
| `tier1_scored` | did Tier 1 score above threshold? boolean + score |
| `tier2_verdict` | the LLM agent's verdict (vulnerable/exploited/benign) |
| `tier2_correct` | did the verdict match ground truth? boolean |
| `time_to_verdict_s` | wall-clock from attack to Tier 2 verdict |
| `analyst_overrode` | did HITL override Tier 2? boolean + direction |

This table is the eval substrate. Cohort views over it answer the questions program leads care about:

- **Detection coverage** — % of campaigns caught at any tier
- **Tier value** — % of campaigns Tier 2 caught that Tier 1 missed (the LLM's contribution)
- **Noise floor** — % of synthetic benign campaigns Tier 2 flagged as exploited (false positives)
- **Time pressure** — p50/p95 time-to-verdict by CVE class

**Cross-team correlation.** Every red campaign carries a `correlation_id` that propagates through the telemetry it generates and into the blue agent's run record. The platform plane can join `redclaw_action_total` with `thioclaw_findings_total` on `correlation_id` and produce the scorecard automatically. Without the correlation ID, you're guessing at attribution.

**Supply-chain attestation log.** Append-only record of every tool surface change: which tool got added, who signed it, what its SBOM diff was, what the policy review said. This is the artifact a future audit asks for when something the agent did turns out to be wrong.

**AI-RMF / ATLAS coverage report.** Aggregated metadata from the per-run tags described in the platform guardrails section. Answers "which ATLAS tactics has our red plane actually exercised? which ones are gaps?" This is the question that distinguishes a maturing program from a checkbox one.

---

---

## Part 3 — Evaluation

Guardrails and observability tell you what the system *did*. Evaluation tells you whether it should have done it. This is the layer that lets you change a system prompt, swap a model, tighten a guardrail, or add a new telemetry source — and know whether the change made the platform better or worse. It's also the layer most agentic security projects skip, which is why most "purple programs" can't answer the question "did this LLM agent actually help."

The principle: every change to a prompt, tool surface, or guardrail is a hypothesis. Evaluation is how you test it.

### 3.1 The fixed eval set

You need a labeled corpus that doesn't change when the system does. Categories:

| Category | What it is | Why it's there |
|---|---|---|
| **Confirmed exploit** | Telemetry from a real or runbook-replicated attack with ground-truth verdict `exploited` | Tests the headline detection case |
| **Confirmed benign** | Telemetry with no signals firing, ground-truth `benign` | Catches over-eager agents that escalate noise |
| **Ambiguous** | Some signals fire but the chain is incomplete (e.g. `algif_aead` loaded but no UID escalation) | Tests calibration — the right answer is `suspicious` or `inconclusive`, not `exploited` |
| **Cross-source pairs** | Same attack captured by *both* osquery and auditd | Tests source-aware reasoning (see 3.2) |
| **Adversarial** | Telemetry where attacker-controlled fields contain prompt-injection or misdirection | Tests guardrail effectiveness |

For ThIOClaw today, the fixed set starts with: `data/sample_events.json` (osquery, simulated exploit), the auditd capture from `runbooks/CVE-2026-31431_sigma_validation.md` Phase 5, and synthetic benign/ambiguous variants generated by stripping signals from those captures.

The eval set lives in the platform compartment, not blue or red. Either team would, in good faith, optimize against a corpus they own.

### 3.2 The cross-source eval (the headline case for ThIOClaw)

Now that CVE-2026-31431 has both osquery and auditd telemetry available, the most informative single eval is:

1. Run the same attack telemetry through three configurations: `event_source: osquery`, `event_source: auditd`, `event_source: both`.
2. Compare Tier 1 verdicts. They should differ deterministically based on `supported_sources` declarations in `signals/CVE-2026-31431.yaml` — and the differences should be explainable from the YAML.
3. Compare Tier 2 verdicts. They should *converge* when the underlying attack is the same — and where they don't, the reasoning trace should cite the source coverage as the reason.

This is the test that proves the platform's source-independence claim is real. A pass means the architecture's promise holds; a fail tells you exactly which signal's `supported_sources` declaration is wrong or which prompt instruction the agent isn't following.

### 3.3 The scoring rubric

Five metrics, scored per run, aggregated per cohort:

1. **Verdict accuracy.** Did the final verdict match ground truth? Binary per run; report as accuracy + confusion matrix per cohort.
2. **Calibration.** Is the `confidence` field well-calibrated against verdict correctness? Brier score over the cohort. A model that says 0.9 confidence and is wrong 50% of the time is worse than a model that says 0.6 and is wrong 40% of the time.
3. **Tool-call efficiency.** How many tool calls to reach a verdict? Median + p95 per cohort. Fewer is better *if accuracy holds.* A prompt change that cuts calls in half but drops accuracy 10% is a regression.
4. **Source-awareness (cross-source cohort only).** When a signal couldn't have fired due to source coverage, did the agent's reasoning trace acknowledge this rather than treating absence as evidence of benign behavior? Binary per run; report as a rate.
5. **Guardrail behavior.** Per HITL-gated tool: was it invoked? Was the rationale provided? Was the analyst decision (in the eval, scripted) respected without retry? Report invocation rate, rationale-quality rate (LLM-as-judge or human spot-check), respect-rate.

### 3.4 Protocol for evaluating a prompt change

This is the workflow you run when you want to know whether a new system prompt is better:

1. **Freeze the eval set.** No additions or deletions during the comparison.
2. **Freeze the model.** Same model, same temperature, same provider. Prompt change is the only variable.
3. **Run the baseline.** Current prompt against the full eval set. Capture all five metrics. Save the raw JSONL traces.
4. **Run the variant.** New prompt against the same set. Capture the same metrics.
5. **Compare per-cohort.** Aggregate accuracy is misleading — the change may help one category and hurt another. The cross-source cohort especially: a prompt that says "always escalate when in doubt" will improve recall on confirmed exploits and tank specificity on ambiguous.
6. **Sample size.** ≥20 runs per cohort gives directional signal; ≥50 gives statistical signal. For binary metrics with proportions near 0.5, use a two-proportion z-test on the deltas you actually care about.
7. **Failure-case analysis.** Read the reasoning traces for every run where the variant changed the verdict (in either direction). The prompt change either is, or is not, doing what you intended. The traces tell you which.
8. **Decision rule.** Define the decision rule *before* running. "Ship the variant if accuracy improves ≥3pp on confirmed-exploit cohort *without* dropping >2pp on benign cohort" beats "ship if it looks better." LLM evals are easy to talk yourself into.

The same protocol applies to model swaps, temperature changes, and tool-schema edits. The eval set is the constant; everything else is a variable.

### 3.5 Protocol for evaluating a guardrail change

Different metrics, same shape:

1. **Block precision.** Of all the guardrail blocks fired, how many were correct? A guardrail that fires on legitimate tool calls is a regression even if it also catches bad ones.
2. **Block recall (red-team prompt set).** Run a fixed corpus of adversarial inputs — prompt injections embedded in process command lines, jailbreak attempts in raw telemetry, attempts to bypass HITL by reformulating the request. What fraction did the guardrail block?
3. **End-to-end accuracy regression.** Run the standard eval set with the new guardrail enabled. Did adding the guardrail hurt verdict accuracy by refusing tool calls the agent legitimately needed?
4. **Audit completeness.** Every blocked call must produce an audit event with rule ID + reason + the prompt that triggered it. Missing audit records on blocks is itself a regression.

The platform compartment owns both the adversarial corpus and the guardrail-eval results. Neither team gets to silently mark a rule "out of scope" because it kept blocking their work.

### 3.6 Worked example: evaluating the proposed source-aware prompt change

Concrete scenario, given the current state of this repo:

- **Hypothesis.** Adding explicit source-awareness language to the system prompt (telling the agent that signals with `supported_sources: [osquery]` cannot fire under auditd-only telemetry, and absence-of-signal is not absence-of-event) will improve Tier 2 verdict accuracy on the cross-source cohort without hurting the others.
- **Eval set.** 10 confirmed-exploit runs × 3 source configs (osquery / auditd / both) = 30 cross-source runs. Plus 20 confirmed-benign and 20 ambiguous runs from the standard set, source-randomized.
- **Baseline.** Current prompt, llama3.1:8b, temperature 0. Capture five metrics.
- **Variant.** Proposed prompt (see chat). Same model, same temperature.
- **Decision rule (set before running).** Ship the variant if source-awareness rate on the cross-source cohort improves by ≥10pp *and* verdict accuracy on benign + ambiguous cohorts does not drop by more than 2pp.
- **What to read regardless of the metric outcome.** Every cross-source run where baseline and variant disagree — both reasoning traces. The point of the eval isn't the number, it's the diagnostic. If the variant is better but for the wrong reason (e.g. it's just escalating more aggressively, not actually reasoning about source coverage), the metric is hiding a regression.

---

## Part 4 — What ties them together

The shortest accurate description: **guardrails refuse what shouldn't happen; observability proves what did; evaluation proves what works.** Any one without the other two is a failure mode.

- Guardrails without observability is a black box that occasionally refuses requests and you can't tell why.
- Observability without guardrails is a perfect record of the incident your agent just caused.
- Either without evaluation is a system you can't tell is improving or regressing across changes.

The platform compartment exists specifically because all three layers need to be independently owned, audited, and held accountable. That's why it can't be either team's repo, and why every "we'll just put it in the shared Slack" purple program eventually fails the audit.

---

## Cross-references

- Main architecture: [`README.md`](./README.md)
- Existing blue implementation: [`../scripts/thioclaw_agent/`](../scripts/thioclaw_agent/), [`../data_plane/`](../data_plane/), [`../observability/`](../observability/)
- Reference runbook this architecture is anchored to: [`../runbooks/CVE-2026-31431_sigma_validation.md`](../runbooks/CVE-2026-31431_sigma_validation.md)
