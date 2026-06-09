# Architecting a Purple Team Platform: Where Agentic Red and Blue Meet

> A purple program is red + blue + platform. The platform is a third compartment neither team owns alone — it holds the shared base context, the eval scorecard, and the audit trail. This document is about that compartment: what it contains, why agentic workflows make it newly tractable, and where guardrails and observability have to live on each side.

The blue half is implemented in this repository (ThIOClaw). The red half is sketched as a symmetric mirror. The platform layer — the part most programs miss — is the focus.

---

## 1. The problem: two teams aren't a program

Most "purple team" efforts fail one of two ways. Either red and blue work in parallel and call a shared Slack channel "the program" — no shared substrate, no scorecard anyone trusts — or one team owns the platform and the other is a customer, which collapses the adversarial dynamic that makes purple work in the first place. Both failures share a root cause: nothing is owned by neither team and serves both.

The agentic shift makes the gap acute. When humans pair-debug a Sigma rule, ad-hoc coordination scales. When red is an LLM agent autonomously synthesizing exploit chains and blue is an LLM agent autonomously triaging detections, "what each agent knows, what it can do, what it should never do" stops fitting in a head. Without a platform compartment that codifies the shared context, the guardrails, and the audit pipeline, you have two unsupervised optimizers in an environment nobody can reproduce.

---

## 2. The insight: shared base context, divergent outcomes

Red and blue are not in different businesses. They consume the same inputs:

- The **control configuration** — what's deployed, where, with what policy
- The **asset inventory** — what workloads exist, who owns them, what data they touch
- The **telemetry schema** — what events the collectors emit and what they mean
- The **threat intelligence** — what techniques are active, what CVEs are in play

The teams differ only in the operator they project these inputs through:

| Input | Blue's operator | Red's operator |
|---|---|---|
| Control config | "where does this fire, and what's missing?" | "where can this be bypassed?" |
| Asset inventory | "what needs containment first if compromised?" | "what's the highest-value reachable target?" |
| Telemetry schema | "what signals do I need stitched to investigate?" | "what signature does my action leave?" |
| Threat intel | "what detections should I have?" | "what's the next campaign?" |

This is the architectural reason a platform is possible at all. Different inputs would mean two products. Same inputs, different operators, means one platform with two operator implementations.

The corollary: anything describing *inputs* belongs in the shared compartment; anything describing an *operator* belongs team-private. Most programs miss this because inputs and operators live in the same file. See `signals/CVE-2026-31431.yaml` in this repo — `rules:` is a blue operator, `agent_context:` is shared input, they share one YAML today. That's the architecture flaw, not the feature.

---

## 3. Three compartments, not two

The compartmentalization model:

```
                    ┌─────────────────────────────────────────┐
                    │            PLATFORM compartment         │
                    │   (Internal — both teams contribute,    │
                    │    neither owns the scorecard alone)    │
                    │                                          │
                    │  - Agent harness / orchestrator         │
                    │  - Runbook spec schema                  │
                    │  - Eval / purple scorecard              │
                    │  - Audit log sink + supply-chain        │
                    │    provenance                           │
                    └────────────┬────────────────────────────┘
                                 │
                ┌────────────────┼────────────────┐
                │                                  │
   ┌────────────▼─────────────┐    ┌──────────────▼──────────────┐
   │   KNOWLEDGE-BASE         │    │   EMBARGO compartment       │
   │   compartment            │    │   (separate org / tight     │
   │   (Internal — shared     │    │    team, short retention,   │
   │    inputs)               │    │    TLP:AMBER/RED material)  │
   │                          │    │                              │
   │  - Exploit chain docs    │    │  - Pre-disclosure PoCs      │
   │  - Asset inventory       │    │  - Customer-data artifacts  │
   │  - Telemetry schemas     │    │  - Embargoed CVE work       │
   │  - Sample telemetry      │    └─────────────────────────────┘
   │  - Threat intel feeds    │
   └──────┬───────────────┬───┘
          │               │
   ┌──────▼──────┐ ┌──────▼──────┐
   │ BLUE        │ │ RED         │
   │ (Private,   │ │ (Private,   │
   │  team-only) │ │  team-only) │
   │             │ │             │
   │ detections  │ │ tooling     │
   │ response    │ │ campaigns   │
   │ containment │ │ payloads    │
   └─────────────┘ └─────────────┘
```

Two things worth saying loudly:

**"Internal" is not compartmentalization.** In GitHub Enterprise, `internal` means every authenticated org member can read it. That's right for the knowledge base and the platform compartment. It's wrong for blue detections or red tooling. Working-team repos must be `private` and team-scoped via CODEOWNERS + branch protection. Programs that conflate the two are running on permissions theater.

**Embargo is a separate compartment, not a folder.** Pre-disclosure CVE material, customer-data-bearing pen-test artifacts, and TLP:RED intel can't sit in the shared knowledge base — every org member would have read access. [FIRST.org TLP 2.0](https://www.first.org/tlp/) treats these as a distinct sharing class with explicit handling rules; the repo topology has to match. A separate org with a tight membership list and short retention is the cleanest implementation.

---

## 4. The blue half: what ThIOClaw demonstrates today

The point of the existing ThIOClaw implementation is to make the blue half real before arguing about red. Today's code (`main` branch of this repo) demonstrates:

**Tier 1 — deterministic, reproducible signal scoring.** `data_plane/cve_2026_31431.py` consumes a normalized telemetry DataFrame, applies weighted rules from `signals/CVE-2026-31431.yaml`, and produces a `tier1.json` verdict that is identical given identical inputs. No LLM. When the agent is unavailable or producing nonsense, the math still runs and the verdict is still auditable.

**Tier 2 — LLM agent with tools, not autonomy.** `scripts/thioclaw_agent/agent.py` runs a tool-calling loop (LiteLLM, defaulting to local Ollama). The agent reads `tier1.json`, requests raw telemetry rows, consults the theoretical exploit chain — but cannot execute new queries or change detection logic without analyst approval through the `propose_query_execution` HITL gate.

**Observability already wired.** Structured JSONL to `logs/agent_runs.jsonl`, Prometheus metrics at `:9090`, OpenTelemetry traces. Per-run findings in both machine-readable YAML (`findings/<run>_finding.yaml`) and human-readable Markdown/HTML (`docs/`). Investigations are reconstructable after the fact — the prerequisite for trusting an agent at all.

**Telemetry source independence.** Tier 1 consumes a normalized DataFrame regardless of collector. osquery and auditd are first-class; per-signal source support is declared via `supported_sources:` in the rule YAML. Blue's detection logic stays portable across whatever telemetry stack red is targeting.

What ThIOClaw is *not*: yet split along the compartmentalization model above. The `agent_context:` block in the signal YAML is shared input that belongs in the knowledge base; the `rules:` block is blue-operator code. They share a file because they share an owner today. The compartment migration would fix that first.

---

## 5. The red mirror: symmetric by design

Red is built as a mirror of blue, not a separate stack. The symmetry is what makes the platform a platform rather than two products glued together.

```
red_plane/<cve_id>.py            ← mirror of data_plane/<cve_id>.py
  Tier 1: deterministic exploitability scoring
          (CVSS + asset reachability + patch status)
  Tier 2: LLM agent invocation

scripts/redclaw_agent/           ← mirror of scripts/thioclaw_agent/
  Tools:
    - fetch_threat_intel         (NVD, GHSA, ExploitDB)
    - enumerate_vulnerable_assets
    - synthesize_exploit_chain
    - propose_attack_execution   ← HITL gate, mirror of
                                   propose_query_execution

runbooks/<cve_id>.yaml           ← machine-readable spec
  Phase 1-3: red triggers (provision, configure, fire)
  Phase 4-5: blue verification (rule match, telemetry capture)
  Owner: knowledge-base (shared input)
  Executor: split — red runs Phase 1-3, blue verifies Phase 4-5
```

The runbook is the keystone. `runbooks/CVE-2026-31431_sigma_validation.md` is the manual markdown version of what a structured YAML contract would carry. Phase 3 (AF_ALG socket, `modprobe algif_aead`, `splice()` as non-root) becomes the red agent's action graph. Phase 4 (verify each Sigma rule fires on the captured audit records) becomes the blue verification contract. Same artifact, two operators. And because the markdown already encodes operational depth — the `-a never,task` gotcha, the splice/PATH stitching requirement, the AF_ALG hex encoding — the platform inherits hard-won knowledge instead of starting blank.

---

## 6. Guardrails, summarized (deep dive in companion doc)

Both sides need guardrails. They are not the same guardrails. See [`guardrails-and-observability.md`](./guardrails-and-observability.md) for the technical detail. The short version:

**Blue guardrails — what ThIOClaw already has and what's missing.** HITL on query proposal exists today; Strands hooks (commit `a0bcded`) carry the shared guardrails policy; Ollama-default keeps telemetry on-host. Missing: an enforced denylist of irreversible response actions (host isolation, credential rotation) without two-person approval, prompt-injection detection on telemetry fields (an attacker who controls the process command line controls part of the agent's prompt), and a max-blast-radius declaration on every tool schema.

**Red guardrails — entirely new surface.** Blast radius declarations on every offensive tool (does this action persist? is it reversible? does it touch production?). Attribution control (no offensive infrastructure may be linkable to corporate identity — [MITRE ATT&CK Resource Development tactic TA0042](https://attack.mitre.org/tactics/TA0042/) describes the adversary's OPSEC requirements; the same discipline applies to authorized red teams). Embargo handling for any tool that produces pre-disclosure material. Hard gates on production-targeted execution that require named-analyst approval, not role-based.

**Platform-layer guardrails — what neither team owns.** Audit log streaming to a sink outside both teams' write access. Supply-chain provenance for every tool the agents can call (SBOM + signing). A third-party (often the platform team, sometimes a CISO-office sign-off) on changes to the eval scorecard schema, because either team will silently optimize against a scorecard they own.

For the AI/ML side specifically — relevant to "secure, air-gapped environments for the safe development and execution of advanced AI/ML models for adversary simulations" in JD-speak — the authorities to map against are [NIST AI RMF (AI 100-1)](https://www.nist.gov/itl/ai-risk-management-framework) and [MITRE ATLAS](https://atlas.mitre.org/). Both make the case that AI red teaming is its own threat model: the model under test can exfiltrate via outputs, the offensive prompts you develop are dual-use research material, and the eval datasets are themselves sensitive artifacts. None of this is addressed by "we use Ollama" alone. It is addressed by the embargo compartment + supply-chain provenance + air-gap network policy enforcement, which is what makes the platform compartment more than a thin orchestrator.

---

## 7. Observability, summarized (deep dive in companion doc)

Three independent observability planes, one cross-cutting correlation layer:

- **Blue plane** — agent run JSONL, Tier 1 signal scoring metrics, time-to-verdict, signal-to-noise ratio per CVE target. Already implemented; see `observability/` in this repo.
- **Red plane** — agent action JSONL, asset reachability deltas (the red agent's view of "what changed about exploitability"), campaign progression metrics, OPSEC posture telemetry (am I leaking attribution?).
- **Platform plane** — the eval scorecard ingest, supply-chain attestation log, cross-team correlation ID linking a red campaign to the blue verdict it generated, the audit log sink that neither team can edit.

The platform plane is where the measurability story for agentic workflows actually lives. Per-CVE rows on the scorecard: did the red campaign produce telemetry the collectors captured? Did Sigma fire? Did Tier 1 score above threshold? Did Tier 2 reach the right verdict? What was the wall-clock time from attack execution to blue verdict? This is the artifact a program lead reads to decide whether the agentic platform is earning its keep.

---

## 8. The eval loop: how you know it works

```
       ┌───────────────────────────────────────────┐
       │     Runbook YAML (knowledge base)         │
       │     — same input for both sides           │
       └─────────────┬────────────────┬────────────┘
                     │                │
              red executor      blue verifier
              (red plane)       (data plane + agent)
                     │                │
                     ▼                ▼
            ┌────────────────┐ ┌────────────────┐
            │ Action log     │ │ Telemetry +    │
            │ Telemetry      │ │ Tier 1 verdict │
            │ produced       │ │ Tier 2 verdict │
            └────────┬───────┘ └────────┬───────┘
                     │                  │
                     └────────┬─────────┘
                              ▼
                  ┌───────────────────────┐
                  │  Eval scorecard       │
                  │  (platform plane)     │
                  │                       │
                  │  - Sigma fired?       │
                  │  - Tier 1 scored?     │
                  │  - Tier 2 verdict     │
                  │    correct?           │
                  │  - Time-to-detect     │
                  │  - Noise floor        │
                  └───────────────────────┘
```

The scorecard is what makes this a program rather than a demo. It also has to be owned by the platform compartment specifically because either team will silently edit the rules of a game they can rewrite. This is the smallest, sharpest argument for the third compartment: someone has to keep the scoreboard.

---

## 9. What most programs get wrong

1. **No platform compartment.** Two teams, shared Slack, no shared substrate. Symptom: the program can't answer "what's our mean time to detect for the techniques we've actually tested?" because nobody owns the test set.
2. **"Internal" repos treated as team-private.** Symptom: red can read blue's detections in the same org and vice versa, and the program calls it "operational separation."
3. **No embargo bucket.** Symptom: pre-disclosure PoCs sit in the same repo as published TTPs, with the same access list.
4. **Eval scorecard owned by red or blue.** Symptom: the scorecard always shows the owning team winning.
5. **AI red teaming not architected at all.** Symptom: the program adds an LLM agent and the threat model doesn't change.

None of these are solved by tooling. They're solved by deciding where things live and who can read them, before any code is written.

---

## Further reading

- Companion: [`guardrails-and-observability.md`](./guardrails-and-observability.md) — technical depth on both sides
- [NIST AI Risk Management Framework (AI 100-1)](https://www.nist.gov/itl/ai-risk-management-framework)
- [MITRE ATLAS](https://atlas.mitre.org/) — adversarial threat landscape for AI systems
- [MITRE ATT&CK — Resource Development (TA0042)](https://attack.mitre.org/tactics/TA0042/)
- [FIRST.org Traffic Light Protocol 2.0](https://www.first.org/tlp/)
- [SigmaHQ/sigma PR #6052](https://github.com/SigmaHQ/sigma/pull/6052) — the live CVE-2026-31431 detection rules this repo's runbook validates
