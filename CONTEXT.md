# CONTEXT.md — ThIOClaw Domain Glossary

Domain vocabulary for the investigation pipeline. Architecture vocabulary
(module / interface / seam / adapter / depth) lives in the
`improve-codebase-architecture` skill; this file names the *domain* concepts so
deepened modules get named after concepts, not implementation details.

Maintained as design decisions crystallize. Terms below are load-bearing —
use them exactly in code, tests, and reports.

---

## Telemetry ingest

- **NormalizedEvent** — the canonical telemetry row schema every collector is
  normalized into before scoring. Columns the scoring layer depends on:
  `workload_id, ts, event_type, pid, ppid, uid, euid, socket_family,
  socket_protocol, process_name, cmdline, module_name, file_path`. This schema
  is the contract at the telemetry seam — defined once in `telemetry/schema.py`,
  not re-derived per CVE.

- **TelemetrySource** — an adapter at the telemetry seam. One per collector
  format (`OsquerySource`, `AuditdSource`). Interface: `load(path, scope) → raw`,
  `normalize(raw) → NormalizedEvent frame`, `validate(frame) → report`,
  `can_see(signal_id) → bool`. Two adapters make the seam real; one makes it a
  claim.

- **source_coverage** — run-level record produced by Tier 1 before scoring:
  which sources were configured, which loaded, which failed validation, and the
  set of signals each loaded source can see. The input to distinguishing
  *absent* from *blind*.

## Verdict & evidence

- **Finding** — the typed Tier 1 → Tier 2 contract object. Replaces the ad-hoc
  `tier1.json` dict. Owns the entire seam: verdict, score, scoped workloads,
  the per-signal `SignalHit` list, `source_coverage`, and the `ResponsePlan`.
  The single test surface for "what Tier 2 sees."

- **SignalHit** — one signal's record inside a Finding: `id, weight, tier,
  fired, evidence_rows, detected_by, blind_sources`.

- **detected_by** — the source(s) whose rows fired a given signal. Falls out of
  per-source scoring (reconciliation decision 1.a). Lets the Finding express
  corroboration ("both osquery and auditd saw the UID escalation").

- **blind_sources** — sources in a signal's `supported_sources` that were *not*
  present/loaded this run. A non-empty `blind_sources` on a signal that did not
  fire means "we couldn't have seen it," not "it didn't happen."

- **blind verdict cap** (decision 3) — when an `exploited`-tier signal is
  structurally invisible this run (no loaded source can see it), Tier 1 caps the
  verdict at `inconclusive`. A blind spot must never resolve to `benign`.

## Response

- **ResponsePlan** — a deterministic, bounded, ranked set of candidate response
  actions emitted by Tier 1, keyed off verdict tier × scoped workloads. Each
  action carries `blast_radius`, `reversibility`, and `required_approval`. Tier 2
  selects and justifies from this set (then HITL on irreversible actions); it
  does not invent actions as free text.

## Ingest policy (locked decisions)

- **Reconciliation (1.a)** — sources are scored independently, then reconciled
  into one Finding. Provenance is preserved; union-then-score is rejected.
- **Validation failure (2.b)** — a malformed source is dropped, recorded as
  `source_unavailable` in `source_coverage`, and the run continues on the rest.
  A failed source is flagged, never silently treated as a clean negative.
