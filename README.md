# ThIOClaw — OpenClaw Vulnerability Investigation Harness

> A local-first, engineering-grade harness built around the **OpenClaw** agent that monitors workload inventory (OSQuery-derived), matches assets to vulnerability signatures, and investigates real-time telemetry events to determine whether a vulnerability was actively exploited.

[![Findings](https://img.shields.io/badge/findings-GitHub%20Pages-blue)](https://tej-nik.github.io/ThIOClaw)

---

## Architecture

```
inventory.csv (OSQuery) ──► Ingester ──► inventory.db (SQLite)
events.json (local/S3)  ──► Notebook  ──► Q2–Q6 pandas analysis
                                       ──► Tier 1 signal scoring
                                       ──► ./openclaw investigate (Tier 2 LLM)
                                       ──► findings/*.yaml
                                       ──► docs/*.md (GitHub Pages)
```

## Quick Start

### 1. Install dependencies

```bash
cd ThIOClaw
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Add your data

Copy your OSQuery inventory CSV:
```bash
cp /path/to/osquery_results.csv data/inventory.csv
```

Copy your telemetry JSON (or configure S3 — see below):
```bash
cp /path/to/events.json data/events.json
```

### 3. Run the harness

```bash
# Single cycle, local telemetry
python -m harness.orchestrator --raw-telemetry local --once

# Continuous loop, local telemetry
python -m harness.orchestrator --raw-telemetry local

# Single cycle, S3 telemetry (requires ~/.aws/credentials named profile)
python -m harness.orchestrator --raw-telemetry s3 --once

# Investigate a specific CVE (e.g., our bundled example)
python -m harness.orchestrator --cve CVE-2026-31431 --once
```

### 4. Run the notebook directly (interactive mode)

```bash
# Example using the bundled CVE-2026-31431 notebook
jupyter lab notebooks/investigate_CVE-2026-31431.ipynb
```

Or headlessly via papermill:
```bash
papermill notebooks/investigate_<CVE-ID>.ipynb \
  findings/executed_notebook.ipynb \
  -p raw_telemetry local \
  -p local_events_path data/events.json \
  -p local_inventory_path data/inventory.csv
```

---

## `--raw-telemetry` Flag

| Value | Source | Credentials |
|---|---|---|
| `local` | `data/events.json` | None |
| `s3` | S3 bucket via `data/s3_manifest.json` | `~/.aws/credentials` named profile |

### S3 Setup

1. Edit `data/s3_manifest.json` with your bucket/key paths
2. Ensure your `~/.aws/credentials` has the profile:
   ```ini
   [default]
   aws_access_key_id = AKIA...
   aws_secret_access_key = ...
   ```
3. Set `aws.profile_name` in `harness.yaml` if using a non-default profile

---

## Project Structure

```
ThIOClaw/
├── harness.yaml                   # Main config
├── targets.yaml                   # CVE investigation targets
├── signals/<CVE-ID>.yaml          # Signal rules + weights (e.g. CVE-2026-31431)
├── queries/<CVE-ID>/              # Reference OSQuery SQL files
├── notebooks/
│   └── investigate_<CVE-ID>.ipynb # Investigation notebook
├── data/
│   ├── sample_inventory.csv       # Sample data (replace with real)
│   ├── sample_events.json         # Sample telemetry (replace with real)
│   └── s3_manifest.json           # S3 config (no secrets)
├── harness/                       # Python orchestrator modules
├── observability/                 # OTel metrics, traces, structured logging
├── findings/                      # Output YAML findings (gitignored)
├── docs/                          # GitHub Pages output
├── logs/                          # Structured JSONL logs (gitignored)
└── tests/                         # Unit tests
```

---

## Example: CVE-2026-31431

ThIOClaw comes with a bundled example for **CVE-2026-31431** to demonstrate the harness's capabilities. The queries used in this example are:

| Query | Signal | Tier |
|---|---|---|
| Q1 | `algif_aead` module loaded? | Inventory |
| Q2 | Unprivileged `AF_ALG` socket opens | Suspicious |
| Q3 | UID escalation after `AF_ALG` open (**primary**) | **Exploited** |
| Q4 | Root shell from non-root parent | **Exploited** |
| Q5 | `algif_aead` module load events | Suspicious |
| Q6 | Exploit staging in `/tmp`, `/dev/shm`, memfd | Suspicious |

---

## Observability

| Feature | Detail |
|---|---|
| Structured logs | `logs/agent_runs.jsonl` — one JSON line per event |
| Metrics | Prometheus at `http://localhost:9090/metrics` |
| Traces | OTel (stdout by default, configurable to OTLP endpoint) |

---

## Running Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=harness --cov=observability --cov-report=term-missing
```

---

## GitHub Pages

Push `docs/` to your `main` branch and enable GitHub Pages in the repo settings (source: `docs/` folder). Findings will be published to `https://tej-nik.github.io/ThIOClaw`.

---

## Investigating Any Vulnerability

ThIOClaw is designed to be highly generic. You can investigate **any** vulnerability by supplying the necessary signals, queries, and notebook:

1. **Define Target**: Add an entry to `targets.yaml` with the CVE-ID and basic metadata.
2. **Configure Signals**: Create `signals/<CVE-ID>.yaml` defining the conditions and weights for exploitation.
3. **Build Queries**: Add relevant OSQuery SQL files to `queries/<CVE-ID>/` to extract telemetry.
4. **Create Notebook**: Duplicate `notebooks/investigate_CVE-2026-31431.ipynb`, rename it to `investigate_<CVE-ID>.ipynb`, and adapt the analysis logic to match the new vulnerability's signature.
