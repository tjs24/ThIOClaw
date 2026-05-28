"""
tests/test_docs_builder.py
Test the docs_builder index regeneration.
"""
import json
import pathlib
import pytest

from harness.docs_builder import build_index, load_findings_index


SAMPLE_FINDINGS = [
    {
        "run_id": "aaaabbbb-1234-5678-abcd-000000000001",
        "cve_id": "CVE-2026-31431",
        "raw_telemetry_source": "local",
        "investigated_at": "2026-05-28T18:00:00Z",
        "workloads_investigated": ["prod-web-42", "prod-db-07"],
        "tier1": {"verdict": "exploited", "signals_fired": ["UID_ESCALATION_AFTER_AFALG"], "total_weight": 1.8},
        "recommended_action": "Isolate workload immediately.",
    },
    {
        "run_id": "bbbbcccc-1234-5678-abcd-000000000002",
        "cve_id": "CVE-2026-31431",
        "raw_telemetry_source": "s3",
        "investigated_at": "2026-05-28T19:00:00Z",
        "workloads_investigated": ["rhel-app-01"],
        "tier1": {"verdict": "suspicious", "signals_fired": ["AF_ALG_SOCKET_OPEN_UNPRIV"], "total_weight": 0.5},
        "recommended_action": "Review and patch.",
    },
]


@pytest.fixture
def jsonl_path(tmp_path):
    p = tmp_path / "findings.jsonl"
    with open(p, "w") as f:
        for finding in SAMPLE_FINDINGS:
            f.write(json.dumps(finding) + "\n")
    return str(p)


def test_load_findings_index(jsonl_path):
    findings = load_findings_index(jsonl_path)
    assert len(findings) == 2


def test_load_empty_file(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.touch()
    findings = load_findings_index(str(p))
    assert findings == []


def test_load_nonexistent_file(tmp_path):
    findings = load_findings_index(str(tmp_path / "nope.jsonl"))
    assert findings == []


def test_build_index_creates_file(jsonl_path, tmp_path):
    docs_dir = str(tmp_path / "docs")
    index_path = build_index(jsonl_path, docs_dir=docs_dir)
    assert index_path.exists()
    content = index_path.read_text()
    assert "CVE-2026-31431" in content
    assert "exploited" in content.lower()


def test_build_index_summary_counts(jsonl_path, tmp_path):
    docs_dir = str(tmp_path / "docs")
    index_path = build_index(jsonl_path, docs_dir=docs_dir)
    content = index_path.read_text()
    # One exploited, one suspicious
    assert "| 1 | 1 | 0 | 0 | 2 |" in content


def test_build_index_data_yaml(jsonl_path, tmp_path):
    docs_dir = str(tmp_path / "docs")
    build_index(jsonl_path, docs_dir=docs_dir)
    data_yaml = pathlib.Path(docs_dir) / "_data" / "findings_index.yaml"
    assert data_yaml.exists()


def test_build_index_empty_jsonl(tmp_path):
    empty_jsonl = str(tmp_path / "empty.jsonl")
    docs_dir = str(tmp_path / "docs")
    index_path = build_index(empty_jsonl, docs_dir=docs_dir)
    content = index_path.read_text()
    assert "No findings yet" in content
