"""
tests/test_notebook_runner.py
Test the notebook_runner module (without actually executing papermill).
"""
import json
import pathlib
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from harness.notebook_runner import run_investigation


@pytest.fixture
def dummy_notebook(tmp_path):
    """A minimal valid notebook file."""
    nb = {
        "cells": [],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    p = tmp_path / "test_notebook.ipynb"
    p.write_text(json.dumps(nb))
    return str(p)


def test_run_investigation_success(dummy_notebook, tmp_path):
    """papermill is mocked — verify returned result structure on success."""
    with patch("harness.notebook_runner.pm") as mock_pm:
        mock_pm.execute_notebook.return_value = None

        result = run_investigation(
            notebook_path=dummy_notebook,
            cve_id="CVE-2026-31431",
            workload_id="ALL",
            raw_telemetry="local",
            output_dir=str(tmp_path / "findings"),
            local_events_path="data/sample_events.json",
            local_inventory_path="data/sample_inventory.csv",
            s3_manifest_path="data/s3_manifest.json",
        )

    assert result["status"] == "success"
    assert "run_id" in result
    assert "output_notebook" in result
    assert "finding_yaml" in result


def test_run_investigation_papermill_error(dummy_notebook, tmp_path):
    """Simulate papermill raising an exception — result should have status=error."""
    with patch("harness.notebook_runner.pm") as mock_pm:
        mock_pm.execute_notebook.side_effect = RuntimeError("kernel died")

        result = run_investigation(
            notebook_path=dummy_notebook,
            cve_id="CVE-2026-31431",
            workload_id="wl_001",
            raw_telemetry="local",
            output_dir=str(tmp_path / "findings"),
            local_events_path="x",
            local_inventory_path="x",
            s3_manifest_path="x",
            run_id="test-run-id",
        )

    assert result["status"] == "error"
    assert "kernel died" in result["error"]
    assert result["run_id"] == "test-run-id"


def test_run_investigation_params_passed(dummy_notebook, tmp_path):
    """Verify papermill receives all expected parameters."""
    captured = {}

    def capture_call(**kwargs):
        captured.update(kwargs)

    with patch("harness.notebook_runner.pm") as mock_pm:
        mock_pm.execute_notebook.side_effect = lambda input_path, output_path, **kwargs: captured.update(kwargs)

        run_investigation(
            notebook_path=dummy_notebook,
            cve_id="CVE-2026-31431",
            workload_id="wl_abc",
            raw_telemetry="s3",
            output_dir=str(tmp_path),
            local_events_path="a.json",
            local_inventory_path="b.csv",
            s3_manifest_path="c.json",
            lookback_hours=48,
        )

    params = captured.get("parameters", {})
    assert params["raw_telemetry"] == "s3"
    assert params["cve_id"] == "CVE-2026-31431"
    assert params["workload_id"] == "wl_abc"
    assert params["lookback_hours"] == 48
