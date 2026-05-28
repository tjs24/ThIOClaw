"""
harness/notebook_runner.py
--------------------------
Executes the investigation Jupyter notebook via papermill.
Injects parameters (cve_id, workload_id, raw_telemetry, etc.) and
captures the output notebook for provenance.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import papermill as pm          # imported at module level so tests can mock it
except ImportError:
    pm = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def run_investigation(
    notebook_path: str,
    cve_id: str,
    workload_id: str,
    raw_telemetry: str,
    output_dir: str,
    local_events_path: str,
    local_inventory_path: str,
    s3_manifest_path: str,
    lookback_hours: int = 24,
    openclaw_bin: str = "./openclaw",
    signals_file: Optional[str] = None,
    run_id: Optional[str] = None,
    extra_params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Execute the investigation notebook via papermill.

    Parameters are injected into the notebook's ``parameters`` cell.
    Returns a result dict with run_id, output paths, and exit status.
    """
    if pm is None:
        raise RuntimeError(
            "papermill is required. Install it with: pip install papermill"
        )

    run_id = run_id or str(uuid.uuid4())
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)

    # Executed notebook saved for provenance
    notebook_name = Path(notebook_path).stem
    output_nb = output_dir_path / f"{notebook_name}_{run_id[:8]}.ipynb"

    params: Dict[str, Any] = {
        "raw_telemetry": raw_telemetry,
        "cve_id": cve_id,
        "workload_id": workload_id,
        "output_dir": str(output_dir),
        "local_events_path": str(local_events_path),
        "local_inventory_path": str(local_inventory_path),
        "s3_manifest_path": str(s3_manifest_path),
        "lookback_hours": lookback_hours,
        "run_id": run_id,
        "openclaw_bin": str(openclaw_bin),
    }
    if signals_file:
        params["signals_file"] = str(signals_file)
    if extra_params:
        params.update(extra_params)

    logger.info(
        "Executing notebook %s | cve=%s workload=%s source=%s run=%s",
        notebook_path, cve_id, workload_id, raw_telemetry, run_id,
    )

    start = time.monotonic()
    try:
        pm.execute_notebook(
            input_path=notebook_path,
            output_path=str(output_nb),
            parameters=params,
            kernel_name="python3",
            progress_bar=False,
            request_save_on_stall=True,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "Notebook completed in %dms | run=%s output=%s",
            elapsed_ms, run_id, output_nb,
        )
        return {
            "run_id": run_id,
            "status": "success",
            "elapsed_ms": elapsed_ms,
            "output_notebook": str(output_nb),
            "finding_yaml": str(output_dir_path / f"{run_id}_finding.yaml"),
            "finding_md": str(
                Path("docs") / f"{cve_id}_{run_id[:8]}.md"
            ),
        }
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.error(
            "Notebook FAILED after %dms | run=%s error=%s",
            elapsed_ms, run_id, exc,
        )
        return {
            "run_id": run_id,
            "status": "error",
            "elapsed_ms": elapsed_ms,
            "error": str(exc),
            "output_notebook": str(output_nb),
        }
