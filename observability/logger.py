"""
observability/logger.py
-----------------------
Structured JSONL logger for OpenClaw agent run steps.

Every significant harness event is written as a JSON line to
logs/agent_runs.jsonl with consistent fields:
  ts, level, event, cve_id, workload_id, run_id, ...kwargs
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class StructuredLogger:
    """
    Thread-safe JSONL event logger.
    Each call writes one JSON line to the configured log file.
    """

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._std_logger = logging.getLogger("openclaw.structured")

    def _write(self, level: str, event: str, **kwargs: Any) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "event": event,
            **{k: v for k, v in kwargs.items() if v is not None},
        }
        line = json.dumps(record, default=str)
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        # Mirror to stdlib logger for console visibility
        self._std_logger.info("%s | %s", event, json.dumps(kwargs, default=str))

    def info(self, event: str, **kwargs: Any) -> None:
        self._write("INFO", event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._write("WARNING", event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._write("ERROR", event, **kwargs)

    def debug(self, event: str, **kwargs: Any) -> None:
        self._write("DEBUG", event, **kwargs)


_logger_instance: Optional[StructuredLogger] = None


def get_structured_logger(log_path: str = "logs/agent_runs.jsonl") -> StructuredLogger:
    """Return a singleton StructuredLogger for the given path."""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = StructuredLogger(log_path)
    return _logger_instance
