"""
harness/ingester.py
-------------------
Ingests inventory.csv into a SQLite database for fast querying.
Re-ingests when the source file changes (mtime-based).
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
from pathlib import Path
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

INVENTORY_TABLE = "inventory"
INVENTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory (
    workload_id          TEXT PRIMARY KEY,
    hostname             TEXT NOT NULL,
    os_name              TEXT,
    os_version           TEXT,
    distro_family        TEXT,
    running_kernel       TEXT,
    pkg_mgr              TEXT,
    kernel_pkg_version   TEXT,
    kmod_version         TEXT,
    algif_aead           TEXT,
    assessment           TEXT,
    action               TEXT,
    collected_at         TEXT,
    _ingested_at         TEXT DEFAULT (datetime('now'))
);
"""


def _file_mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except FileNotFoundError:
        return 0.0


def _db_path(csv_path: str) -> str:
    """Derive SQLite DB path from CSV path."""
    p = Path(csv_path)
    return str(p.parent / (p.stem + ".db"))


class InventoryIngester:
    """
    Loads inventory.csv → SQLite and keeps it fresh.
    Tracks last ingested mtime to avoid unnecessary re-reads.
    """

    def __init__(self, csv_path: str, db_path: Optional[str] = None):
        self.csv_path = csv_path
        self.db_path = db_path or _db_path(csv_path)
        self._last_mtime: float = 0.0
        self._conn: Optional[sqlite3.Connection] = None

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_schema(self) -> None:
        conn = self._get_conn()
        conn.execute(INVENTORY_SCHEMA)
        conn.commit()

    def ingest(self, force: bool = False) -> int:
        """
        Ingest CSV → SQLite if the file has changed since last ingest.
        Returns number of rows inserted/replaced.
        """
        current_mtime = _file_mtime(self.csv_path)
        if not force and current_mtime <= self._last_mtime:
            logger.debug("inventory.csv unchanged, skipping ingest")
            return 0

        if not Path(self.csv_path).exists():
            logger.warning("Inventory CSV not found: %s", self.csv_path)
            return 0

        self._init_schema()
        df = pd.read_csv(self.csv_path, dtype=str).fillna("")

        # Ensure workload_id exists; derive if missing
        if "workload_id" not in df.columns:
            df["workload_id"] = df.apply(
                lambda r: "wl_" + hashlib.sha256(
                    (str(r.get("hostname", "")) + str(r.get("collected_at", ""))).encode()
                ).hexdigest()[:12],
                axis=1,
            )

        conn = self._get_conn()
        # Use INSERT OR REPLACE for upsert behaviour
        conn.execute(f"DELETE FROM {INVENTORY_TABLE}")
        df.to_sql(INVENTORY_TABLE, conn, if_exists="append", index=False)
        conn.commit()

        self._last_mtime = current_mtime
        n = len(df)
        logger.info("Ingested %d rows from %s → %s", n, self.csv_path, self.db_path)
        return n

    def get_vulnerable_workloads(self, trigger_assessments: list[str]) -> pd.DataFrame:
        """Return inventory rows whose assessment is in trigger_assessments."""
        self.ingest()
        placeholders = ",".join("?" * len(trigger_assessments))
        query = (
            f"SELECT * FROM {INVENTORY_TABLE} "
            f"WHERE assessment IN ({placeholders})"
        )
        conn = self._get_conn()
        return pd.read_sql_query(query, conn, params=trigger_assessments)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
