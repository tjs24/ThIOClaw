"""
tests/test_ingester.py
Test the InventoryIngester CSV → SQLite pipeline.
"""
import os
import tempfile
import textwrap

import pandas as pd
import pytest

from harness.ingester import InventoryIngester


SAMPLE_CSV = textwrap.dedent("""\
    workload_id,hostname,os_name,os_version,distro_family,running_kernel,pkg_mgr,kernel_pkg_version,kmod_version,algif_aead,assessment,action,collected_at
    wl_001,host-a,ubuntu,22.04,ubuntu,5.15.0-91-generic,deb,5.15.0-91.101,29-1ubuntu1.0,loaded,vulnerable_or_not_confirmed_fixed,upgrade kmod,2026-05-28T18:00:00Z
    wl_002,host-b,ubuntu,22.04,ubuntu,5.15.0-91-generic,deb,5.15.0-91.101,29-1ubuntu1.1,not_loaded_or_built_in_unknown,mitigated_by_kmod,OK,2026-05-28T18:00:00Z
    wl_003,host-c,red hat enterprise linux,8.10,redhat_family,4.18.0-553.120.1.el8_10.x86_64,rpm,4.18.0-553.121.1.el8_10,not_installed_or_not_deb,loaded,patched_kernel_pkg_exact_match,OK,2026-05-28T18:00:00Z
""")


@pytest.fixture
def csv_file(tmp_path):
    p = tmp_path / "inventory.csv"
    p.write_text(SAMPLE_CSV)
    return str(p)


@pytest.fixture
def ingester(csv_file, tmp_path):
    db = str(tmp_path / "inventory.db")
    return InventoryIngester(csv_path=csv_file, db_path=db)


def test_ingest_row_count(ingester):
    n = ingester.ingest()
    assert n == 3


def test_ingest_idempotent(ingester):
    ingester.ingest()
    n2 = ingester.ingest()  # mtime unchanged → skips
    assert n2 == 0


def test_ingest_force(ingester):
    ingester.ingest()
    n2 = ingester.ingest(force=True)
    assert n2 == 3


def test_get_vulnerable_workloads(ingester):
    ingester.ingest()
    df = ingester.get_vulnerable_workloads(["vulnerable_or_not_confirmed_fixed"])
    assert len(df) == 1
    assert df.iloc[0]["hostname"] == "host-a"


def test_get_vulnerable_workloads_multiple(ingester):
    ingester.ingest()
    df = ingester.get_vulnerable_workloads([
        "vulnerable_or_not_confirmed_fixed",
        "mitigated_by_kmod",
    ])
    assert len(df) == 2


def test_no_csv_file(tmp_path):
    ing = InventoryIngester(
        csv_path=str(tmp_path / "nonexistent.csv"),
        db_path=str(tmp_path / "test.db"),
    )
    n = ing.ingest()
    assert n == 0
