"""
telemetry/sources/auditd.py
---------------------------
auditd adapter. Parses raw audit records (ausearch-style snapshot, see
runbooks/CVE-2026-31431_sigma_validation.md Phase 5) and normalizes them into
the NormalizedEvent schema.

Grounded in the runbook's record shapes (Phase 4 table + Appendix C):

  - SYSCALL syscall=41 (socket) a0=0x26  -> event_type=socket, socket_family=38
  - EXECVE a0=modprobe a1=algif_aead     -> event_type=kernel_module (the load
                                            normalized into osquery's shape so
                                            MODULE_LOAD_EVENT fires either way)
  - SYSCALL syscall=59 (execve)          -> event_type=process
  - PATH name=/tmp.. paired with SYSCALL -> event_type=file

Honest blind spots this adapter does NOT paper over (Appendix C):
  - splice() emits no PATH record, and the same-PID uid->euid escalation needs
    auparse-level session stitching. So UID_ESCALATION_AFTER_AFALG (Q3) is
    osquery-only in the signal YAML, and this adapter never synthesizes it.
    That is the whole point of source coverage: a signal auditd cannot see is
    `blind`, not `benign`.

auditd snapshots are per-host and carry no workload_id, so it is stamped from
the ingest scope (workload_id_default for 'ALL').
"""
from __future__ import annotations

import re

import pandas as pd

from telemetry.sources.base import TelemetrySource

# audit(1748448120.123:401) or audit(1748448120:401) -> (ts, event_id)
_AUDIT_ID = re.compile(r"audit\((\d+)(?:\.\d+)?:(\d+)\)")
# key=value, value either "quoted" or bare token
_KV = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")

# x86_64 syscall numbers we key on.
_SYS_SOCKET = 41
_SYS_EXECVE = 59

_STAGING_PREFIXES = ("/tmp/", "/dev/shm/", "/proc/")


def _strip(v: str) -> str:
    return v[1:-1] if len(v) >= 2 and v[0] == '"' and v[-1] == '"' else v


def _to_int(v):
    if v is None:
        return None
    try:
        return int(v, 16) if isinstance(v, str) and v.lower().startswith("0x") else int(v)
    except (TypeError, ValueError):
        return None


class AuditdSource(TelemetrySource):
    name = "auditd"

    def load(self, path: str) -> str:
        with open(path) as f:
            return f.read()

    def normalize(self, raw: str) -> pd.DataFrame:
        events = self._group_by_event(raw)
        rows = [self._row_from_event(ev) for ev in events.values()]
        rows = [r for r in rows if r is not None]
        return pd.DataFrame(rows)

    # --- parsing ----------------------------------------------------------
    def _group_by_event(self, text: str) -> dict[str, dict]:
        """Merge all records sharing an audit event id into one dict.

        Each event accumulates: ts, the set of record types, merged key=values,
        and EXECVE positional args (a0, a1, ...).
        """
        events: dict[str, dict] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line == "----":
                continue
            m = _AUDIT_ID.search(line)
            if not m:
                continue
            ts, eid = m.group(1), m.group(2)
            ev = events.setdefault(eid, {"ts": int(ts), "types": set(), "f": {}, "argv": {}})

            kvs = {k: _strip(v) for k, v in _KV.findall(line)}
            rtype = kvs.get("type", "")
            ev["types"].add(rtype)
            if rtype == "EXECVE":
                for k, v in kvs.items():
                    if re.fullmatch(r"a\d+", k):
                        ev["argv"][k] = v
            # Last-writer-wins merge; SYSCALL carries the identity fields we need.
            for k, v in kvs.items():
                if k != "type":
                    ev["f"][k] = v
        return events

    # --- mapping ----------------------------------------------------------
    def _row_from_event(self, ev: dict) -> dict | None:
        f = ev["f"]
        types = ev["types"]
        argv = ev["argv"]
        syscall = _to_int(f.get("syscall"))

        row = {
            "workload_id": f.get("workload_id") or self.workload_id_default or "ALL",
            "ts": ev["ts"],
            "pid": _to_int(f.get("pid")),
            "ppid": _to_int(f.get("ppid")),
            "uid": _to_int(f.get("uid")),
            "euid": _to_int(f.get("euid")),
            "process_name": f.get("comm"),
            "cmdline": f.get("exe"),
            "event_type": None,
            "socket_family": None,
            "socket_protocol": None,
            "module_name": None,
            "file_path": None,
        }

        a0 = argv.get("a0", "")
        a1 = argv.get("a1", "")

        # 1. Module load via modprobe/insmod execve -> normalize to kernel_module.
        if "EXECVE" in types and a0 in ("modprobe", "insmod") and "algif_aead" in a1:
            row["event_type"] = "kernel_module"
            row["module_name"] = "algif_aead"
            row["process_name"] = a0
            row["cmdline"] = f"{a0} {a1}".strip()
            return row

        # 2. AF_ALG socket creation.
        if syscall == _SYS_SOCKET:
            row["event_type"] = "socket"
            row["socket_family"] = _to_int(f.get("a0"))      # a0=0x26 -> 38
            row["socket_protocol"] = _to_int(f.get("a2"))
            return row

        # 3. File staging — PATH record names a target path.
        if "PATH" in types and f.get("name"):
            name = f["name"]
            if name.startswith(_STAGING_PREFIXES):
                row["event_type"] = "file"
                row["file_path"] = name
                return row

        # 4. Generic process execution (root shells, exploit binaries).
        if syscall == _SYS_EXECVE or "EXECVE" in types:
            row["event_type"] = "process"
            return row

        return None
