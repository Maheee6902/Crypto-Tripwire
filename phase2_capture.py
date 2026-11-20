"""Phase 2: Automated Volatile Evidence Capture & SHA-256 Chain-of-Custody Manifest."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

try:
    import psutil
except ImportError:
    psutil = None


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json_atomic(path: Path, data: dict) -> tuple[int, str]:
    raw = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return len(raw), hashlib.sha256(raw).hexdigest()


def collect_processes() -> list[dict]:
    rows: list[dict] = []
    if psutil is None:
        return rows
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
        try:
            info = proc.info
            ct = info.get("create_time")
            ct_utc = (
                datetime.datetime.fromtimestamp(ct, tz=datetime.timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
                if ct
                else None
            )
            rows.append(
                {
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name") or "unknown",
                    "exe": info.get("exe") or "",
                    "cmdline": " ".join(info.get("cmdline") or []),
                    "create_time_utc": ct_utc,
                }
            )
        except Exception:
            continue
    return rows


def collect_network() -> list[dict]:
    rows: list[dict] = []
    if psutil is None:
        return rows
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []
    for c in conns:
        rows.append(
            {
                "pid": c.pid,
                "status": c.status,
                "local_ip": c.laddr.ip if c.laddr else "",
                "local_port": c.laddr.port if c.laddr else None,
                "remote_ip": c.raddr.ip if c.raddr else "",
                "remote_port": c.raddr.port if c.raddr else None,
            }
        )
    return rows


def run_phase2_capture(trigger_info: dict, output_root: Path) -> Path:
    """Create a timestamped case folder, capture volatile state, and hash every artifact."""
    t0 = time.perf_counter()
    case_id = f"case_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:6]}"
    case_dir = output_root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[PHASE 2 | phase2_capture.py] Creating case folder: {case_dir}")

    # 1. Save Phase 1 trigger record
    trigger_payload = {"case_id": case_id, "captured_utc": utc_now(), **trigger_info}
    trig_size, trig_hash = write_json_atomic(case_dir / "trigger.json", trigger_payload)

    # 2. Capture running processes
    procs = collect_processes()
    proc_size, proc_hash = write_json_atomic(
        case_dir / "processes.json",
        {"captured_utc": utc_now(), "count": len(procs), "processes": procs},
    )

    # 3. Capture active network sockets
    sockets = collect_network()
    net_size, net_hash = write_json_atomic(
        case_dir / "network.json",
        {"captured_utc": utc_now(), "count": len(sockets), "connections": sockets},
    )

    duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    # 4. Write SHA-256 chain-of-custody manifest (never hashes itself)
    manifest = {
        "case_id": case_id,
        "captured_utc": utc_now(),
        "capture_duration_ms": duration_ms,
        "artifacts": [
            {"file": "trigger.json", "size_bytes": trig_size, "sha256": trig_hash},
            {"file": "processes.json", "size_bytes": proc_size, "sha256": proc_hash},
            {"file": "network.json", "size_bytes": net_size, "sha256": net_hash},
        ],
    }
    write_json_atomic(case_dir / "manifest.json", manifest)

    print(
        f"[PHASE 2 | phase2_capture.py] Captured {len(procs)} processes, "
        f"{len(sockets)} sockets, and SHA-256 manifest in {duration_ms} ms."
    )
    return case_dir
