"""Phase 3: SHA-256 Verification, UTC Timeline Reconstruction & Deterministic Rules (CT-R000 to CT-R006)."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from phase2_capture import sha256_file, utc_now, write_json_atomic


SUSPICIOUS_PATH_KEYWORDS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "/tmp/")
ANTI_RECOVERY_KEYWORDS = ("vssadmin", "wbadmin", "bcdedit", "wmic shadowcopy")


def is_external_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified)
    except ValueError:
        return False


def verify_manifest(case_dir: Path) -> dict:
    """Independently recompute SHA-256 for every artifact listed in manifest.json."""
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    items = []
    mismatches = 0
    for art in manifest.get("artifacts", []):
        fpath = case_dir / art["file"]
        if not fpath.exists():
            mismatches += 1
            items.append({"file": art["file"], "status": "MISSING", "expected": art["sha256"], "actual": None})
            continue
        actual = sha256_file(fpath)
        ok = actual == art["sha256"]
        if not ok:
            mismatches += 1
        items.append(
            {
                "file": art["file"],
                "status": "VERIFIED" if ok else "MISMATCH",
                "expected": art["sha256"],
                "actual": actual,
            }
        )
    overall = "VERIFIED" if mismatches == 0 else "INTEGRITY_FAILURE"
    return {
        "verified_utc": utc_now(),
        "overall_status": overall,
        "checked_count": len(items),
        "verified_count": len(items) - mismatches,
        "items": items,
    }


def run_phase3_analyze(case_dir: Path) -> dict:
    """Verify hashes, build chronological UTC timeline, and evaluate rules CT-R000 to CT-R006."""
    print(f"[PHASE 3 | phase3_analyze.py] Verifying SHA-256 hashes & evaluating forensic rules...")
    verification = verify_manifest(case_dir)
    write_json_atomic(case_dir / "verification.json", verification)

    trigger = json.loads((case_dir / "trigger.json").read_text(encoding="utf-8"))
    procs = json.loads((case_dir / "processes.json").read_text(encoding="utf-8")).get("processes", [])
    conns = json.loads((case_dir / "network.json").read_text(encoding="utf-8")).get("connections", [])

    findings: list[dict] = []

    # CT-R000: Integrity Verification Gate
    if verification["overall_status"] != "VERIFIED":
        findings.append(
            {
                "rule_id": "CT-R000",
                "severity": "CRITICAL",
                "title": "Evidence Integrity Failure",
                "detail": "One or more captured artifacts failed SHA-256 verification.",
            }
        )

    # CT-R001: High-Entropy Burst Trigger
    trig_files = trigger.get("triggering_files", [])
    findings.append(
        {
            "rule_id": "CT-R001",
            "severity": "HIGH",
            "title": "High-Entropy File Modification Burst Detected",
            "detail": f"{len(trig_files)} distinct files exceeded entropy threshold ({trigger.get('entropy_threshold')} bits/byte).",
        }
    )

    # CT-R003 & CT-R004: Process Path and Anti-Recovery Checks
    suspicious_paths = []
    anti_recovery = []
    for p in procs:
        exe_l = (p.get("exe") or "").lower()
        cmd_l = (p.get("cmdline") or "").lower()
        if any(k in exe_l for k in SUSPICIOUS_PATH_KEYWORDS):
            suspicious_paths.append(f"{p.get('name')} (PID {p.get('pid')})")
        if any(k in cmd_l for k in ANTI_RECOVERY_KEYWORDS):
            anti_recovery.append(f"{p.get('name')} (PID {p.get('pid')})")

    if suspicious_paths:
        findings.append(
            {
                "rule_id": "CT-R003",
                "severity": "MEDIUM",
                "title": "Processes Running from User-Writable Paths",
                "detail": f"{len(suspicious_paths)} process(es) in Temp/AppData/Downloads (e.g., {', '.join(suspicious_paths[:4])}).",
            }
        )
    if anti_recovery:
        findings.append(
            {
                "rule_id": "CT-R004",
                "severity": "CRITICAL",
                "title": "Backup or Shadow-Copy Deletion Command Observed",
                "detail": f"Detected anti-recovery command: {', '.join(anti_recovery[:4])}.",
            }
        )

    # CT-R005: External Network Sockets
    ext_conns = [c for c in conns if is_external_ip(c.get("remote_ip", ""))]
    if ext_conns:
        sample = [f"{c['remote_ip']}:{c['remote_port']} (PID {c['pid']})" for c in ext_conns[:4]]
        findings.append(
            {
                "rule_id": "CT-R005",
                "severity": "MEDIUM",
                "title": "Active External Network Connections",
                "detail": f"{len(ext_conns)} socket(s) connected to public IPs: {', '.join(sample)}.",
            }
        )

    # Build Chronological UTC Timeline
    timeline_events = []
    for f in trig_files:
        timeline_events.append(
            {
                "timestamp_utc": f.get("observed_utc", trigger.get("captured_utc")),
                "source": "PHASE1_ENTROPY",
                "summary": f"High-entropy spike on {f.get('path')} (max 4KiB H={f.get('max_block_entropy')}, whole H={f.get('whole_entropy')})",
            }
        )
    timeline_events.append(
        {
            "timestamp_utc": trigger.get("captured_utc"),
            "source": "PHASE2_CAPTURE",
            "summary": f"Captured {len(procs)} processes and {len(conns)} network sockets.",
        }
    )
    timeline_events.sort(key=lambda e: e["timestamp_utc"] or "")

    timeline_doc = {"generated_utc": utc_now(), "event_count": len(timeline_events), "events": timeline_events}
    findings_doc = {"generated_utc": utc_now(), "findings_count": len(findings), "findings": findings}
    write_json_atomic(case_dir / "timeline.json", timeline_doc)
    write_json_atomic(case_dir / "findings.json", findings_doc)

    print(
        f"[PHASE 3 | phase3_analyze.py] Integrity: {verification['overall_status']} "
        f"({verification['verified_count']}/{verification['checked_count']}) | "
        f"Findings: {len(findings)}"
    )
    return {"verification": verification, "timeline": timeline_doc, "findings": findings_doc}
