"""Benign Academic Test Harness & Live 4-Phase Demo for Crypto-Tripwire.

Safety Guardrail:
    This script ONLY creates and modifies synthetic dummy files inside
    `./demo_watched_folder/`. It never touches user directories, OS files,
    registry keys, shadow copies, or network settings.

Usage:
    python demo.py --open                  # Run all 3 academic scenarios + open HTML report
    python demo.py --scenario benign       # Scenario 1: Benign ZIP & PDF (0 false alarms)
    python demo.py --scenario full         # Scenario 2: Full-file high-entropy burst
    python demo.py --scenario partial      # Scenario 3: Partial/header-only entropy burst
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import time
import webbrowser
import zipfile

from crypto_tripwire.config import AppConfig
from crypto_tripwire.pipeline import CryptoTripwirePipeline


def _assert_inside_sandbox(path: Path, sandbox_root: Path) -> None:
    if path.resolve().parent != sandbox_root.resolve():
        raise RuntimeError(f"Safety guardrail blocked write outside demo_watched_folder: {path}")


def _make_benign_pdf_bytes() -> bytes:
    body = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    padding = b"Academic benign PDF document content line for baseline test.\n" * 120
    return body + padding + b"\n%%EOF\n"


def _seed_decoy_files(watch_dir: Path, prefix: str, count: int = 4, size_kb: int = 32) -> list[Path]:
    files: list[Path] = []
    line = b"Quarterly engineering record - plaintext baseline sample data 0123456789.\n"
    repeats = max(1, (size_kb * 1024) // len(line))
    payload = line * repeats
    for i in range(1, count + 1):
        p = watch_dir / f"{prefix}_0{i}.txt"
        _assert_inside_sandbox(p, watch_dir)
        p.write_bytes(payload)
        files.append(p)
    return files


def _print_case_summary(label: str, res: dict) -> None:
    case_dir = Path(res["case_dir"])
    html_report = Path(res["phase4"]["html_report"])
    pdf_report = Path(res["phase4"]["pdf_report"])
    print("\n" + "-" * 68)
    print(f"  RESULT: {label}")
    print("-" * 68)
    print(f"  [PHASE 1 | entropy.py & detector.py] Case ID   : {res['case_id']}")
    print(f"  [PHASE 2 | capture.py]               Case Dir  : {case_dir}")
    print(f"  [PHASE 3 | timeline.py]              Integrity : {res['phase3']['verification']['overall_status']}")
    print(f"  [PHASE 3 | timeline.py]              Findings  : {res['phase3']['findings']['findings_count']} (CT-R000 to CT-R006)")
    print(f"  [PHASE 4 | reporting.py]             HTML      : {html_report}")
    print(f"  [PHASE 4 | reporting.py]             PDF       : {pdf_report}")
    print("-" * 68)


def main() -> int:
    parser = argparse.ArgumentParser(description="Crypto-Tripwire Benign Academic Test Harness")
    parser.add_argument(
        "--scenario",
        choices=["all", "benign", "full", "partial"],
        default="all",
        help="Which academic test scenario to run (default: all)",
    )
    parser.add_argument("--open", action="store_true", help="Open latest HTML incident report in browser")
    args = parser.parse_args()

    base = Path(__file__).resolve().parent
    watch_dir = base / "demo_watched_folder"
    out_dir = base / "demo_cases_output"
    log_dir = base / "demo_logs"

    shutil.rmtree(watch_dir, ignore_errors=True)
    watch_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    cfg = AppConfig()
    cfg.monitored_roots = [str(watch_dir)]
    cfg.output_root = str(out_dir)
    cfg.log_dir = str(log_dir)
    cfg.detector.cooldown_seconds = 1.5
    cfg.capture.enable_ram_acquisition = False
    cfg.capture.enable_volatility = False

    completed: list[dict] = []

    print("=" * 68)
    print("  CRYPTO-TRIPWIRE: BENIGN ACADEMIC TEST HARNESS (PHASES 1 TO 4)")
    print("=" * 68)
    print(f"  Scenario Mode  : {args.scenario.upper()}")
    print(f"  Sandbox Folder : {watch_dir}")
    print(f"  Output Folder  : {out_dir}")
    print("=" * 68)

    pipeline = CryptoTripwirePipeline(cfg, on_case_completed=lambda res: completed.append(res))
    pipeline.start()
    time.sleep(0.4)

    try:
        # SCENARIO 1: Benign Compressed ZIP & PDF Control (False-Positive Test)
        if args.scenario in ("all", "benign"):
            before = len(completed)
            print("\n[SCENARIO 1 | Benign Control - False-Positive Suppression]")
            print("  Writing 3 normal compressed ZIP files (PK header) + 1 normal PDF (%PDF-)...")
            for idx in range(1, 4):
                zp = watch_dir / f"benign_archive_0{idx}.zip"
                _assert_inside_sandbox(zp, watch_dir)
                with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("blob.bin", os.urandom(24576))
                time.sleep(0.15)
            pdf_p = watch_dir / "benign_paper.pdf"
            _assert_inside_sandbox(pdf_p, watch_dir)
            pdf_p.write_bytes(_make_benign_pdf_bytes())
            time.sleep(0.9)
            delta = len(completed) - before
            status = "PASS (0 false alarms!)" if delta == 0 else f"UNEXPECTED ({delta} alerts)"
            print(f"  Scenario 1 Outcome: {status}")

        # SCENARIO 2: Full-File High-Entropy Burst (Classic Ransomware Pattern)
        if args.scenario in ("all", "full"):
            before = len(completed)
            print("\n[SCENARIO 2 | Full-File Encryption Burst - Classic Pattern]")
            decoys = _seed_decoy_files(watch_dir, "classic_doc", count=4, size_kb=32)
            time.sleep(0.6)
            print("  Overwriting 4 decoy files with full high-entropy bytes (> 7.2 bits/byte)...")
            for f in decoys:
                _assert_inside_sandbox(f, watch_dir)
                f.write_bytes(os.urandom(32768))
                print(f"    -> Full overwrite: {f.name}")
                time.sleep(0.2)
            deadline = time.monotonic() + 12.0
            while len(completed) == before and time.monotonic() < deadline:
                time.sleep(0.1)
            pipeline.wait_for_idle(timeout=10.0)
            if len(completed) > before:
                _print_case_summary("Scenario 2 (Full-File Encryption Burst)", completed[-1])
            else:
                print("  [WARN] Scenario 2 did not trigger within timeout.")

        # Wait for cooldown re-arming between Scenario 2 and Scenario 3
        if args.scenario == "all":
            print("\n  Waiting 2.0s for Phase 1 cooldown re-arming before Scenario 3...")
            time.sleep(2.0)

        # SCENARIO 3: Partial / Header-Only High-Entropy Burst (Intermittent Pattern)
        if args.scenario in ("all", "partial"):
            before = len(completed)
            print("\n[SCENARIO 3 | Partial Header-Only Encryption - Intermittent Pattern]")
            decoys = _seed_decoy_files(watch_dir, "intermittent_doc", count=4, size_kb=64)
            time.sleep(0.8)
            print("  Overwriting ONLY the leading 25% header (16 KiB of 64 KiB) with high-entropy bytes...")
            for f in decoys:
                _assert_inside_sandbox(f, watch_dir)
                raw = bytearray(f.read_bytes())
                header_len = len(raw) // 4
                raw[:header_len] = os.urandom(header_len)
                f.write_bytes(bytes(raw))
                print(f"    -> 25% header overwrite: {f.name} ({header_len} / {len(raw)} bytes)")
                time.sleep(0.2)
            deadline = time.monotonic() + 12.0
            while len(completed) == before and time.monotonic() < deadline:
                time.sleep(0.1)
            pipeline.wait_for_idle(timeout=10.0)
            if len(completed) > before:
                _print_case_summary("Scenario 3 (Partial 25% Header Encryption)", completed[-1])
            else:
                print("  [WARN] Scenario 3 did not trigger within timeout.")
    finally:
        pipeline.stop()

    print("\n" + "=" * 68)
    print(f"  DEMO COMPLETE | Total Incidents Captured & Verified: {len(completed)}")
    print("=" * 68)

    if args.open and completed:
        latest_html = Path(completed[-1]["phase4"]["html_report"])
        if latest_html.exists():
            webbrowser.open(latest_html.as_uri())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
