r"""Live Phase 1 -> Phase 4 Launcher wired directly to the Crypto-Tripwire Paper Pipeline.

Watches all standard user folders (Desktop, Documents, Downloads, Pictures, Videos, Music)
using the exact 4-phase package described in the paper:
    Phase 1: crypto_tripwire/entropy.py & detector.py
    Phase 2: crypto_tripwire/capture.py
    Phase 3: crypto_tripwire/timeline.py (CT-R000 to CT-R006 + SHA-256 verification)
    Phase 4: crypto_tripwire/reporting.py (JSON, HTML, A4 PDF)

Usage:
    python phase1_monitor.py --open-report
    python phase1_monitor.py --watch C:\Users\mahes\Documents --open-report
"""

from __future__ import annotations

import argparse
from pathlib import Path
import time
import webbrowser

from crypto_tripwire.config import AppConfig
from crypto_tripwire.pipeline import CryptoTripwirePipeline


def default_user_folders() -> list[str]:
    home = Path.home()
    candidates = ["Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music"]
    found = [str(home / name) for name in candidates if (home / name).is_dir()]
    if not found:
        fallback = Path.cwd() / "watched_folder"
        fallback.mkdir(parents=True, exist_ok=True)
        return [str(fallback)]
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Crypto-Tripwire Live 4-Phase Monitor (Paper Pipeline)")
    parser.add_argument("--watch", nargs="*", help="Folder(s) to monitor (default: all standard user folders)")
    parser.add_argument("--output", default="cases_output", help="Case output folder (default: ./cases_output)")
    parser.add_argument("--open-report", action="store_true", help="Open HTML incident report automatically")
    args = parser.parse_args()

    watch_dirs = [str(Path(w).resolve()) for w in args.watch] if args.watch else default_user_folders()
    output_root = Path(args.output).resolve()
    log_dir = (Path.cwd() / "logs").resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    cfg = AppConfig()
    cfg.monitored_roots = watch_dirs
    cfg.output_root = str(output_root)
    cfg.log_dir = str(log_dir)
    cfg.excluded_paths = [
        str(output_root),
        str(log_dir),
        str(Path.home() / "AppData"),
    ]
    cfg.capture.enable_ram_acquisition = False
    cfg.capture.enable_volatility = False

    def _on_completed(res: dict) -> None:
        trig = res.get("trigger", {})
        n_files = len(trig.get("triggering_files", []))
        ver = res["phase3"]["verification"]
        finds = res["phase3"]["findings"]["findings_count"]
        html_p = res["phase4"]["html_report"]
        pdf_p = res["phase4"]["pdf_report"]
        json_p = res["phase4"]["json_report"]
        print("\n" + "=" * 68)
        print(f"[PHASE 1 | entropy.py & detector.py] TRIGGERED ({n_files} files) -> {res['case_id']}")
        print(f"[PHASE 2 | capture.py]               Captured volatile evidence -> {res['case_dir']}")
        print(f"[PHASE 3 | timeline.py]              SHA-256: {ver['overall_status']} ({ver['verified_count']}/{ver['checked_count']}) | Findings: {finds} (CT-R000 to CT-R006)")
        print(f"[PHASE 4 | reporting.py]             HTML : {html_p}")
        print(f"[PHASE 4 | reporting.py]             PDF  : {pdf_p}")
        print(f"[PHASE 4 | reporting.py]             JSON : {json_p}")
        print("=" * 68 + "\n")
        if args.open_report and Path(html_p).exists():
            webbrowser.open(Path(html_p).as_uri())

    print("=" * 68)
    print("  CRYPTO-TRIPWIRE: LIVE 4-PHASE DFIR PIPELINE (PAPER EDITION)")
    print("=" * 68)
    print(f"  Phase 1 Watching : {', '.join(watch_dirs)}")
    print(f"  Cases Output     : {output_root}")
    print(f"  Trigger Rule     : >= {cfg.detector.count_threshold} distinct files (block H >= {cfg.detector.entropy_threshold}) in {cfg.detector.time_window_seconds}s")
    print("  Press Ctrl+C to stop.")
    print("=" * 68)

    pipeline = CryptoTripwirePipeline(cfg, on_case_completed=_on_completed, seed_existing_baselines=False)
    pipeline.start()
    try:
        while True:
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\n[Monitor] Stopping gracefully...")
    finally:
        pipeline.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
