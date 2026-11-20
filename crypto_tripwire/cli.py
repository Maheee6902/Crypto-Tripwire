"""Command-line interface for Crypto-Tripwire (monitor, verify-case, analyze-case)."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
import time
from typing import List, Optional

from crypto_tripwire import SCHEMA_VERSION, __version__
from crypto_tripwire.capture import verify_case_manifest
from crypto_tripwire.config import AppConfig
from crypto_tripwire.pipeline import CryptoTripwirePipeline


def setup_logging(log_dir: str) -> None:
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_file = Path(log_dir) / "crypto_tripwire.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def cmd_monitor(args: argparse.Namespace) -> int:
    cfg = AppConfig.load(args.config) if args.config else AppConfig()
    if args.watch_dir:
        cfg.monitored_roots = [args.watch_dir]
    if args.output_root:
        cfg.output_root = args.output_root

    errs = cfg.validate()
    if errs:
        for e in errs:
            print(f"[CONFIG ERROR] {e}", file=sys.stderr)
        return 2

    setup_logging(cfg.log_dir)
    print("=" * 68)
    print(f"  CRYPTO-TRIPWIRE v{__version__} (Schema {SCHEMA_VERSION})")
    print(f"  Phase 1 Detector : Format-Aware Magic Header & 4 KiB Block Entropy")
    print(f"  Monitored Roots  : {', '.join(cfg.monitored_roots)}")
    print(f"  Cases Output Root: {cfg.output_root}")
    print("=" * 68)

    def _on_completed(res: dict) -> None:
        print(f"\n[Pipeline] Completed Case {res['case_id']}")
        print(f"           Directory : {res['case_dir']}")
        print(f"           Integrity : {res['phase3']['verification']['overall_status']}")
        print(f"           Findings  : {res['phase3']['findings']['findings_count']}")
        print(f"           PDF Report: {res['phase4']['pdf_report']}")
        print(f"           HTML      : {res['phase4']['html_report']}")
        print(f"           JSON      : {res['phase4']['json_report']}\n")

    pipeline = CryptoTripwirePipeline(cfg, on_case_completed=_on_completed)
    pipeline.start()
    print("[Monitor] Watching target directories. Press Ctrl+C to stop.")
    start_t = time.monotonic()
    try:
        while True:
            time.sleep(0.25)
            if args.duration and (time.monotonic() - start_t) >= args.duration:
                print(f"[Monitor] Reached configured duration ({args.duration}s). Stopping...")
                break
    except KeyboardInterrupt:
        print("\n[Monitor] Stopping gracefully...")
    finally:
        pipeline.stop()
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    case_dir = Path(args.case_dir)
    if not case_dir.exists():
        print(f"[ERROR] Case directory does not exist: {case_dir}", file=sys.stderr)
        return 2
    rep = verify_case_manifest(case_dir, manifest_filename=args.manifest_name)
    print(json.dumps(rep.to_dict(), indent=2))
    return 0 if rep.overall_status == "VERIFIED" else 1


def cmd_analyze(args: argparse.Namespace) -> int:
    src_dir = Path(args.case_dir)
    if not src_dir.exists():
        print(f"[ERROR] Case directory does not exist: {src_dir}", file=sys.stderr)
        return 2
    target_dir = Path(args.output_dir) if args.output_dir else src_dir
    if target_dir.resolve() != src_dir.resolve():
        import shutil
        if target_dir.exists():
            shutil.rmtree(target_dir)
        shutil.copytree(src_dir, target_dir)

    cfg = AppConfig.load(args.config) if args.config else AppConfig()
    pipeline = CryptoTripwirePipeline(cfg, seed_existing_baselines=False)
    res = pipeline.analyze_existing_case_directory(target_dir, revision=args.revision)
    summary = {
        "case_id": res["case_id"],
        "case_dir": res["case_dir"],
        "verification_status": res["phase3"]["verification"]["overall_status"],
        "verified_files_count": res["phase3"]["verification"]["verified_count"],
        "total_timeline_events": res["phase3"]["timeline"]["total_events"],
        "findings_count": res["phase3"]["findings"]["findings_count"],
        "reports": res["phase4"],
    }
    print(json.dumps(summary, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypto-tripwire",
        description="Crypto-Tripwire: Entropy-Based Ransomware Detection for Automated Volatile Evidence Capture and Incident Response.",
    )
    parser.add_argument("--version", action="version", version=f"crypto-tripwire {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_mon = sub.add_parser("monitor", help="Start live Phase 1->4 monitoring on target folder(s).")
    p_mon.add_argument("--config", type=str, default=None, help="Path to JSON configuration file.")
    p_mon.add_argument("--watch-dir", type=str, default=None, help="Override monitored directory.")
    p_mon.add_argument("--output-root", type=str, default=None, help="Override cases output directory.")
    p_mon.add_argument("--duration", type=float, default=None, help="Optional bounded run duration in seconds.")
    p_mon.set_defaults(func=cmd_monitor)

    p_ver = sub.add_parser("verify-case", help="Independently recompute SHA-256 hashes for a captured case directory.")
    p_ver.add_argument("case_dir", type=str, help="Path to case directory containing manifest.json.")
    p_ver.add_argument("--manifest-name", type=str, default="manifest.json", help="Manifest filename.")
    p_ver.set_defaults(func=cmd_verify)

    p_ana = sub.add_parser(
        "analyze-case", help="Run Phase 3 SHA-256 verification/timeline and Phase 4 reporting on a captured case directory."
    )
    p_ana.add_argument("case_dir", type=str, help="Path to captured case directory.")
    p_ana.add_argument("--output-dir", type=str, default=None, help="Optional output directory copy.")
    p_ana.add_argument("--config", type=str, default=None, help="Optional path to JSON configuration file.")
    p_ana.add_argument("--revision", type=int, default=1, help="Report revision number.")
    p_ana.set_defaults(func=cmd_analyze)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
