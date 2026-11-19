"""
Inspect and extract verified metrics from real captured case directories (e.g. cases_output/case_* or historical_reference/evidence_output).
Usage:
    python scripts/extract_case_metrics.py [case_dir_or_cases_root]
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto_tripwire.config import AppConfig
from crypto_tripwire.pipeline import CryptoTripwirePipeline


def inspect_single_case(case_dir: Path, pipeline: CryptoTripwirePipeline) -> dict:
    res = pipeline.analyze_existing_case_directory(case_dir)
    ver = res["phase3"]["verification"]
    tl = res["phase3"]["timeline"]
    fd = res["phase3"]["findings"]
    manifest_path = case_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    return {
        "case_id": res["case_id"],
        "case_dir": str(case_dir),
        "sha256_integrity": ver["overall_status"],
        "verified_artifacts_count": ver["verified_count"],
        "capture_duration_ms": manifest.get("capture_duration_ms"),
        "trigger_to_capture_delay_ms": manifest.get("trigger_to_capture_delay_ms"),
        "stream_counts": tl.get("stream_counts", {}),
        "total_timeline_events": tl.get("total_events"),
        "findings_count": fd.get("findings_count"),
        "triggered_rules": [f["rule_id"] for f in fd.get("findings", [])],
        "reports": res["phase4"],
    }


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else (ROOT / "historical_reference" / "evidence_output")
    if not target.exists():
        print(f"[ERROR] Path not found: {target}", file=sys.stderr)
        return 2

    pipeline = CryptoTripwirePipeline(AppConfig(), seed_existing_baselines=False)
    results = []
    if (target / "manifest.json").exists() or (target / "processes.json").exists():
        results.append(inspect_single_case(target, pipeline))
    else:
        for child in sorted(target.iterdir()):
            if child.is_dir() and ((child / "manifest.json").exists() or (child / "processes.json").exists()):
                results.append(inspect_single_case(child, pipeline))

    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
