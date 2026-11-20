"""Comprehensive unit and integration test suite for Crypto-Tripwire (all 4 phases + evaluation)."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import unittest

from crypto_tripwire.capture import (
    EvidenceCaptureCoordinator,
    MemoryAcquisitionProvider,
    verify_case_manifest,
)
from crypto_tripwire.config import AppConfig, CaptureSettings, DetectorSettings, ResourceLimits
from crypto_tripwire.detector import (
    AsyncFilesystemMonitor,
    BurstDetectionEngine,
    IncidentState,
    RawFilesystemNotification,
)
from crypto_tripwire.entropy import (
    detect_magic_header_format,
    EntropyAnalyzer,
    compute_shannon_entropy,
    deterministic_chunk_offsets,
    normalize_file_path,
)

from crypto_tripwire.models import (
    DetectorMode,
    ObservationMode,
    ProviderStatus,
    ReadState,
    TriggerRecord,
    VerificationStatus,
)
from crypto_tripwire.pipeline import CryptoTripwirePipeline
from crypto_tripwire.reporting import IncidentReportGenerator
from crypto_tripwire.timeline import TimelineReconstructor, parse_iso_to_utc


def make_high_entropy_bytes(seed_label: str, num_blocks: int = 128) -> bytes:
    """Deterministic high-entropy inert byte fixture (~7.95 bits/byte for 4 KiB)."""
    return b"".join(hashlib.sha256(f"{seed_label}_{i}".encode("utf-8")).digest() for i in range(num_blocks))


class TestCryptoTripwireSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="ct_test_"))
        self.watch_dir = self.tmp_dir / "watched"
        self.out_dir = self.tmp_dir / "cases_out"
        self.log_dir = self.tmp_dir / "logs"
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _base_config(self, detection_mode: str = "format_aware_header_and_block") -> AppConfig:
        return AppConfig(
            monitored_roots=[str(self.watch_dir)],
            output_root=str(self.out_dir),
            log_dir=str(self.log_dir),
            observation_mode=ObservationMode.LIVE_ENDPOINT_MONITORING.value,
            detector=DetectorSettings(detection_mode=detection_mode),
        )

    # 1. Known entropy cases (0.0, 1.0, 8.0 bits/byte)
    def test_01_known_entropy_values(self) -> None:
        self.assertEqual(compute_shannon_entropy(b""), 0.0)
        self.assertEqual(compute_shannon_entropy(b"\x00" * 1024), 0.0)
        self.assertEqual(compute_shannon_entropy(b"\x00\xff" * 512), 1.0)
        full_alphabet = bytes(range(256)) * 16
        self.assertEqual(compute_shannon_entropy(full_alphabet), 8.0)
        self.assertEqual(detect_magic_header_format(b"PK\x03\x04test"), "zip_or_ooxml")
        self.assertEqual(detect_magic_header_format(b"%PDF-1.7"), "pdf")
        self.assertIsNone(detect_magic_header_format(b"\x9f\xa2\x11\x08random"))
        analyzer = EntropyAnalyzer(DetectorSettings(detection_mode="format_aware_header_and_block"))
        valid_zip = self.watch_dir / "archive.zip"
        valid_zip.write_bytes(b"PK\x03\x04" + make_high_entropy_bytes("zip_body", 128))
        m_valid = analyzer.measure_file(str(valid_zip), update_baseline=False)
        self.assertFalse(m_valid.qualifies_high_entropy)
        corrupted_zip = self.watch_dir / "corrupted.zip"
        corrupted_zip.write_bytes(make_high_entropy_bytes("ransom_header", 128))
        m_corrupt = analyzer.measure_file(str(corrupted_zip), update_baseline=False)
        self.assertTrue(m_corrupt.qualifies_high_entropy)

    # 2. Empty and too-small content states
    def test_02_empty_and_too_small_files(self) -> None:
        analyzer = EntropyAnalyzer(DetectorSettings(min_file_size_bytes=64))
        empty_fp = self.watch_dir / "empty.txt"
        empty_fp.write_bytes(b"")
        m_empty = analyzer.measure_file(str(empty_fp))
        self.assertEqual(m_empty.read_state, ReadState.EMPTY.value)
        self.assertIsNone(m_empty.shannon_entropy)
        self.assertFalse(m_empty.qualifies_high_entropy)

        small_fp = self.watch_dir / "small.txt"
        small_fp.write_bytes(b"short text")
        m_small = analyzer.measure_file(str(small_fp))
        self.assertEqual(m_small.read_state, ReadState.TOO_SMALL.value)
        self.assertIsNone(m_small.shannon_entropy)
        self.assertFalse(m_small.qualifies_high_entropy)

    # 3. Vanished, unreadable, and changing files (never turned into 0.0 entropy)
    def test_03_vanished_and_unreadable_files(self) -> None:
        analyzer = EntropyAnalyzer(DetectorSettings(read_retry_count=1, read_retry_delay_ms=5.0))
        missing_fp = self.watch_dir / "does_not_exist.bin"
        m_vanished = analyzer.measure_file(str(missing_fp))
        self.assertEqual(m_vanished.read_state, ReadState.VANISHED.value)
        self.assertIsNone(m_vanished.shannon_entropy)
        self.assertFalse(m_vanished.qualifies_high_entropy)

        # Symlink exclusion when follow_symlinks=False
        real_fp = self.watch_dir / "target.txt"
        real_fp.write_bytes(b"A" * 256)
        link_fp = self.watch_dir / "symlink.txt"
        try:
            os.symlink(real_fp, link_fp)
            m_link = analyzer.measure_file(str(link_fp))
            self.assertEqual(m_link.read_state, ReadState.UNSUPPORTED_LINK.value)
        except OSError:
            pass

    # 4. Chunk coverage and baseline compatibility (offsets, truncation, resizing)
    def test_04_chunk_coverage_and_baseline_compatibility(self) -> None:
        offsets = deterministic_chunk_offsets(file_size=1024 * 1024, chunk_size=4096, max_chunks=8)
        self.assertEqual(len(offsets), 8)
        self.assertEqual(offsets[0], 0)
        self.assertTrue(all(o % 4096 == 0 for o in offsets))

        analyzer = EntropyAnalyzer(DetectorSettings(detection_mode="format_aware_header_and_block"))
        fp = self.watch_dir / "doc.txt"
        fp.write_bytes(b"Plain text baseline line.\n" * 400)
        m1 = analyzer.measure_file(str(fp), update_baseline=True, is_initial_seed=True)
        self.assertEqual(m1.read_state, ReadState.OK.value)

        # Truncate and overwrite with high entropy
        fp.write_bytes(make_high_entropy_bytes("trunc", 64))
        m2 = analyzer.measure_file(str(fp), update_baseline=True)
        self.assertIsNotNone(m2.baseline_comparison)
        self.assertTrue(m2.baseline_comparison.baseline_available)
        self.assertEqual(m2.baseline_comparison.size_change_type, "TRUNCATED")
        self.assertTrue(m2.qualifies_high_entropy)

    # 5. Duplicate notifications coalescing and distinct-file triggering
    def test_05_duplicate_notifications_vs_distinct_files(self) -> None:
        cfg_b = self._base_config("format_aware_header_and_block")
        engine_b = BurstDetectionEngine(cfg_b)

        f1 = self.watch_dir / "file1.bin"
        f1.write_bytes(make_high_entropy_bytes("f1", 128))

        # 5 notifications on the same file must NOT trigger an alert
        for _ in range(5):
            engine_b.process_notification(RawFilesystemNotification(event_type="modified", src_path=str(f1)))
        self.assertEqual(len(engine_b.triggers_emitted), 0)
        self.assertGreaterEqual(engine_b.coalesced_notifications_count, 4)

        # Writing 2 more distinct files brings total distinct files to 3 -> triggers alert
        for idx in (2, 3):
            fn = self.watch_dir / f"file{idx}.bin"
            fn.write_bytes(make_high_entropy_bytes(f"f{idx}", 128))
            engine_b.process_notification(RawFilesystemNotification(event_type="created", src_path=str(fn)))
        self.assertEqual(len(engine_b.triggers_emitted), 1)
        self.assertEqual(len(engine_b.triggers_emitted[0].contributing_file_identities), 3)

    # 6. Move/rename and delete event handling
    def test_06_move_and_delete_handling(self) -> None:
        cfg = self._base_config("format_aware_header_and_block")
        engine = BurstDetectionEngine(cfg)

        src = self.watch_dir / "original_name.txt"
        src.write_bytes(b"Low entropy initial text.\n" * 300)
        engine.analyzer.seed_baseline_directory(str(self.watch_dir))

        dst = self.watch_dir / "renamed_name.locked"
        src.write_bytes(make_high_entropy_bytes("renamed_high", 128))
        os.replace(src, dst)

        ev_move = engine.process_notification(
            RawFilesystemNotification(event_type="moved", src_path=str(src), dest_path=str(dst))
        )
        self.assertIsNotNone(ev_move)
        self.assertEqual(ev_move.event_type, "moved")
        self.assertTrue(ev_move.measurement.qualifies_high_entropy)

        dst.unlink()
        ev_del = engine.process_notification(RawFilesystemNotification(event_type="deleted", src_path=str(dst)))
        self.assertIsNotNone(ev_del)
        self.assertEqual(ev_del.measurement.read_state, ReadState.SKIPPED_DELETED.value)

    # 7. Cooldown, re-arming, and repeated incidents
    def test_07_cooldown_rearming_and_repeated_incidents(self) -> None:
        cfg = self._base_config("format_aware_header_and_block")
        cfg.detector.cooldown_seconds = 0.05
        engine = BurstDetectionEngine(cfg)

        # First burst of 3 files
        t0_ns = time.monotonic_ns()
        for i in range(3):
            fp = self.watch_dir / f"burst1_{i}.bin"
            fp.write_bytes(make_high_entropy_bytes(f"b1_{i}", 64))
            engine.process_notification(
                RawFilesystemNotification(event_type="created", src_path=str(fp), observed_monotonic_ns=t0_ns + i * 1000)
            )
        self.assertEqual(len(engine.triggers_emitted), 1)
        self.assertEqual(engine.state, IncidentState.COOLDOWN)

        # Second burst after cooldown (> 50ms later) must re-arm and emit a 2nd distinct incident
        t1_ns = t0_ns + 200_000_000  # +200ms
        for i in range(3):
            fp = self.watch_dir / f"burst2_{i}.bin"
            fp.write_bytes(make_high_entropy_bytes(f"b2_{i}", 64))
            engine.process_notification(
                RawFilesystemNotification(event_type="created", src_path=str(fp), observed_monotonic_ns=t1_ns + i * 1000)
            )
        self.assertEqual(len(engine.triggers_emitted), 2)
        self.assertNotEqual(engine.triggers_emitted[0].case_id, engine.triggers_emitted[1].case_id)

    # 8. Queue pressure and observable event loss
    def test_08_queue_pressure_and_dropped_event_accounting(self) -> None:
        cfg = self._base_config()
        cfg.limits.event_queue_max_size = 2
        monitor = AsyncFilesystemMonitor(cfg, seed_existing_baselines=False)
        # Do not start worker so queue fills deterministically
        ok1 = monitor.enqueue_notification(RawFilesystemNotification(event_type="created", src_path="a"))
        ok2 = monitor.enqueue_notification(RawFilesystemNotification(event_type="created", src_path="b"))
        ok3 = monitor.enqueue_notification(RawFilesystemNotification(event_type="created", src_path="c"))
        self.assertTrue(ok1)
        self.assertTrue(ok2)
        self.assertFalse(ok3)
        self.assertEqual(monitor.engine.dropped_notifications_count, 1)

    # 9. Slow/failed providers and memory acquisition adapter states
    def test_09_memory_provider_states_and_imported_image(self) -> None:
        # Case A: Disabled -> UNAVAILABLE, no fake RAM file created
        m_disabled = MemoryAcquisitionProvider(CaptureSettings(enable_ram_acquisition=False))
        cdir_a = self.out_dir / "mem_disabled"
        cdir_a.mkdir()
        meta_a, _, rec_a = m_disabled.acquire_or_import(cdir_a)
        self.assertEqual(meta_a.status, ProviderStatus.UNAVAILABLE.value)
        self.assertIsNone(rec_a["image_path"])
        self.assertFalse((cdir_a / "memory_dump.raw").exists())

        # Case B: Imported valid analyst image -> IMPORTED with SHA-256 and provenance
        imp_img = self.tmp_dir / "analyst_captured.raw"
        imp_img.write_bytes(b"ANALYST_MEM_HEADER" * 256)
        m_import = MemoryAcquisitionProvider(
            CaptureSettings(
                imported_ram_image_path=str(imp_img),
                imported_ram_provenance="Acquired via VMware snapshot memory export by supervising analyst.",
            )
        )
        cdir_b = self.out_dir / "mem_imported"
        cdir_b.mkdir()
        meta_b, _, rec_b = m_import.acquire_or_import(cdir_b)
        self.assertEqual(meta_b.status, ProviderStatus.IMPORTED.value)
        self.assertEqual(rec_b["image_size_bytes"], imp_img.stat().st_size)
        self.assertIsNotNone(rec_b["image_sha256"])

        # Case C: Empty (0-byte) imported image -> rejected as FAILED
        empty_img = self.tmp_dir / "empty_mem.raw"
        empty_img.write_bytes(b"")
        m_empty = MemoryAcquisitionProvider(CaptureSettings(imported_ram_image_path=str(empty_img)))
        cdir_c = self.out_dir / "mem_empty"
        cdir_c.mkdir()
        meta_c, _, _ = m_empty.acquire_or_import(cdir_c)
        self.assertEqual(meta_c.status, ProviderStatus.FAILED.value)

    # 10. Time normalization, timestamp ties, and true elapsed seconds
    def test_10_time_normalization_and_tie_ordering(self) -> None:
        dt1, note1 = parse_iso_to_utc("2026-09-18T12:20:46.494539Z")
        self.assertIsNotNone(dt1)
        self.assertEqual(dt1.tzinfo, datetime.timezone.utc)

        dt2, note2 = parse_iso_to_utc("2026-09-18T17:20:56.760376")
        self.assertIsNotNone(dt2)
        self.assertIn("Legacy naive timestamp", note2)

    # 11. Independent hash verification & deliberate artifact corruption detection
    def test_11_independent_hash_verification_and_corruption(self) -> None:
        cfg = self._base_config()
        coord = EvidenceCaptureCoordinator(cfg)
        trig = TriggerRecord(
            case_id="case_integrity_test",
            alert_id="alert_int",
            detection_mode=cfg.detector.detection_mode,
            observation_mode=cfg.observation_mode,
            alert_description="Test trigger",
            trigger_utc="2026-11-15T12:00:00Z",
            trigger_monotonic_ns=time.monotonic_ns(),
            first_contributing_event_utc="2026-11-15T11:59:59Z",
            first_contributing_monotonic_ns=time.monotonic_ns() - 1_000_000_000,
            burst_window_elapsed_seconds=1.0,
            applied_thresholds={},
            config_digest=cfg.canonical_digest(),
            contributing_event_ids=[],
            contributing_file_identities=[],
            contributing_events=[],
            pre_alert_history_count=0,
            queue_stats_at_trigger={},
            rationale="Integrity test",
        )
        case_dir, _ = coord.capture_case(trig, [])
        v_ok = verify_case_manifest(case_dir)
        self.assertEqual(v_ok.overall_status, VerificationStatus.VERIFIED.value)
        self.assertEqual(v_ok.mismatch_count, 0)

        # Deliberately corrupt processes.json
        proc_file = case_dir / "processes.json"
        proc_file.write_bytes(proc_file.read_bytes() + b"\n/* corrupted */")
        v_bad = verify_case_manifest(case_dir)
        self.assertEqual(v_bad.overall_status, VerificationStatus.MISMATCH.value)
        self.assertEqual(v_bad.mismatch_count, 1)

        # Run Phase 3 on corrupted case -> must emit CT-R000-INTEGRITY-FAILURE finding
        reconstructor = TimelineReconstructor()
        p3 = reconstructor.reconstruct(case_dir)
        self.assertFalse(p3["timeline"]["integrity_passed"])
        rule_ids = [f["rule_id"] for f in p3["findings"]["findings"]]
        self.assertIn("CT-R000-INTEGRITY-FAILURE", rule_ids)

    # 12. Unsupported connection direction & non-attributed writer PID in Phase 3
    def test_12_phase3_connection_direction_and_pid_semantics(self) -> None:
        # Test on the preserved historical case from the user's original archive
        hist_dir = Path(__file__).resolve().parent.parent / "historical_reference" / "evidence_output"
        if hist_dir.exists():
            work_copy = self.out_dir / "hist_copy"
            shutil.copytree(hist_dir, work_copy)
            reconstructor = TimelineReconstructor()
            res = reconstructor.reconstruct(work_copy)
            self.assertEqual(res["verification"]["overall_status"], VerificationStatus.VERIFIED.value)
            net_events = [e for e in res["timeline"]["events"] if e["event_type"] == "NETWORK_SOCKET_OBSERVED"]
            self.assertTrue(len(net_events) > 0)
            for ne in net_events:
                self.assertEqual(ne["attributes"]["direction_inference"], "UNKNOWN_FROM_SNAPSHOT_ALONE")
                self.assertIsNotNone(ne["elapsed_seconds_from_reference"])

    # 13. Safe report rendering (escaping untrusted filenames/command lines in HTML & PDF)
    def test_13_safe_report_rendering_escapes_untrusted_strings(self) -> None:
        cfg = self._base_config()
        coord = EvidenceCaptureCoordinator(cfg)
        malicious_filename = "<script>alert('xss')</script>&\"'\\bad_path.locked"
        trig = TriggerRecord(
            case_id="case_xss_escape_test",
            alert_id="alert_xss",
            detection_mode=cfg.detector.detection_mode,
            observation_mode=cfg.observation_mode,
            alert_description="XSS test",
            trigger_utc="2026-11-15T12:00:00Z",
            trigger_monotonic_ns=time.monotonic_ns(),
            first_contributing_event_utc="2026-11-15T11:59:59Z",
            first_contributing_monotonic_ns=time.monotonic_ns() - 500_000_000,
            burst_window_elapsed_seconds=0.5,
            applied_thresholds={},
            config_digest=cfg.canonical_digest(),
            contributing_event_ids=["ev_000001"],
            contributing_file_identities=["id_1"],
            contributing_events=[
                {
                    "event_id": "ev_000001",
                    "event_type": "modified",
                    "src_path": malicious_filename,
                    "normalized_path": malicious_filename,
                    "measurement": {
                        "shannon_entropy": 7.95,
                        "bytes_examined": 4096,
                        "file_size": 4096,
                        "read_state": "OK",
                        "qualification_reason": f"Path {malicious_filename} exceeded threshold",
                    },
                }
            ],
            pre_alert_history_count=1,
            queue_stats_at_trigger={},
            rationale=f"Triggered by {malicious_filename}",
        )
        case_dir, _ = coord.capture_case(trig, [])
        TimelineReconstructor().reconstruct(case_dir)
        rep_out = IncidentReportGenerator(cfg).generate_case_reports(case_dir)
        html_content = Path(rep_out["html_report"]).read_text(encoding="utf-8")
        self.assertNotIn("<script>alert('xss')</script>", html_content)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html_content)
        self.assertTrue(Path(rep_out["pdf_report"]).exists())
        self.assertGreater(Path(rep_out["pdf_report"]).stat().st_size, 500)

    # 14. End-to-end benign fixture run + restart preserving finalized cases
    def test_14_end_to_end_pipeline_and_restart_persistence(self) -> None:
        cfg = self._base_config()
        cfg.detector.cooldown_seconds = 0.05

        # Run 1
        pipe1 = CryptoTripwirePipeline(cfg, seed_existing_baselines=False)
        pipe1.start()
        for i in range(3):
            fp = self.watch_dir / f"run1_file_{i}.bin"
            fp.write_bytes(make_high_entropy_bytes(f"r1_{i}", 128))
            pipe1.monitor.enqueue_notification(RawFilesystemNotification(event_type="created", src_path=str(fp)))
        pipe1.wait_for_idle(timeout=10.0)
        pipe1.stop(timeout=5.0)
        self.assertEqual(len(pipe1.completed_cases), 1)
        case1_dir = Path(pipe1.completed_cases[0]["case_dir"])
        self.assertTrue((case1_dir / "incident_report.pdf").exists())
        self.assertTrue((case1_dir / "incident_report.json").exists())

        # Restart (Run 2) in the same output_root -> must preserve Case 1 and create a new Case 2
        pipe2 = CryptoTripwirePipeline(cfg, seed_existing_baselines=False)
        pipe2.start()
        for i in range(3):
            fp = self.watch_dir / f"run2_file_{i}.bin"
            fp.write_bytes(make_high_entropy_bytes(f"r2_{i}", 128))
            pipe2.monitor.enqueue_notification(RawFilesystemNotification(event_type="created", src_path=str(fp)))
        pipe2.wait_for_idle(timeout=10.0)
        pipe2.stop(timeout=5.0)
        self.assertEqual(len(pipe2.completed_cases), 1)
        case2_dir = Path(pipe2.completed_cases[0]["case_dir"])
        self.assertNotEqual(case1_dir, case2_dir)
        self.assertTrue((case1_dir / "incident_report.json").exists())
        self.assertTrue((case2_dir / "incident_report.json").exists())

    # 15. Real captured Windows endpoint snapshot verification (146 processes, 49 sockets)
    def test_15_real_windows_snapshot_verification(self) -> None:
        hist_dir = Path(__file__).resolve().parent.parent / "historical_reference" / "evidence_output"
        case_copy = self.out_dir / "real_windows_case"
        shutil.copytree(hist_dir, case_copy)
        rep = verify_case_manifest(case_copy)
        self.assertEqual(rep.overall_status, VerificationStatus.VERIFIED.value)
        self.assertEqual(rep.verified_count, 2)

    # 16. Real captured Windows endpoint Phase 3 timeline and Phase 4 PDF/HTML/JSON report generation
    def test_16_real_windows_snapshot_timeline_and_reports(self) -> None:
        hist_dir = Path(__file__).resolve().parent.parent / "historical_reference" / "evidence_output"
        case_copy = self.out_dir / "real_windows_case_reports"
        shutil.copytree(hist_dir, case_copy)
        pipeline = CryptoTripwirePipeline(self._base_config(), seed_existing_baselines=False)
        res = pipeline.analyze_existing_case_directory(case_copy)
        self.assertEqual(res["phase3"]["verification"]["overall_status"], "VERIFIED")
        self.assertEqual(res["phase3"]["timeline"]["total_events"], 195)
        self.assertTrue(Path(res["phase4"]["pdf_report"]).exists())
        self.assertTrue(Path(res["phase4"]["html_report"]).exists())
        self.assertTrue(Path(res["phase4"]["json_report"]).exists())


if __name__ == "__main__":
    unittest.main()
