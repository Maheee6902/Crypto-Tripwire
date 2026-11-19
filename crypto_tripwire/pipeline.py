"""End-to-end 4-phase pipeline coordinator for Crypto-Tripwire."""

from __future__ import annotations

import logging
from pathlib import Path
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from crypto_tripwire.capture import EvidenceCaptureCoordinator, verify_case_manifest
from crypto_tripwire.config import AppConfig
from crypto_tripwire.detector import AsyncFilesystemMonitor, RawFilesystemNotification
from crypto_tripwire.models import MonitoredFileEvent, TriggerRecord
from crypto_tripwire.reporting import IncidentReportGenerator
from crypto_tripwire.timeline import TimelineReconstructor


logger = logging.getLogger("crypto_tripwire")


class CryptoTripwirePipeline:
    """
    Coordinates the complete 4-phase workflow:
    Phase 1 (Entropy-based detection trigger) ->
    Phase 2 (Fast volatile evidence capture & SHA-256 manifest) ->
    Phase 3 (Independent hash verification & deterministic timeline reconstruction) ->
    Phase 4 (Automatic JSON, HTML, and PDF incident reporting).

    Capture and reporting execute on a dedicated incident worker thread so that Phase 1
    monitoring continues observing without blocking on I/O.
    """

    def __init__(
        self,
        config: AppConfig,
        on_case_completed: Optional[Callable[[Dict[str, Any]], None]] = None,
        seed_existing_baselines: bool = True,
    ) -> None:
        self.config = config
        self.capture_coord = EvidenceCaptureCoordinator(config)
        self.reconstructor = TimelineReconstructor()
        self.reporter = IncidentReportGenerator(config)
        self.on_case_completed = on_case_completed

        self.incident_queue: "queue.Queue[Optional[Tuple[TriggerRecord, List[MonitoredFileEvent]]]]" = queue.Queue(
            maxsize=config.limits.incident_queue_max_size
        )
        self.dropped_incidents_count: int = 0
        self.completed_cases: List[Dict[str, Any]] = []
        self._stop_event = threading.Event()
        self._incident_worker: Optional[threading.Thread] = None

        self.monitor = AsyncFilesystemMonitor(
            config=config,
            on_incident_trigger=self._enqueue_incident,
            seed_existing_baselines=seed_existing_baselines,
        )

    def _enqueue_incident(self, trigger: TriggerRecord, pre_alert_events: List[MonitoredFileEvent]) -> None:
        try:
            self.incident_queue.put_nowait((trigger, pre_alert_events))
        except queue.Full:
            self.dropped_incidents_count += 1
            logger.error("Incident queue full; dropped incident %s", trigger.case_id)

    def start(self) -> None:
        Path(self.config.output_root).mkdir(parents=True, exist_ok=True)
        Path(self.config.log_dir).mkdir(parents=True, exist_ok=True)
        self._stop_event.clear()
        self._incident_worker = threading.Thread(
            target=self._incident_loop, name="CryptoTripwire-IncidentWorker", daemon=True
        )
        self._incident_worker.start()
        self.monitor.start()

    def _incident_loop(self) -> None:
        while not self._stop_event.is_set() or not self.incident_queue.empty():
            try:
                item = self.incident_queue.get(timeout=0.05)
            except queue.Empty:
                continue
            if item is None:
                self.incident_queue.task_done()
                break
            trigger, pre_events = item
            try:
                result = self.execute_incident_workflow(trigger, pre_events)
                self.completed_cases.append(result)
                if self.on_case_completed is not None:
                    self.on_case_completed(result)
            except Exception as exc:
                logger.exception("Error completing incident workflow for %s: %s", trigger.case_id, exc)
            finally:
                self.incident_queue.task_done()

    def execute_incident_workflow(
        self,
        trigger: TriggerRecord,
        pre_alert_events: List[MonitoredFileEvent],
    ) -> Dict[str, Any]:
        """Run Phase 2 -> Phase 3 -> Phase 4 for a triggered incident synchronously on the incident worker."""
        case_dir, manifest = self.capture_coord.capture_case(trigger, pre_alert_events)
        phase3_out = self.reconstructor.reconstruct(case_dir)
        phase4_out = self.reporter.generate_case_reports(case_dir, revision=1)
        return {
            "case_id": trigger.case_id,
            "case_dir": str(case_dir),
            "trigger": trigger.to_dict(),
            "manifest": manifest,
            "phase3": phase3_out,
            "phase4": phase4_out,
        }

    def analyze_existing_case_directory(self, case_dir: str | Path, revision: int = 1) -> Dict[str, Any]:
        """Run Phase 3 verification/timeline and Phase 4 reporting on an existing or historical case folder."""
        cpath = Path(case_dir)
        phase3_out = self.reconstruct_only(cpath)
        phase4_out = self.reporter.generate_case_reports(cpath, revision=revision)
        return {
            "case_id": phase4_out["case_id"],
            "case_dir": str(cpath),
            "phase3": phase3_out,
            "phase4": phase4_out,
        }

    def reconstruct_only(self, case_dir: str | Path) -> Dict[str, Any]:
        return self.reconstructor.reconstruct(case_dir)

    def wait_for_idle(self, timeout: float = 10.0) -> None:
        self.monitor.flush(timeout=timeout)
        deadline = time.monotonic() + timeout
        while not self.incident_queue.empty() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.incident_queue.join()

    def stop(self, timeout: float = 10.0) -> None:
        self.monitor.stop(timeout=timeout)
        self._stop_event.set()
        try:
            self.incident_queue.put_nowait(None)
        except queue.Full:
            pass
        if self._incident_worker is not None and self._incident_worker.is_alive():
            self._incident_worker.join(timeout=timeout)
