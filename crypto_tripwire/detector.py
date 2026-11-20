"""Phase 1: Reliable entropy-triggered filesystem monitor, burst detector, and incident lifecycle."""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
import os
from pathlib import Path
import queue
import threading
import time
from typing import Callable, Deque, Dict, List, Optional, Tuple
import uuid

from crypto_tripwire.config import AppConfig
from crypto_tripwire.entropy import (
    EntropyAnalyzer,
    FileBaselineEntry,
    normalize_file_path,
    resolve_file_identity,
    utc_now_iso,
)
from crypto_tripwire.models import (
    DetectorMode,
    EntropyMeasurement,
    MonitoredFileEvent,
    ReadState,
    TriggerRecord,
)


@dataclass
class RawFilesystemNotification:
    event_type: str  # created, modified, moved, deleted
    src_path: str
    dest_path: Optional[str] = None
    observed_utc: str = ""
    observed_monotonic_ns: int = 0
    source_timestamp_utc: Optional[str] = None


class IncidentState(str):
    ARMED = "ARMED"
    GROUPING_BURST = "GROUPING_BURST"
    COOLDOWN = "COOLDOWN"
    PERMANENTLY_SUPPRESSED_LEGACY = "PERMANENTLY_SUPPRESSED_LEGACY"


class BurstDetectionEngine:
    """
    Stateful Phase 1 format-aware header and block-entropy burst detection engine.
    Processes raw filesystem notifications without blocking event callbacks,
    coalesces rapid duplicate notifications, tracks distinct file identities,
    maintains a bounded pre-alert ring buffer, and manages incident lifecycle re-arming.
    """

    def __init__(
        self,
        config: AppConfig,
        on_incident_trigger: Optional[Callable[[TriggerRecord, List[MonitoredFileEvent]], None]] = None,
    ) -> None:
        self.config = config
        self.settings = config.detector
        self.analyzer = EntropyAnalyzer(self.settings, follow_symlinks=config.follow_symlinks_or_reparse)
        self.on_incident_trigger = on_incident_trigger

        self.pre_alert_buffer: Deque[MonitoredFileEvent] = deque(maxlen=max(16, self.settings.pre_alert_buffer_size))
        self.all_observed_events: Deque[MonitoredFileEvent] = deque(maxlen=max(256, self.settings.pre_alert_buffer_size * 4))

        # Sliding window of qualifying high-entropy events:
        # Maps distinct OS file_identity (dev:ino) -> latest qualifying MonitoredFileEvent within time window.
        self._legacy_window: Deque[MonitoredFileEvent] = deque()
        self._distinct_window: OrderedDict[str, MonitoredFileEvent] = OrderedDict()

        # Coalescing cache: (event_type, normalized_path) -> (last_monotonic_ns, last_mtime_ns, last_size, MonitoredFileEvent)
        self._recent_notifications: Dict[Tuple[str, str], Tuple[int, Optional[int], Optional[int], MonitoredFileEvent]] = {}

        self.state: str = IncidentState.ARMED
        self.last_trigger_monotonic_ns: int = 0
        self.active_incident_count: int = 0
        self.event_sequence: int = 0

        # Telemetry & overload accounting
        self.total_notifications_received: int = 0
        self.coalesced_notifications_count: int = 0
        self.dropped_notifications_count: int = 0
        self.excluded_notifications_count: int = 0
        self.unreadable_or_vanished_count: int = 0
        self.triggers_emitted: List[TriggerRecord] = []

        self._excluded_norm_paths = [
            normalize_file_path(p)
            for p in (
                list(config.excluded_paths)
                + [config.output_root, config.log_dir]
            )
        ]
        self._excluded_exts = {ext.lower() for ext in config.excluded_extensions}
        self._lock = threading.Lock()

    def is_path_excluded(self, filepath: str) -> bool:
        norm = normalize_file_path(filepath)
        for ex in self._excluded_norm_paths:
            if norm == ex or norm.startswith(ex + os.sep):
                return True
        ext = os.path.splitext(norm)[1].lower()
        if ext in self._excluded_exts:
            return True
        return False

    def process_notification(self, raw: RawFilesystemNotification) -> Optional[MonitoredFileEvent]:
        """Process a single filesystem notification synchronously (called by worker or replay driver)."""
        with self._lock:
            self.total_notifications_received += 1
            obs_ns = raw.observed_monotonic_ns or time.monotonic_ns()
            obs_utc = raw.observed_utc or utc_now_iso()

            target_path = raw.dest_path if (raw.event_type == "moved" and raw.dest_path) else raw.src_path
            if self.is_path_excluded(target_path) or self.is_path_excluded(raw.src_path):
                self.excluded_notifications_count += 1
                return None

            # Basic watcher suppression check
            if (
                self.settings.detection_mode == "raw_legacy"
                and self.state == IncidentState.PERMANENTLY_SUPPRESSED_LEGACY
            ):
                return None

            # Basic watcher event filter
            if self.settings.detection_mode == "raw_legacy" and raw.event_type not in (
                "created",
                "modified",
            ):
                return None

            norm_target = normalize_file_path(target_path)
            norm_src = normalize_file_path(raw.src_path)

            # Check 150 ms duplicate OS save notification coalescing
            if self.settings.detection_mode != "raw_legacy" and raw.event_type in ("created", "modified"):
                coalesce_ns = int(self.settings.coalesce_interval_ms * 1_000_000)
                st_cur: Optional[os.stat_result] = None
                try:
                    st_cur = os.stat(target_path) if self.config.follow_symlinks_or_reparse else os.lstat(target_path)
                except OSError:
                    st_cur = None
                cur_mtime = getattr(st_cur, "st_mtime_ns", None)
                cur_size = getattr(st_cur, "st_size", None)

                for key_type in (raw.event_type, "created", "modified"):
                    prev_entry = self._recent_notifications.get((key_type, norm_target))
                    if prev_entry is not None:
                        prev_ns, prev_mtime, prev_size, prev_event = prev_entry
                        if (obs_ns - prev_ns) <= coalesce_ns and cur_mtime == prev_mtime and cur_size == prev_size and cur_mtime is not None:
                            self.coalesced_notifications_count += 1
                            prev_event.coalesced_count += 1
                            return prev_event

            self.event_sequence += 1
            ev_id = f"ev_{self.event_sequence:06d}"

            # Handle move/rename baseline continuity before measurement
            if raw.event_type == "moved" and raw.dest_path:
                src_id, _, _, _ = resolve_file_identity(raw.src_path, self.config.follow_symlinks_or_reparse)
                dst_id, id_source, _, _ = resolve_file_identity(raw.dest_path, self.config.follow_symlinks_or_reparse)
                old_base = self.analyzer.baselines.get(src_id) or self.analyzer.baselines.get(f"path:{norm_src}")
                if old_base is not None:
                    self.analyzer.baselines.put(
                        FileBaselineEntry(
                            file_identity=dst_id,
                            normalized_path=norm_target,
                            file_size=old_base.file_size,
                            chunk_size=old_base.chunk_size,
                            chunk_entropies=dict(old_base.chunk_entropies),
                            whole_entropy=old_base.whole_entropy,
                            recorded_utc=obs_utc,
                        )
                    )
                measurement = self.analyzer.measure_file(raw.dest_path, update_baseline=True)
                file_id = measurement.file_identity
                id_source = measurement.identity_source
            elif raw.event_type == "deleted":
                file_id, id_source, _, _ = resolve_file_identity(raw.src_path, self.config.follow_symlinks_or_reparse)
                measurement = EntropyMeasurement(
                    filepath=raw.src_path,
                    normalized_path=norm_src,
                    file_identity=file_id,
                    identity_source=id_source,
                    shannon_entropy=None,
                    estimator="none",
                    measurement_mode="none",
                    file_size=None,
                    bytes_examined=0,
                    sampling_coverage_ratio=0.0,
                    chunk_samples=[],
                    read_state=ReadState.SKIPPED_DELETED.value,
                    retry_count=0,
                    retry_outcome="DELETED_EVENT_PRESERVED",
                    read_budget_bytes=0,
                    measurement_utc=obs_utc,
                    measurement_monotonic_ns=obs_ns,
                    duration_ms=0.0,
                    file_extension=os.path.splitext(norm_src)[1].lower(),
                    qualifies_high_entropy=False,
                    qualification_reason="Delete event preserved in history; file content no longer present.",
                )
            else:
                measurement = self.analyzer.measure_file(target_path, update_baseline=True)
                file_id = measurement.file_identity
                id_source = measurement.identity_source

            if measurement.read_state in (ReadState.UNREADABLE.value, ReadState.VANISHED.value):
                self.unreadable_or_vanished_count += 1

            mon_event = MonitoredFileEvent(
                event_id=ev_id,
                event_type=raw.event_type,
                src_path=raw.src_path,
                dest_path=raw.dest_path,
                normalized_path=norm_target,
                file_identity=file_id,
                identity_source=id_source,
                observed_utc=obs_utc,
                observed_monotonic_ns=obs_ns,
                source_timestamp_utc=raw.source_timestamp_utc,
                coalesced_count=1,
                measurement=measurement,
                contributed_to_trigger=False,
            )

            # Update coalescing lookup
            if raw.event_type in ("created", "modified"):
                try:
                    st_after = os.stat(target_path) if self.config.follow_symlinks_or_reparse else os.lstat(target_path)
                    self._recent_notifications[(raw.event_type, norm_target)] = (
                        obs_ns,
                        st_after.st_mtime_ns,
                        st_after.st_size,
                        mon_event,
                    )
                except OSError:
                    pass

            self.pre_alert_buffer.append(mon_event)
            self.all_observed_events.append(mon_event)

            self._evaluate_burst_window(mon_event, obs_ns, obs_utc)
            return mon_event

    def _evaluate_burst_window(self, mon_event: MonitoredFileEvent, obs_ns: int, obs_utc: str) -> None:
        window_ns = int(self.settings.time_window_seconds * 1_000_000_000)
        cooldown_ns = int(self.settings.cooldown_seconds * 1_000_000_000)

        # Transition from COOLDOWN to ARMED if cooldown elapsed
        if self.state == IncidentState.COOLDOWN:
            if (obs_ns - self.last_trigger_monotonic_ns) >= cooldown_ns:
                self.state = IncidentState.ARMED
            else:
                # Still observing events into pre_alert_buffer during cooldown, but do not re-trigger yet
                return

        meas = mon_event.measurement
        if meas is None or not meas.qualifies_high_entropy:
            return

        if self.settings.detection_mode == "raw_legacy":
            self._legacy_window.append(mon_event)
            while self._legacy_window and (obs_ns - self._legacy_window[0].observed_monotonic_ns) > window_ns:
                self._legacy_window.popleft()
            if len(self._legacy_window) >= self.settings.count_threshold:
                self.state = IncidentState.PERMANENTLY_SUPPRESSED_LEGACY
                contributing = list(self._legacy_window)
                self._emit_trigger(contributing, obs_ns, obs_utc)
            return

        # Count distinct OS file identities (dev:ino) within monotonic time window
        if mon_event.file_identity in self._distinct_window:
            del self._distinct_window[mon_event.file_identity]
        self._distinct_window[mon_event.file_identity] = mon_event

        stale_keys = [
            fid
            for fid, ev in self._distinct_window.items()
            if (obs_ns - ev.observed_monotonic_ns) > window_ns
        ]
        for fid in stale_keys:
            del self._distinct_window[fid]

        if len(self._distinct_window) >= self.settings.count_threshold:
            contributing = list(self._distinct_window.values())
            self._distinct_window.clear()
            self.state = IncidentState.COOLDOWN
            self.last_trigger_monotonic_ns = obs_ns
            self._emit_trigger(contributing, obs_ns, obs_utc)

    def _emit_trigger(self, contributing: List[MonitoredFileEvent], trigger_ns: int, trigger_utc: str) -> None:
        self.active_incident_count += 1
        ts_compact = trigger_utc.replace("-", "").replace(":", "").replace(".", "")[:15]
        short_uid = uuid.uuid4().hex[:6]
        case_id = f"case_{ts_compact}_{self.active_incident_count:03d}_{short_uid}"
        alert_id = f"alert_{self.active_incident_count:03d}_{short_uid}"

        for ev in contributing:
            ev.contributed_to_trigger = True

        first_ev = min(contributing, key=lambda e: e.observed_monotonic_ns)
        elapsed_s = round(max(0.0, (trigger_ns - first_ev.observed_monotonic_ns) / 1_000_000_000.0), 6)

        distinct_fids = list(dict.fromkeys(e.file_identity for e in contributing))
        thresholds_summary = {
            "detection_mode": self.settings.detection_mode,
            "entropy_threshold_bits_per_byte": self.settings.entropy_threshold,
            "count_threshold_distinct_files": self.settings.count_threshold,
            "time_window_seconds": self.settings.time_window_seconds,
            "cooldown_seconds": self.settings.cooldown_seconds,
            "chunk_size_bytes": self.settings.chunk_size_bytes,
            "max_sampled_chunks": self.settings.max_sampled_chunks,
            "chunk_high_entropy_threshold": self.settings.chunk_high_entropy_threshold,
            "min_high_entropy_chunk_fraction": self.settings.min_high_entropy_chunk_fraction,
            "entropy_delta_threshold": self.settings.entropy_delta_threshold,
            "threshold_provenance_label": self.settings.threshold_provenance_label,
        }

        rationale = (
            f"Suspicious high-entropy file activity burst detected under {self.settings.detection_mode}: "
            f"{len(contributing)} qualifying event(s) across {len(distinct_fids)} distinct file identity/identities "
            f"within {elapsed_s:.4f}s (configured window <= {self.settings.time_window_seconds:.2f}s, "
            f"threshold >= {self.settings.count_threshold}). Ground-truth ransomware attribution requires "
            f"independent analyst/lab verification."
        )

        trigger = TriggerRecord(
            case_id=case_id,
            alert_id=alert_id,
            detection_mode=self.settings.detection_mode,
            observation_mode=self.config.observation_mode,
            alert_description="Suspicious high-entropy file modification burst detected (not automatic ransomware ground truth).",
            trigger_utc=trigger_utc,
            trigger_monotonic_ns=trigger_ns,
            first_contributing_event_utc=first_ev.observed_utc,
            first_contributing_monotonic_ns=first_ev.observed_monotonic_ns,
            burst_window_elapsed_seconds=elapsed_s,
            applied_thresholds=thresholds_summary,
            config_digest=self.config.canonical_digest(),
            contributing_event_ids=[e.event_id for e in contributing],
            contributing_file_identities=distinct_fids,
            contributing_events=[e.to_dict() for e in contributing],
            pre_alert_history_count=len(self.pre_alert_buffer),
            queue_stats_at_trigger=self.get_telemetry(),
            rationale=rationale,
        )
        self.triggers_emitted.append(trigger)
        pre_history_snapshot = list(self.pre_alert_buffer)

        if self.on_incident_trigger is not None:
            self.on_incident_trigger(trigger, pre_history_snapshot)

    def get_telemetry(self) -> Dict[str, int | str]:
        return {
            "state": self.state,
            "total_notifications_received": self.total_notifications_received,
            "coalesced_notifications_count": self.coalesced_notifications_count,
            "dropped_notifications_count": self.dropped_notifications_count,
            "excluded_notifications_count": self.excluded_notifications_count,
            "unreadable_or_vanished_count": self.unreadable_or_vanished_count,
            "incidents_triggered": self.active_incident_count,
            "baseline_entries_cached": len(self.analyzer.baselines),
        }


class AsyncFilesystemMonitor:
    """
    Non-blocking filesystem watcher that enqueues notifications into a bounded queue
    for a background worker thread, using `watchdog` when installed or a deterministic
    high-frequency directory snapshot poller as a cross-platform fallback.
    """

    def __init__(
        self,
        config: AppConfig,
        on_incident_trigger: Optional[Callable[[TriggerRecord, List[MonitoredFileEvent]], None]] = None,
        seed_existing_baselines: bool = True,
    ) -> None:
        self.config = config
        self.engine = BurstDetectionEngine(config, on_incident_trigger=on_incident_trigger)
        self.event_queue: "queue.Queue[Optional[RawFilesystemNotification]]" = queue.Queue(
            maxsize=config.limits.event_queue_max_size
        )
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._poller_thread: Optional[threading.Thread] = None
        self._watchdog_observer = None
        self.watcher_backend: str = "unstarted"

        if seed_existing_baselines and config.detector.detection_mode == "format_aware_header_and_block":
            for r in config.monitored_roots:
                self.engine.analyzer.seed_baseline_directory(r, config.excluded_paths)

    def enqueue_notification(self, notification: RawFilesystemNotification) -> bool:
        """Non-blocking enqueue called by OS watcher callbacks; records dropped events on queue overload."""
        if not notification.observed_monotonic_ns:
            notification.observed_monotonic_ns = time.monotonic_ns()
        if not notification.observed_utc:
            notification.observed_utc = utc_now_iso()
        try:
            self.event_queue.put_nowait(notification)
            return True
        except queue.Full:
            self.engine.dropped_notifications_count += 1
            return False

    def start(self) -> None:
        self._stop_event.clear()
        self._worker_thread = threading.Thread(
            target=self._worker_loop, name="CryptoTripwire-DetectorWorker", daemon=True
        )
        self._worker_thread.start()

        # Try starting watchdog if available, else fallback to deterministic poller
        try:
            from watchdog.events import FileSystemEventHandler  # type: ignore
            from watchdog.observers import Observer  # type: ignore

            monitor_ref = self

            class _WatchdogBridge(FileSystemEventHandler):  # type: ignore
                def on_created(self, event):
                    if not event.is_directory:
                        monitor_ref.enqueue_notification(
                            RawFilesystemNotification(event_type="created", src_path=event.src_path)
                        )

                def on_modified(self, event):
                    if not event.is_directory:
                        monitor_ref.enqueue_notification(
                            RawFilesystemNotification(event_type="modified", src_path=event.src_path)
                        )

                def on_moved(self, event):
                    if not event.is_directory:
                        monitor_ref.enqueue_notification(
                            RawFilesystemNotification(
                                event_type="moved", src_path=event.src_path, dest_path=event.dest_path
                            )
                        )

                def on_deleted(self, event):
                    if not event.is_directory:
                        monitor_ref.enqueue_notification(
                            RawFilesystemNotification(event_type="deleted", src_path=event.src_path)
                        )

            obs = Observer()
            bridge = _WatchdogBridge()
            for r in self.config.monitored_roots:
                os.makedirs(r, exist_ok=True)
                obs.schedule(bridge, r, recursive=True)
            obs.start()
            self._watchdog_observer = obs
            self.watcher_backend = "watchdog_native"
        except ImportError:
            self.watcher_backend = "stdlib_stat_poller"
            self._poller_thread = threading.Thread(
                target=self._poll_loop, name="CryptoTripwire-StatPoller", daemon=True
            )
            self._poller_thread.start()

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set() or not self.event_queue.empty():
            try:
                item = self.event_queue.get(timeout=0.05)
            except queue.Empty:
                continue
            if item is None:
                self.event_queue.task_done()
                break
            try:
                self.engine.process_notification(item)
            finally:
                self.event_queue.task_done()

    def _snapshot_roots(self) -> Dict[str, Tuple[int, int, int]]:
        """Map normalized path -> (inode_or_zero, size, mtime_ns)."""
        snap: Dict[str, Tuple[int, int, int]] = {}
        for r in self.config.monitored_roots:
            os.makedirs(r, exist_ok=True)
            for dirpath, _, filenames in os.walk(r, followlinks=self.config.follow_symlinks_or_reparse):
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    if self.engine.is_path_excluded(full):
                        continue
                    try:
                        st = os.stat(full) if self.config.follow_symlinks_or_reparse else os.lstat(full)
                        snap[normalize_file_path(full)] = (int(st.st_ino or 0), int(st.st_size), int(st.st_mtime_ns))
                    except OSError:
                        continue
        return snap

    def _poll_loop(self) -> None:
        prev = self._snapshot_roots()
        interval_s = max(0.02, self.config.limits.polling_interval_ms / 1000.0)
        while not self._stop_event.is_set():
            time.sleep(interval_s)
            curr = self._snapshot_roots()
            prev_paths = set(prev.keys())
            curr_paths = set(curr.keys())

            added = curr_paths - prev_paths
            removed = prev_paths - curr_paths
            common = curr_paths & prev_paths

            # Detect moves via matching non-zero inode
            moved_pairs: List[Tuple[str, str]] = []
            if added and removed:
                rem_by_ino = {prev[p][0]: p for p in removed if prev[p][0] != 0}
                for a_path in list(added):
                    a_ino = curr[a_path][0]
                    if a_ino != 0 and a_ino in rem_by_ino:
                        old_p = rem_by_ino.pop(a_ino)
                        moved_pairs.append((old_p, a_path))
                        added.discard(a_path)
                        removed.discard(old_p)

            for old_p, new_p in sorted(moved_pairs):
                self.enqueue_notification(RawFilesystemNotification(event_type="moved", src_path=old_p, dest_path=new_p))
            for a_path in sorted(added):
                self.enqueue_notification(RawFilesystemNotification(event_type="created", src_path=a_path))
            for c_path in sorted(common):
                if curr[c_path][1:] != prev[c_path][1:]:
                    self.enqueue_notification(RawFilesystemNotification(event_type="modified", src_path=c_path))
            for r_path in sorted(removed):
                self.enqueue_notification(RawFilesystemNotification(event_type="deleted", src_path=r_path))

            prev = curr

    def flush(self, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while not self.event_queue.empty() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.event_queue.join()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._watchdog_observer is not None:
            try:
                self._watchdog_observer.stop()
                self._watchdog_observer.join(timeout=timeout)
            except Exception:
                pass
        if self._poller_thread is not None and self._poller_thread.is_alive():
            self._poller_thread.join(timeout=timeout)
        try:
            self.event_queue.put_nowait(None)
        except queue.Full:
            pass
        if self._worker_thread is not None and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
