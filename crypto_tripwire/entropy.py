"""Phase 1: Bounded whole-file and chunk/change-aware Shannon entropy measurement."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import datetime
import hashlib
import math
import os
from pathlib import Path
import stat
import time
from typing import Dict, List, Optional, Tuple

from crypto_tripwire.config import DetectorSettings
from crypto_tripwire.models import (
    BaselineComparison,
    ChunkSample,
    DetectorMode,
    EntropyMeasurement,
    ReadState,
)


COMPRESSED_OR_HIGH_ENTROPY_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tgz",
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".mkv", ".mp3",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt",
}

KNOWN_COMPRESSED_MAGIC_PREFIXES: List[Tuple[bytes, str]] = [
    (b"PK\x03\x04", "zip_or_ooxml"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"%PDF-", "pdf"),
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf'\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
]


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def compute_shannon_entropy(data: bytes) -> float:
    """Compute exact byte-level Shannon entropy in bits/byte [0.0, 8.0]."""
    n = len(data)
    if n == 0:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def compute_legacy_entropy(filepath: str) -> float:
    """Basic whole-file Shannon entropy helper (`detector.py`)."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        return compute_shannon_entropy(data)
    except Exception:
        return 0.0


def normalize_file_path(filepath: str) -> str:
    """Normalize path string safely across platforms."""
    abs_path = os.path.abspath(filepath)
    norm_path = os.path.normpath(abs_path)
    if os.name == "nt":
        norm_path = os.path.normcase(norm_path)
    return norm_path


def resolve_file_identity(filepath: str, follow_symlinks: bool = False) -> Tuple[str, str, Optional[os.stat_result], bool]:
    """
    Resolve file identity and check whether the target is a symlink/reparse point.
    Returns (file_identity, identity_source, stat_result, is_unsupported_link).
    """
    norm_path = normalize_file_path(filepath)
    try:
        lstat_res = os.lstat(filepath)
        is_link = stat.S_ISLNK(lstat_res.st_mode)
        # On Windows Python 3.8+, st_reparse_tag indicates reparse points/junctions
        if getattr(lstat_res, "st_reparse_tag", 0) != 0:
            is_link = True
        if is_link and not follow_symlinks:
            return f"path:{norm_path}", "path_normalized_fallback", lstat_res, True
        st_res = os.stat(filepath) if follow_symlinks else lstat_res
        if st_res.st_ino and st_res.st_dev:
            return f"dev:{st_res.st_dev}:ino:{st_res.st_ino}", "os_inode_dev", st_res, False
        return f"path:{norm_path}", "path_normalized_fallback", st_res, False
    except OSError:
        return f"path:{norm_path}", "path_normalized_fallback", None, False


def deterministic_chunk_offsets(file_size: int, chunk_size: int, max_chunks: int) -> List[int]:
    """
    Compute deterministic chunk start offsets across a file of `file_size`.
    If the file fits within `chunk_size * max_chunks`, all sequential chunks are read.
    Otherwise, evenly spaced deterministic offsets spanning head, interior, and tail are selected.
    """
    if file_size <= 0:
        return []
    total_possible_chunks = max(1, math.ceil(file_size / chunk_size))
    if total_possible_chunks <= max_chunks:
        return [i * chunk_size for i in range(total_possible_chunks)]
    if max_chunks == 1:
        return [0]
    max_start_offset = max(0, file_size - chunk_size)
    offsets: List[int] = []
    for idx in range(max_chunks):
        raw_offset = int(round((idx / (max_chunks - 1)) * max_start_offset))
        aligned_offset = (raw_offset // chunk_size) * chunk_size
        if aligned_offset > max_start_offset:
            aligned_offset = max_start_offset
        if not offsets or aligned_offset != offsets[-1]:
            offsets.append(aligned_offset)
    return offsets


def detect_magic_header_format(header_bytes: bytes) -> Optional[str]:
    """Return the recognized file format name if the first bytes match a known magic header signature."""
    for magic, fmt_name in KNOWN_COMPRESSED_MAGIC_PREFIXES:
        if header_bytes.startswith(magic):
            return fmt_name
    return None


def is_likely_compressed_container(ext: str, header_bytes: bytes) -> bool:
    if detect_magic_header_format(header_bytes) is not None:
        return True
    if ext.lower() in COMPRESSED_OR_HIGH_ENTROPY_EXTENSIONS:
        return True
    return False


@dataclass
class FileBaselineEntry:
    file_identity: str
    normalized_path: str
    file_size: int
    chunk_size: int
    chunk_entropies: Dict[int, float]
    whole_entropy: Optional[float]
    recorded_utc: str


class BaselineStore:
    """Bounded LRU store of prior compatible file entropy measurements."""

    def __init__(self, max_entries: int = 2048) -> None:
        self.max_entries = max(1, max_entries)
        self._store: OrderedDict[str, FileBaselineEntry] = OrderedDict()

    def get(self, file_identity: str) -> Optional[FileBaselineEntry]:
        entry = self._store.get(file_identity)
        if entry is not None:
            self._store.move_to_end(file_identity)
        return entry

    def put(self, entry: FileBaselineEntry) -> None:
        self._store[entry.file_identity] = entry
        self._store.move_to_end(entry.file_identity)
        while len(self._store) > self.max_entries:
            self._store.popitem(last=False)

    def remove(self, file_identity: str) -> None:
        self._store.pop(file_identity, None)

    def __len__(self) -> int:
        return len(self._store)


class EntropyAnalyzer:
    """Performs bounded whole-file or chunk/change-aware entropy measurement with retries and baseline tracking."""

    def __init__(self, settings: DetectorSettings, follow_symlinks: bool = False) -> None:
        self.settings = settings
        self.follow_symlinks = follow_symlinks
        self.baselines = BaselineStore(max_entries=settings.baseline_cache_max_entries)

    def seed_baseline_directory(self, root_dir: str, excluded_paths: Optional[List[str]] = None) -> int:
        """Optionally pre-scan existing files in a monitored root to populate initial baselines."""
        seeded = 0
        excluded_norm = [normalize_file_path(p) for p in (excluded_paths or [])]
        root_path = Path(root_dir)
        if not root_path.exists():
            return 0
        for dirpath, _, filenames in os.walk(root_path, followlinks=self.follow_symlinks):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                norm = normalize_file_path(full)
                if any(norm == ex or norm.startswith(ex + os.sep) for ex in excluded_norm):
                    continue
                m = self.measure_file(full, update_baseline=True, is_initial_seed=True)
                if m.read_state == ReadState.OK.value:
                    seeded += 1
        return seeded

    def measure_file(
        self,
        filepath: str,
        update_baseline: bool = True,
        is_initial_seed: bool = False,
    ) -> EntropyMeasurement:
        start_ns = time.monotonic_ns()
        meas_utc = utc_now_iso()
        norm_path = normalize_file_path(filepath)
        ext = os.path.splitext(norm_path)[1].lower()

        mode = self.settings.detection_mode

        file_id, id_source, st_before, is_link = resolve_file_identity(filepath, self.follow_symlinks)
        if is_link:
            return EntropyMeasurement(
                filepath=filepath,
                normalized_path=norm_path,
                file_identity=file_id,
                identity_source=id_source,
                shannon_entropy=None,
                estimator="shannon_byte_log2",
                measurement_mode="none",
                file_size=None,
                bytes_examined=0,
                sampling_coverage_ratio=0.0,
                read_state=ReadState.UNSUPPORTED_LINK.value,
                retry_count=0,
                retry_outcome="UNSUPPORTED_SYMLINK_OR_REPARSE",
                read_budget_bytes=0,
                measurement_utc=meas_utc,
                measurement_monotonic_ns=start_ns,
                duration_ms=(time.monotonic_ns() - start_ns) / 1_000_000.0,
                file_extension=ext,
                qualifies_high_entropy=False,
                qualification_reason="Unsupported symlink or reparse point excluded by policy.",
            )

        is_chunk_mode = mode == "format_aware_header_and_block"
        measurement_mode = "chunk_sampled" if is_chunk_mode else "whole_file"
        read_budget = (
            self.settings.chunk_size_bytes * self.settings.max_sampled_chunks
            if is_chunk_mode
            else self.settings.max_whole_file_bytes
        )

        max_attempts = max(1, 1 + self.settings.read_retry_count)
        last_error: Optional[str] = None
        last_state: ReadState = ReadState.UNREADABLE

        for attempt in range(max_attempts):
            if attempt > 0 and self.settings.read_retry_delay_ms > 0:
                time.sleep(self.settings.read_retry_delay_ms / 1000.0)
            try:
                st1 = os.stat(filepath) if self.follow_symlinks else os.lstat(filepath)
                fsize = st1.st_size
                if st1.st_ino and st1.st_dev:
                    file_id = f"dev:{st1.st_dev}:ino:{st1.st_ino}"
                    id_source = "os_inode_dev"

                if fsize == 0:
                    return EntropyMeasurement(
                        filepath=filepath,
                        normalized_path=norm_path,
                        file_identity=file_id,
                        identity_source=id_source,
                        shannon_entropy=None,
                        estimator="shannon_byte_log2",
                        measurement_mode=measurement_mode,
                        file_size=0,
                        bytes_examined=0,
                        sampling_coverage_ratio=0.0,
                        read_state=ReadState.EMPTY.value,
                        retry_count=attempt,
                        retry_outcome="EMPTY_FILE",
                        read_budget_bytes=read_budget,
                        measurement_utc=meas_utc,
                        measurement_monotonic_ns=start_ns,
                        duration_ms=(time.monotonic_ns() - start_ns) / 1_000_000.0,
                        file_extension=ext,
                        qualifies_high_entropy=False,
                        qualification_reason="File is empty (0 bytes); entropy undefined/not triggered.",
                    )

                if fsize < self.settings.min_file_size_bytes:
                    return EntropyMeasurement(
                        filepath=filepath,
                        normalized_path=norm_path,
                        file_identity=file_id,
                        identity_source=id_source,
                        shannon_entropy=None,
                        estimator="shannon_byte_log2",
                        measurement_mode=measurement_mode,
                        file_size=fsize,
                        bytes_examined=0,
                        sampling_coverage_ratio=0.0,
                        read_state=ReadState.TOO_SMALL.value,
                        retry_count=attempt,
                        retry_outcome="BELOW_MIN_SIZE",
                        read_budget_bytes=read_budget,
                        measurement_utc=meas_utc,
                        measurement_monotonic_ns=start_ns,
                        duration_ms=(time.monotonic_ns() - start_ns) / 1_000_000.0,
                        file_extension=ext,
                        qualifies_high_entropy=False,
                        qualification_reason=(
                            f"File size ({fsize} B) is below min_file_size_bytes ({self.settings.min_file_size_bytes} B)."
                        ),
                    )

                chunk_samples: List[ChunkSample] = []
                combined_hasher = hashlib.sha256()
                all_bytes_Parts: List[bytes] = []
                header_bytes = b""

                with open(filepath, "rb") as f:
                    if is_chunk_mode:
                        offsets = deterministic_chunk_offsets(
                            fsize, self.settings.chunk_size_bytes, self.settings.max_sampled_chunks
                        )
                        for off in offsets:
                            f.seek(off)
                            chunk_data = f.read(self.settings.chunk_size_bytes)
                            if off == 0:
                                header_bytes = chunk_data[:16]
                            if not chunk_data:
                                continue
                            c_ent = compute_shannon_entropy(chunk_data)
                            c_sha = hashlib.sha256(chunk_data).hexdigest()
                            chunk_samples.append(
                                ChunkSample(
                                    offset=off,
                                    length=len(chunk_data),
                                    entropy_bits_per_byte=c_ent,
                                    sha256=c_sha,
                                )
                            )
                            combined_hasher.update(chunk_data)
                            all_bytes_Parts.append(chunk_data)
                    else:
                        to_read = min(fsize, self.settings.max_whole_file_bytes)
                        raw_data = f.read(to_read)
                        header_bytes = raw_data[:16]
                        all_bytes_Parts.append(raw_data)
                        combined_hasher.update(raw_data)
                        if raw_data:
                            chunk_samples.append(
                                ChunkSample(
                                    offset=0,
                                    length=len(raw_data),
                                    entropy_bits_per_byte=compute_shannon_entropy(raw_data),
                                    sha256=hashlib.sha256(raw_data).hexdigest(),
                                )
                            )

                st2 = os.stat(filepath) if self.follow_symlinks else os.lstat(filepath)
                if st2.st_size != st1.st_size or st2.st_mtime_ns != st1.st_mtime_ns:
                    last_state = ReadState.CHANGED_DURING_READ
                    last_error = "File size or mtime_ns changed while reading."
                    if attempt + 1 < max_attempts:
                        continue
                else:
                    last_state = ReadState.OK

                examined_bytes = sum(len(p) for p in all_bytes_Parts)
                if examined_bytes == 0:
                    last_state = ReadState.INCOMPLETE
                    last_error = "Zero bytes read from non-empty file."
                    if attempt + 1 < max_attempts:
                        continue

                if not is_chunk_mode and fsize > self.settings.max_whole_file_bytes and last_state == ReadState.OK:
                    last_state = ReadState.INCOMPLETE

                overall_entropy = compute_shannon_entropy(b"".join(all_bytes_Parts))
                coverage = round(min(1.0, examined_bytes / fsize), 4) if fsize > 0 else 0.0
                magic_fmt = detect_magic_header_format(header_bytes)
                compressed_ctx = is_likely_compressed_container(ext, header_bytes)
                has_corrupted_magic = (ext in COMPRESSED_OR_HIGH_ENTROPY_EXTENSIONS) and (magic_fmt is None)

                baseline_comp = self._compare_with_baseline(
                    file_id=file_id,
                    fsize=fsize,
                    chunk_samples=chunk_samples,
                    overall_entropy=overall_entropy,
                )

                qualifies, reason = self._evaluate_qualification(
                    mode=mode,
                    read_state=last_state,
                    overall_entropy=overall_entropy,
                    chunk_samples=chunk_samples,
                    baseline_comp=baseline_comp,
                    compressed_ctx=compressed_ctx,
                    is_initial_seed=is_initial_seed,
                    magic_fmt=magic_fmt,
                    has_corrupted_magic=has_corrupted_magic,
                )

                if update_baseline and last_state in (ReadState.OK, ReadState.INCOMPLETE):
                    self.baselines.put(
                        FileBaselineEntry(
                            file_identity=file_id,
                            normalized_path=norm_path,
                            file_size=fsize,
                            chunk_size=self.settings.chunk_size_bytes,
                            chunk_entropies={cs.offset: cs.entropy_bits_per_byte for cs in chunk_samples},
                            whole_entropy=overall_entropy,
                            recorded_utc=meas_utc,
                        )
                    )

                retry_outcome = "FIRST_ATTEMPT_OK" if attempt == 0 else f"RESOLVED_AFTER_{attempt}_RETRIES"
                if last_state != ReadState.OK:
                    retry_outcome = f"TERMINATED_IN_STATE_{last_state.value}_AFTER_{attempt}_RETRIES"

                return EntropyMeasurement(
                    filepath=filepath,
                    normalized_path=norm_path,
                    file_identity=file_id,
                    identity_source=id_source,
                    shannon_entropy=overall_entropy,
                    estimator="shannon_byte_log2",
                    measurement_mode=measurement_mode,
                    file_size=fsize,
                    bytes_examined=examined_bytes,
                    sampling_coverage_ratio=coverage,
                    chunk_samples=chunk_samples,
                    read_state=last_state.value,
                    retry_count=attempt,
                    retry_outcome=retry_outcome,
                    read_budget_bytes=read_budget,
                    measurement_utc=meas_utc,
                    measurement_monotonic_ns=start_ns,
                    duration_ms=round((time.monotonic_ns() - start_ns) / 1_000_000.0, 4),
                    file_extension=ext,
                    likely_compressed_container=compressed_ctx,
                    magic_header_hex=header_bytes[:8].hex(),
                    content_sha256_examined=combined_hasher.hexdigest(),
                    baseline_comparison=baseline_comp,
                    qualifies_high_entropy=qualifies,
                    qualification_reason=reason,
                    error_detail=last_error if last_state != ReadState.OK else None,
                )

            except FileNotFoundError as exc:
                last_state = ReadState.VANISHED
                last_error = f"{type(exc).__name__}: {exc}"
            except PermissionError as exc:
                last_state = ReadState.UNREADABLE
                last_error = f"{type(exc).__name__}: {exc}"
            except OSError as exc:
                last_state = ReadState.UNREADABLE
                last_error = f"{type(exc).__name__}: {exc}"

        return EntropyMeasurement(
            filepath=filepath,
            normalized_path=norm_path,
            file_identity=file_id,
            identity_source=id_source,
            shannon_entropy=None,
            estimator="shannon_byte_log2",
            measurement_mode=measurement_mode,
            file_size=st_before.st_size if st_before else None,
            bytes_examined=0,
            sampling_coverage_ratio=0.0,
            chunk_samples=[],
            read_state=last_state.value,
            retry_count=max_attempts - 1,
            retry_outcome=f"FAILED_{last_state.value}_AFTER_{max_attempts - 1}_RETRIES",
            read_budget_bytes=read_budget,
            measurement_utc=meas_utc,
            measurement_monotonic_ns=start_ns,
            duration_ms=round((time.monotonic_ns() - start_ns) / 1_000_000.0, 4),
            file_extension=ext,
            qualifies_high_entropy=False,
            qualification_reason=f"Measurement failed with state {last_state.value}; not treated as zero entropy.",
            error_detail=last_error,
        )

    def _compare_with_baseline(
        self,
        file_id: str,
        fsize: int,
        chunk_samples: List[ChunkSample],
        overall_entropy: float,
    ) -> BaselineComparison:
        prev = self.baselines.get(file_id)
        if prev is None:
            return BaselineComparison(
                baseline_available=False,
                compatible_offsets=False,
                previous_size=None,
                current_size=fsize,
                size_change_type="NEW_OR_UNSEEN_FILE",
                matched_chunk_count=0,
                mean_entropy_delta=None,
                max_entropy_delta=None,
                notes="No prior baseline exists for this file identity; prior entropy is treated as unknown (never assumed 0).",
            )

        if fsize == prev.file_size:
            size_change = "UNCHANGED"
        elif fsize < prev.file_size:
            size_change = "TRUNCATED"
        else:
            size_change = "RESIZED"

        if prev.chunk_size != self.settings.chunk_size_bytes:
            return BaselineComparison(
                baseline_available=True,
                compatible_offsets=False,
                previous_size=prev.file_size,
                current_size=fsize,
                size_change_type=size_change,
                matched_chunk_count=0,
                mean_entropy_delta=None,
                max_entropy_delta=None,
                notes="Prior baseline used a different chunk size; offsets incompatible.",
            )

        deltas: List[float] = []
        for cs in chunk_samples:
            if cs.offset in prev.chunk_entropies:
                deltas.append(round(cs.entropy_bits_per_byte - prev.chunk_entropies[cs.offset], 4))

        if not deltas:
            if prev.whole_entropy is not None:
                d = round(overall_entropy - prev.whole_entropy, 4)
                return BaselineComparison(
                    baseline_available=True,
                    compatible_offsets=True,
                    previous_size=prev.file_size,
                    current_size=fsize,
                    size_change_type=size_change,
                    matched_chunk_count=1,
                    mean_entropy_delta=d,
                    max_entropy_delta=d,
                    notes="Compared whole-file entropy against prior baseline.",
                )
            return BaselineComparison(
                baseline_available=True,
                compatible_offsets=False,
                previous_size=prev.file_size,
                current_size=fsize,
                size_change_type=size_change,
                matched_chunk_count=0,
                mean_entropy_delta=None,
                max_entropy_delta=None,
                notes="No overlapping chunk offsets between baseline and current sample.",
            )

        mean_d = round(sum(deltas) / len(deltas), 4)
        max_d = round(max(deltas), 4)
        return BaselineComparison(
            baseline_available=True,
            compatible_offsets=True,
            previous_size=prev.file_size,
            current_size=fsize,
            size_change_type=size_change,
            matched_chunk_count=len(deltas),
            mean_entropy_delta=mean_d,
            max_entropy_delta=max_d,
            notes=f"Compared {len(deltas)} compatible chunk offset(s).",
        )

    def _evaluate_qualification(
        self,
        mode: str,
        read_state: ReadState,
        overall_entropy: float,
        chunk_samples: List[ChunkSample],
        baseline_comp: BaselineComparison,
        compressed_ctx: bool,
        is_initial_seed: bool,
        magic_fmt: Optional[str] = None,
        has_corrupted_magic: bool = False,
    ) -> Tuple[bool, str]:
        if is_initial_seed:
            return False, "Initial baseline seeding pass."
        if read_state not in (ReadState.OK, ReadState.INCOMPLETE, ReadState.CHANGED_DURING_READ):
            return False, f"Read state {read_state.value} is not eligible for entropy qualification."

        if mode == "basic_whole_file":
            if overall_entropy >= self.settings.entropy_threshold:
                return (
                    True,
                    f"Whole-file Shannon entropy {overall_entropy:.4f} >= threshold {self.settings.entropy_threshold:.4f} bits/byte.",
                )
            return (
                False,
                f"Whole-file Shannon entropy {overall_entropy:.4f} < threshold {self.settings.entropy_threshold:.4f} bits/byte.",
            )

        # Format-aware magic-header and 16x4KiB block-entropy rule
        if not chunk_samples:
            return False, "No chunk samples available."

        effective_chunk_thresh = self.settings.chunk_high_entropy_threshold
        if compressed_ctx:
            effective_chunk_thresh = min(7.98, effective_chunk_thresh + self.settings.compressed_container_delta_margin)

        high_chunks = [c for c in chunk_samples if c.entropy_bits_per_byte >= effective_chunk_thresh]
        high_fraction = len(high_chunks) / len(chunk_samples)

        # Case 1: Baseline exists with compatible offsets
        if baseline_comp.baseline_available and baseline_comp.compatible_offsets and baseline_comp.max_entropy_delta is not None:
            max_d = baseline_comp.max_entropy_delta
            mean_d = baseline_comp.mean_entropy_delta or 0.0
            # Positive entropy spike on existing file (either whole-file or localized intermittent chunk encryption)
            if max_d >= self.settings.entropy_delta_threshold and len(high_chunks) >= 1:
                return (
                    True,
                    f"Existing file exhibited positive chunk entropy spike (max_delta={max_d:+.4f} >= "
                    f"{self.settings.entropy_delta_threshold:.4f}, mean_delta={mean_d:+.4f}) with "
                    f"{len(high_chunks)}/{len(chunk_samples)} chunk(s) >= {effective_chunk_thresh:.2f} bits/byte.",
                )
            # If an already high-entropy compressed file was re-saved without significant entropy change, suppress benign re-save
            if compressed_ctx and abs(mean_d) < 0.15 and high_fraction >= self.settings.min_high_entropy_chunk_fraction:
                return (
                    False,
                    f"Existing compressed container re-saved with negligible entropy change (mean_delta={mean_d:+.4f}); "
                    f"not flagged by chunk/change-aware rule.",
                )
            # If an existing file was overwritten with high-entropy content even if baseline was already moderate
            if not compressed_ctx and high_fraction >= self.settings.min_high_entropy_chunk_fraction and mean_d >= 0.40:
                return (
                    True,
                    f"Existing non-compressed file overwritten with high-entropy chunks "
                    f"({len(high_chunks)}/{len(chunk_samples)} chunks >= {effective_chunk_thresh:.2f}, mean_delta={mean_d:+.4f}).",
                )
            return (
                False,
                f"Existing file baseline comparison did not meet change threshold (max_delta={max_d:+.4f}, "
                f"high_chunks={len(high_chunks)}/{len(chunk_samples)}).",
            )

        # Magic-header format validation: if a known compressed format has a valid intact magic header (PK, %PDF-, PNG) and no baseline spike, suppress benign compressed save
        if magic_fmt is not None and not has_corrupted_magic and (not baseline_comp.baseline_available or (baseline_comp.max_entropy_delta or 0.0) < self.settings.entropy_delta_threshold):
            return (
                False,
                f"Valid magic header signature ({magic_fmt}) intact with no positive entropy spike; suppressed benign compressed file save.",
            )
        # If a file with a compressed extension has its magic header destroyed/missing and high first-block header entropy, flag immediately
        if has_corrupted_magic and chunk_samples and chunk_samples[0].entropy_bits_per_byte >= self.settings.chunk_high_entropy_threshold:
            return (
                True,
                f"Compressed extension missing valid magic header with high first-block header entropy ({chunk_samples[0].entropy_bits_per_byte:.4f} bits/byte).",
            )

        # Case 2: No baseline available (new file or replacement) -> never assume prior entropy was 0
        if high_fraction >= self.settings.min_high_entropy_chunk_fraction and overall_entropy >= effective_chunk_thresh:
            ctx_note = " (with compressed-container margin applied)" if compressed_ctx else ""
            return (
                True,
                f"New/unbaselined file met chunk high-entropy rule{ctx_note}: "
                f"{len(high_chunks)}/{len(chunk_samples)} chunks ({high_fraction:.0%}) >= {effective_chunk_thresh:.2f} bits/byte "
                f"and aggregate entropy {overall_entropy:.4f} bits/byte.",
            )

        return (
            False,
            f"Unbaselined file below chunk/aggregate threshold: {len(high_chunks)}/{len(chunk_samples)} chunks >= "
            f"{effective_chunk_thresh:.2f} bits/byte (overall={overall_entropy:.4f}).",
        )

    def _measure_legacy(
        self,
        filepath: str,
        norm_path: str,
        ext: str,
        meas_utc: str,
        start_ns: int,
    ) -> EntropyMeasurement:
        """Basic whole-file measurement baseline."""
        h = compute_legacy_entropy(filepath)
        try:
            fsize = os.path.getsize(filepath)
        except OSError:
            fsize = None
        qualifies = h >= self.settings.entropy_threshold
        return EntropyMeasurement(
            filepath=filepath,
            normalized_path=norm_path,
            file_identity=f"legacy_path:{filepath}",
            identity_source="legacy_raw_path",
            shannon_entropy=h,
            estimator="shannon_byte_log2_legacy",
            measurement_mode="original_legacy",
            file_size=fsize,
            bytes_examined=fsize or 0,
            sampling_coverage_ratio=1.0 if fsize else 0.0,
            chunk_samples=[],
            read_state=ReadState.OK.value if fsize else ReadState.UNREADABLE.value,
            retry_count=0,
            retry_outcome="LEGACY_NO_RETRY",
            read_budget_bytes=0,
            measurement_utc=meas_utc,
            measurement_monotonic_ns=start_ns,
            duration_ms=round((time.monotonic_ns() - start_ns) / 1_000_000.0, 4),
            file_extension=ext,
            qualifies_high_entropy=qualifies,
            qualification_reason=(
                f"Legacy whole-file entropy {h:.4f} {'≥' if qualifies else '<'} {self.settings.entropy_threshold:.4f}"
            ),
        )
