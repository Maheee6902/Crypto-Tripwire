"""Phase 1: Format-Aware Magic-Header & 4 KiB Block-Entropy Live Folder Monitor.

Monitors all user folders (or any folder passed via --watch).
When 3 distinct files spike in entropy within 5 seconds, automatically triggers:
    Phase 2 (phase2_capture.py) -> Phase 3 (phase3_analyze.py) -> Phase 4 (phase4_report.py)

Usage:
    python phase1_monitor.py                       # Watch all user folders (Desktop, Documents, Downloads, Pictures, Videos, Music)
    python phase1_monitor.py --watch ./test_folder # Watch a specific folder
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
import math
import os
from pathlib import Path
import queue
import threading
import time
import webbrowser

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = object
    Observer = None

from phase2_capture import run_phase2_capture, utc_now
from phase3_analyze import run_phase3_analyze
from phase4_report import run_phase4_report


# Phase 1 Detection Settings (matches Crypto-Tripwire paper)
ENTROPY_THRESHOLD = 7.2        # bits/byte
COUNT_THRESHOLD = 3            # distinct files required to trigger
TIME_WINDOW_SECONDS = 5.0      # sliding burst window
COOLDOWN_SECONDS = 3.0         # re-arm cooldown after an alert
DEDUP_INTERVAL_SECONDS = 0.15  # 150 ms OS duplicate-save filter
CHUNK_SIZE = 4096              # 4 KiB block size
MAX_CHUNKS = 16                # 16 x 4 KiB = 64 KiB read cap
MIN_FILE_BYTES = 64

# Legitimate compressed formats whose intact magic headers prevent false positives
COMPRESSED_MAGIC_HEADERS = {
    b"PK\x03\x04": "ZIP/DOCX/XLSX",
    b"%PDF-": "PDF",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"7z\xbc\xaf'\x1c": "7Z",
    b"Rar!\x1a\x07": "RAR",
}

EXCLUDED_DIR_NAMES = {"appdata", "cases_output", ".venv", "__pycache__", ".git", "node_modules"}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def detect_magic_header(header_bytes: bytes) -> str | None:
    for magic, label in COMPRESSED_MAGIC_HEADERS.items():
        if header_bytes.startswith(magic):
            return label
    return None


def analyze_file_blocks(path: Path) -> dict | None:
    """Read up to 16 x 4 KiB blocks (64 KiB cap) and check magic header + block entropy."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size < MIN_FILE_BYTES:
        return None

    try:
        with open(path, "rb") as f:
            if size <= CHUNK_SIZE * MAX_CHUNKS:
                raw = f.read()
                blocks = [raw[i : i + CHUNK_SIZE] for i in range(0, len(raw), CHUNK_SIZE)]
            else:
                step = (size - CHUNK_SIZE) // (MAX_CHUNKS - 1)
                blocks = []
                for idx in range(MAX_CHUNKS):
                    f.seek(idx * step)
                    blocks.append(f.read(CHUNK_SIZE))
    except OSError:
        return None

    if not blocks:
        return None

    magic = detect_magic_header(blocks[0])
    block_entropies = [shannon_entropy(b) for b in blocks if b]
    whole_h = sum(block_entropies) / len(block_entropies)
    max_block_h = max(block_entropies)
    header_h = block_entropies[0]

    return {
        "path": str(path),
        "size_bytes": size,
        "magic_header": magic,
        "whole_entropy": round(whole_h, 4),
        "header_entropy": round(header_h, 4),
        "max_block_entropy": round(max_block_h, 4),
        "observed_utc": utc_now(),
    }


class TripwireHandler(FileSystemEventHandler):
    def __init__(self, event_queue: queue.Queue, output_root: Path) -> None:
        self.event_queue = event_queue
        self.output_root = output_root.resolve()

    def _enqueue(self, src_path: str) -> None:
        p = Path(src_path)
        parts_lower = {part.lower() for part in p.parts}
        if parts_lower & EXCLUDED_DIR_NAMES:
            return
        try:
            if self.output_root in p.resolve().parents:
                return
        except OSError:
            pass
        try:
            self.event_queue.put_nowait(p)
        except queue.Full:
            pass

    def on_created(self, event) -> None:
        if not event.is_directory:
            self._enqueue(event.src_path)

    def on_modified(self, event) -> None:
        if not event.is_directory:
            self._enqueue(event.src_path)


def default_user_folders() -> list[Path]:
    home = Path.home()
    candidates = ["Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music"]
    found = [home / name for name in candidates if (home / name).is_dir()]
    return found if found else [Path.cwd() / "watched_folder"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Crypto-Tripwire Phase 1 to Phase 4 Live Pipeline")
    parser.add_argument("--watch", nargs="*", help="Folder(s) to monitor (default: all standard user folders)")
    parser.add_argument("--output", default="cases_output", help="Case output folder (default: ./cases_output)")
    parser.add_argument("--open-report", action="store_true", help="Automatically open HTML report after capture")
    args = parser.parse_args()

    watch_dirs = [Path(w).resolve() for w in args.watch] if args.watch else default_user_folders()
    for d in watch_dirs:
        d.mkdir(parents=True, exist_ok=True)
    output_root = Path(args.output).resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    event_queue: queue.Queue[Path] = queue.Queue(maxsize=1024)
    stop_poll = threading.Event()
    observer = None
    handler = TripwireHandler(event_queue, output_root)
    if Observer is not None:
        observer = Observer()
        for d in watch_dirs:
            observer.schedule(handler, str(d), recursive=True)
        observer.start()
    else:
        def _poll_loop() -> None:
            seen_sig: dict[str, tuple[int, int]] = {}
            while not stop_poll.is_set():
                for root in watch_dirs:
                    for dirpath, dirnames, filenames in os.walk(root):
                        dirnames[:] = [dn for dn in dirnames if dn.lower() not in EXCLUDED_DIR_NAMES]
                        for fn in filenames:
                            fp = Path(dirpath) / fn
                            try:
                                st = fp.stat()
                                sig = (st.st_mtime_ns, st.st_size)
                            except OSError:
                                continue
                            k = str(fp)
                            if seen_sig.get(k) != sig:
                                seen_sig[k] = sig
                                handler._enqueue(k)
                stop_poll.wait(0.1)
        threading.Thread(target=_poll_loop, daemon=True).start()

    print("=" * 68)
    print("  CRYPTO-TRIPWIRE: LIVE 4-PHASE AUTOMATED DFIR PIPELINE")
    print("=" * 68)
    print(f"  Phase 1 Watching : {', '.join(str(d) for d in watch_dirs)}")
    print(f"  Cases Output     : {output_root}")
    print(f"  Trigger Rule     : >= {COUNT_THRESHOLD} distinct files with block H >= {ENTROPY_THRESHOLD} in {TIME_WINDOW_SECONDS}s")
    print("  Press Ctrl+C to stop.")
    print("=" * 68)

    recent_hits: deque[tuple[float, str, dict]] = deque()
    last_seen: dict[str, float] = {}
    baseline_header_h: dict[str, float] = {}
    cooldown_until = 0.0

    try:
        while True:
            try:
                fpath = event_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            now = time.monotonic()
            key = str(fpath)
            if now - last_seen.get(key, 0.0) < DEDUP_INTERVAL_SECONDS:
                continue
            last_seen[key] = now

            info = analyze_file_blocks(fpath)
            if info is None:
                continue

            prev_h = baseline_header_h.get(key)
            baseline_header_h[key] = info["header_entropy"]

            # Suppress legitimate compressed containers with intact magic headers
            if info["magic_header"] is not None:
                print(
                    f"[PHASE 1 | SUPPRESSED] {fpath.name} has valid {info['magic_header']} header "
                    f"(H={info['whole_entropy']}) -> 0 false alarm"
                )
                continue

            # Flag if max 4 KiB block >= 7.2 (catches both full-file and 25% header-only encryption)
            delta = (info["header_entropy"] - prev_h) if prev_h is not None else 0.0
            if info["max_block_entropy"] >= ENTROPY_THRESHOLD:
                print(
                    f"[PHASE 1 | FLAGGED]    {fpath.name} | Whole H={info['whole_entropy']} | "
                    f"Header 4KiB H={info['header_entropy']} (delta={delta:+.2f})"
                )
                if now < cooldown_until:
                    continue

                recent_hits.append((now, key, info))
                while recent_hits and (now - recent_hits[0][0]) > TIME_WINDOW_SECONDS:
                    recent_hits.popleft()

                distinct_files = {k: m for _, k, m in recent_hits}
                if len(distinct_files) >= COUNT_THRESHOLD:
                    cooldown_until = now + COOLDOWN_SECONDS
                    trigger_payload = {
                        "entropy_threshold": ENTROPY_THRESHOLD,
                        "count_threshold": COUNT_THRESHOLD,
                        "time_window_seconds": TIME_WINDOW_SECONDS,
                        "triggering_files": list(distinct_files.values()),
                    }
                    recent_hits.clear()

                    print("\n" + "=" * 68)
                    print(f"[PHASE 1 | TRIGGERED]  Entropy burst detected across {len(distinct_files)} files!")
                    print("                       Automatically launching Phase 2 -> Phase 3 -> Phase 4...")
                    print("=" * 68)

                    # Automatically run Phase 2 -> Phase 3 -> Phase 4
                    case_dir = run_phase2_capture(trigger_payload, output_root)
                    p3 = run_phase3_analyze(case_dir)
                    p4 = run_phase4_report(case_dir, p3)
                    print("=" * 68 + "\n")
                    if args.open_report:
                        webbrowser.open(Path(p4["html"]).as_uri())
    except KeyboardInterrupt:
        print("\n[PHASE 1] Stopping live monitor cleanly...")
    finally:
        stop_poll.set()
        if observer is not None:
            observer.stop()
            observer.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
