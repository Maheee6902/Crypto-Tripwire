"""Safe Multi-Folder Random Entropy-Spike Simulator with Automatic Cleanup.

Safety Guardrail:
    - Creates ONLY its own uniquely prefixed dummy files (`_ct_sim_decoy_*.tmp_sim`
      and `_ct_sim_benign_*.zip`) across randomly chosen monitored user folders.
    - Never reads, modifies, or deletes any existing user file.
    - Automatically erases every dummy file it created once Phases 1-4 finish.

Usage:
    python simulate_entropy_spike.py
    python simulate_entropy_spike.py --dirs ./folderA ./folderB ./folderC
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import random
import time
import uuid
import zipfile


def get_candidate_folders(custom_dirs: list[str] | None) -> list[Path]:
    if custom_dirs:
        dirs = [Path(d).resolve() for d in custom_dirs]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
        return dirs
    home = Path.home()
    names = ["Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music"]
    found = [home / n for n in names if (home / n).is_dir()]
    if not found:
        fallback = Path.cwd() / "watched_folder"
        fallback.mkdir(parents=True, exist_ok=True)
        return [fallback]
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe Random Multi-Folder Entropy-Spike Simulator")
    parser.add_argument("--dirs", nargs="*", help="Optional custom folders (default: all standard user folders)")
    parser.add_argument("--cleanup-delay", type=float, default=3.0, help="Seconds to wait before auto-erasing decoys")
    args = parser.parse_args()

    folders = get_candidate_folders(args.dirs)
    created_files: list[Path] = []
    run_tag = uuid.uuid4().hex[:6]

    print("=" * 68)
    print("  CRYPTO-TRIPWIRE: RANDOM MULTI-FOLDER DECOY SIMULATOR")
    print("=" * 68)
    print(f"  Candidate Folders : {', '.join(f.name for f in folders)}")
    print(f"  Run Tag           : {run_tag} (auto-cleanup enabled)")
    print("=" * 68)

    try:
        # Step 1: Benign compressed ZIP in a random folder (0 false alarms expected)
        z_dir = random.choice(folders)
        zp = z_dir / f"_ct_sim_benign_{run_tag}.zip"
        with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("sample.bin", os.urandom(24576))
        created_files.append(zp)
        print(f"\n[Step 1 | Benign ZIP] Created {zp.name} in {z_dir.name}/ (intact PK header -> 0 alerts)")
        time.sleep(1.0)

        # Step 2: 25% Header-only entropy spike across randomly chosen folders
        print("\n[Step 2 | 25% Header Spike] Creating 4 plaintext decoys across random folders...")
        plain = (b"Plaintext academic baseline decoy content 0123456789.\n" * 300)[:16384]
        partial_decoys: list[Path] = []
        for i in range(1, 5):
            d = random.choice(folders)
            f = d / f"_ct_sim_decoy_partial_{run_tag}_{i}.tmp_sim"
            f.write_bytes(plain)
            created_files.append(f)
            partial_decoys.append(f)
        time.sleep(0.8)

        for f in partial_decoys:
            buf = bytearray(f.read_bytes())
            buf[:4096] = os.urandom(4096)  # Leading 4 KiB (25% header)
            f.write_bytes(bytes(buf))
            print(f"  -> Spiked 25% header in {f.parent.name}/{f.name}")
            time.sleep(0.25)

        print("\n[Cooldown] Waiting 4.0s for Phase 1 to re-arm...")
        time.sleep(4.0)

        # Step 3: Full-file entropy spike across randomly chosen folders
        print("\n[Step 3 | 100% Full Spike] Spiking 4 decoy files across random folders...")
        for i in range(1, 5):
            d = random.choice(folders)
            f = d / f"_ct_sim_decoy_full_{run_tag}_{i}.tmp_sim"
            f.write_bytes(os.urandom(32768))
            created_files.append(f)
            print(f"  -> Spiked 100% entropy in {f.parent.name}/{f.name}")
            time.sleep(0.25)

        print(f"\n[Waiting] Giving Phases 2-4 {args.cleanup_delay:.1f}s to finish before auto-cleanup...")
        time.sleep(args.cleanup_delay)
    finally:
        # Automatically erase ONLY the exact dummy files created in this run
        erased = 0
        for f in created_files:
            try:
                if f.exists():
                    f.unlink()
                    erased += 1
            except OSError:
                pass
        print(f"[Auto-Cleanup] Erased {erased}/{len(created_files)} temporary decoy files. Your folders are spotless!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
