# Crypto-Tripwire: Entropy-Based Ransomware Detection for Automated Volatile Evidence Capture and Incident Response

**Author:** Mahesh Ravi (`AM.SC.P2CSN25010`)  
**Program:** M.Tech Cybersecurity Systems and Networks  
**Institution:** Center for Cybersecurity Systems and Networks, Amrita Vishwa Vidyapeetham, Amritapuri Campus  
**Project Guide:** Sreelakshmi R Syam  

## 1. What the Project Does

**Crypto-Tripwire** is a low-latency, four-phase Digital Forensics and Incident Response (DFIR) pipeline . It monitors user directories (`Desktop`, `Documents`, `Downloads`, `Pictures`, `Videos`, `Music`) for ransomware file-encryption bursts and automatically captures volatile evidence before the offending process exits:

1. **Phase 1 (`crypto_tripwire/entropy.py`, `detector.py`, `phase1_monitor.py`) - Format-Aware Magic-Header & Block-Entropy Trigger:** Checks file magic headers (`PK` `0x504B0304`, `%PDF-`, `PNG`, `7z`, `Rar!`), samples up to `16 x 4 KiB` (`64 KiB` cap) blocks, tracks per-file baselines (`BaselineStore`), filters `150 ms` duplicate OS saves, and triggers Phase 2 when `3` distinct files spike past `7.2 bits/byte` within `5.0 s`.
2. **Phase 2 (`crypto_tripwire/capture.py`) - Automated Volatile Evidence Capture:** Creates a timestamped case folder (`cases_output/case_<UTC>_<seq>_<uid>/`), saves `trigger.json`, `pre_alert_events.json`, running processes (`processes.json`), active network sockets (`network.json`), and optional WinPmem physical RAM metadata (`memory_acquisition.json`), writing every file atomically (`fsync`) with SHA-256 digests in `manifest.json`.
3. **Phase 3 (`crypto_tripwire/timeline.py`) - SHA-256 Verification, UTC Timeline & Rule Engine:** Recomputes SHA-256 digests (`verify_case_manifest()` -> `verification.json`), normalizes timestamps to UTC (`timeline.json`), and evaluates all seven deterministic forensic rules `CT-R000` to `CT-R006` (`findings.json`).
4. **Phase 4 (`crypto_tripwire/reporting.py`) - Automated Incident Reporting:** Sanitizes untrusted filenames and command lines (`html.escape` / `xml_escape`) and writes `incident_report.json`, `incident_report.html`, and A4 `incident_report.pdf`.

## 2. Why the Project Is Useful

- **Beats the Volatile Evidence Loss Window:** Automates process, socket, and SHA-256 manifest capture in milliseconds rather than waiting for manual analyst action.
- **Eliminates `.zip` / `.pdf` False Alarms & Catches Partial Header Encryption:** Combines magic-header validation with `16 x 4 KiB` block-entropy deltas so normal compressed archives trigger `0` false alarms while `25%` header-only encryption is still caught.
- **Tamper-Evident & Analyst-Ready:** Independently re-verifies SHA-256 hashes before timeline parsing and compiles browser-ready HTML and printable PDF reports automatically.

## 3. Architectural Block Diagram & Module Summary

![Architectural Block Diagram](docs/architecture_block_diagram.png)

| Module / File | Phase | Key Classes & Functions | Inputs | Outputs |
| :--- | :--- | :--- | :--- | :--- |
| `phase1_monitor.py` | Live Launcher | `default_user_folders()`, `main()` | All standard user folders (or `--watch`) | Runs full 4-phase `CryptoTripwirePipeline` live |
| `crypto_tripwire/entropy.py`, `models.py` | Phase 1 | `compute_shannon_entropy()`, `detect_magic_header_format()`, `BaselineStore`, `EntropyAnalyzer` | File path on disk | `EntropyMeasurement` (`16 x 4 KiB` blocks, magic header, baseline delta) |
| `crypto_tripwire/detector.py`, `pipeline.py` | Phase 1 & Coordinator | `AsyncFilesystemMonitor`, `BurstDetectionEngine`, `CryptoTripwirePipeline` | OS file events (`watchdog` / `os.stat`) | Filters `150 ms` duplicates; emits `TriggerRecord` to background worker |
| `crypto_tripwire/capture.py` | Phase 2 | `EvidenceCaptureCoordinator`, `ProcessProvider`, `NetworkProvider`, `MemoryAcquisitionProvider`, `verify_case_manifest()` | `TriggerRecord` + pre-alert buffer | `trigger.json`, `processes.json`, `network.json`, `memory_acquisition.json`, `manifest.json` |
| `crypto_tripwire/timeline.py` | Phase 3 | `TimelineReconstructor`, `_evaluate_rules()` | Case directory + `VerificationReport` | `verification.json`, `timeline.json`, `findings.json` (`CT-R000` to `CT-R006`) |
| `crypto_tripwire/reporting.py`, `cli.py` | Phase 4 & CLI | `IncidentReportGenerator`, `_render_html()`, `_render_pdf()` | Case JSON artifacts | Escaped `incident_report.json`, `.html`, A4 `.pdf` |
| `simulate_entropy_spike.py` | Safe Simulator | `get_candidate_folders()`, `main()` | Random monitored user folders | Benign ZIP (`0` alerts) + 25% header & 100% full decoy spikes (auto-erased) |
| `tests/test_crypto_tripwire.py` | Verification | `TestCryptoTripwireSuite` (`test_01` to `test_16`) | Synthetic tests + `historical_reference/` | `16/16` unit & integration checks |

## 4. Requirements

- **OS:** Windows 10/11 or Linux
- **Python:** Python `3.10` or higher
- **Libraries (`requirements.txt`):** `watchdog`, `psutil`, `reportlab`

## 5. Quick Start (< 30 Seconds on Default Settings)

```powershell
git clone https://github.com/AmritaCSN/Crypto-Tripwire.git
cd Crypto-Tripwire
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Run the 16 Automated Unit & Integration Tests
```powershell
python -m unittest discover -s tests -v
```

### Run the Live 4-Phase Demo (2 VS Code Terminals)
- **Terminal 1 (Start Live Monitoring Across All User Folders):**
  ```powershell
  python phase1_monitor.py --open-report
  ```
- **Terminal 2 (Run Safe Random Multi-Folder Entropy-Spike Simulation):**
  ```powershell
  python simulate_entropy_spike.py
  ```

## 6. Advanced Usage - Parameters & Arguments

- **Monitor specific folders or custom output directory:**
  ```powershell
  python phase1_monitor.py --watch C:\Users\mahes\Documents C:\Users\mahes\Desktop --output D:\Cases --open-report
  ```
- **Run CLI subcommands directly (verify or re-analyze the captured Windows snapshot):**
  ```powershell
  python -m crypto_tripwire verify-case historical_reference/evidence_output
  python -m crypto_tripwire analyze-case historical_reference/evidence_output --output-dir ./snapshot_out
  ```
- **Adjust detection parameters in `configs/default_config.json`:**
  - `detector.entropy_threshold` (default `7.2`): Raise to `7.5` for stricter alerts or lower to `7.0` for higher sensitivity.
  - `detector.count_threshold` (default `3`) & `detector.time_window_seconds` (default `5.0`): Adjust burst size and window.
  - `capture.enable_ram_acquisition` (default `false`): Set `true` with `ram_tool_executable` (Velocidex WinPmem) for optional physical RAM dumps.
