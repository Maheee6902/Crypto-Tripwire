"""Configuration schema, validation, defaults, and canonical hashing for Crypto-Tripwire."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class DetectorSettings:
    detection_mode: str = "format_aware_header_and_block"
    entropy_threshold: float = 7.2
    count_threshold: int = 3
    time_window_seconds: float = 5.0
    cooldown_seconds: float = 3.0
    burst_grouping_window_seconds: float = 2.0
    coalesce_interval_ms: float = 150.0
    min_file_size_bytes: int = 64
    max_whole_file_bytes: int = 16 * 1024 * 1024  # 16 MiB bound for whole-file read
    chunk_size_bytes: int = 4096
    max_sampled_chunks: int = 16
    read_retry_count: int = 2
    read_retry_delay_ms: float = 25.0
    pre_alert_buffer_size: int = 256
    baseline_cache_max_entries: int = 2048
    # Phase 1 Format-Aware Magic Header & 4 KiB Block Entropy parameters
    chunk_high_entropy_threshold: float = 7.2
    min_high_entropy_chunk_fraction: float = 0.5
    entropy_delta_threshold: float = 1.25
    compressed_container_delta_margin: float = 0.20
    threshold_provenance_label: str = "inherited_or_engineering_default_uncalibrated"


@dataclass
class CaptureSettings:
    collect_processes: bool = True
    collect_network: bool = True
    enable_ram_acquisition: bool = False
    ram_tool_executable: Optional[str] = None
    ram_tool_type: str = "winpmem"  # winpmem or custom_fixed
    ram_timeout_seconds: float = 120.0
    ram_min_free_disk_mb: int = 1024
    imported_ram_image_path: Optional[str] = None
    imported_ram_provenance: Optional[str] = None
    enable_volatility: bool = False
    volatility_executable: Optional[str] = None
    volatility_plugins: List[str] = field(default_factory=lambda: ["windows.pslist.PsList", "windows.netscan.NetScan"])
    volatility_timeout_seconds: float = 90.0


@dataclass
class ResourceLimits:
    event_queue_max_size: int = 1024
    incident_queue_max_size: int = 64
    worker_threads: int = 1
    report_wait_for_slow_providers_seconds: float = 5.0
    polling_interval_ms: float = 100.0


@dataclass
class AppConfig:
    config_version: str = "2.0"
    monitored_roots: List[str] = field(default_factory=lambda: ["watched_folder"])
    excluded_paths: List[str] = field(default_factory=list)
    excluded_extensions: List[str] = field(default_factory=lambda: [".tmp_ct", ".part_ct"])
    follow_symlinks_or_reparse: bool = False
    output_root: str = "cases_output"
    log_dir: str = "logs"
    observation_mode: str = "live_endpoint_monitoring"
    detector: DetectorSettings = field(default_factory=DetectorSettings)
    capture: CaptureSettings = field(default_factory=CaptureSettings)
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    generate_html_report: bool = True
    generate_pdf_report: bool = True

    def validate(self) -> List[str]:
        """Validate configuration and ensure output/log paths never overlap monitored roots."""
        errors: List[str] = []
        if not self.monitored_roots:
            errors.append("At least one monitored_root must be configured.")
        if not (0.0 < self.detector.entropy_threshold <= 8.0):
            errors.append("detector.entropy_threshold must be in (0.0, 8.0].")
        if self.detector.count_threshold < 1:
            errors.append("detector.count_threshold must be >= 1.")
        if self.detector.time_window_seconds <= 0:
            errors.append("detector.time_window_seconds must be > 0.")
        if self.detector.chunk_size_bytes < 64:
            errors.append("detector.chunk_size_bytes must be >= 64.")
        if self.detector.max_sampled_chunks < 1:
            errors.append("detector.max_sampled_chunks must be >= 1.")
        if self.limits.event_queue_max_size < 1:
            errors.append("limits.event_queue_max_size must be >= 1.")
        if self.detector.detection_mode not in {"format_aware_header_and_block", "basic_whole_file"}:
            errors.append(f"Unsupported detector.detection_mode: {self.detector.detection_mode}")
        if self.observation_mode not in {"live_endpoint_monitoring", "case_replay_verification"}:
            errors.append(f"Unsupported observation_mode: {self.observation_mode}")

        out_abs = Path(self.output_root).resolve()
        log_abs = Path(self.log_dir).resolve()
        for root in self.monitored_roots:
            root_abs = Path(root).resolve()
            if out_abs == root_abs or root_abs in out_abs.parents:
                errors.append(
                    f"output_root ({out_abs}) cannot be inside monitored_root ({root_abs}) to prevent self-triggering."
                )
            if log_abs == root_abs or root_abs in log_abs.parents:
                errors.append(
                    f"log_dir ({log_abs}) cannot be inside monitored_root ({root_abs}) to prevent self-triggering."
                )
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def canonical_digest(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AppConfig":
        det_data = data.get("detector", {})
        cap_data = data.get("capture", {})
        lim_data = data.get("limits", {})
        cfg = cls(
            config_version=str(data.get("config_version", "2.0")),
            monitored_roots=list(data.get("monitored_roots", ["watched_folder"])),
            excluded_paths=list(data.get("excluded_paths", [])),
            excluded_extensions=list(data.get("excluded_extensions", [".tmp_ct", ".part_ct"])),
            follow_symlinks_or_reparse=bool(data.get("follow_symlinks_or_reparse", False)),
            output_root=str(data.get("output_root", "cases_output")),
            log_dir=str(data.get("log_dir", "logs")),
            observation_mode=str(data.get("observation_mode", "live_endpoint_monitoring")),
            detector=DetectorSettings(**{k: v for k, v in det_data.items() if k in DetectorSettings.__dataclass_fields__}),
            capture=CaptureSettings(**{k: v for k, v in cap_data.items() if k in CaptureSettings.__dataclass_fields__}),
            limits=ResourceLimits(**{k: v for k, v in lim_data.items() if k in ResourceLimits.__dataclass_fields__}),
            generate_html_report=bool(data.get("generate_html_report", True)),
            generate_pdf_report=bool(data.get("generate_pdf_report", True)),
        )
        errs = cfg.validate()
        if errs:
            raise ValueError("Invalid configuration:\n- " + "\n- ".join(errs))
        return cfg

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "AppConfig":
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            raise ValueError("Configuration root must be a JSON object.")
        return cls.from_dict(raw)

    def save(self, path: str | os.PathLike[str]) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=False)
