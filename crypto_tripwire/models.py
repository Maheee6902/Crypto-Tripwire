"""Data models, enumerations, and schema contracts for Crypto-Tripwire."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ReadState(str, Enum):
    OK = "OK"
    EMPTY = "EMPTY"
    TOO_SMALL = "TOO_SMALL"
    UNREADABLE = "UNREADABLE"
    VANISHED = "VANISHED"
    CHANGED_DURING_READ = "CHANGED_DURING_READ"
    INCOMPLETE = "INCOMPLETE"
    SKIPPED_DELETED = "SKIPPED_DELETED"
    UNSUPPORTED_LINK = "UNSUPPORTED_LINK"


class DetectorMode(str, Enum):
    BASIC_WHOLE_FILE = "basic_whole_file"
    FORMAT_AWARE_HEADER_AND_BLOCK = "format_aware_header_and_block"


class ObservationMode(str, Enum):
    LIVE_ENDPOINT_MONITORING = "live_endpoint_monitoring"
    CASE_REPLAY_VERIFICATION = "case_replay_verification"


class ProviderStatus(str, Enum):
    SUCCESS = "SUCCESS"
    ZERO_RECORDS = "ZERO_RECORDS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    IMPORTED = "IMPORTED"
    SKIPPED = "SKIPPED"
    TIMEOUT = "TIMEOUT"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    MISMATCH = "MISMATCH"
    MISSING_ARTIFACT = "MISSING_ARTIFACT"
    MANIFEST_MISSING = "MANIFEST_MISSING"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    UNVERIFIED = "UNVERIFIED"


@dataclass
class ChunkSample:
    offset: int
    length: int
    entropy_bits_per_byte: float
    sha256: str


@dataclass
class BaselineComparison:
    baseline_available: bool
    compatible_offsets: bool
    previous_size: Optional[int] = None
    current_size: Optional[int] = None
    size_change_type: str = "UNKNOWN"  # UNCHANGED, RESIZED, TRUNCATED, REPLACED, NEW_FILE, UNKNOWN
    matched_chunk_count: int = 0
    mean_entropy_delta: Optional[float] = None
    max_entropy_delta: Optional[float] = None
    notes: str = ""


@dataclass
class EntropyMeasurement:
    filepath: str
    normalized_path: str
    file_identity: str
    identity_source: str  # os_inode_dev, path_normalized_fallback, replay_record
    shannon_entropy: Optional[float]
    estimator: str
    measurement_mode: str  # whole_file, chunk_sampled, none
    file_size: Optional[int]
    bytes_examined: int
    sampling_coverage_ratio: float
    chunk_samples: List[ChunkSample] = field(default_factory=list)
    read_state: str = ReadState.OK.value
    retry_count: int = 0
    retry_outcome: str = "FIRST_ATTEMPT_OK"
    read_budget_bytes: int = 0
    measurement_utc: str = ""
    measurement_monotonic_ns: int = 0
    duration_ms: float = 0.0
    file_extension: str = ""
    likely_compressed_container: bool = False
    magic_header_hex: str = ""
    content_sha256_examined: Optional[str] = None
    baseline_comparison: Optional[BaselineComparison] = None
    qualifies_high_entropy: bool = False
    qualification_reason: str = ""
    error_detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MonitoredFileEvent:
    event_id: str
    event_type: str  # created, modified, moved, deleted
    src_path: str
    dest_path: Optional[str]
    normalized_path: str
    file_identity: str
    identity_source: str
    observed_utc: str
    observed_monotonic_ns: int
    source_timestamp_utc: Optional[str] = None
    coalesced_count: int = 1
    measurement: Optional[EntropyMeasurement] = None
    contributed_to_trigger: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TriggerRecord:
    case_id: str
    alert_id: str
    detection_mode: str
    observation_mode: str
    alert_description: str
    trigger_utc: str
    trigger_monotonic_ns: int
    first_contributing_event_utc: str
    first_contributing_monotonic_ns: int
    burst_window_elapsed_seconds: float
    applied_thresholds: Dict[str, Any]
    config_digest: str
    contributing_event_ids: List[str]
    contributing_file_identities: List[str]
    contributing_events: List[Dict[str, Any]]
    pre_alert_history_count: int
    queue_stats_at_trigger: Dict[str, Any]
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProviderMetadata:
    provider_name: str
    start_utc: str
    end_utc: str
    duration_ms: float
    status: str
    record_count: int
    tool_or_provider_version: str
    errors: List[str] = field(default_factory=list)
    notes: str = ""
    artifact_relpath: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ManifestArtifactEntry:
    relative_path: str
    size_bytes: int
    sha256: str
    acquisition_start_utc: str
    acquisition_end_utc: str
    acquisition_duration_ms: float
    schema_version: str
    provider_name: str
    provider_status: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationItemResult:
    relative_path: str
    expected_sha256: str
    actual_sha256: Optional[str]
    expected_size: Optional[int]
    actual_size: Optional[int]
    status: str  # VERIFIED, MISMATCH, MISSING_ARTIFACT

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationReport:
    case_id: str
    verified_utc: str
    manifest_relpath: str
    manifest_sha256: Optional[str]
    overall_status: str
    schema_version: str
    checked_count: int
    verified_count: int
    mismatch_count: int
    missing_count: int
    items: List[VerificationItemResult] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    trust_boundary_statement: str = (
        "SHA-256 digests stored beside evidence detect accidental corruption or uncoordinated post-capture "
        "modification of individual files, but they do not prove integrity against a privileged adversary "
        "capable of replacing both the evidence files and the manifest simultaneously."
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NormalizedTimelineEvent:
    event_id: str
    case_id: str
    source_artifact: str
    source_record_ref: str
    source_timestamp_utc: Optional[str]
    observation_timestamp_utc: str
    effective_sort_timestamp_utc: str
    timestamp_basis: str  # SOURCE_TIMESTAMP, OBSERVATION_TIMESTAMP, UNKNOWN
    elapsed_seconds_from_reference: Optional[float]
    reference_event_id: str
    event_type: str  # FILE_EVENT, TRIGGER_ALERT, CAPTURE_INTERVAL, PROCESS_OBSERVED, NETWORK_SOCKET_OBSERVED, MEMORY_ARTIFACT
    summary: str
    attributes: Dict[str, Any] = field(default_factory=list)
    uncertainty_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuleFinding:
    finding_id: str
    rule_id: str
    rule_version: str
    title: str
    severity: str  # INFO, LOW, MEDIUM, HIGH
    confidence: str  # OBSERVED_FACT, HEURISTIC_INDICATOR, CORRELATED_ACTIVITY
    supporting_event_ids: List[str]
    supporting_artifacts: List[str]
    rationale: str
    limitations: str
    recommended_analyst_action: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
