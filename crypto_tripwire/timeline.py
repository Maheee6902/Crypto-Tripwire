"""Phase 3: Evidence-linked deterministic timeline reconstruction and explainable rule evaluation."""

from __future__ import annotations

import csv
import datetime
import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from crypto_tripwire import SCHEMA_VERSION
from crypto_tripwire.capture import atomic_write_bytes, atomic_write_json, verify_case_manifest
from crypto_tripwire.entropy import utc_now_iso
from crypto_tripwire.models import (
    NormalizedTimelineEvent,
    RuleFinding,
    VerificationReport,
    VerificationStatus,
)


SUPPORTED_SCHEMA_VERSIONS = {"1.0_legacy", "1.0", "2.0"}

USER_WRITABLE_PATH_MARKERS = (
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\downloads\\",
    "\\users\\public\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)

SHADOW_OR_RECOVERY_MARKERS = (
    "vssadmin",
    "wmic shadowcopy",
    "bcdedit",
    "wbadmin",
    "delete shadows",
    "recoveryenabled no",
    "wevtutil cl",
)


def parse_iso_to_utc(ts_str: Optional[str]) -> Tuple[Optional[datetime.datetime], str]:
    """
    Parse an ISO-8601 timestamp string into a timezone-aware UTC datetime.
    Returns (dt_utc, note). Handles trailing 'Z', explicit offsets, and legacy naive strings.
    """
    if not ts_str or not isinstance(ts_str, str):
        return None, "Timestamp absent"
    cleaned = ts_str.strip()
    if not cleaned or cleaned.lower() == "unknown":
        return None, "Timestamp marked unknown"
    try:
        if cleaned.endswith("Z"):
            dt = datetime.datetime.fromisoformat(cleaned[:-1]).replace(tzinfo=datetime.timezone.utc)
            return dt, "Parsed explicit UTC (Z)"
        dt = datetime.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            # Legacy v1.0 processes.json stored naive local timestamps (`datetime.fromtimestamp(...)`)
            dt_utc = dt.replace(tzinfo=datetime.timezone.utc)
            return dt_utc, "Legacy naive timestamp normalized to UTC with timezone uncertainty noted"
        return dt.astimezone(datetime.timezone.utc), "Converted offset-aware timestamp to UTC"
    except ValueError:
        return None, f"Unparseable timestamp format: {cleaned}"


def is_external_ip(endpoint: str) -> bool:
    if not endpoint:
        return False
    host = endpoint
    if endpoint.startswith("[") and "]:" in endpoint:
        host = endpoint[1 : endpoint.rfind("]:")]
    elif ":" in endpoint:
        host = endpoint.rsplit(":", 1)[0]
    try:
        ip_obj = ipaddress.ip_address(host)
        return not (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


class TimelineReconstructor:
    """
    Reconstructs a deterministic, evidence-linked chronology and evaluates explainable rules.
    Validates integrity before deriving conclusions, preserves tie-breaking order, computes true
    elapsed seconds from a reference timestamp, and never fabricates process-to-file-write attribution.
    """

    def reconstruct(self, case_dir: str | os.PathLike[str]) -> Dict[str, Any]:
        cpath = Path(case_dir)
        reconstructed_utc = utc_now_iso()
        verification: VerificationReport = verify_case_manifest(cpath)
        integrity_passed = verification.overall_status == VerificationStatus.VERIFIED.value

        atomic_write_json(cpath / "verification.json", verification.to_dict())

        raw_events: List[Tuple[int, NormalizedTimelineEvent]] = []
        seq_counter = 0
        schema_warnings: List[str] = []

        # Load artifacts if present
        trigger_data = self._load_json_if_exists(cpath / "trigger.json", "trigger.json", schema_warnings)
        pre_alert_data = self._load_json_if_exists(cpath / "pre_alert_events.json", "pre_alert_events.json", schema_warnings)
        proc_data = self._load_json_if_exists(cpath / "processes.json", "processes.json", schema_warnings)
        net_data = self._load_json_if_exists(cpath / "network.json", "network.json", schema_warnings)
        mem_data = self._load_json_if_exists(cpath / "memory_acquisition.json", "memory_acquisition.json", schema_warnings)
        manifest_data = self._load_json_if_exists(cpath / "manifest.json", "manifest.json", schema_warnings)

        case_id = str(
            (trigger_data or {}).get("case_id")
            or (manifest_data or {}).get("case_id")
            or cpath.name
        )

        # Reference time selection:
        # 1. Trigger timestamp if available
        # 2. Capture timestamp in manifest.json or processes.json
        # 3. Current reconstruction UTC as last fallback
        ref_utc_str = (
            (trigger_data or {}).get("trigger_utc")
            or (manifest_data or {}).get("capture_start_utc")
            or (manifest_data or {}).get("timestamp")
            or (proc_data or {}).get("captured_utc")
            or (proc_data or {}).get("timestamp")
            or reconstructed_utc
        )
        ref_dt, _ = parse_iso_to_utc(ref_utc_str)
        ref_event_id = "tl_trigger_0001" if trigger_data else "tl_capture_ref"

        # 1. Pre-alert and contributing file events
        seen_file_event_ids = set()
        if pre_alert_data and isinstance(pre_alert_data.get("events"), list):
            for idx, fev in enumerate(pre_alert_data["events"]):
                if not isinstance(fev, dict):
                    continue
                seq_counter += 1
                fev_id = str(fev.get("event_id") or f"file_{idx:04d}")
                seen_file_event_ids.add(fev_id)
                obs_ts = str(fev.get("observed_utc") or ref_utc_str)
                src_ts = fev.get("source_timestamp_utc")
                meas = fev.get("measurement") or {}
                ent_val = meas.get("shannon_entropy")
                ent_str = f"{ent_val:.4f} bits/byte" if isinstance(ent_val, (int, float)) else str(meas.get("read_state", "N/A"))
                contrib = bool(fev.get("contributed_to_trigger", False))

                raw_events.append(
                    (
                        seq_counter,
                        self._make_event(
                            event_id=f"tl_{fev_id}",
                            case_id=case_id,
                            source_artifact="pre_alert_events.json",
                            source_record_ref=f"events[{idx}] (event_id={fev_id})",
                            source_ts=src_ts,
                            obs_ts=obs_ts,
                            ref_dt=ref_dt,
                            ref_event_id=ref_event_id,
                            event_type="FILE_EVENT_CONTRIBUTING" if contrib else "FILE_EVENT_PRE_ALERT",
                            summary=(
                                f"File {fev.get('event_type', 'modified')}: {os.path.basename(str(fev.get('normalized_path') or fev.get('src_path', '')))} "
                                f"[entropy={ent_str}, state={meas.get('read_state', 'UNKNOWN')}, contributed={contrib}]"
                            ),
                            attributes={
                                "original_event_id": fev_id,
                                "event_type": fev.get("event_type"),
                                "src_path": fev.get("src_path"),
                                "dest_path": fev.get("dest_path"),
                                "normalized_path": fev.get("normalized_path"),
                                "file_identity": fev.get("file_identity"),
                                "shannon_entropy": ent_val,
                                "read_state": meas.get("read_state"),
                                "qualifies_high_entropy": meas.get("qualifies_high_entropy"),
                                "qualification_reason": meas.get("qualification_reason"),
                                "contributed_to_trigger": contrib,
                                "writer_pid": None,
                            },
                            uncertainty_note=(
                                "Filesystem watcher records path-level modification time; responsible writer PID is not provided by OS watcher."
                            ),
                        ),
                    )
                )

        # 2. Trigger event
        if trigger_data:
            seq_counter += 1
            t_utc = str(trigger_data.get("trigger_utc") or ref_utc_str)
            raw_events.append(
                (
                    seq_counter,
                    self._make_event(
                        event_id="tl_trigger_0001",
                        case_id=case_id,
                        source_artifact="trigger.json",
                        source_record_ref=f"alert_id={trigger_data.get('alert_id', 'alert_001')}",
                        source_ts=t_utc,
                        obs_ts=t_utc,
                        ref_dt=ref_dt,
                        ref_event_id=ref_event_id,
                        event_type="TRIGGER_ALERT",
                        summary=str(trigger_data.get("rationale") or trigger_data.get("alert_description") or "Phase 1 entropy alert fired."),
                        attributes={
                            "alert_id": trigger_data.get("alert_id"),
                            "detection_mode": trigger_data.get("detection_mode"),
                            "contributing_event_ids": trigger_data.get("contributing_event_ids", []),
                            "contributing_file_identities": trigger_data.get("contributing_file_identities", []),
                            "burst_window_elapsed_seconds": trigger_data.get("burst_window_elapsed_seconds"),
                            "applied_thresholds": trigger_data.get("applied_thresholds", {}),
                        },
                        uncertainty_note="Alert indicates high-entropy file burst; ransomware attribution requires independent ground truth.",
                    ),
                )
            )

        # 3. Process snapshot observations
        proc_list: List[Dict[str, Any]] = []
        proc_obs_utc = ref_utc_str
        if proc_data and isinstance(proc_data.get("processes"), list):
            proc_list = proc_data["processes"]
            proc_obs_utc = str(proc_data.get("captured_utc") or proc_data.get("timestamp") or ref_utc_str)
            for idx, p in enumerate(proc_list):
                if not isinstance(p, dict):
                    continue
                seq_counter += 1
                pid = p.get("pid")
                name = str(p.get("name") or "unknown")
                raw_ctime = p.get("create_time_utc") if "create_time_utc" in p else p.get("create_time")
                dt_c, c_note = parse_iso_to_utc(raw_ctime)
                norm_ctime = dt_c.isoformat().replace("+00:00", "Z") if dt_c else None

                # Filter out epoch-0 placeholder timestamps (`1970-01-01...`) from being treated as real start times
                if norm_ctime and norm_ctime.startswith("1970-01-01"):
                    norm_ctime = None
                    c_note = "Kernel/idle process epoch-0 placeholder excluded as real start time; sorted by observation time."

                raw_events.append(
                    (
                        seq_counter,
                        self._make_event(
                            event_id=f"tl_proc_{idx:04d}_pid_{pid}",
                            case_id=case_id,
                            source_artifact="processes.json",
                            source_record_ref=f"processes[{idx}] (pid={pid})",
                            source_ts=norm_ctime,
                            obs_ts=proc_obs_utc,
                            ref_dt=ref_dt,
                            ref_event_id=ref_event_id,
                            event_type="PROCESS_OBSERVED",
                            summary=(
                                f"Process observed in snapshot: {name} (PID {pid}, PPID {p.get('ppid')}) "
                                f"[create_time={norm_ctime or 'UNAVAILABLE'}]"
                            ),
                            attributes={
                                "pid": pid,
                                "ppid": p.get("ppid"),
                                "name": name,
                                "exe": p.get("exe"),
                                "cmdline": p.get("cmdline"),
                                "create_time_utc": norm_ctime,
                                "access_status": p.get("access_status", "OK"),
                            },
                            uncertainty_note=(
                                f"{c_note}. Process presence in snapshot does not prove it wrote the triggering files; PID reuse is possible."
                            ),
                        ),
                    )
                )

        # 4. Network snapshot observations
        conn_list: List[Dict[str, Any]] = []
        net_obs_utc = ref_utc_str
        if net_data and isinstance(net_data.get("connections"), list):
            conn_list = net_data["connections"]
            net_obs_utc = str(net_data.get("captured_utc") or net_data.get("timestamp") or ref_utc_str)
            for idx, c in enumerate(conn_list):
                if not isinstance(c, dict):
                    continue
                seq_counter += 1
                laddr = str(c.get("laddr") or "")
                raddr = str(c.get("raddr") or "")
                status = str(c.get("status") or "UNKNOWN")
                cpid = c.get("pid")

                raw_events.append(
                    (
                        seq_counter,
                        self._make_event(
                            event_id=f"tl_net_{idx:04d}",
                            case_id=case_id,
                            source_artifact="network.json",
                            source_record_ref=f"connections[{idx}]",
                            source_ts=None,  # Socket opening time is unknown from snapshot alone
                            obs_ts=net_obs_utc,
                            ref_dt=ref_dt,
                            ref_event_id=ref_event_id,
                            event_type="NETWORK_SOCKET_OBSERVED",
                            summary=(
                                f"Socket observed at capture: local={laddr} <-> remote={raddr or 'NONE'} "
                                f"[state={status}, pid={cpid if cpid is not None else 'UNKNOWN'}, direction=UNKNOWN]"
                            ),
                            attributes={
                                "laddr": laddr,
                                "raddr": raddr,
                                "status": status,
                                "pid": cpid,
                                "direction_inference": "UNKNOWN_FROM_SNAPSHOT_ALONE",
                                "external_remote_ip": is_external_ip(raddr),
                            },
                            uncertainty_note=(
                                "Socket opening timestamp and initiation direction (inbound vs outbound) cannot be determined from a point-in-time table snapshot."
                            ),
                        ),
                    )
                )

        # 5. Memory acquisition record
        if mem_data:
            seq_counter += 1
            m_start = str(mem_data.get("acquisition_start_utc") or ref_utc_str)
            m_end = str(mem_data.get("acquisition_end_utc") or m_start)
            m_status = str(mem_data.get("status") or "UNKNOWN")
            raw_events.append(
                (
                    seq_counter,
                    self._make_event(
                        event_id="tl_mem_0001",
                        case_id=case_id,
                        source_artifact="memory_acquisition.json",
                        source_record_ref="memory_acquisition",
                        source_ts=m_start,
                        obs_ts=m_end,
                        ref_dt=ref_dt,
                        ref_event_id=ref_event_id,
                        event_type="MEMORY_ACQUISITION_STATE",
                        summary=(
                            f"Memory acquisition provider state: {m_status} "
                            f"[provenance={mem_data.get('provenance', 'N/A')}, size={mem_data.get('image_size_bytes', 0)} B]"
                        ),
                        attributes=mem_data,
                        uncertainty_note="Memory acquisition runs after fast snapshot collection; short-lived processes may exit prior to dump completion.",
                    ),
                )
            )

        # Deterministic sorting by (effective_sort_timestamp_utc_dt, original_sequence)
        def _sort_key(item: Tuple[int, NormalizedTimelineEvent]) -> Tuple[float, int]:
            seq, ev = item
            dt, _ = parse_iso_to_utc(ev.effective_sort_timestamp_utc)
            epoch = dt.timestamp() if dt else float("inf")
            return (epoch, seq)

        sorted_events = [ev for _, ev in sorted(raw_events, key=_sort_key)]
        event_id_map = {ev.event_id: ev for ev in sorted_events}

        # Evaluate deterministic, explainable rules
        findings = self._evaluate_rules(
            case_id=case_id,
            integrity_passed=integrity_passed,
            verification=verification,
            trigger_data=trigger_data,
            sorted_events=sorted_events,
            ref_dt=ref_dt,
            mem_data=mem_data,
        )

        # Validate that every finding's supporting_event_ids and supporting_artifacts exist
        validation_errors = self._validate_references(cpath, findings, event_id_map)

        timeline_payload = {
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id,
            "reconstructed_utc": reconstructed_utc,
            "reference_timestamp_utc": ref_utc_str,
            "reference_event_id": ref_event_id,
            "manifest_sha256_reference": verification.manifest_sha256,
            "integrity_verification_status": verification.overall_status,
            "integrity_passed": integrity_passed,
            "schema_warnings": schema_warnings,
            "reference_validation_errors": validation_errors,
            "total_events": len(sorted_events),
            "total_findings": len(findings),
            "events": [e.to_dict() for e in sorted_events],
        }
        findings_payload = {
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id,
            "generated_utc": reconstructed_utc,
            "manifest_sha256_reference": verification.manifest_sha256,
            "integrity_verification_status": verification.overall_status,
            "integrity_passed": integrity_passed,
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }

        atomic_write_json(cpath / "timeline.json", timeline_payload)
        atomic_write_json(cpath / "findings.json", findings_payload)
        self._write_csv_export(cpath / "timeline.csv", sorted_events)

        return {
            "verification": verification.to_dict(),
            "timeline": timeline_payload,
            "findings": findings_payload,
        }

    def _load_json_if_exists(self, path: Path, label: str, warnings: List[str]) -> Optional[Dict[str, Any]]:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                warnings.append(f"{label} root is not a JSON object.")
                return None
            sver = str(data.get("schema_version", "1.0_legacy"))
            if sver not in SUPPORTED_SCHEMA_VERSIONS:
                warnings.append(f"{label} declares unsupported schema_version '{sver}'; parsed in best-effort mode.")
            return data
        except Exception as exc:
            warnings.append(f"Failed loading {label}: {type(exc).__name__}: {exc}")
            return None

    def _make_event(
        self,
        event_id: str,
        case_id: str,
        source_artifact: str,
        source_record_ref: str,
        source_ts: Optional[str],
        obs_ts: str,
        ref_dt: Optional[datetime.datetime],
        ref_event_id: str,
        event_type: str,
        summary: str,
        attributes: Dict[str, Any],
        uncertainty_note: str,
    ) -> NormalizedTimelineEvent:
        dt_src, _ = parse_iso_to_utc(source_ts)
        dt_obs, _ = parse_iso_to_utc(obs_ts)

        if dt_src is not None:
            eff_dt = dt_src
            basis = "SOURCE_TIMESTAMP"
        elif dt_obs is not None:
            eff_dt = dt_obs
            basis = "OBSERVATION_TIMESTAMP"
        else:
            eff_dt = None
            basis = "UNKNOWN"

        eff_str = eff_dt.isoformat().replace("+00:00", "Z") if eff_dt else obs_ts
        elapsed: Optional[float] = None
        if eff_dt is not None and ref_dt is not None:
            elapsed = round((eff_dt - ref_dt).total_seconds(), 4)

        return NormalizedTimelineEvent(
            event_id=event_id,
            case_id=case_id,
            source_artifact=source_artifact,
            source_record_ref=source_record_ref,
            source_timestamp_utc=dt_src.isoformat().replace("+00:00", "Z") if dt_src else None,
            observation_timestamp_utc=dt_obs.isoformat().replace("+00:00", "Z") if dt_obs else obs_ts,
            effective_sort_timestamp_utc=eff_str,
            timestamp_basis=basis,
            elapsed_seconds_from_reference=elapsed,
            reference_event_id=ref_event_id,
            event_type=event_type,
            summary=summary,
            attributes=attributes,
            uncertainty_note=uncertainty_note,
        )

    def _evaluate_rules(
        self,
        case_id: str,
        integrity_passed: bool,
        verification: VerificationReport,
        trigger_data: Optional[Dict[str, Any]],
        sorted_events: List[NormalizedTimelineEvent],
        ref_dt: Optional[datetime.datetime],
        mem_data: Optional[Dict[str, Any]],
    ) -> List[RuleFinding]:
        findings: List[RuleFinding] = []

        # Rule 0: Integrity Verification Gate
        if not integrity_passed:
            findings.append(
                RuleFinding(
                    finding_id="F_CT_INTEGRITY_000",
                    rule_id="CT-R000-INTEGRITY-FAILURE",
                    rule_version="2.0",
                    title="Evidence Integrity Verification Failed",
                    severity="HIGH",
                    confidence="OBSERVED_FACT",
                    supporting_event_ids=[sorted_events[0].event_id] if sorted_events else [],
                    supporting_artifacts=[verification.manifest_relpath],
                    rationale=(
                        f"Independent SHA-256 verification returned status '{verification.overall_status}' "
                        f"(verified={verification.verified_count}, mismatch={verification.mismatch_count}, "
                        f"missing={verification.missing_count}). Subsequent findings are provisionally flagged and "
                        f"must not be used for unqualified conclusions."
                    ),
                    limitations=verification.trust_boundary_statement,
                    recommended_analyst_action="Inspect verification.json to identify modified or missing artifacts before relying on case data.",
                )
            )

        integrity_qualifier = (
            "" if integrity_passed else " [PROVISIONAL: Evidence integrity check failed; verify raw artifacts before relying on this finding.]"
        )

        # Rule 1: High-Entropy File Modification Burst (CT-R001)
        contrib_events = [e for e in sorted_events if e.event_type == "FILE_EVENT_CONTRIBUTING"]
        trig_events = [e for e in sorted_events if e.event_type == "TRIGGER_ALERT"]
        if trig_events or contrib_events:
            supp_ids = [e.event_id for e in (trig_events + contrib_events)]
            supp_arts = sorted(list({e.source_artifact for e in (trig_events + contrib_events)}))
            findings.append(
                RuleFinding(
                    finding_id="F_CT_BURST_001",
                    rule_id="CT-R001-ENTROPY-BURST",
                    rule_version="2.0",
                    title="High-Entropy Multi-File Modification Burst Observed",
                    severity="HIGH",
                    confidence="OBSERVED_FACT",
                    supporting_event_ids=supp_ids,
                    supporting_artifacts=supp_arts,
                    rationale=(
                        f"Observed {len(contrib_events)} high-entropy file event(s) exceeding configured burst thresholds."
                        f"{integrity_qualifier}"
                    ),
                    limitations=(
                        "High Shannon entropy alone does not prove cryptographic ransomware activity (legitimate compression, "
                        "archives, media writes, or installers also produce high-entropy blocks). Furthermore, a user-space "
                        "filesystem watcher does not identify the writer PID."
                    ),
                    recommended_analyst_action=(
                        "Review contributing file paths, baseline entropy deltas, and correlate with proximate process execution or Sysmon/ETW logs."
                    ),
                )
            )

        # Rule 2: Temporally Proximate Process Creation Near Trigger (CT-R002)
        proximate_procs: List[NormalizedTimelineEvent] = []
        for ev in sorted_events:
            if ev.event_type == "PROCESS_OBSERVED" and ev.source_timestamp_utc and ev.elapsed_seconds_from_reference is not None:
                # Process created within [-120s, +15s] of the reference trigger/capture time
                if -120.0 <= ev.elapsed_seconds_from_reference <= 15.0:
                    proximate_procs.append(ev)

        if proximate_procs:
            findings.append(
                RuleFinding(
                    finding_id="F_CT_PROC_PROX_002",
                    rule_id="CT-R002-TEMPORAL-PROCESS-PROXIMITY",
                    rule_version="2.0",
                    title="Processes Created in Close Temporal Proximity to High-Entropy Trigger",
                    severity="MEDIUM",
                    confidence="CORRELATED_ACTIVITY",
                    supporting_event_ids=[e.event_id for e in proximate_procs],
                    supporting_artifacts=["processes.json"],
                    rationale=(
                        f"Identified {len(proximate_procs)} process(es) whose recorded creation timestamp falls within "
                        f"[-120s, +15s] of the incident reference timestamp.{integrity_qualifier}"
                    ),
                    limitations=(
                        "Temporal proximity indicates a candidate process started shortly before capture, but does NOT prove "
                        "that the process performed the file writes. Short-lived processes that exited before snapshot enumeration are not visible."
                    ),
                    recommended_analyst_action=(
                        "Inspect executable paths, parent-child relationships, and command-line arguments of temporally proximate processes."
                    ),
                )
            )

        # Rule 3: Process Executing from User-Writable / Temp Directory or Suspicious Command Line (CT-R003)
        susp_exec_procs: List[NormalizedTimelineEvent] = []
        recovery_inhibit_procs: List[NormalizedTimelineEvent] = []
        for ev in sorted_events:
            if ev.event_type != "PROCESS_OBSERVED":
                continue
            exe_s = str(ev.attributes.get("exe") or "").lower()
            cmd_s = str(ev.attributes.get("cmdline") or "").lower()
            combined = f"{exe_s} {cmd_s}"
            if any(marker in combined for marker in USER_WRITABLE_PATH_MARKERS):
                susp_exec_procs.append(ev)
            if any(marker in combined for marker in SHADOW_OR_RECOVERY_MARKERS):
                recovery_inhibit_procs.append(ev)

        if susp_exec_procs:
            findings.append(
                RuleFinding(
                    finding_id="F_CT_USERDIR_EXEC_003",
                    rule_id="CT-R003-USER-WRITABLE-EXECUTION-PATH",
                    rule_version="2.0",
                    title="Process Executing from User-Writable or Temporary Directory",
                    severity="MEDIUM",
                    confidence="HEURISTIC_INDICATOR",
                    supporting_event_ids=[e.event_id for e in susp_exec_procs],
                    supporting_artifacts=["processes.json"],
                    rationale=(
                        f"Observed {len(susp_exec_procs)} process(es) with executable or command-line paths referencing "
                        f"user-writable/temporary directories (e.g., AppData, Temp, Downloads, /tmp).{integrity_qualifier}"
                    ),
                    limitations=(
                        "Legitimate updaters, developer scripts, and test runners also execute from temporary or user directories; "
                        "path location alone is not a malware verdict."
                    ),
                    recommended_analyst_action="Verify binary hash and code signature of executables running from user-writable paths.",
                )
            )

        if recovery_inhibit_procs:
            findings.append(
                RuleFinding(
                    finding_id="F_CT_RECOVERY_INHIBIT_004",
                    rule_id="CT-R004-RECOVERY-INHIBITION-CMDLINE",
                    rule_version="2.0",
                    title="Command-Line Pattern Associated with Shadow Copy or Recovery Tampering",
                    severity="HIGH",
                    confidence="HEURISTIC_INDICATOR",
                    supporting_event_ids=[e.event_id for e in recovery_inhibit_procs],
                    supporting_artifacts=["processes.json"],
                    rationale=(
                        f"Observed {len(recovery_inhibit_procs)} process(es) matching recovery/shadow-copy inhibition command strings.{integrity_qualifier}"
                    ),
                    limitations="Command-line inspection relies on process remaining alive at snapshot time and accessible to the current user context.",
                    recommended_analyst_action="Preserve full command line, parent process chain, and check Volume Shadow Copy service logs.",
                )
            )

        # Rule 5: Active External Network Socket Correlated with Running Process (CT-R005)
        ext_net_events = [
            ev
            for ev in sorted_events
            if ev.event_type == "NETWORK_SOCKET_OBSERVED"
            and ev.attributes.get("status") == "ESTABLISHED"
            and ev.attributes.get("external_remote_ip") is True
        ]
        if ext_net_events:
            # Also link any matching process event IDs by PID if observed in same snapshot
            net_pids = {ev.attributes.get("pid") for ev in ext_net_events if ev.attributes.get("pid") is not None}
            matching_proc_events = [
                ev
                for ev in sorted_events
                if ev.event_type == "PROCESS_OBSERVED" and ev.attributes.get("pid") in net_pids
            ]
            supp_ids = [e.event_id for e in (ext_net_events + matching_proc_events)]
            supp_arts = ["network.json"] + (["processes.json"] if matching_proc_events else [])
            findings.append(
                RuleFinding(
                    finding_id="F_CT_EXT_NET_005",
                    rule_id="CT-R005-EXTERNAL-ESTABLISHED-SOCKET",
                    rule_version="2.0",
                    title="Established External Network Socket(s) Present at Capture Time",
                    severity="LOW",
                    confidence="OBSERVED_FACT",
                    supporting_event_ids=supp_ids,
                    supporting_artifacts=supp_arts,
                    rationale=(
                        f"Observed {len(ext_net_events)} ESTABLISHED network socket(s) with non-private remote IP endpoints "
                        f"associated with {len(net_pids)} distinct PID(s) at capture time.{integrity_qualifier}"
                    ),
                    limitations=(
                        "Point-in-time socket enumeration does not record when the connection opened or which side initiated "
                        "the handshake (direction is unknown). Background browsers, OS telemetry, and cloud sync clients "
                        "routinely maintain established external HTTPS connections."
                    ),
                    recommended_analyst_action=(
                        "Cross-reference remote IP endpoints and owning PIDs against firewall/DNS logs and threat intelligence."
                    ),
                )
            )

        # Rule 6: Unreadable or Vanished File Observations During Burst (CT-R006)
        unreadable_events = [
            ev
            for ev in sorted_events
            if ev.event_type.startswith("FILE_EVENT")
            and ev.attributes.get("read_state") in ("UNREADABLE", "VANISHED", "CHANGED_DURING_READ")
        ]
        if unreadable_events:
            findings.append(
                RuleFinding(
                    finding_id="F_CT_FILE_CONTENTION_006",
                    rule_id="CT-R006-FILE-CONTENTION-OR-DELETION",
                    rule_version="2.0",
                    title="File Lock Contention, Rapid Replacement, or Deletion Observed During Monitoring",
                    severity="INFO",
                    confidence="OBSERVED_FACT",
                    supporting_event_ids=[e.event_id for e in unreadable_events],
                    supporting_artifacts=["pre_alert_events.json"],
                    rationale=(
                        f"Observed {len(unreadable_events)} file event(s) that were unreadable, vanished before read completion, "
                        f"or changed during read retries.{integrity_qualifier}"
                    ),
                    limitations=(
                        "Rapid temp-file creation/deletion occurs in both atomic document saves and ransomware rename-and-unlink patterns."
                    ),
                    recommended_analyst_action="Review file event sequence around vanished paths to determine whether target files were replaced.",
                )
            )

        return findings

    def _validate_references(
        self,
        case_dir: Path,
        findings: List[RuleFinding],
        event_id_map: Dict[str, NormalizedTimelineEvent],
    ) -> List[str]:
        errors: List[str] = []
        for f in findings:
            for eid in f.supporting_event_ids:
                if eid not in event_id_map:
                    errors.append(f"Finding {f.finding_id} references non-existent event_id '{eid}'.")
            for art in f.supporting_artifacts:
                if not (case_dir / art).exists():
                    errors.append(f"Finding {f.finding_id} references missing artifact '{art}'.")
        return errors

    def _write_csv_export(self, csv_path: Path, events: List[NormalizedTimelineEvent]) -> None:
        rows: List[List[str]] = [
            [
                "event_id",
                "effective_sort_timestamp_utc",
                "timestamp_basis",
                "elapsed_seconds_from_reference",
                "event_type",
                "source_artifact",
                "source_record_ref",
                "summary",
                "uncertainty_note",
            ]
        ]
        for ev in events:
            el_str = (
                f"{ev.elapsed_seconds_from_reference:+.4f}"
                if ev.elapsed_seconds_from_reference is not None
                else "UNKNOWN"
            )
            rows.append(
                [
                    ev.event_id,
                    ev.effective_sort_timestamp_utc,
                    ev.timestamp_basis,
                    el_str,
                    ev.event_type,
                    ev.source_artifact,
                    ev.source_record_ref,
                    ev.summary,
                    ev.uncertainty_note,
                ]
            )
        buf: List[str] = []
        import io

        sio = io.StringIO()
        writer = csv.writer(sio)
        writer.writerows(rows)
        atomic_write_bytes(csv_path, sio.getvalue().encode("utf-8"))
