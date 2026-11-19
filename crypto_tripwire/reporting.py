"""Phase 4: Automatic incident report generation (canonical JSON, offline HTML, and readable PDF)."""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from crypto_tripwire import SCHEMA_VERSION, __version__
from crypto_tripwire.capture import atomic_write_bytes, atomic_write_json
from crypto_tripwire.config import AppConfig
from crypto_tripwire.entropy import utc_now_iso


class IncidentReportGenerator:
    """
    Produces consistent, evidence-linked incident reports in JSON, offline HTML, and PDF formats.
    Strictly escapes all untrusted strings (filenames, paths, command lines, process names),
    distinguishes observed facts from heuristic findings and advisory recommendations,
    and explicitly versions report revisions.
    """

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        self.config = config or AppConfig()

    def generate_case_reports(
        self,
        case_dir: str | os.PathLike[str],
        revision: int = 1,
    ) -> Dict[str, Any]:
        cpath = Path(case_dir)
        report_start_utc = utc_now_iso()
        report_start_ns = time.monotonic_ns()

        manifest = self._read_json(cpath / "manifest.json") or {}
        trigger = self._read_json(cpath / "trigger.json") or {}
        verification = self._read_json(cpath / "verification.json") or {}
        timeline = self._read_json(cpath / "timeline.json") or {}
        findings_doc = self._read_json(cpath / "findings.json") or {}
        mem_doc = self._read_json(cpath / "memory_acquisition.json") or {}

        case_id = str(
            trigger.get("case_id")
            or manifest.get("case_id")
            or timeline.get("case_id")
            or cpath.name
        )

        # Build advisory recommendations strictly grounded in observed findings and provider outcomes
        recommendations = self._build_recommendations(
            verification=verification,
            findings=findings_doc.get("findings", []),
            mem_doc=mem_doc,
        )

        limitations = [
            "Entropy-based detection flags rapid high-entropy file writes; it is a behavioral indicator, not definitive proof of cryptographic ransomware without independent ground truth.",
            "User-space monitoring observes file modifications after or during write operations; it does not block writes, prevent encryption, or guarantee process capture before exit.",
            "Standard filesystem change notifications do not identify the writer PID; process observations in processes.json represent point-in-time co-occurring processes.",
            "Point-in-time network socket tables do not record connection opening timestamps or TCP handshake initiation direction (inbound vs. outbound).",
            "SHA-256 digests stored in manifest.json detect accidental corruption or uncoordinated post-capture edits, but cannot prevent a privileged attacker from replacing both evidence and manifest.",
        ]

        report_end_utc = utc_now_iso()
        gen_duration_ms = round((time.monotonic_ns() - report_start_ns) / 1_000_000.0, 4)

        timings_summary = {
            "first_contributing_event_utc": trigger.get("first_contributing_event_utc", "UNAVAILABLE"),
            "trigger_utc": trigger.get("trigger_utc", "UNAVAILABLE"),
            "burst_window_elapsed_seconds": trigger.get("burst_window_elapsed_seconds"),
            "capture_start_utc": manifest.get("capture_start_utc") or manifest.get("timestamp", "UNAVAILABLE"),
            "capture_end_utc": manifest.get("capture_end_utc", "UNAVAILABLE"),
            "trigger_to_capture_delay_ms": manifest.get("trigger_to_capture_delay_ms"),
            "capture_duration_ms": manifest.get("capture_duration_ms"),
            "timeline_reconstructed_utc": timeline.get("reconstructed_utc", "UNAVAILABLE"),
            "report_generated_utc": report_end_utc,
            "report_generation_duration_ms": gen_duration_ms,
        }

        canonical_report: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "report_revision": revision,
            "case_id": case_id,
            "generated_utc": report_end_utc,
            "application_version": __version__,
            "configuration_version": self.config.config_version,
            "configuration_digest": trigger.get("config_digest") or self.config.canonical_digest(),
            "observation_mode": trigger.get("observation_mode") or self.config.observation_mode,
            "detection_mode": trigger.get("detection_mode") or self.config.detector.detection_mode,
            "monitored_scope": {
                "monitored_roots": self.config.monitored_roots,
                "excluded_paths": self.config.excluded_paths,
                "excluded_extensions": self.config.excluded_extensions,
                "follow_symlinks_or_reparse": self.config.follow_symlinks_or_reparse,
            },
            "trigger_summary": {
                "alert_id": trigger.get("alert_id", "LEGACY_OR_IMPORTED_CASE"),
                "alert_description": trigger.get(
                    "alert_description",
                    "Historical/imported evidence case without live Phase 1 trigger.json.",
                ),
                "rationale": trigger.get("rationale", "Trigger rationale unavailable (imported/legacy case)."),
                "applied_thresholds": trigger.get("applied_thresholds", {}),
                "contributing_event_ids": trigger.get("contributing_event_ids", []),
                "contributing_file_identities": trigger.get("contributing_file_identities", []),
                "contributing_events": trigger.get("contributing_events", []),
                "queue_stats_at_trigger": trigger.get("queue_stats_at_trigger", {}),
            },
            "evidence_inventory": manifest.get("artifacts", []),
            "legacy_hashes": manifest.get("hashes", {}),
            "provider_outcomes": manifest.get("providers", []),
            "memory_acquisition_summary": mem_doc,
            "verification_summary": verification,
            "chronology_summary": {
                "reference_timestamp_utc": timeline.get("reference_timestamp_utc"),
                "reference_event_id": timeline.get("reference_event_id"),
                "total_events": timeline.get("total_events", 0),
                "events": timeline.get("events", []),
            },
            "findings": findings_doc.get("findings", []),
            "measured_timings": timings_summary,
            "limitations": limitations,
            "advisory_recommendations": recommendations,
        }

        json_rel = "incident_report.json" if revision == 1 else f"incident_report_v{revision}.json"
        atomic_write_json(cpath / json_rel, canonical_report)

        html_rel: Optional[str] = None
        if self.config.generate_html_report:
            html_rel = "incident_report.html" if revision == 1 else f"incident_report_v{revision}.html"
            html_bytes = self._render_html(canonical_report).encode("utf-8")
            atomic_write_bytes(cpath / html_rel, html_bytes)

        pdf_rel: Optional[str] = None
        if self.config.generate_pdf_report:
            pdf_rel = "incident_report.pdf" if revision == 1 else f"incident_report_v{revision}.pdf"
            self._render_pdf(cpath / pdf_rel, canonical_report)

        return {
            "case_id": case_id,
            "report_revision": revision,
            "json_report": str(cpath / json_rel),
            "html_report": str(cpath / html_rel) if html_rel else None,
            "pdf_report": str(cpath / pdf_rel) if pdf_rel else None,
            "canonical_report": canonical_report,
        }

    def _read_json(self, path: Path) -> Optional[Dict[str, Any]]:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def _build_recommendations(
        self,
        verification: Dict[str, Any],
        findings: List[Dict[str, Any]],
        mem_doc: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        recs: List[Dict[str, str]] = []
        v_status = str(verification.get("overall_status", "UNVERIFIED"))
        if v_status != "VERIFIED":
            recs.append(
                {
                    "priority": "IMMEDIATE",
                    "basis": f"Integrity verification returned status '{v_status}'.",
                    "recommendation": (
                        "Do not rely on derived timeline conclusions until artifact hash mismatches or missing files "
                        "in verification.json are investigated."
                    ),
                }
            )
        else:
            recs.append(
                {
                    "priority": "STANDARD",
                    "basis": "All captured case artifacts passed independent SHA-256 verification.",
                    "recommendation": (
                        "Preserve the finalized case directory on read-only or external analyst storage to maintain chain of custody."
                    ),
                }
            )

        for f in findings:
            act = f.get("recommended_analyst_action")
            if act:
                recs.append(
                    {
                        "priority": str(f.get("severity", "INFO")),
                        "basis": f"Finding {f.get('finding_id')} ({f.get('rule_id')})",
                        "recommendation": str(act),
                    }
                )

        m_status = str(mem_doc.get("status", "UNAVAILABLE"))
        if m_status in ("UNAVAILABLE", "FAILED", "TIMEOUT"):
            recs.append(
                {
                    "priority": "ADVISORY",
                    "basis": f"Memory acquisition status was '{m_status}'.",
                    "recommendation": (
                        "If volatile memory analysis is required by lab protocol, acquire a host/hypervisor memory snapshot "
                        "via VMware (.vmem) or an administrator-elevated WinPmem session and import it with explicit provenance."
                    ),
                }
            )
        return recs

    def _render_html(self, report: Dict[str, Any]) -> str:
        e = lambda val: html.escape(str(val if val is not None else "N/A"), quote=True)
        ver = report.get("verification_summary", {})
        v_status = str(ver.get("overall_status", "UNVERIFIED"))
        v_banner_color = "#166534" if v_status == "VERIFIED" else "#991b1b"
        v_banner_bg = "#dcfce7" if v_status == "VERIFIED" else "#fee2e2"

        trig = report.get("trigger_summary", {})
        contrib_rows = []
        for ce in trig.get("contributing_events", []):
            meas = ce.get("measurement") or {}
            contrib_rows.append(
                f"<tr>"
                f"<td><code>{e(ce.get('event_id'))}</code></td>"
                f"<td>{e(ce.get('event_type'))}</td>"
                f"<td class='path'>{e(ce.get('normalized_path') or ce.get('src_path'))}</td>"
                f"<td class='num'>{e(meas.get('shannon_entropy'))}</td>"
                f"<td class='num'>{e(meas.get('bytes_examined'))} / {e(meas.get('file_size'))}</td>"
                f"<td>{e(meas.get('read_state'))}</td>"
                f"<td>{e(meas.get('qualification_reason'))}</td>"
                f"</tr>"
            )
        contrib_html = "".join(contrib_rows) or "<tr><td colspan='7'>No live Phase 1 contributing file events recorded (imported/legacy case).</td></tr>"

        prov_rows = []
        for p in report.get("provider_outcomes", []):
            errs = "; ".join(str(x) for x in p.get("errors", [])) or "None"
            prov_rows.append(
                f"<tr>"
                f"<td>{e(p.get('provider_name'))}</td>"
                f"<td><strong>{e(p.get('status'))}</strong></td>"
                f"<td class='num'>{e(p.get('record_count'))}</td>"
                f"<td class='num'>{e(p.get('duration_ms'))} ms</td>"
                f"<td>{e(p.get('tool_or_provider_version'))}</td>"
                f"<td>{e(errs)}</td>"
                f"</tr>"
            )
        prov_html = "".join(prov_rows) or "<tr><td colspan='6'>No provider metadata blocks recorded (legacy manifest schema).</td></tr>"

        ver_rows = []
        for item in ver.get("items", []):
            ver_rows.append(
                f"<tr>"
                f"<td><code>{e(item.get('relative_path'))}</code></td>"
                f"<td><strong>{e(item.get('status'))}</strong></td>"
                f"<td class='num'>{e(item.get('actual_size'))}</td>"
                f"<td><code>{e(item.get('expected_sha256'))}</code></td>"
                f"<td><code>{e(item.get('actual_sha256'))}</code></td>"
                f"</tr>"
            )
        ver_html = "".join(ver_rows) or "<tr><td colspan='5'>No artifact verification items available.</td></tr>"

        find_rows = []
        for f in report.get("findings", []):
            supp = ", ".join(str(x) for x in f.get("supporting_event_ids", [])[:8])
            if len(f.get("supporting_event_ids", [])) > 8:
                supp += f" (+{len(f['supporting_event_ids']) - 8} more)"
            find_rows.append(
                f"<div class='card'>"
                f"<h4>[{e(f.get('severity'))}] {e(f.get('title'))} <small>({e(f.get('rule_id'))} v{e(f.get('rule_version'))} | {e(f.get('confidence'))})</small></h4>"
                f"<p><strong>Observed Rationale:</strong> {e(f.get('rationale'))}</p>"
                f"<p><strong>Supporting Event IDs:</strong> <code>{e(supp)}</code> | <strong>Artifacts:</strong> <code>{e(', '.join(f.get('supporting_artifacts', [])))}</code></p>"
                f"<p><strong>Methodological Limitation:</strong> {e(f.get('limitations'))}</p>"
                f"</div>"
            )
        find_html = "".join(find_rows) or "<p>No rule findings triggered.</p>"

        tl_events = report.get("chronology_summary", {}).get("events", [])
        tl_rows = []
        for ev in tl_events[:80]:
            el = ev.get("elapsed_seconds_from_reference")
            el_str = f"{el:+.4f}s" if isinstance(el, (int, float)) else "UNKNOWN"
            tl_rows.append(
                f"<tr>"
                f"<td><code>{e(ev.get('event_id'))}</code></td>"
                f"<td class='num'><code>{e(el_str)}</code></td>"
                f"<td><code>{e(ev.get('effective_sort_timestamp_utc'))}</code><br/><small>{e(ev.get('timestamp_basis'))}</small></td>"
                f"<td>{e(ev.get('event_type'))}</td>"
                f"<td><code>{e(ev.get('source_artifact'))}</code></td>"
                f"<td class='path'>{e(ev.get('summary'))}</td>"
                f"</tr>"
            )
        tl_note = ""
        if len(tl_events) > 80:
            tl_note = f"<p><em>Showing first 80 of {len(tl_events)} normalized events. Full chronology is preserved in timeline.json and timeline.csv.</em></p>"

        rec_items = []
        for r in report.get("advisory_recommendations", []):
            rec_items.append(
                f"<li><strong>[{e(r.get('priority'))}]</strong> ({e(r.get('basis'))}): {e(r.get('recommendation'))}</li>"
            )
        rec_html = "".join(rec_items)

        lim_items = "".join(f"<li>{e(lim)}</li>" for lim in report.get("limitations", []))
        timings = report.get("measured_timings", {})

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Crypto-Tripwire Incident Report - {e(report.get('case_id'))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1f2937; margin: 24px auto; max-width: 1100px; padding: 0 20px; line-height: 1.5; }}
  h1 {{ color: #0f172a; border-bottom: 3px solid #1e3a8a; padding-bottom: 8px; }}
  h2 {{ color: #1e3a8a; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; margin-top: 28px; }}
  .banner {{ padding: 12px 16px; border-radius: 6px; background: {v_banner_bg}; color: {v_banner_color}; font-weight: 600; margin: 16px 0; border: 1px solid {v_banner_color}; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; table-layout: fixed; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; vertical-align: top; overflow-wrap: break-word; word-break: break-word; }}
  th {{ background: #1e3a8a; color: #ffffff; }}
  td.num {{ text-align: right;  }}
  .card {{ border: 1px solid #cbd5e1; border-left: 4px solid #1e3a8a; border-radius: 4px; padding: 12px 16px; margin: 12px 0; background: #f8fafc; }}
  .card h4 {{ margin: 0 0 8px 0; color: #0f172a; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; background: #f1f5f9; padding: 14px; border-radius: 6px; font-size: 13.5px; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; background: #e2e8f0; padding: 1px 4px; border-radius: 3px; }}
</style>
</head>
<body>
  <h1>Crypto-Tripwire Automated Incident Report</h1>
  <div class="banner">
    Evidence Integrity Status: {e(v_status)}
    (Checked: {e(ver.get('checked_count', 0))}, Verified: {e(ver.get('verified_count', 0))}, Mismatches: {e(ver.get('mismatch_count', 0))}, Missing: {e(ver.get('missing_count', 0))})
  </div>

  <h2>1. Case Identity &amp; Observation Scope</h2>
  <div class="meta-grid">
    <div><strong>Case ID:</strong> <code>{e(report.get('case_id'))}</code> (Revision {e(report.get('report_revision'))})</div>
    <div><strong>Generated UTC:</strong> <code>{e(report.get('generated_utc'))}</code></div>
    <div><strong>Application / Schema Version:</strong> v{e(report.get('application_version'))} / Schema {e(report.get('schema_version'))}</div>
    <div><strong>Phase 1 Detection Mode:</strong> <code>{e(report.get('detection_mode'))}</code></div>
    <div><strong>Observation Mode:</strong> <code>{e(report.get('observation_mode'))}</code></div>
    <div><strong>Configuration Digest:</strong> <code>{e(report.get('configuration_digest'))}</code></div>
    <div><strong>Monitored Roots:</strong> <code>{e(', '.join(report.get('monitored_scope', {}).get('monitored_roots', [])))}</code></div>
    <div><strong>Manifest SHA-256:</strong> <code>{e(ver.get('manifest_sha256'))}</code></div>
  </div>

  <h2>2. Phase 1 Trigger Rationale &amp; Contributing File Events</h2>
  <p><strong>Alert ID:</strong> <code>{e(trig.get('alert_id'))}</code> - {e(trig.get('rationale'))}</p>
  <table>
    <thead>
      <tr>
        <th style="width:10%">Event ID</th>
        <th style="width:9%">Type</th>
        <th style="width:27%">Normalized Path</th>
        <th style="width:10%">Entropy</th>
        <th style="width:12%">Bytes Examined</th>
        <th style="width:10%">Read State</th>
        <th style="width:22%">Qualification Reason</th>
      </tr>
    </thead>
    <tbody>{contrib_html}</tbody>
  </table>

  <h2>3. Phase 2 Volatile Capture Provider Outcomes &amp; Measured Timings</h2>
  <div class="meta-grid">
    <div><strong>First Contributing Event UTC:</strong> <code>{e(timings.get('first_contributing_event_utc'))}</code></div>
    <div><strong>Trigger UTC:</strong> <code>{e(timings.get('trigger_utc'))}</code></div>
    <div><strong>Trigger-to-Capture Start Delay:</strong> <code>{e(timings.get('trigger_to_capture_delay_ms'))} ms</code></div>
    <div><strong>Total Capture Duration:</strong> <code>{e(timings.get('capture_duration_ms'))} ms</code></div>
  </div>
  <table>
    <thead>
      <tr>
        <th style="width:18%">Provider</th>
        <th style="width:14%">Status</th>
        <th style="width:10%">Records</th>
        <th style="width:12%">Duration</th>
        <th style="width:18%">Provider Version</th>
        <th style="width:28%">Errors / Notes</th>
      </tr>
    </thead>
    <tbody>{prov_html}</tbody>
  </table>

  <h2>4. Independent SHA-256 Artifact Verification</h2>
  <p><small>{e(ver.get('trust_boundary_statement'))}</small></p>
  <table>
    <thead>
      <tr>
        <th style="width:18%">Artifact Path</th>
        <th style="width:12%">Status</th>
        <th style="width:10%">Size (B)</th>
        <th style="width:30%">Expected SHA-256</th>
        <th style="width:30%">Recomputed SHA-256</th>
      </tr>
    </thead>
    <tbody>{ver_html}</tbody>
  </table>

  <h2>5. Phase 3 Evidence-Linked Rule Findings</h2>
  {find_html}

  <h2>6. Reconstructed Chronology (Reference: {e(report.get('chronology_summary', {}).get('reference_timestamp_utc'))})</h2>
  {tl_note}
  <table>
    <thead>
      <tr>
        <th style="width:12%">Event ID</th>
        <th style="width:10%">Offset (s)</th>
        <th style="width:20%">Effective UTC &amp; Basis</th>
        <th style="width:15%">Event Type</th>
        <th style="width:13%">Source Artifact</th>
        <th style="width:30%">Observed Summary</th>
      </tr>
    </thead>
    <tbody>{''.join(tl_rows)}</tbody>
  </table>

  <h2>7. Methodological &amp; Operational Limitations</h2>
  <ul>{lim_items}</ul>

  <h2>8. Advisory Analyst Recommendations (Separated from Observed Facts)</h2>
  <ul>{rec_html}</ul>
</body>
</html>
"""

    def _render_pdf(self, pdf_path: Path, report: Dict[str, Any]) -> None:
        """
        Render a multi-page PDF incident report using ReportLab Platypus (with safe XML escaping,
        word-wrapping cells, and pagination) or a minimal deterministic PDF writer fallback if ReportLab is absent.
        """
        try:
            from reportlab.lib import colors  # type: ignore
            from reportlab.lib.pagesizes import A4  # type: ignore
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # type: ignore
            from reportlab.lib.units import mm  # type: ignore
            from reportlab.platypus import (  # type: ignore
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
            import io

            buf = io.BytesIO()
            doc = SimpleDocTemplate(
                buf,
                pagesize=A4,
                leftMargin=15 * mm,
                rightMargin=15 * mm,
                topMargin=16 * mm,
                bottomMargin=16 * mm,
                title=f"Crypto-Tripwire Incident Report - {report.get('case_id')}",
            )
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "CTTitle",
                parent=styles["Heading1"],
                fontSize=16,
                leading=20,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=8,
            )
            h2_style = ParagraphStyle(
                "CTH2",
                parent=styles["Heading2"],
                fontSize=12,
                leading=15,
                textColor=colors.HexColor("#1e3a8a"),
                spaceBefore=12,
                spaceAfter=6,
            )
            body_style = ParagraphStyle(
                "CTBody",
                parent=styles["BodyText"],
                fontSize=9,
                leading=12,
                wordWrap="CJK",
            )
            cell_style = ParagraphStyle(
                "CTCell",
                parent=styles["BodyText"],
                fontSize=7.5,
                leading=9.5,
                wordWrap="CJK",
            )
            header_cell_style = ParagraphStyle(
                "CTHeaderCell",
                parent=cell_style,
                textColor=colors.white,
                fontName="Helvetica-Bold",
            )

            def p_safe(val: Any, st=cell_style) -> Paragraph:
                txt = xml_escape(str(val if val is not None else "N/A"))
                return Paragraph(txt, st)

            story: List[Any] = []
            story.append(p_safe(f"Crypto-Tripwire Automated Incident Report - {report.get('case_id')}", title_style))

            ver = report.get("verification_summary", {})
            v_status = str(ver.get("overall_status", "UNVERIFIED"))
            story.append(
                p_safe(
                    f"Integrity Verification Status: {v_status} "
                    f"(Checked: {ver.get('checked_count', 0)}, Verified: {ver.get('verified_count', 0)}, "
                    f"Mismatches: {ver.get('mismatch_count', 0)}, Missing: {ver.get('missing_count', 0)})",
                    body_style,
                )
            )
            story.append(Spacer(1, 6))

            # Section 1: Case Metadata
            story.append(p_safe("1. Case Identity & Observation Scope", h2_style))
            timings = report.get("measured_timings", {})
            meta_rows = [
                [p_safe("Field", header_cell_style), p_safe("Observed Value", header_cell_style)],
                [p_safe("Case ID / Revision"), p_safe(f"{report.get('case_id')} (v{report.get('report_revision')})")],
                [p_safe("Generated UTC"), p_safe(report.get("generated_utc"))],
                [p_safe("App / Schema Version"), p_safe(f"v{report.get('application_version')} / Schema {report.get('schema_version')}")],
                [p_safe("Phase 1 Detection Mode"), p_safe(report.get("detection_mode"))],
                [p_safe("Observation Mode"), p_safe(report.get("observation_mode"))],
                [p_safe("Configuration Digest"), p_safe(report.get("configuration_digest"))],
                [p_safe("Monitored Roots"), p_safe(", ".join(report.get("monitored_scope", {}).get("monitored_roots", [])))],
                [p_safe("Trigger UTC"), p_safe(timings.get("trigger_utc"))],
                [p_safe("Trigger-to-Capture Delay (ms)"), p_safe(timings.get("trigger_to_capture_delay_ms"))],
                [p_safe("Total Capture Duration (ms)"), p_safe(timings.get("capture_duration_ms"))],
            ]
            t_meta = Table(meta_rows, colWidths=[55 * mm, 125 * mm], repeatRows=1)
            t_meta.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ]
                )
            )
            story.append(t_meta)

            # Section 2: Trigger & Contributing Events
            story.append(p_safe("2. Phase 1 Trigger Rationale & Contributing File Events", h2_style))
            trig = report.get("trigger_summary", {})
            story.append(p_safe(f"Rationale: {trig.get('rationale')}", body_style))
            story.append(Spacer(1, 4))

            c_rows = [
                [
                    p_safe("Event ID", header_cell_style),
                    p_safe("Type", header_cell_style),
                    p_safe("Normalized Path", header_cell_style),
                    p_safe("Entropy", header_cell_style),
                    p_safe("State", header_cell_style),
                    p_safe("Qualification Reason", header_cell_style),
                ]
            ]
            for ce in trig.get("contributing_events", []):
                meas = ce.get("measurement") or {}
                c_rows.append(
                    [
                        p_safe(ce.get("event_id")),
                        p_safe(ce.get("event_type")),
                        p_safe(ce.get("normalized_path") or ce.get("src_path")),
                        p_safe(meas.get("shannon_entropy")),
                        p_safe(meas.get("read_state")),
                        p_safe(meas.get("qualification_reason")),
                    ]
                )
            if len(c_rows) == 1:
                c_rows.append([p_safe("N/A"), p_safe("N/A"), p_safe("Imported/legacy case"), p_safe("N/A"), p_safe("N/A"), p_safe("N/A")])
            t_contrib = Table(c_rows, colWidths=[18 * mm, 16 * mm, 56 * mm, 18 * mm, 22 * mm, 50 * mm], repeatRows=1)
            t_contrib.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(t_contrib)

            # Section 3: Provider Outcomes & Verification
            story.append(p_safe("3. Phase 2 Provider Outcomes & Integrity Verification", h2_style))
            p_rows = [
                [
                    p_safe("Provider", header_cell_style),
                    p_safe("Status", header_cell_style),
                    p_safe("Records", header_cell_style),
                    p_safe("Duration (ms)", header_cell_style),
                    p_safe("Version", header_cell_style),
                    p_safe("Errors / Notes", header_cell_style),
                ]
            ]
            for p in report.get("provider_outcomes", []):
                errs = "; ".join(str(x) for x in p.get("errors", [])) or p.get("notes") or "None"
                p_rows.append(
                    [
                        p_safe(p.get("provider_name")),
                        p_safe(p.get("status")),
                        p_safe(p.get("record_count")),
                        p_safe(p.get("duration_ms")),
                        p_safe(p.get("tool_or_provider_version")),
                        p_safe(errs),
                    ]
                )
            if len(p_rows) == 1:
                p_rows.append([p_safe("legacy"), p_safe("IMPORTED"), p_safe("-"), p_safe("-"), p_safe("1.0"), p_safe("Legacy manifest schema")])
            t_prov = Table(p_rows, colWidths=[30 * mm, 24 * mm, 16 * mm, 22 * mm, 30 * mm, 58 * mm], repeatRows=1)
            t_prov.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(t_prov)
            story.append(Spacer(1, 6))

            v_rows = [
                [
                    p_safe("Artifact", header_cell_style),
                    p_safe("Status", header_cell_style),
                    p_safe("Size (B)", header_cell_style),
                    p_safe("Expected SHA-256", header_cell_style),
                    p_safe("Recomputed SHA-256", header_cell_style),
                ]
            ]
            for it in ver.get("items", []):
                v_rows.append(
                    [
                        p_safe(it.get("relative_path")),
                        p_safe(it.get("status")),
                        p_safe(it.get("actual_size")),
                        p_safe(it.get("expected_sha256")),
                        p_safe(it.get("actual_sha256")),
                    ]
                )
            t_ver = Table(v_rows, colWidths=[38 * mm, 22 * mm, 16 * mm, 52 * mm, 52 * mm], repeatRows=1)
            t_ver.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(t_ver)

            # Section 4: Findings
            story.append(p_safe("4. Phase 3 Evidence-Linked Rule Findings", h2_style))
            for f in report.get("findings", []):
                story.append(
                    p_safe(
                        f"[{f.get('severity')}] {f.get('title')} ({f.get('rule_id')} v{f.get('rule_version')} | {f.get('confidence')})",
                        body_style,
                    )
                )
                story.append(p_safe(f"Rationale: {f.get('rationale')}", cell_style))
                story.append(
                    p_safe(
                        f"Supporting Events: {', '.join(f.get('supporting_event_ids', [])[:10])} | "
                        f"Artifacts: {', '.join(f.get('supporting_artifacts', []))}",
                        cell_style,
                    )
                )
                story.append(p_safe(f"Limitation: {f.get('limitations')}", cell_style))
                story.append(Spacer(1, 4))

            # Section 5: Reconstructed Chronology (bounded table in PDF, full in JSON/CSV)
            story.append(p_safe("5. Reconstructed Event Timeline (Excerpt)", h2_style))
            tl_events = report.get("chronology_summary", {}).get("events", [])
            tl_rows = [
                [
                    p_safe("Event ID", header_cell_style),
                    p_safe("Offset (s)", header_cell_style),
                    p_safe("Effective UTC", header_cell_style),
                    p_safe("Type", header_cell_style),
                    p_safe("Summary", header_cell_style),
                ]
            ]
            for ev in tl_events[:40]:
                el = ev.get("elapsed_seconds_from_reference")
                el_s = f"{el:+.4f}s" if isinstance(el, (int, float)) else "UNKNOWN"
                tl_rows.append(
                    [
                        p_safe(ev.get("event_id")),
                        p_safe(el_s),
                        p_safe(ev.get("effective_sort_timestamp_utc")),
                        p_safe(ev.get("event_type")),
                        p_safe(ev.get("summary")),
                    ]
                )
            t_tl = Table(tl_rows, colWidths=[28 * mm, 20 * mm, 38 * mm, 35 * mm, 59 * mm], repeatRows=1)
            t_tl.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(t_tl)

            # Section 6: Limitations & Recommendations
            story.append(p_safe("6. Limitations & Advisory Analyst Recommendations", h2_style))
            for lim in report.get("limitations", []):
                story.append(p_safe(f"• Limitation: {lim}", cell_style))
            story.append(Spacer(1, 4))
            for rec in report.get("advisory_recommendations", []):
                story.append(
                    p_safe(
                        f"• [{rec.get('priority')}] ({rec.get('basis')}): {rec.get('recommendation')}",
                        cell_style,
                    )
                )

            doc.build(story)
            atomic_write_bytes(pdf_path, buf.getvalue())
        except ImportError:
            # Minimal pure-Python PDF 1.4 generator fallback so zero external dependencies can still emit a readable PDF
            lines = [
                f"Crypto-Tripwire Incident Report - {report.get('case_id')}",
                f"Generated UTC: {report.get('generated_utc')}",
                f"Phase 1 Detection Mode: {report.get('detection_mode')} | Mode: {report.get('observation_mode')}",
                f"Integrity Status: {report.get('verification_summary', {}).get('overall_status')}",
                f"Trigger Rationale: {report.get('trigger_summary', {}).get('rationale')}",
                f"Total Timeline Events: {report.get('chronology_summary', {}).get('total_events')}",
                f"Findings Count: {len(report.get('findings', []))}",
            ]
            for f in report.get("findings", []):
                lines.append(f"- [{f.get('severity')}] {f.get('rule_id')}: {f.get('title')}")
            pdf_bytes = self._build_minimal_pdf(lines)
            atomic_write_bytes(pdf_path, pdf_bytes)

    @staticmethod
    def _build_minimal_pdf(lines: List[str]) -> bytes:
        def esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

        content_ops = ["BT", "/F1 10 Tf", "50 780 Td", "14 TL"]
        for line in lines[:45]:
            content_ops.append(f"({esc(line[:95])}) Tj T*")
        content_ops.append("ET")
        stream_data = "\n".join(content_ops).encode("latin-1", errors="replace")

        objs: List[bytes] = []
        objs.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
        objs.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
        objs.append(
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
        )
        objs.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
        objs.append(
            f"5 0 obj << /Length {len(stream_data)} >> stream\n".encode("ascii")
            + stream_data
            + b"\nendstream endobj\n"
        )

        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for o in objs:
            offsets.append(len(out))
            out.extend(o)
        xref_pos = len(out)
        out.extend(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode("ascii"))
        for off in offsets[1:]:
            out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
        out.extend(
            f"trailer << /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
        )
        return bytes(out)
