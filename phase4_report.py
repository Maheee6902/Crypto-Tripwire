"""Phase 4: Automated Escaped JSON, HTML, and A4 PDF Incident Report Generator."""

from __future__ import annotations

import html
import json
from pathlib import Path

from phase2_capture import utc_now, write_json_atomic

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
except ImportError:
    A4 = None


def _render_html(report: dict) -> str:
    esc = html.escape
    v = report["verification"]
    f_rows = "".join(
        f"<tr><td><b>{esc(f['rule_id'])}</b></td><td>{esc(f['severity'])}</td>"
        f"<td><b>{esc(f['title'])}</b><br><small>{esc(f['detail'])}</small></td></tr>"
        for f in report["findings"]["findings"]
    )
    a_rows = "".join(
        f"<tr><td><code>{esc(it['file'])}</code></td><td><b>{esc(it['status'])}</b></td>"
        f"<td><code>{esc(str(it['actual']))}</code></td></tr>"
        for it in v["items"]
    )
    t_rows = "".join(
        f"<tr><td><code>{esc(str(e['timestamp_utc']))}</code></td><td>{esc(e['source'])}</td>"
        f"<td>{esc(e['summary'])}</td></tr>"
        for e in report["timeline"]["events"]
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Crypto-Tripwire Incident Report - {esc(report['case_id'])}</title>
<style>
  body {{ font-family: Segoe UI, Arial, sans-serif; margin: 28px; color: #1f2937; background: #f8fafc; }}
  .box {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 18px; margin-bottom: 18px; }}
  h1 {{ margin: 0 0 6px; color: #0f172a; }}
  h2 {{ margin: 0 0 10px; color: #0369a1; font-size: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 8px; text-align: left; }}
  th {{ background: #f1f5f9; }}
  .ok {{ color: #15803d; font-weight: 700; }}
  .bad {{ color: #b91c1c; font-weight: 700; }}
</style>
</head>
<body>
  <div class="box">
    <h1>Crypto-Tripwire Automated DFIR Incident Report</h1>
    <p><b>Case ID:</b> {esc(report['case_id'])} &nbsp;|&nbsp;
       <b>Generated (UTC):</b> {esc(report['generated_utc'])} &nbsp;|&nbsp;
       <b>Integrity:</b> <span class="{'ok' if v['overall_status']=='VERIFIED' else 'bad'}">{esc(v['overall_status'])}</span></p>
  </div>
  <div class="box">
    <h2>1. Deterministic Rule Findings (Phase 3)</h2>
    <table><thead><tr><th>Rule</th><th>Severity</th><th>Finding</th></tr></thead><tbody>{f_rows}</tbody></table>
  </div>
  <div class="box">
    <h2>2. SHA-256 Chain-of-Custody Verification (Phase 2 &amp; 3)</h2>
    <table><thead><tr><th>Artifact</th><th>Status</th><th>SHA-256 Digest</th></tr></thead><tbody>{a_rows}</tbody></table>
  </div>
  <div class="box">
    <h2>3. Chronological UTC Incident Timeline</h2>
    <table><thead><tr><th>UTC Timestamp</th><th>Source</th><th>Event</th></tr></thead><tbody>{t_rows}</tbody></table>
  </div>
</body>
</html>"""


def _render_pdf(pdf_path: Path, report: dict) -> None:
    if A4 is None:
        pdf_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return
    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"<b>Crypto-Tripwire Incident Report: {html.escape(report['case_id'])}</b>", styles["Title"]),
        Spacer(1, 8),
        Paragraph(
            f"Generated (UTC): {html.escape(report['generated_utc'])} | "
            f"Integrity: <b>{html.escape(report['verification']['overall_status'])}</b>",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("<b>1. Forensic Rule Findings</b>", styles["Heading2"]),
    ]
    for f in report["findings"]["findings"]:
        story.append(
            Paragraph(
                f"<b>{html.escape(f['rule_id'])} [{html.escape(f['severity'])}]</b> - "
                f"{html.escape(f['title'])}: {html.escape(f['detail'])}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 4))
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>2. SHA-256 Verified Artifacts</b>", styles["Heading2"]))
    for it in report["verification"]["items"]:
        story.append(
            Paragraph(
                f"{html.escape(it['file'])} -> <b>{html.escape(it['status'])}</b> ({html.escape(str(it['actual']))})",
                styles["Normal"],
            )
        )
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>3. Chronological UTC Timeline</b>", styles["Heading2"]))
    for e in report["timeline"]["events"]:
        story.append(
            Paragraph(
                f"[{html.escape(str(e['timestamp_utc']))}] <b>{html.escape(e['source'])}</b>: {html.escape(e['summary'])}",
                styles["Normal"],
            )
        )
    doc.build(story)


def run_phase4_report(case_dir: Path, phase3_results: dict) -> dict:
    """Generate incident_report.json, incident_report.html, and incident_report.pdf."""
    print(f"[PHASE 4 | phase4_report.py] Generating JSON, HTML, and PDF incident reports...")
    trigger = json.loads((case_dir / "trigger.json").read_text(encoding="utf-8"))
    report = {
        "case_id": trigger["case_id"],
        "generated_utc": utc_now(),
        "trigger": trigger,
        "verification": phase3_results["verification"],
        "findings": phase3_results["findings"],
        "timeline": phase3_results["timeline"],
    }

    json_path = case_dir / "incident_report.json"
    html_path = case_dir / "incident_report.html"
    pdf_path = case_dir / "incident_report.pdf"

    write_json_atomic(json_path, report)
    html_path.write_text(_render_html(report), encoding="utf-8")
    _render_pdf(pdf_path, report)

    print(f"[PHASE 4 | phase4_report.py] Reports ready:")
    print(f"    HTML : {html_path}")
    print(f"    PDF  : {pdf_path}")
    print(f"    JSON : {json_path}")
    return {"json": str(json_path), "html": str(html_path), "pdf": str(pdf_path)}
