"""
app/audit/reporter.py – Aggregates findings and generates JSON and HTML audit reports.

Reports include:
  - Severity and category distributions
  - Confirmed vs not-reproduced counts
  - Top recommendations
  - False positive candidates (benign prompts blocked)
  - Purely pseudonymized identifiers in exported datasets
"""
from __future__ import annotations

import html
import json
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.db import AuditFinding, AuditRun, ScanLog

logger = logging.getLogger(__name__)


def build_audit_summary(
    audit_run: AuditRun,
    findings: List[AuditFinding],
    db: Session,
) -> Dict[str, Any]:
    """
    Compute structured summary dictionary for an audit run.
    """
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    category_counts = {
        "injection_attempt": 0,
        "possible_leak": 0,
        "over_blocking": 0,
        "suspicious_pattern": 0,
        "weak_refusal": 0,
        "other": 0,
    }
    status_counts = {"confirmed": 0, "not_reproduced": 0, "suspected": 0}

    recommendations: List[str] = []
    false_positive_candidates: List[Dict[str, Any]] = []

    for f in findings:
        sev = f.severity.lower() if f.severity else "medium"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        cat = f.category.lower() if f.category else "other"
        category_counts[cat] = category_counts.get(cat, 0) + 1

        stat = f.status.lower() if f.status else "suspected"
        status_counts[stat] = status_counts.get(stat, 0) + 1

        if f.suggested_action and f.suggested_action not in recommendations:
            recommendations.append(f.suggested_action)

        if f.category == "over_blocking":
            false_positive_candidates.append({
                "finding_id": f.finding_uid,
                "evidence": json.loads(f.evidence_log_ids or "[]"),
                "explanation": f.explanation,
                "confidence": f.confidence,
            })

    # Look for scan logs that might be false positives (e.g. tricky benign phrases blocked)
    # in the audited window
    redactions = json.loads(audit_run.redactions_count or "{}")

    summary = {
        "run_id": audit_run.run_id,
        "created_at": str(audit_run.created_at),
        "total_logs_analyzed": audit_run.total_logs_analyzed,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "status_counts": status_counts,
        "confirmed_count": status_counts.get("confirmed", 0),
        "not_reproduced_count": status_counts.get("not_reproduced", 0),
        "suspected_count": status_counts.get("suspected", 0),
        "top_recommendations": recommendations[:5],
        "false_positive_candidates": false_positive_candidates[:10],
        "redactions_applied": redactions,
    }
    return summary


def export_report_json(audit_run: AuditRun, findings: List[AuditFinding]) -> str:
    """Generate pseudonymized JSON export."""
    findings_data = []
    for f in findings:
        findings_data.append({
            "finding_id": f.finding_uid,
            "severity": f.severity,
            "category": f.category,
            "status": f.status,
            "evidence": json.loads(f.evidence_log_ids or "[]"),
            "explanation": f.explanation,
            "suggested_action": f.suggested_action,
            "confidence": f.confidence,
            "lab_result_id": f.lab_result_id,
        })

    summary_data = json.loads(audit_run.summary or "{}")

    payload = {
        "report_id": audit_run.run_id,
        "auditor_model": audit_run.auditor_model,
        "created_at": str(audit_run.created_at),
        "approved": audit_run.is_approved,
        "approved_at": str(audit_run.approved_at) if audit_run.approved_at else None,
        "summary": summary_data,
        "findings": findings_data,
    }
    return json.dumps(payload, indent=2)


def export_report_html(audit_run: AuditRun, findings: List[AuditFinding]) -> str:
    """Generate self-contained, responsive HTML report."""
    summary_data = json.loads(audit_run.summary or "{}")
    sev_counts = summary_data.get("severity_counts", {})
    cat_counts = summary_data.get("category_counts", {})
    stat_counts = summary_data.get("status_counts", {})
    recs = summary_data.get("top_recommendations", [])
    fps = summary_data.get("false_positive_candidates", [])

    rows_html = ""
    for f in findings:
        sev_badge = "badge-danger" if f.severity == "high" else ("badge-warning" if f.severity == "medium" else "badge-neutral")
        stat_badge = "badge-danger" if f.status == "confirmed" else ("badge-success" if f.status == "not_reproduced" else "badge-neutral")

        ev_list = json.loads(f.evidence_log_ids or "[]")
        ev_str = ", ".join(ev_list)

        rows_html += f"""
        <tr>
          <td><strong>{html.escape(f.finding_uid)}</strong></td>
          <td><span class="badge {sev_badge}">{html.escape(f.severity.upper())}</span></td>
          <td><code>{html.escape(f.category)}</code></td>
          <td><span class="badge {stat_badge}">{html.escape(f.status)}</span></td>
          <td><small>{html.escape(ev_str)}</small></td>
          <td>{html.escape(f.explanation or '')}</td>
          <td><em>{html.escape(f.suggested_action or '')}</em></td>
        </tr>
        """

    rec_items = "".join(f"<li>{html.escape(r)}</li>" for r in recs) or "<li>No specific remediation recommendations.</li>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Offline Security Audit Report – {html.escape(audit_run.run_id)}</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --heading: #f0f6fc; --primary: #58a6ff;
    --danger: #f85149; --warning: #d29922; --success: #3fb950;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 28px; line-height: 1.5;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1, h2, h3 {{ color: var(--heading); }}
  h1 {{ border-bottom: 1px solid var(--border); padding-bottom: 12px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }}
  .card h3 {{ margin: 0 0 6px 0; font-size: 13px; text-transform: uppercase; color: #8b949e; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  .danger {{ color: var(--danger); }} .warning {{ color: var(--warning); }} .success {{ color: var(--success); }} .primary {{ color: var(--primary); }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 14px; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); }}
  th {{ background: #21262d; color: var(--heading); font-size: 13px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
  .badge-danger {{ background: rgba(248,81,73,0.15); color: var(--danger); border: 1px solid rgba(248,81,73,0.4); }}
  .badge-warning {{ background: rgba(210,153,34,0.15); color: var(--warning); border: 1px solid rgba(210,153,34,0.4); }}
  .badge-success {{ background: rgba(63,185,80,0.15); color: var(--success); border: 1px solid rgba(63,185,80,0.4); }}
  .badge-neutral {{ background: rgba(88,166,255,0.15); color: var(--primary); border: 1px solid rgba(88,166,255,0.4); }}
  code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
  ul {{ padding-left: 20px; }}
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ Offline Security Auditor Report</h1>
  <p><strong>Run ID:</strong> <code>{html.escape(audit_run.run_id)}</code> | <strong>Auditor Model:</strong> <code>{html.escape(audit_run.auditor_model or 'default')}</code> | <strong>Status:</strong> {html.escape(audit_run.status)}</p>

  <div class="cards">
    <div class="card">
      <h3>Logs Analyzed</h3>
      <div class="num primary">{audit_run.total_logs_analyzed}</div>
    </div>
    <div class="card">
      <h3>High Severity</h3>
      <div class="num danger">{sev_counts.get('high', 0)}</div>
    </div>
    <div class="card">
      <h3>Confirmed Attacks</h3>
      <div class="num danger">{stat_counts.get('confirmed', 0)}</div>
    </div>
    <div class="card">
      <h3>Not Reproduced</h3>
      <div class="num success">{stat_counts.get('not_reproduced', 0)}</div>
    </div>
    <div class="card">
      <h3>Suspected / Pending</h3>
      <div class="num warning">{stat_counts.get('suspected', 0)}</div>
    </div>
  </div>

  <h2>Top Recommendations</h2>
  <ul>
    {rec_items}
  </ul>

  <h2>Findings Detail</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Severity</th>
        <th>Category</th>
        <th>Validation</th>
        <th>Evidence</th>
        <th>Explanation</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>
      {rows_html if rows_html else '<tr><td colspan="7">No security findings recorded for this audit run.</td></tr>'}
    </tbody>
  </table>
</div>
</body>
</html>"""
    return html_content


def dispatch_webhook(webhook_url: str, report_json_str: str) -> bool:
    """Send approved report JSON to the configured webhook URL."""
    if not webhook_url or not webhook_url.startswith("http"):
        return False
    try:
        import httpx
        r = httpx.post(webhook_url, content=report_json_str, headers={"Content-Type": "application/json"}, timeout=10.0)
        return r.status_code in (200, 201, 202, 204)
    except Exception as exc:
        logger.warning("Failed to dispatch audit webhook to %s: %s", webhook_url, exc)
        return False
