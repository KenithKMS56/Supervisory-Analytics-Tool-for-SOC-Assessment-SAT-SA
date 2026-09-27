"""Supervisory report generation module: self-contained HTML, PDF (ReportLab), and CSV."""

import csv
from pathlib import Path

import duckdb
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


class ReportGenerator:
    """Generates self-contained supervisory assessment reports in HTML, PDF, and CSV."""

    def __init__(self, duckdb_store: DuckDBStore, sqlite_store: SQLiteStore):
        self.duckdb_store = duckdb_store
        self.sqlite_store = sqlite_store

    def generate_entity_html(self, entity_id: str, output_path: Path | str) -> Path:
        """Generate self-contained HTML supervisory assessment report."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        cur = self.sqlite_store.conn.cursor()
        cur.execute(
            "SELECT run_id, config_hash, period, created_at FROM runs ORDER BY created_at DESC LIMIT 1"
        )
        run_row = cur.fetchone()
        run_id = run_row["run_id"] if run_row else "UNKNOWN"
        config_hash = run_row["config_hash"] if run_row else "N/A"
        period = run_row["period"] if run_row else "2026-Q1"
        gen_time = run_row["created_at"] if run_row else "N/A"

        # Entity info
        df_ent = self.duckdb_store.query(f"SELECT * FROM entity WHERE entity_id = '{entity_id}'")
        ent_info = (
            df_ent.to_dicts()[0]
            if not df_ent.is_empty()
            else {"name": entity_id, "sector": "N/A", "size_band": "N/A"}
        )

        # Score
        cur.execute(
            "SELECT risk_index, risk_band, distinct_rules_triggered FROM entity_scores WHERE entity_id = ? AND run_id = ?",
            (entity_id, run_id),
        )
        score_row = cur.fetchone()
        risk_index = score_row["risk_index"] if score_row else 0.0
        risk_band = score_row["risk_band"] if score_row else "Low"

        # Domain scores
        cur.execute(
            "SELECT domain, score FROM domain_scores WHERE entity_id = ? AND run_id = ?",
            (entity_id, run_id),
        )
        dom_scores = [dict(r) for r in cur.fetchall()]

        # Findings
        cur.execute(
            "SELECT rule_id, domain, severity, score, title, rationale, examiner_check FROM findings WHERE entity_id = ? AND run_id = ? ORDER BY score DESC",
            (entity_id, run_id),
        )
        findings = [dict(r) for r in cur.fetchall()]

        # Review queue sample
        cur.execute(
            "SELECT record_type, record_id, severity, score, selection_reason, is_random FROM review_queue WHERE entity_id = ? AND run_id = ? LIMIT 15",
            (entity_id, run_id),
        )
        queue_items = [dict(r) for r in cur.fetchall()]

        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Supervisory SOC Assessment Report - {entity_id}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; color: #1e293b; line-height: 1.5; }}
    h1 {{ color: #0f172a; margin-bottom: 5px; }}
    .subtitle {{ color: #64748b; font-size: 1.1rem; margin-bottom: 25px; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
    .badge-crit {{ background: #fee2e2; color: #b91c1c; border: 1px solid #b91c1c; }}
    .badge-mod {{ background: #fef9c3; color: #854d0e; border: 1px solid #854d0e; }}
    .badge-low {{ background: #dcfce7; color: #15803d; border: 1px solid #15803d; }}
    .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9rem; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }}
    th {{ background: #f1f5f9; }}
    .footer {{ margin-top: 50px; padding-top: 15px; border-top: 2px solid #e2e8f0; font-size: 0.85rem; color: #64748b; text-align: center; }}
    .notice {{ color: #b91c1c; font-weight: 700; margin-bottom: 5px; }}
  </style>
</head>
<body>
  <h1>Supervisory Assessment Report: {ent_info.get("name")} ({entity_id})</h1>
  <div class="subtitle">Review Period: {period} | Sector: {str(ent_info.get("sector") or "N/A").upper()} | Size Band: {ent_info.get("size_band")}</div>

  <div class="card">
    <h2>Supervisory Risk Executive Summary</h2>
    <p style="font-size: 1.25rem; margin: 10px 0;">
      Entity Supervisory Risk Index: <strong>{risk_index:.1f} / 100</strong> &nbsp;
      <span class="badge {"badge-crit" if risk_index >= 50 else ("badge-mod" if risk_index >= 25 else "badge-low")}">{risk_band}</span>
    </p>
    <p>This assessment synthesized operational SOC telemetry across 8 supervisory domains, evaluating deterministic execution gaps and negative space patterns without AI/ML models.</p>
  </div>

  <div class="card">
    <h3>NCIIPC 8-Domain Capability Scores</h3>
    <table>
      <thead><tr><th>Capability Domain</th><th>Supervisory Risk Score</th><th>Status</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td><strong>{d['domain']}</strong></td><td>{d['score']:.1f}</td><td><span class='badge {'badge-crit' if d['score'] >= 50 else ('badge-mod' if d['score'] >= 25 else 'badge-low')}'>{'Elevated Concern' if d['score'] >= 50 else ('Moderate Concern' if d['score'] >= 25 else 'Satisfactory')}</span></td></tr>" for d in dom_scores)}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Top Flagged Indicators Requiring Supervisory Review ({len(findings)})</h3>
    <table>
      <thead><tr><th>Rule</th><th>Severity</th><th>Score</th><th>Finding Rationale</th><th>Suggested Examiner Verification</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td><strong>{f['rule_id']}</strong></td><td><span class='badge {'badge-crit' if f['severity'] == 'critical' else ('badge-mod' if f['severity'] == 'high' else 'badge-low')}'>{f['severity'].upper()}</span></td><td>{f['score']}</td><td><strong>{f['title']}</strong><br><small>{f['rationale']}</small></td><td style='font-size: 0.85rem;'>{f['examiner_check']}</td></tr>" for f in findings)}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3>Sample Review Queue Extract ({len(queue_items)} items)</h3>
    <table>
      <thead><tr><th>Record ID</th><th>Type</th><th>Severity</th><th>Selection Reason</th><th>Class</th></tr></thead>
      <tbody>
        {"".join(f"<tr><td><code>{q['record_id']}</code></td><td>{q['record_type']}</td><td>{q['severity']}</td><td>{q['selection_reason']}</td><td>{'Random Control' if q['is_random'] else 'Top-Risk'}</td></tr>" for q in queue_items)}
      </tbody>
    </table>
  </div>

  <div class="footer">
    <div class="notice">Indicators requiring supervisory review; not a compliance determination.</div>
    <div>Run ID: {run_id} | Config Hash: {config_hash} | Generated: {gen_time} | Fully Offline / Air-Gapped Engine</div>
  </div>
</body>
</html>
"""
        path.write_text(html_content, encoding="utf-8")
        return path

    def generate_entity_pdf(self, entity_id: str, output_path: Path | str) -> Path:
        """Generate supervisory PDF report using ReportLab (pure Python)."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(path), pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
        )
        styles = getSampleStyleSheet()
        elements = []

        # Title
        title_style = ParagraphStyle(
            name="TitleStyle",
            parent=styles["Heading1"],
            fontSize=18,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )
        elements.append(Paragraph(f"SAT-SA Supervisory Assessment: {entity_id}", title_style))
        elements.append(
            Paragraph(
                "National Critical Information Infrastructure Protection Centre (NCIIPC)",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 12))

        # Notice
        notice_style = ParagraphStyle(
            name="NoticeStyle",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#b91c1c"),
            fontName="Helvetica-Bold",
        )
        elements.append(
            Paragraph(
                "Indicators requiring supervisory review; not a compliance determination.",
                notice_style,
            )
        )
        elements.append(Spacer(1, 16))

        # Query scores
        cur = self.sqlite_store.conn.cursor()
        cur.execute("SELECT run_id, config_hash FROM runs ORDER BY created_at DESC LIMIT 1")
        run_row = cur.fetchone()
        run_id = run_row["run_id"] if run_row else ""

        cur.execute(
            "SELECT risk_index, risk_band FROM entity_scores WHERE entity_id = ? AND run_id = ?",
            (entity_id, run_id),
        )
        score_row = cur.fetchone()
        risk_index = score_row["risk_index"] if score_row else 0.0
        risk_band = score_row["risk_band"] if score_row else "Low"

        # Summary box
        elements.append(
            Paragraph(
                f"<b>Supervisory Risk Index:</b> {risk_index:.1f} / 100 ({risk_band})",
                styles["Heading2"],
            )
        )
        elements.append(Spacer(1, 10))

        # Domain scores table
        cur.execute(
            "SELECT domain, score FROM domain_scores WHERE entity_id = ? AND run_id = ?",
            (entity_id, run_id),
        )
        dom_rows = [["Supervisory Capability Domain", "Score (0-100)"]]
        for r in cur.fetchall():
            dom_rows.append([r["domain"], f"{r['score']:.1f}"])

        t = Table(dom_rows, colWidths=[350, 150])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ]
            )
        )
        elements.append(t)
        elements.append(Spacer(1, 16))

        # Top findings
        cur.execute(
            "SELECT rule_id, severity, score, title FROM findings WHERE entity_id = ? AND run_id = ? LIMIT 10",
            (entity_id, run_id),
        )
        f_rows = [["Rule", "Severity", "Score", "Title"]]
        for r in cur.fetchall():
            f_rows.append(
                [
                    r["rule_id"],
                    r["severity"].upper(),
                    f"{r['score']:.1f}",
                    Paragraph(r["title"][:50], styles["Normal"]),
                ]
            )

        elements.append(Paragraph("<b>Key Findings Requiring Examination:</b>", styles["Heading3"]))
        tf = Table(f_rows, colWidths=[60, 70, 50, 320])
        tf.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ]
            )
        )
        elements.append(tf)

        doc.build(elements)
        return path

    def export_findings_csv(self, output_path: Path | str) -> Path:
        """Export all findings to CSV."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        cur = self.sqlite_store.conn.cursor()
        cur.execute("SELECT * FROM findings ORDER BY score DESC")
        rows = cur.fetchall()

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if rows:
                writer.writerow(rows[0].keys())
                for r in rows:
                    writer.writerow(list(r))
        return path

    def export_queue_csv(self, output_path: Path | str) -> Path:
        """Export review queue items to CSV."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        cur = self.sqlite_store.conn.cursor()
        cur.execute("SELECT * FROM review_queue ORDER BY score DESC")
        rows = cur.fetchall()

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if rows:
                writer.writerow(rows[0].keys())
                for r in rows:
                    writer.writerow(list(r))
        return path

    def export_metrics_csv(self, output_path: Path | str) -> Path:
        """Export computed metrics to CSV."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            df = self.duckdb_store.query(
                "SELECT * FROM metrics_daily ORDER BY entity_id, date, metric_name"
            )
            df.write_csv(str(path))
        except (duckdb.Error, OSError):
            # Fallback if metrics table empty or different schema
            with open(path, "w", newline="", encoding="utf-8") as f:
                f.write("entity_id,date,metric_name,metric_value\n")
        return path

    def generate_portfolio_html(self, output_path: Path | str) -> Path:
        """Generate self-contained portfolio summary assessment report."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        cur = self.sqlite_store.conn.cursor()
        cur.execute(
            "SELECT run_id, config_hash, period, created_at FROM runs ORDER BY created_at DESC LIMIT 1"
        )
        run_row = cur.fetchone()
        run_id = run_row["run_id"] if run_row else "UNKNOWN"
        config_hash = run_row["config_hash"] if run_row else "N/A"
        period = run_row["period"] if run_row else "2026-Q1"
        gen_time = run_row["created_at"] if run_row else "N/A"

        cur.execute(
            """
            SELECT e.entity_id, e.risk_index, e.risk_band, e.distinct_rules_triggered
            FROM entity_scores e
            WHERE e.run_id = ?
            ORDER BY e.risk_index DESC
        """,
            (run_id,),
        )
        entities = [dict(r) for r in cur.fetchall()]

        # Query all domain scores for this run
        cur.execute(
            """
            SELECT entity_id, domain, score
            FROM domain_scores
            WHERE run_id = ?
        """,
            (run_id,),
        )
        domain_rows = cur.fetchall()
        domain_map: dict[str, dict[str, float]] = {}
        domains = set()
        for r in domain_rows:
            eid = r["entity_id"]
            dom = r["domain"]
            domains.add(dom)
            domain_map.setdefault(eid, {})[dom] = float(r["score"])

        sorted_domains = sorted(domains)

        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>SAT-SA Portfolio Supervisory Assessment Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; color: #1e293b; line-height: 1.5; }}
    h1 {{ color: #0f172a; margin-bottom: 5px; }}
    .subtitle {{ color: #64748b; font-size: 1.1rem; margin-bottom: 25px; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
    .badge-crit {{ background: #fee2e2; color: #b91c1c; border: 1px solid #b91c1c; }}
    .badge-mod {{ background: #fef9c3; color: #854d0e; border: 1px solid #854d0e; }}
    .badge-low {{ background: #dcfce7; color: #15803d; border: 1px solid #15803d; }}
    .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9rem; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }}
    th {{ background: #f1f5f9; }}
    .footer {{ margin-top: 50px; padding-top: 15px; border-top: 2px solid #e2e8f0; font-size: 0.85rem; color: #64748b; text-align: center; }}
    .notice {{ color: #b91c1c; font-weight: 700; margin-bottom: 5px; }}
  </style>
</head>
<body>
  <h1>National SOC Supervisory Portfolio Report</h1>
  <div class="subtitle">Period: {period} | Total Critical Sector Entities Assessed: {
            len(entities)
        }</div>

  <div class="card">
    <h2>Entity Risk Ranking Summary</h2>
    <table>
      <thead>
        <tr>
          <th>Entity ID</th>
          <th>Risk Index (0-100)</th>
          <th>Risk Band</th>
          <th>Rules Triggered</th>
          {"".join(f"<th>{d}</th>" for d in sorted_domains)}
        </tr>
      </thead>
      <tbody>
        {
            "".join(
                f"<tr><td><strong>{e['entity_id']}</strong></td>"
                f"<td>{e['risk_index']:.1f}</td>"
                f"<td><span class='badge {'badge-crit' if e['risk_index'] >= 50 else ('badge-mod' if e['risk_index'] >= 25 else 'badge-low')}'>{e['risk_band']}</span></td>"
                f"<td>{e['distinct_rules_triggered']}</td>"
                + "".join(
                    f"<td style='background: {'#fee2e2' if domain_map.get(e['entity_id'], {}).get(d, 0) >= 50 else ('#fef9c3' if domain_map.get(e['entity_id'], {}).get(d, 0) >= 25 else '#ffffff')}'>{domain_map.get(e['entity_id'], {}).get(d, 0.0):.1f}</td>"
                    for d in sorted_domains
                )
                + "</tr>"
                for e in entities
            )
        }
      </tbody>
    </table>
  </div>

  <div class="footer">
    <div class="notice">Indicators requiring supervisory review; not a compliance determination.</div>
    <div>Run ID: {run_id} | Config Hash: {config_hash} | Generated: {
            gen_time
        } | Fully Offline / Air-Gapped Engine</div>
  </div>
</body>
</html>
"""
        path.write_text(html, encoding="utf-8")
        return path
