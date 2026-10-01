"""Supervisory report generation module: self-contained HTML, PDF (ReportLab), and CSV."""

import csv
import html
import json
from pathlib import Path
from typing import Any

import duckdb
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from satsa import FINDING_NOTICE
from satsa.peers.anomaly_scan import format_value
from satsa.report.pdf_charts import (
    CRITICAL_THRESHOLD,
    MODERATE_THRESHOLD,
    band_bar_chart,
    band_for,
    band_for_label,
    domain_weakness_chart,
    risk_gauge,
)
from satsa.report.pdf_layout import (
    CONTENT_W,
    INK,
    PANEL,
    RULE,
    STYLES,
    RunMeta,
    badge,
    build_pdf,
    comparison_block,
    data_table,
    esc,
    finding_card,
    section,
    technical_detail,
)
from satsa.report.plain_language import (
    CRIT_BG,
    CRIT_FG,
    LOW_BG,
    LOW_FG,
    MOD_BG,
    MOD_FG,
    action_for,
    headline,
)
from satsa.scoring.scorer import band_tier
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

# Fixed display order of the eight NCIIPC capability domains (as on the entity page).
DOMAIN_ORDER = [
    "Threat Detection",
    "Investigation",
    "Escalation",
    "Incident Response",
    "Security Operations",
    "Governance and Oversight",
    "Operational Discipline",
    "Cyber Resilience",
]
DOMAIN_ABBR = {
    "Threat Detection": "TD",
    "Investigation": "INV",
    "Escalation": "ESC",
    "Incident Response": "IR",
    "Security Operations": "SO",
    "Governance and Oversight": "GOV",
    "Operational Discipline": "OD",
    "Cyber Resilience": "CR",
}


class ReportNotFoundError(LookupError):
    """The requested run, entity, finding or report data does not exist (HTTP 404)."""

    def __init__(self, what: str):
        super().__init__(f"{what} not found")
        self.what = what


def _hex(color: colors.Color) -> str:
    return "#" + color.hexval()[2:]


_BADGE_CLASS = {"critical": "badge-crit", "moderate": "badge-mod", "low": "badge-low"}


def _tier_bg(risk_band: str) -> colors.Color:
    """Cell background for an entity's stored risk band."""
    return colors.HexColor({"critical": CRIT_BG, "moderate": MOD_BG, "low": LOW_BG}[band_tier(risk_band)])


def _band_bg(score: float) -> colors.Color:
    if score >= CRITICAL_THRESHOLD:
        return colors.HexColor(CRIT_BG)
    if score >= MODERATE_THRESHOLD:
        return colors.HexColor(MOD_BG)
    return colors.HexColor(LOW_BG)


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
        df_ent = self.duckdb_store.query("SELECT * FROM entity WHERE entity_id = ?", [entity_id])
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

        # Exploratory leads: shown apart from the findings, never scored (DECISIONS.md ADR-007).
        lead_rows = "".join(
            "<tr><td>{kind}</td><td>{label}</td><td>{value}</td><td>{baseline}</td><td><small>{why}</small></td></tr>".format(
                kind="Peer outlier" if s["kind"] == "peer_outlier" else "Time shift",
                label=html.escape(s["label"]),
                value=format_value(s["value"], s["detail"].get("scale", "per_unit")),
                baseline=format_value(s["baseline"], s["detail"].get("scale", "per_unit")),
                why=html.escape(s["rationale"]),
            )
            for s in self.sqlite_store.get_anomaly_signals(run_id, entity_id)
        )
        leads_card = (
            f"""
  <div class="card">
    <h3>Exploratory Leads (not scored)</h3>
    <p style="font-size: 0.85rem;">Rates at this entity that stand out from its peers or shifted within the period. No rule tests most of them and they are not part of the risk index. Ask the entity what explains each one.</p>
    <table>
      <thead><tr><th>Kind</th><th>Indicator</th><th>Entity value</th><th>Baseline</th><th>Why it was flagged</th></tr></thead>
      <tbody>{lead_rows}</tbody>
    </table>
  </div>
"""
            if lead_rows
            else ""
        )

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
      <span class="badge {_BADGE_CLASS[band_tier(risk_band)]}">{risk_band}</span>
    </p>
    <p>This assessment analysed the entity's periodic SOC submission across 8 supervisory domains, evaluating deterministic execution gaps and negative space patterns without AI/ML models.</p>
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
{leads_card}
  <div class="footer">
    <div class="notice">Indicators requiring supervisory review; not a compliance determination.</div>
    <div>Run ID: {run_id} | Config Hash: {config_hash} | Generated: {gen_time} | Fully Offline / Air-Gapped Engine</div>
  </div>
</body>
</html>
"""
        path.write_text(html_content, encoding="utf-8")
        return path

    # --- PDF reports (A4; shared layout in pdf_layout.py, charts in pdf_charts.py) ---

    def resolve_run(self, run_id: str | None = None) -> RunMeta:
        """Return the given run (default: latest); raise ReportNotFoundError if absent."""
        cur = self.sqlite_store.conn.cursor()
        if run_id is None:
            cur.execute(
                "SELECT run_id, config_hash, period, created_at FROM runs ORDER BY created_at DESC LIMIT 1"
            )
        else:
            cur.execute(
                "SELECT run_id, config_hash, period, created_at FROM runs WHERE run_id = ?",
                (run_id,),
            )
        row = cur.fetchone()
        if row is None:
            raise ReportNotFoundError("Assessment run")
        return RunMeta(
            run_id=row["run_id"],
            config_hash=row["config_hash"],
            period=row["period"],
            created_at=str(row["created_at"]),
        )

    def _load_findings(self, where: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        """Stored findings (with parsed peer comparison and evidence rows), highest score first.

        `where` is always a constant clause from this module; values go in `params`.
        """
        cur = self.sqlite_store.conn.cursor()
        cur.execute(
            "SELECT finding_id, run_id, entity_id, rule_id, rule_version, domain, severity, score, "
            "confidence, title, rationale, peer_comparison_json, benign_explanations_json, "
            f"examiner_check, created_at FROM findings WHERE {where} "
            "ORDER BY score DESC, finding_id",
            params,
        )
        findings = [dict(r) for r in cur.fetchall()]
        for f in findings:
            try:
                pc = json.loads(f.get("peer_comparison_json") or "{}")
            except json.JSONDecodeError:
                pc = {}
            f["peer_comparison"] = pc if isinstance(pc, dict) else {}
            try:
                benign = json.loads(f.get("benign_explanations_json") or "[]")
            except json.JSONDecodeError:
                benign = []
            f["benign_explanations"] = benign if isinstance(benign, list) else []
            cur.execute(
                "SELECT record_type, record_id FROM finding_evidences WHERE finding_id = ? ORDER BY rowid",
                (f["finding_id"],),
            )
            f["evidences"] = [dict(r) for r in cur.fetchall()]
        return findings

    def _entity_info(self, entity_id: str) -> dict[str, Any]:
        try:
            df = self.duckdb_store.query("SELECT * FROM entity WHERE entity_id = ?", [entity_id])
        except duckdb.Error:
            return {}
        return df.to_dicts()[0] if not df.is_empty() else {}

    @staticmethod
    def _ordered_domains(scores: dict[str, float]) -> list[str]:
        known = [d for d in DOMAIN_ORDER if d in scores]
        return known + sorted(d for d in scores if d not in DOMAIN_ORDER)

    def generate_entity_pdf(
        self, entity_id: str, output_path: Path | str, run_id: str | None = None
    ) -> Path:
        """CSE supervisory report: risk gauge, domain chart and layered findings (A4)."""
        path = Path(output_path)
        meta = self.resolve_run(run_id)
        cur = self.sqlite_store.conn.cursor()

        cur.execute(
            "SELECT risk_index, risk_band, distinct_rules_triggered FROM entity_scores WHERE entity_id = ? AND run_id = ?",
            (entity_id, meta.run_id),
        )
        score_row = cur.fetchone()
        if score_row is None:
            raise ReportNotFoundError("Entity")
        risk_index = float(score_row["risk_index"])
        ent_info = self._entity_info(entity_id)

        cur.execute(
            "SELECT domain, score FROM domain_scores WHERE entity_id = ? AND run_id = ?",
            (entity_id, meta.run_id),
        )
        dom_scores = {r["domain"]: float(r["score"]) for r in cur.fetchall()}
        findings = self._load_findings("entity_id = ? AND run_id = ?", (entity_id, meta.run_id))

        band = band_for_label(score_row["risk_band"])
        counts = {a: 0 for a in ("ESCALATE", "MONITOR", "NOTE")}
        for f in findings:
            counts[action_for(f["severity"]).label] += 1

        st = STYLES
        story: list[Flowable] = [
            Paragraph("CSE SUPERVISORY ASSESSMENT", st["tech_title"]),
            Paragraph(esc(f"{ent_info.get('name') or entity_id} ({entity_id})"), st["h1"]),
            Paragraph(
                esc(
                    f"Review period {meta.period}  |  Sector: {str(ent_info.get('sector') or 'N/A').upper()}"
                    f"  |  Size band: {ent_info.get('size_band') or 'N/A'}"
                ),
                st["lead"],
            ),
            Spacer(1, 10),
        ]
        big = ParagraphStyle(
            "risk_big",
            parent=st["h1"],
            fontSize=30,
            leading=34,
            textColor=band.text,
        )
        summary = Table(
            [
                [
                    [
                        Paragraph("SUPERVISORY RISK INDEX", st["tech_title"]),
                        Paragraph(
                            f"{risk_index:.1f}<font size=12 color='#64748b'> / 100</font>", big
                        ),
                    ],
                    [
                        badge(f"{band.name} BAND", "#ffffff", _hex(band.text), size=9, width=120),
                        Spacer(1, 5),
                        Paragraph(
                            esc(
                                f"{len(findings)} finding(s) from {score_row['distinct_rules_triggered']} "
                                f"rule(s): {counts['ESCALATE']} to escalate, {counts['MONITOR']} to "
                                f"monitor, {counts['NOTE']} to note."
                            ),
                            st["body"],
                        ),
                    ],
                ]
            ],
            colWidths=[170, CONTENT_W - 170],
        )
        summary.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                    ("BOX", (0, 0), (-1, -1), 0.7, RULE),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ]
            )
        )
        story += [summary, Spacer(1, 6), risk_gauge(risk_index, CONTENT_W)]
        story.append(
            Paragraph(
                "Where this CSE sits against the existing SAT-SA bands: below 25 low, 25 to 49.9 "
                "moderate, 50 and above critical.",
                st["caption"],
            )
        )

        domains = self._ordered_domains(dom_scores)
        if domains:
            story += section(
                "Capability domains",
                "One bar per NCIIPC capability domain; a longer bar means more supervisory "
                "concern in that area.",
            )
            story.append(
                band_bar_chart(domains, [dom_scores[d] for d in domains], CONTENT_W, label_w=135)
            )

        story += section(
            "Findings requiring examination",
            "Each finding starts with the recommended action and a plain-language summary. The "
            "shaded Technical Detail box beneath it holds the supervisor's record: rule, "
            "rationale, measured values and evidence IDs.",
        )
        if findings:
            for f in findings:
                story += [
                    finding_card(f, f["peer_comparison"], f["evidences"], show_entity=False),
                    Spacer(1, 9),
                ]
        else:
            story.append(
                Paragraph("No rule findings were recorded for this CSE in this run.", st["body"])
            )

        if domains:
            story += section("Appendix: domain scores")
            story.append(
                data_table(
                    ["Capability domain", "Score (0-100)", "Band"],
                    [[d, f"{dom_scores[d]:.1f}", band_for(dom_scores[d]).name] for d in domains],
                    [260, 110, CONTENT_W - 370],
                )
            )

        return build_pdf(path, story, meta, f"CSE Report  |  {entity_id}  |  {meta.period}")

    def generate_portfolio_pdf(self, output_path: Path | str, run_id: str | None = None) -> Path:
        """Portfolio supervisory report: cover callout, ranking and domain charts, escalations."""
        path = Path(output_path)
        meta = self.resolve_run(run_id)
        cur = self.sqlite_store.conn.cursor()
        cur.execute(
            "SELECT entity_id, risk_index, risk_band, distinct_rules_triggered FROM entity_scores "
            "WHERE run_id = ? ORDER BY risk_index DESC, entity_id",
            (meta.run_id,),
        )
        entities = [dict(r) for r in cur.fetchall()]
        if not entities:
            raise ReportNotFoundError("Report data")
        cur.execute(
            "SELECT entity_id, domain, score FROM domain_scores WHERE run_id = ?", (meta.run_id,)
        )
        domain_map: dict[str, dict[str, float]] = {}
        for r in cur.fetchall():
            domain_map.setdefault(r["entity_id"], {})[r["domain"]] = float(r["score"])
        findings = self._load_findings("run_id = ?", (meta.run_id,))
        cur.execute(
            "SELECT entity_id, check_name, severity, count, details FROM dq_issues "
            "ORDER BY count DESC, entity_id, check_name"
        )
        dq_rows = [dict(r) for r in cur.fetchall()]

        total = len(entities)
        # Same "requires action" definition as the portfolio dashboard: any band above low.
        attention = sum(1 for e in entities if band_tier(e["risk_band"]) != "low")
        band_counts = {"CRITICAL": 0, "MODERATE": 0, "LOW": 0}
        for e in entities:
            band_counts[band_tier(e["risk_band"]).upper()] += 1
        escalations = [f for f in findings if action_for(f["severity"]).label == "ESCALATE"]
        n_monitor = sum(1 for f in findings if action_for(f["severity"]).label == "MONITOR")
        n_note = len(findings) - len(escalations) - n_monitor

        st = STYLES
        story: list[Flowable] = [Spacer(1, 18)]
        story += self._portfolio_cover(
            meta, total, attention, band_counts, findings, escalations, dq_rows
        )
        story.append(PageBreak())

        story += section(
            "Entity risk ranking",
            "Each bar is one CSE's overall supervisory risk index (0-100), highest first. Dashed "
            "lines mark the moderate (25) and critical (50) thresholds.",
        )
        chunk = 30
        for start in range(0, total, chunk):
            part = entities[start : start + chunk]
            if total > chunk:
                story.append(
                    Paragraph(
                        f"Entities {start + 1}&#8211;{start + len(part)} of {total}", st["cell_b"]
                    )
                )
            story.append(
                band_bar_chart(
                    [e["entity_id"] for e in part], [e["risk_index"] for e in part], CONTENT_W
                )
            )
            story.append(Spacer(1, 6))

        all_domains = self._ordered_domains(
            {d: 0.0 for scores in domain_map.values() for d in scores}
        )
        if all_domains:
            weak_rows = [
                (
                    d,
                    sum(
                        1
                        for e in entities
                        if domain_map.get(e["entity_id"], {}).get(d, 0.0) >= CRITICAL_THRESHOLD
                    ),
                    total,
                )
                for d in all_domains
            ]
            story.append(
                KeepTogether(
                    [
                        *section(
                            "Where is the sector weak?",
                            "For each capability domain: how many CSEs score in the critical "
                            "band (50+) for that domain.",
                        ),
                        domain_weakness_chart(weak_rows, CONTENT_W),
                    ]
                )
            )

        story.append(PageBreak())
        story += section(
            "Findings requiring escalation",
            "Critical-severity findings across the portfolio, highest score first. "
            f"A further {n_monitor} finding(s) are rated MONITOR and {n_note} NOTE; they appear "
            "in each CSE report.",
        )
        if escalations:
            for f in escalations:
                story += [finding_card(f, f["peer_comparison"], f["evidences"]), Spacer(1, 9)]
        else:
            story.append(Paragraph("No critical-severity findings in this run.", st["body"]))

        story += section("Data-quality limitations")
        if dq_rows:
            story.append(
                Paragraph(
                    "Issues recorded when submissions were ingested (not scoped to a single "
                    "assessment run). Findings for the affected CSEs should be read with these in "
                    "mind.",
                    st["small"],
                )
            )
            story.append(Spacer(1, 4))
            for r in dq_rows:
                story.append(
                    Paragraph(
                        esc(
                            f"{r['count']} record(s) for {r['entity_id']} were flagged by the "
                            f"'{r['check_name']}' check ({r['severity']}): {r['details']}"
                        ),
                        st["body"],
                        bulletText="•",
                    )
                )
        else:
            story.append(Paragraph("No data-quality issues recorded for this period.", st["body"]))

        story += section(
            "Appendix: portfolio data table",
            "Domain columns: "
            + "; ".join(f"{DOMAIN_ABBR.get(d, d)} = {d}" for d in all_domains)
            + ". Shading follows the same bands as the charts.",
        )
        fixed = [52, 36, 60, 32]
        dom_w = (CONTENT_W - sum(fixed)) / max(len(all_domains), 1)
        rows: list[list[Any]] = []
        extra: list[tuple[Any, ...]] = []
        for i, e in enumerate(entities, start=1):
            row: list[Any] = [
                e["entity_id"],
                f"{e['risk_index']:.1f}",
                band_for_label(e["risk_band"]).name,
                str(e["distinct_rules_triggered"]),
            ]
            extra.append(("BACKGROUND", (1, i), (2, i), _tier_bg(e["risk_band"])))
            for j, d in enumerate(all_domains):
                score = domain_map.get(e["entity_id"], {}).get(d)
                row.append("-" if score is None else f"{score:.0f}")
                if score is not None:
                    extra.append(("BACKGROUND", (4 + j, i), (4 + j, i), _band_bg(score)))
            rows.append(row)
        story.append(
            data_table(
                ["Entity", "Risk", "Band", "Rules", *[DOMAIN_ABBR.get(d, d) for d in all_domains]],
                rows,
                [*fixed, *([dom_w] * len(all_domains))],
                extra,
            )
        )

        return build_pdf(path, story, meta, f"Portfolio Report  |  {meta.period}", cover=True)

    def _portfolio_cover(
        self,
        meta: RunMeta,
        total: int,
        attention: int,
        band_counts: dict[str, int],
        findings: list[dict[str, Any]],
        escalations: list[dict[str, Any]],
        dq_rows: list[dict[str, Any]],
    ) -> list[Flowable]:
        st = STYLES
        white = colors.white
        hero_num = ParagraphStyle(
            "hero_num", fontName="Helvetica-Bold", fontSize=64, leading=70, textColor=white
        )
        hero_txt = ParagraphStyle(
            "hero_txt", fontName="Helvetica-Bold", fontSize=17, leading=22, textColor=white
        )
        hero_sub = ParagraphStyle(
            "hero_sub",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#cbd5e1"),
        )
        hero = Table(
            [
                [Paragraph(f"{attention}<font size=30> of {total}</font>", hero_num)],
                [Paragraph("Critical Sector Entities require supervisory attention", hero_txt)],
                [
                    Paragraph(
                        "Classified above the low band (by risk index, or by a critical or high severity finding), the "
                        "same threshold the SAT-SA portfolio dashboard uses.",
                        hero_sub,
                    )
                ],
            ],
            colWidths=[CONTENT_W],
        )
        hero.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), INK),
                    ("LINEBEFORE", (0, 0), (0, -1), 6, colors.HexColor(CRIT_FG)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 26),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 26),
                    ("TOPPADDING", (0, 0), (-1, 0), 26),
                    ("BOTTOMPADDING", (0, -1), (-1, -1), 26),
                ]
            )
        )

        tile_specs = [
            ("CRITICAL", "Risk index 50+", CRIT_BG, CRIT_FG),
            ("MODERATE", "Risk index 25 to 49.9", MOD_BG, MOD_FG),
            ("LOW", "Risk index below 25", LOW_BG, LOW_FG),
        ]
        tiles_row: list[Any] = []
        tile_styles: list[tuple[Any, ...]] = []
        for i, (name, rng, bg, fg) in enumerate(tile_specs):
            num = ParagraphStyle(
                f"tile_{name}",
                fontName="Helvetica-Bold",
                fontSize=30,
                leading=34,
                textColor=colors.HexColor(fg),
            )
            lab = ParagraphStyle(
                f"tile_l_{name}",
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=12,
                textColor=colors.HexColor(fg),
            )
            tiles_row.append(
                [
                    Paragraph(str(band_counts[name]), num),
                    Paragraph(f"{name} BAND", lab),
                    Paragraph(rng, st["small"]),
                ]
            )
            tile_styles += [
                ("BACKGROUND", (i, 0), (i, 0), colors.HexColor(bg)),
                ("BOX", (i, 0), (i, 0), 1.2, colors.HexColor(fg)),
            ]
        gap = 10
        tile_w = (CONTENT_W - 2 * gap) / 3
        tiles = Table(
            [[tiles_row[0], "", tiles_row[1], "", tiles_row[2]]],
            colWidths=[tile_w, gap, tile_w, gap, tile_w],
        )
        tile_styles = [
            (cmd, (c0 * 2, r0), (c1 * 2, r1), *rest)
            for cmd, (c0, r0), (c1, r1), *rest in tile_styles
        ]
        tiles.setStyle(
            TableStyle(
                [
                    ("LEFTPADDING", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    *tile_styles,
                ]
            )
        )

        facts = data_table(
            ["Key fact", "Value"],
            [
                ["Findings recommended for escalation (critical severity)", str(len(escalations))],
                [
                    "All findings in this run",
                    f"{len(findings)} across {len({f['rule_id'] for f in findings})} rules",
                ],
                ["Data-quality issues recorded at ingestion", str(len(dq_rows))],
                ["Assessment run", meta.run_id],
                ["Run created", meta.created_at],
            ],
            [300, CONTENT_W - 300],
        )
        return [
            Paragraph("NCIIPC  |  SUPERVISORY PORTFOLIO REPORT", st["tech_title"]),
            Spacer(1, 4),
            Paragraph("National SOC Supervisory Portfolio Report", st["h1"]),
            Paragraph(
                esc(
                    f"Assessment period {meta.period}  |  {total} Critical Sector Entities assessed"
                ),
                st["lead"],
            ),
            Spacer(1, 18),
            hero,
            Spacer(1, 14),
            tiles,
            Spacer(1, 16),
            facts,
            Spacer(1, 14),
            Paragraph("How to read this report", st["h3"]),
            Paragraph(
                "Charts come first: the entity ranking shows which CSEs need attention, and the "
                "domain chart shows where the sector as a whole is weak. Each escalation finding "
                "then gives a recommended action and a one-sentence plain-language summary, "
                "followed by a shaded Technical Detail box for supervisors. Every number comes "
                "from the stored assessment run named in the footer.",
                st["body"],
            ),
        ]

    def generate_finding_pdf(self, finding_id: str, output_path: Path | str) -> Path:
        """Single-finding evidence report: one clear verdict, then the technical record."""
        path = Path(output_path)
        rows = self._load_findings("finding_id = ?", (finding_id,))
        if not rows:
            raise ReportNotFoundError("Finding")
        f = rows[0]
        meta = self.resolve_run(f["run_id"])
        ent_name = self._entity_info(f["entity_id"]).get("name")
        action = action_for(f["severity"])
        pc = f["peer_comparison"]
        st = STYLES

        text = headline(f["rule_id"], f["entity_id"], pc, f["title"])
        hero = Table(
            [
                [badge(action.label, action.bg, action.fg, size=16, width=150)],
                [Paragraph(esc(text), st["hero"])],
                [
                    Paragraph(
                        esc(
                            f"{ent_name + ' ' if ent_name else ''}({f['entity_id']})  |  "
                            f"{f['domain']}  |  Rule {f['rule_id']}  |  Severity {f['severity']}"
                        ),
                        st["meta"],
                    )
                ],
            ],
            colWidths=[CONTENT_W],
        )
        hero.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                    ("BOX", (0, 0), (-1, -1), 0.7, RULE),
                    ("LINEBEFORE", (0, 0), (0, -1), 6, colors.HexColor(action.fg)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 18),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 18),
                    ("TOPPADDING", (0, 0), (-1, 0), 18),
                    ("TOPPADDING", (0, 1), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, -1), (-1, -1), 16),
                ]
            )
        )
        story: list[Flowable] = [
            Paragraph("FINDING REPORT", st["tech_title"]),
            Paragraph(esc(f["title"]), st["h2"]),
            Spacer(1, 8),
            hero,
            Spacer(1, 12),
        ]
        cmp = comparison_block(f, pc, CONTENT_W)
        if cmp:
            story += section("How this CSE compares")
            story += cmp
            story.append(Spacer(1, 10))
        story += [Spacer(1, 4), technical_detail(f, pc, f["evidences"], CONTENT_W)]
        if f.get("examiner_check"):
            story += section("Suggested verification step")
            story.append(Paragraph(esc(f["examiner_check"]), st["body"]))
        benign = [b for b in f["benign_explanations"] if b]
        if benign:
            story += section(
                "Possible benign explanations",
                "Legitimate reasons that can produce this pattern; rule them out before escalating.",
            )
            for b in benign:
                story.append(Paragraph(esc(b), st["body"], bulletText="•"))

        return build_pdf(
            path, story, meta, f"Finding Report  |  {f['entity_id']}  |  {f['rule_id']}"
        )

    def export_findings_csv(self, output_path: Path | str) -> Path:
        """Export all findings to CSV."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        cur = self.sqlite_store.conn.cursor()
        cur.execute("SELECT * FROM findings ORDER BY score DESC")
        rows = cur.fetchall()

        # Every exported row carries the notice: a CSV is read and forwarded without the
        # page it was downloaded from.
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if rows:
                writer.writerow([*rows[0].keys(), "supervisory_notice"])
                for r in rows:
                    writer.writerow([*r, FINDING_NOTICE])
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
                writer.writerow([*rows[0].keys(), "supervisory_notice"])
                for r in rows:
                    writer.writerow([*r, FINDING_NOTICE])
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
                f"<td><span class='badge {_BADGE_CLASS[band_tier(e['risk_band'])]}'>{e['risk_band']}</span></td>"
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
