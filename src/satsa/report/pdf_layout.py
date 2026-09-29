"""Shared page layout, typography and finding cards for the SAT-SA PDF reports.

All three PDF reports (portfolio, CSE, finding) are built from this module so
they share one A4 page template, one type scale and one palette.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from satsa.report.pdf_charts import paired_bars
from satsa.report.plain_language import action_for, headline, paired_comparison

PAGE_W, PAGE_H = A4
MARGIN_X = 18 * mm
MARGIN_TOP = 24 * mm
MARGIN_BOTTOM = 22 * mm
CONTENT_W = PAGE_W - 2 * MARGIN_X

INK = colors.HexColor("#0f172a")
BODY = colors.HexColor("#1e293b")
MUTED = colors.HexColor("#64748b")
RULE = colors.HexColor("#e2e8f0")
PANEL = colors.HexColor("#f8fafc")
TECH_BG = colors.HexColor("#f1f5f9")
TECH_BORDER = colors.HexColor("#cbd5e1")
NOTICE_RED = colors.HexColor("#b91c1c")

NOTICE = "Indicators requiring supervisory review; not a compliance determination."


def esc(value: Any) -> str:
    """Escape a stored value for use inside a reportlab Paragraph (which parses markup)."""
    return escape("" if value is None else str(value))


def _style(name: str, **kw: Any) -> ParagraphStyle:
    base = {"fontName": "Helvetica", "fontSize": 9.5, "leading": 13, "textColor": BODY}
    base.update(kw)
    return ParagraphStyle(name=name, **base)


STYLES: dict[str, ParagraphStyle] = {
    "h1": _style("h1", fontName="Helvetica-Bold", fontSize=22, leading=27, textColor=INK),
    "h2": _style(
        "h2",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=INK,
        spaceBefore=6,
        spaceAfter=4,
    ),
    "h3": _style("h3", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=INK),
    "body": _style("body"),
    "lead": _style("lead", fontSize=10.5, leading=15, textColor=MUTED),
    "small": _style("small", fontSize=8, leading=10.5, textColor=MUTED),
    "notice": _style("notice", fontName="Helvetica-Bold", fontSize=8.5, textColor=NOTICE_RED),
    "headline": _style(
        "headline", fontName="Helvetica-Bold", fontSize=12.5, leading=16.5, textColor=INK
    ),
    "hero": _style("hero", fontName="Helvetica-Bold", fontSize=16, leading=21, textColor=INK),
    "meta": _style("meta", fontSize=8.5, leading=11, textColor=MUTED),
    "tech_label": _style(
        "tech_label", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED
    ),
    "tech": _style("tech", fontSize=8, leading=10.5, textColor=BODY),
    "tech_title": _style(
        "tech_title", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED
    ),
    "cell": _style("cell", fontSize=8, leading=10),
    "cell_b": _style("cell_b", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=INK),
    "caption": _style("caption", fontSize=7.5, leading=10, textColor=MUTED),
}


@dataclass
class RunMeta:
    run_id: str
    config_hash: str
    period: str
    created_at: str


class _NumberedCanvas(rl_canvas.Canvas):
    """Defers page output until the end so every footer can say 'Page X of Y'."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_pages: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_pages.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved_pages)
        for state in self._saved_pages:
            self.__dict__.update(state)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(MUTED)
            self.drawRightString(
                PAGE_W - MARGIN_X,
                MARGIN_BOTTOM - 14 * mm + 4,
                f"Page {self._pageNumber} of {total}",
            )
            super().showPage()
        super().save()


def _draw_footer(c: rl_canvas.Canvas, meta: RunMeta) -> None:
    y = MARGIN_BOTTOM - 8 * mm
    c.setStrokeColor(RULE)
    c.setLineWidth(0.8)
    c.line(MARGIN_X, y + 10, PAGE_W - MARGIN_X, y + 10)
    c.setFont("Helvetica-Bold", 7.5)
    c.setFillColor(NOTICE_RED)
    c.drawString(MARGIN_X, y, NOTICE)
    c.setFont("Helvetica", 7)
    c.setFillColor(MUTED)
    c.drawString(
        MARGIN_X,
        y - 6 * mm + 4,
        f"Run {meta.run_id}  |  Config {meta.config_hash}  |  Generated {meta.created_at}"
        "  |  Offline engine",
    )


def _draw_header(c: rl_canvas.Canvas, report_label: str) -> None:
    y = PAGE_H - MARGIN_TOP + 9 * mm
    c.setFillColor(INK)
    c.rect(MARGIN_X, y - 1, 3.2, 12, stroke=0, fill=1)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(MARGIN_X + 7, y + 1, "SAT-SA")
    c.setFont("Helvetica", 7.5)
    c.setFillColor(MUTED)
    c.drawString(MARGIN_X + 50, y + 2, "Supervisory Analytics Tool for SOC Assessment")
    c.drawRightString(PAGE_W - MARGIN_X, y + 2, report_label)
    c.setStrokeColor(RULE)
    c.setLineWidth(0.8)
    c.line(MARGIN_X, y - 5, PAGE_W - MARGIN_X, y - 5)


def build_pdf(
    path: Path, story: list[Flowable], meta: RunMeta, report_label: str, cover: bool = False
) -> Path:
    """Build `story` into `path` atomically (temp file + os.replace), on A4.

    With `cover=True` the first page has no running header (a presentation
    cover); every page carries the footer, the notice and 'Page X of Y'.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    frame = Frame(
        MARGIN_X,
        MARGIN_BOTTOM,
        CONTENT_W,
        PAGE_H - MARGIN_TOP - MARGIN_BOTTOM,
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
        id="body",
    )
    cover_frame = Frame(
        MARGIN_X,
        MARGIN_BOTTOM,
        CONTENT_W,
        PAGE_H - MARGIN_X - MARGIN_BOTTOM,
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
        id="cover",
    )

    def on_body(c: rl_canvas.Canvas, _doc: Any) -> None:
        _draw_header(c, report_label)
        _draw_footer(c, meta)

    def on_cover(c: rl_canvas.Canvas, _doc: Any) -> None:
        _draw_footer(c, meta)

    templates = [PageTemplate(id="body", frames=[frame], onPage=on_body)]
    if cover:
        templates.insert(0, PageTemplate(id="cover", frames=[cover_frame], onPage=on_cover))
        story = [NextPageTemplate("body"), *story]
    doc = BaseDocTemplate(
        str(tmp),
        pagesize=A4,
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM,
        title=f"SAT-SA {report_label}",
        author="SAT-SA (offline engine)",
        pageTemplates=templates,
    )
    try:
        doc.build(story, canvasmaker=_NumberedCanvas)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    return path


def badge(label: str, bg: str, fg: str, size: float = 8.5, width: float = 64) -> Table:
    style = _style(
        f"badge_{label}_{size}",
        fontName="Helvetica-Bold",
        fontSize=size,
        leading=size + 2,
        textColor=colors.HexColor(fg),
        alignment=TA_CENTER,
    )
    t = Table([[Paragraph(esc(label), style)]], colWidths=[width])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg)),
                ("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor(fg)),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return t


def section(title: str, intro: str | None = None) -> list[Flowable]:
    out: list[Flowable] = [Spacer(1, 6), Paragraph(esc(title), STYLES["h2"])]
    if intro:
        out.append(Paragraph(esc(intro), STYLES["small"]))
    out.append(Spacer(1, 6))
    return out


def _fmt_value(v: Any) -> str:
    if isinstance(v, float):
        return f"{v:.4g}"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


def technical_detail(
    finding: dict[str, Any],
    peer_comparison: dict[str, Any],
    evidences: Sequence[dict[str, Any]],
    width: float,
) -> Table:
    """Tier 2: the unchanged technical record of the finding, visually secondary.

    Rows with no underlying data are omitted rather than shown blank.
    """
    rows: list[tuple[str, str]] = [
        (
            "Rule",
            f"{finding['rule_id']} v{finding.get('rule_version') or '?'}  |  "
            f"Domain: {finding['domain']}  |  Score: {float(finding['score']):.1f}"
            + (
                f"  |  Confidence: {float(finding['confidence']):.2f}"
                if finding.get("confidence") is not None
                else ""
            ),
        ),
        ("Technical rationale", str(finding["rationale"])),
    ]
    if peer_comparison:
        rows.append(
            (
                "Measured values",
                "; ".join(f"{k} = {_fmt_value(v)}" for k, v in peer_comparison.items()),
            )
        )
    if evidences:
        by_type: dict[str, list[str]] = {}
        for ev in evidences:
            by_type.setdefault(str(ev["record_type"]), []).append(str(ev["record_id"]))
        rows.append(
            (
                "Evidence records",
                "  |  ".join(f"{rt} ({len(ids)}): {', '.join(ids)}" for rt, ids in by_type.items()),
            )
        )
    stamps = []
    if finding.get("created_at"):
        stamps.append(f"Finding recorded {finding['created_at']}")
    if finding.get("run_id"):
        stamps.append(f"Run {finding['run_id']}")
    if stamps:
        rows.append(("Recorded", "  |  ".join(stamps)))

    data: list[list[Any]] = [[Paragraph("TECHNICAL DETAIL", STYLES["tech_title"]), ""]]
    data += [
        [Paragraph(esc(label), STYLES["tech_label"]), Paragraph(esc(value), STYLES["tech"])]
        for label, value in rows
    ]
    label_w = 88
    t = Table(data, colWidths=[label_w, width - label_w])
    t.setStyle(
        TableStyle(
            [
                ("SPAN", (0, 0), (-1, 0)),
                ("BACKGROUND", (0, 0), (-1, -1), TECH_BG),
                ("BOX", (0, 0), (-1, -1), 0.7, TECH_BORDER),
                ("LINEBELOW", (0, 0), (-1, 0), 0.5, TECH_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return t


def comparison_block(
    finding: dict[str, Any], peer_comparison: dict[str, Any], width: float
) -> list[Flowable]:
    """Paired bars for findings whose stored values share a unit; [] otherwise."""
    cmp = paired_comparison(finding["rule_id"], peer_comparison)
    if cmp is None:
        return []
    action = action_for(finding.get("severity"))
    return [
        Paragraph(esc(cmp.title), STYLES["cell_b"]),
        paired_bars(cmp, action.fg, width),
        Paragraph("The gap between the two bars is the finding.", STYLES["caption"]),
    ]


def finding_card(
    finding: dict[str, Any],
    peer_comparison: dict[str, Any],
    evidences: Sequence[dict[str, Any]],
    width: float = CONTENT_W,
    show_entity: bool = True,
) -> Flowable:
    """Layered finding: Tier 1 (badge + plain-language headline) above Tier 2 (technical box).

    Kept on one page where it fits; a card taller than a page still splits by row.
    """
    action = action_for(finding.get("severity"))
    inner_w = width - 20
    meta_bits = [finding["domain"], f"Rule {finding['rule_id']}"]
    if show_entity:
        meta_bits.insert(0, finding["entity_id"])
    head = Table(
        [
            [
                badge(action.label, action.bg, action.fg),
                Paragraph(esc("  |  ".join(meta_bits)), STYLES["meta"]),
            ]
        ],
        colWidths=[72, inner_w - 72],
    )
    head.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    text = headline(finding["rule_id"], finding["entity_id"], peer_comparison, finding["title"])
    rows: list[list[Any]] = [[head], [Paragraph(esc(text), STYLES["headline"])]]
    rows += [[f] for f in comparison_block(finding, peer_comparison, inner_w)]
    rows.append([technical_detail(finding, peer_comparison, evidences, inner_w)])
    card = Table(rows, colWidths=[width])
    card.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.7, RULE),
                ("LINEBEFORE", (0, 0), (0, -1), 3.5, colors.HexColor(action.fg)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
            ]
        )
    )
    return KeepTogether([card])


def data_table(
    header: Sequence[str],
    rows: Sequence[Sequence[Any]],
    col_widths: Sequence[float],
    extra_styles: Sequence[tuple[Any, ...]] = (),
) -> Table:
    """Compact appendix table that repeats its header row across page breaks."""
    data: list[list[Any]] = [[Paragraph(esc(h), STYLES["cell_b"]) for h in header]]
    for r in rows:
        data.append(
            [c if isinstance(c, Flowable) else Paragraph(esc(c), STYLES["cell"]) for c in r]
        )
    t = Table(data, colWidths=list(col_widths), repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), TECH_BG),
                ("GRID", (0, 0), (-1, -1), 0.4, TECH_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                *extra_styles,
            ]
        )
    )
    return t
