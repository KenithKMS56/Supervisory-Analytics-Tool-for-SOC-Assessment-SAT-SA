"""Render docs/architecture_2page.md to the 2-page PDF submitted for evaluation.

    python scripts/render_architecture_pdf.py [--out docs/SAT-SA_Architecture.pdf]

The Markdown is the source; this reads the small subset it uses (headings, paragraphs, bullets,
tables, **bold**, *italic*, `code`) and draws the mermaid block's flow as a vector diagram. It
fails if the result is longer than the PS limit of 2 pages, so an edit that overflows is caught.
Offline: ReportLab only, standard PDF fonts.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "docs" / "architecture_2page.md"
MAX_PAGES = 2
MARGIN = 1.35 * cm
INK = colors.HexColor("#1f2937")
ACCENT = colors.HexColor("#1d4ed8")
RULE = colors.HexColor("#cbd5e1")
FILL = colors.HexColor("#eef2ff")

BASE = ParagraphStyle("base", fontName="Helvetica", fontSize=8.4, leading=10.4, textColor=INK, alignment=TA_LEFT)
STYLES = {
    "title": ParagraphStyle("title", parent=BASE, fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=ACCENT),
    "h2": ParagraphStyle("h2", parent=BASE, fontName="Helvetica-Bold", fontSize=10, leading=12, textColor=ACCENT,
                         spaceBefore=5, spaceAfter=2),
    "subtitle": ParagraphStyle("subtitle", parent=BASE, fontSize=7.8, leading=9.6, textColor=colors.HexColor("#475569"),
                               spaceAfter=3),
    "body": ParagraphStyle("body", parent=BASE, spaceAfter=3),
    "cell": ParagraphStyle("cell", parent=BASE, fontSize=7.7, leading=9.3),
}

# The mermaid block's boxes, with labels short enough to fit the drawn boxes.
DIAGRAM = [
    ("CSE submissions", ["CSV / ZIP bundles", "JSON batch API", "DB and REST exports", "Splunk, ServiceNow,", "TheHive mappings"]),
    ("Ingestion service", ["validate, bind entity", "and period", "pseudonymise, redact", "data-quality checks", "hold / reject errors"]),
    ("Immutable store", ["Parquet batches", "publication catalog", "corrections are", "new versions,", "never rewrites"]),
    ("Assessment engine", ["job worker, DuckDB", "20 rules, peers", "anomaly scan", "scoring", "review queue"]),
    ("State and audit", ["SQLite: runs,", "findings, evidence", "cases, config", "snapshots, hash-", "chained audit log"]),
    ("Examiner portal", ["portfolio, drill-", "down, trends, cases", "blind review", "HTML / PDF / CSV", "reports"]),
]


def inline(text: str) -> str:
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"`([^`]+)`", r'<font face="Courier">\1</font>', text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    return re.sub(r"(?<![*\w])\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)


def diagram(width: float) -> Drawing:
    n = len(DIAGRAM)
    gap = 0.42 * cm
    box_w = (width - gap * (n - 1)) / n
    box_h = 2.25 * cm
    top_pad = 0.05 * cm
    d = Drawing(width, box_h + top_pad + 0.55 * cm)
    y = 0.55 * cm
    for i, (title, lines) in enumerate(DIAGRAM):
        x = i * (box_w + gap)
        d.add(Rect(x, y, box_w, box_h, rx=4, ry=4, fillColor=FILL, strokeColor=ACCENT, strokeWidth=0.8))
        d.add(String(x + box_w / 2, y + box_h - 11, title, fontName="Helvetica-Bold", fontSize=7.4,
                     fillColor=ACCENT, textAnchor="middle"))
        for j, line in enumerate(lines):
            d.add(String(x + box_w / 2, y + box_h - 22 - j * 8.2, line, fontName="Helvetica", fontSize=6.5,
                         fillColor=INK, textAnchor="middle"))
        if i < n - 1:
            ax, ay = x + box_w + 2, y + box_h / 2
            d.add(Line(ax, ay, ax + gap - 6, ay, strokeColor=INK, strokeWidth=0.9))
            d.add(Polygon([ax + gap - 6, ay + 2.6, ax + gap - 2, ay, ax + gap - 6, ay - 2.6], fillColor=INK,
                          strokeColor=INK, strokeWidth=0.5))
    # Published data is also read directly by the portal (store -> portal), below the boxes.
    sx = 2 * (box_w + gap) + box_w / 2
    ux = 5 * (box_w + gap) + box_w / 2
    low = 0.22 * cm
    for x0, y0, x1, y1 in ((sx, y, sx, low), (sx, low, ux, low)):
        d.add(Line(x0, y0, x1, y1, strokeColor=colors.HexColor("#64748b"), strokeWidth=0.7, strokeDashArray=[2, 2]))
    d.add(Line(ux, low, ux, y - 3, strokeColor=colors.HexColor("#64748b"), strokeWidth=0.7, strokeDashArray=[2, 2]))
    d.add(Polygon([ux - 2.4, y - 5, ux, y - 1, ux + 2.4, y - 5], fillColor=colors.HexColor("#64748b"),
                  strokeColor=colors.HexColor("#64748b"), strokeWidth=0.5))
    d.add(String((sx + ux) / 2, low + 2.5, "published data, read by the portal (cached; reloaded when data is published)",
                 fontName="Helvetica-Oblique", fontSize=6.2, fillColor=colors.HexColor("#475569"), textAnchor="middle"))
    return d


def table(rows: list[list[str]], width: float) -> Table:
    first_col = 4.3 * cm if rows[0][0].strip().lower() == "layer" else 5.2 * cm
    data = [[Paragraph(inline(c), STYLES["cell"]) for c in row] for row in rows]
    t = Table(data, colWidths=[first_col, width - first_col], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), FILL),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 1.6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8),
    ]))
    return t


def _bullets(items: list, mark: str) -> ListFlowable:
    return ListFlowable(items, bulletType="bullet", start=mark, leftIndent=9, bulletFontSize=6.5, bulletOffsetY=-1)


def flowables(markdown: str, width: float) -> list:
    out: list = []
    lines = markdown.splitlines()
    i = 0
    paragraphs_seen = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
        elif line.startswith("```"):
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                i += 1
            i += 1
            out += [diagram(width), Spacer(1, 3)]
        elif line.startswith("# "):
            out.append(Paragraph(inline(line[2:]), STYLES["title"]))
            i += 1
        elif line.startswith("## "):
            out.append(Paragraph(inline(line[3:]), STYLES["h2"]))
            i += 1
        elif line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            out += [table(rows, width), Spacer(1, 3)]
        elif line.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                # A top-level item: its text, then "  - " sub-items and indented paragraphs below it
                # (a blank line may separate them), until the next top-level line.
                parts: list = [Paragraph(inline(lines[i][2:]), STYLES["body"])]
                i += 1
                subs: list = []
                while i < len(lines) and (lines[i].startswith("  ") or (not lines[i].strip() and i + 1 < len(lines)
                                                                      and lines[i + 1].startswith("  "))):
                    text = lines[i].strip()
                    i += 1
                    if text.startswith("- "):
                        subs.append(ListItem(Paragraph(inline(text[2:]), STYLES["body"]), leftIndent=9))
                    elif text:
                        if subs:
                            parts.append(_bullets(subs, "–"))
                            subs = []
                        parts.append(Paragraph(inline(text), STYLES["body"]))
                if subs:
                    parts.append(_bullets(subs, "–"))
                items.append(ListItem(parts, leftIndent=9))
            out.append(_bullets(items, "•"))
        else:
            text = []
            while i < len(lines) and lines[i].strip() and not lines[i].startswith(("#", "|", "- ", "```")):
                text.append(lines[i].strip())
                i += 1
            style = "subtitle" if paragraphs_seen == 0 else "body"
            paragraphs_seen += 1
            out.append(Paragraph(inline(" ".join(text)), STYLES[style]))
    return out


def render(out: Path) -> int:
    pages = []

    def count(canvas, doc) -> None:  # type: ignore[no-untyped-def]
        pages.append(doc.page)
        canvas.saveState()
        canvas.setFont("Helvetica", 6.8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(MARGIN, 0.75 * cm, "SAT-SA solution architecture · PS SIH26157 · indicators for supervisory "
                                             "review, not a compliance determination")
        canvas.drawRightString(A4[0] - MARGIN, 0.75 * cm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=1.2 * cm,
                            bottomMargin=1.25 * cm, title="SAT-SA: Solution Architecture", author="SAT-SA team",
                            subject="PS SIH26157 architecture document")
    doc.build(flowables(SOURCE.read_text(encoding="utf-8"), doc.width), onFirstPage=count, onLaterPages=count)
    return len(pages)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(REPO / "docs" / "SAT-SA_Architecture.pdf"))
    args = parser.parse_args()
    pages = render(Path(args.out))
    print(f"wrote {args.out}: {pages} page(s)")
    if pages > MAX_PAGES:
        print(f"longer than the {MAX_PAGES}-page limit", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
