"""Charts for the PDF reports, drawn with reportlab.graphics only (fully offline).

Every chart must still read correctly in grayscale, so severity is never shown
by hue alone: critical bars are solid and dark, moderate bars are light with a
diagonal hatch, low bars are light and plain, and every bar carries a text
label naming its band.
"""

from __future__ import annotations

import math
from collections.abc import Iterator, Sequence

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing, Group, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.pdfbase.pdfmetrics import stringWidth

from satsa.report.plain_language import (
    CRIT_BG,
    CRIT_FG,
    LOW_BG,
    LOW_FG,
    MOD_BG,
    MOD_FG,
    Comparison,
)

INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
GRID = colors.HexColor("#e2e8f0")
NEUTRAL = colors.HexColor("#94a3b8")

# Existing risk-band thresholds used across SAT-SA (HTML reports, UI).
CRITICAL_THRESHOLD = 50.0
MODERATE_THRESHOLD = 25.0


class BandStyle:
    def __init__(self, name: str, fill: str, stroke: str, text: str, hatch: bool) -> None:
        self.name = name
        self.fill = colors.HexColor(fill)
        self.stroke = colors.HexColor(stroke)
        self.text = colors.HexColor(text)
        self.hatch = hatch


BAND_CRITICAL = BandStyle("CRITICAL", CRIT_FG, CRIT_FG, CRIT_FG, hatch=False)
BAND_MODERATE = BandStyle("MODERATE", MOD_BG, MOD_FG, MOD_FG, hatch=True)
BAND_LOW = BandStyle("LOW", LOW_BG, LOW_FG, LOW_FG, hatch=False)


def band_for(score: float) -> BandStyle:
    if score >= CRITICAL_THRESHOLD:
        return BAND_CRITICAL
    if score >= MODERATE_THRESHOLD:
        return BAND_MODERATE
    return BAND_LOW


def _hatch(x: float, y: float, w: float, h: float, color: colors.Color, step: float = 4.0) -> Group:
    """Diagonal hatch lines clipped (analytically) to the rectangle x, y, w, h."""
    g = Group()
    if w <= 0 or h <= 0:
        return g
    # Lines of slope 1: points (x + t + s, y + s) for s in [0, h]; t sweeps from -h to w.
    t = -h
    while t < w:
        s0 = max(0.0, -t)
        s1 = min(h, w - t)
        if s1 > s0:
            g.add(Line(x + t + s0, y + s0, x + t + s1, y + s1, strokeColor=color, strokeWidth=0.6))
        t += step
    return g


def _backing(
    x: float, y: float, text: str, size: float, fill: colors.Color, anchor: str = "start"
) -> Rect:
    """A borderless box behind a label so gridlines, thresholds and hatching never cross it."""
    w = stringWidth(text, "Helvetica-Bold", size)
    left = {"start": x, "middle": x - w / 2, "end": x - w}[anchor]
    return Rect(left - 2, y - 2.5, w + 4, size + 2.5, fillColor=fill, strokeColor=None)


def _iter_rects(node: object) -> Iterator[Rect]:
    if isinstance(node, Rect):
        yield node
    for child in getattr(node, "contents", []) or []:
        yield from _iter_rects(child)


def _base_chart(
    n: int, width: float, label_w: float, end_label_w: float, row_h: float, bottom: float
) -> HorizontalBarChart:
    bc = HorizontalBarChart()
    bc.x = label_w
    bc.y = bottom
    bc.width = width - label_w - end_label_w
    bc.height = n * row_h
    bc.barWidth = 10
    bc.groupSpacing = 6
    bc.categoryAxis.labels.fontName = "Helvetica"
    bc.categoryAxis.labels.fontSize = 8
    bc.categoryAxis.labels.fillColor = INK
    bc.categoryAxis.labels.boxAnchor = "e"
    bc.categoryAxis.labels.dx = -6
    bc.categoryAxis.strokeColor = MUTED
    bc.categoryAxis.tickLeft = 0
    bc.valueAxis.labels.fontName = "Helvetica"
    bc.valueAxis.labels.fontSize = 7
    bc.valueAxis.labels.fillColor = MUTED
    bc.valueAxis.strokeColor = MUTED
    bc.valueAxis.visibleGrid = 1
    bc.valueAxis.gridStrokeColor = GRID
    bc.valueAxis.gridStrokeWidth = 0.5
    return bc


def band_bar_chart(
    labels: Sequence[str], values: Sequence[float], width: float, label_w: float = 90
) -> Drawing:
    """Horizontal bars on a 0-100 scale, highest first, each styled and labelled by band."""
    n = len(values)
    row_h = 17.0
    bottom = 18.0
    top_pad = 16.0
    d = Drawing(width, n * row_h + bottom + top_pad)
    if n == 0:
        return d

    # HorizontalBarChart draws category 0 at the bottom, so reverse for highest-on-top.
    rev_labels = list(reversed(labels))
    rev_values = [float(v) for v in reversed(values)]
    bc = _base_chart(n, width, label_w, 88, row_h, bottom)
    bc.data = [rev_values]
    bc.categoryAxis.categoryNames = rev_labels
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = 100
    bc.valueAxis.valueStep = 25
    bands = [band_for(v) for v in rev_values]
    for i, band in enumerate(bands):
        bc.bars[(0, i)].fillColor = band.fill
        bc.bars[(0, i)].strokeColor = band.stroke
        bc.bars[(0, i)].strokeWidth = 1.0
    g = bc.draw()
    d.add(g)

    # Hatch the moderate bars (identified by their fill), so they read in grayscale.
    for rect in _iter_rects(g):
        if rect.fillColor == BAND_MODERATE.fill and rect.width > 0 and rect.height < row_h:
            d.add(_hatch(rect.x, rect.y, rect.width, rect.height, BAND_MODERATE.stroke))

    _threshold_lines(d, bc)

    slot = bc.height / n
    for i, (v, band) in enumerate(zip(rev_values, bands, strict=True)):
        x_end = bc.x + bc.width * max(0.0, min(v, 100.0)) / 100.0
        y_mid = bc.y + (i + 0.5) * slot
        text = f"{v:.1f}  {band.name}"
        d.add(_backing(x_end + 5, y_mid - 3, text, 7.5, colors.white))
        d.add(
            String(
                x_end + 5,
                y_mid - 3,
                text,
                fontName="Helvetica-Bold",
                fontSize=7.5,
                fillColor=band.text,
            )
        )
    return d


def _threshold_lines(d: Drawing, bc: HorizontalBarChart) -> None:
    for value, label, color in (
        (MODERATE_THRESHOLD, "Moderate 25+", BAND_MODERATE.stroke),
        (CRITICAL_THRESHOLD, "Critical 50+", BAND_CRITICAL.stroke),
    ):
        x = bc.x + bc.width * value / 100.0
        d.add(
            Line(
                x,
                bc.y,
                x,
                bc.y + bc.height + 4,
                strokeColor=color,
                strokeWidth=0.8,
                strokeDashArray=[3, 2],
            )
        )
        d.add(
            String(
                x,
                bc.y + bc.height + 7,
                label,
                fontName="Helvetica",
                fontSize=6.5,
                fillColor=color,
                textAnchor="middle",
            )
        )


def domain_weakness_chart(rows: Sequence[tuple[str, int, int]], width: float) -> Drawing:
    """One bar per domain: share of entities whose domain score is in the critical band.

    `rows` are (domain, entities_in_critical_band, total_entities).
    """
    ordered = sorted(rows, key=lambda r: (-r[1], r[0]))
    n = len(ordered)
    row_h = 19.0
    bottom = 18.0
    d = Drawing(width, n * row_h + bottom + 6)
    if n == 0:
        return d
    rev = list(reversed(ordered))
    pcts = [(c / t * 100.0) if t else 0.0 for _, c, t in rev]
    bc = _base_chart(n, width, 135, 110, row_h, bottom)
    bc.data = [pcts]
    bc.categoryAxis.categoryNames = [dom for dom, _, _ in rev]
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = 100
    bc.valueAxis.valueStep = 25
    bc.valueAxis.labelTextFormat = "%d%%"
    bc.bars[0].fillColor = BAND_CRITICAL.fill
    bc.bars[0].strokeColor = BAND_CRITICAL.stroke
    d.add(bc.draw())
    slot = bc.height / n
    for i, ((_, c, t), p) in enumerate(zip(rev, pcts, strict=True)):
        x_end = bc.x + bc.width * p / 100.0
        d.add(
            String(
                x_end + 5,
                bc.y + (i + 0.5) * slot - 3,
                f"{c}/{t} entities ({p:.0f}%)",
                fontName="Helvetica-Bold" if c else "Helvetica",
                fontSize=7.5,
                fillColor=BAND_CRITICAL.text if c else MUTED,
            )
        )
    return d


def risk_gauge(value: float, width: float) -> Drawing:
    """A single 0-100 bar split into the low / moderate / critical bands, with a marker."""
    v = max(0.0, min(float(value), 100.0))
    h = 70.0
    d = Drawing(width, h)
    x0, x1 = 8.0, width - 8.0
    bar_y, bar_h = 20.0, 20.0

    def sx(val: float) -> float:
        return x0 + (x1 - x0) * val / 100.0

    for lo, hi, band in (
        (0.0, MODERATE_THRESHOLD, BAND_LOW),
        (MODERATE_THRESHOLD, CRITICAL_THRESHOLD, BAND_MODERATE),
        (CRITICAL_THRESHOLD, 100.0, BAND_CRITICAL),
    ):
        fill = colors.HexColor(CRIT_BG) if band is BAND_CRITICAL else band.fill
        d.add(
            Rect(
                sx(lo),
                bar_y,
                sx(hi) - sx(lo),
                bar_h,
                fillColor=fill,
                strokeColor=band.stroke,
                strokeWidth=0.8,
            )
        )
        if band.hatch:
            d.add(_hatch(sx(lo), bar_y, sx(hi) - sx(lo), bar_h, band.stroke, step=5))
        d.add(
            _backing((sx(lo) + sx(hi)) / 2, bar_y + bar_h / 2 - 3, band.name, 7.5, fill, "middle")
        )
        d.add(
            String(
                (sx(lo) + sx(hi)) / 2,
                bar_y + bar_h / 2 - 3,
                band.name,
                fontName="Helvetica-Bold",
                fontSize=7.5,
                fillColor=band.text,
                textAnchor="middle",
            )
        )
    for tick in (0, 25, 50, 100):
        d.add(Line(sx(tick), bar_y - 3, sx(tick), bar_y, strokeColor=MUTED, strokeWidth=0.6))
        d.add(
            String(
                sx(tick),
                bar_y - 12,
                str(tick),
                fontName="Helvetica",
                fontSize=7,
                fillColor=MUTED,
                textAnchor="middle",
            )
        )
    xm = sx(v)
    d.add(Line(xm, bar_y - 2, xm, bar_y + bar_h + 2, strokeColor=INK, strokeWidth=2.2))
    d.add(
        Polygon(
            [xm - 5, bar_y + bar_h + 10, xm + 5, bar_y + bar_h + 10, xm, bar_y + bar_h + 3],
            fillColor=INK,
            strokeColor=INK,
        )
    )
    anchor = "start" if v < 12 else ("end" if v > 88 else "middle")
    d.add(
        String(
            xm,
            bar_y + bar_h + 14,
            f"{float(value):.1f} / 100",
            fontName="Helvetica-Bold",
            fontSize=9,
            fillColor=INK,
            textAnchor=anchor,
        )
    )
    return d


def _nice_max(v: float) -> float:
    if v <= 0:
        return 1.0
    mag = 10 ** math.floor(math.log10(v))
    for step in (1, 2, 2.5, 5, 10):
        if v <= step * mag:
            return step * mag
    return 10 * mag


def paired_bars(cmp: Comparison, entity_color: str, width: float) -> Drawing:
    """This entity's value directly against its comparison value (same unit)."""
    row_h = 22.0
    bottom = 16.0
    d = Drawing(width, 2 * row_h + bottom + 4)
    step = _nice_max(max(cmp.entity_value, cmp.baseline_value) * 1.1 / 5)
    vmax = step * 5
    bc = _base_chart(2, width, 120, 70, row_h, bottom)
    bc.barWidth = 12
    bc.groupSpacing = 8
    # Category 0 is drawn at the bottom: baseline below, entity on top.
    bc.data = [[cmp.baseline_value, cmp.entity_value]]
    bc.categoryAxis.categoryNames = [cmp.baseline_label, cmp.entity_label]
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = vmax
    bc.valueAxis.valueStep = step
    unit_fmt = "%.0f%%" if cmp.unit == "%" else "%.0f"
    bc.valueAxis.labelTextFormat = unit_fmt
    bc.bars[(0, 0)].fillColor = NEUTRAL
    bc.bars[(0, 0)].strokeColor = INK
    bc.bars[(0, 0)].strokeDashArray = [2, 2]
    bc.bars[(0, 1)].fillColor = colors.HexColor(entity_color)
    bc.bars[(0, 1)].strokeColor = colors.HexColor(entity_color)
    d.add(bc.draw())
    slot = bc.height / 2
    for i, v in enumerate((cmp.baseline_value, cmp.entity_value)):
        text = f"{v:.1f}%" if cmp.unit == "%" else f"{v:.1f} min"
        d.add(
            String(
                bc.x + bc.width * v / vmax + 5,
                bc.y + (i + 0.5) * slot - 3,
                text,
                fontName="Helvetica-Bold",
                fontSize=8,
                fillColor=INK,
            )
        )
    return d
