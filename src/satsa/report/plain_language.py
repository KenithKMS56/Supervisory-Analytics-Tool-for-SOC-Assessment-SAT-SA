"""Plain-language (Tier-1) wording for findings in the PDF reports.

Presentation only: every value placed into a headline comes from the finding's
own stored `entity_id` and `peer_comparison_json`. Nothing is recomputed from
raw data, and if a template's keys are missing the finding's stored title is
used instead, so a headline can never show an invented number.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# Palette shared with the HTML reports (generator.py) and the UI badges.
CRIT_BG, CRIT_FG = "#fee2e2", "#b91c1c"
MOD_BG, MOD_FG = "#fef9c3", "#854d0e"
LOW_BG, LOW_FG = "#dcfce7", "#15803d"


@dataclass(frozen=True)
class Action:
    label: str
    bg: str
    fg: str


ESCALATE = Action("ESCALATE", CRIT_BG, CRIT_FG)
MONITOR = Action("MONITOR", MOD_BG, MOD_FG)
NOTE = Action("NOTE", LOW_BG, LOW_FG)

# Findings are stored with severity critical / high / medium; the mapping
# mirrors the existing HTML report badges (critical=red, high=amber, else green).
ACTION_BY_SEVERITY = {"critical": ESCALATE, "high": MONITOR}


def action_for(severity: str | None) -> Action:
    """Return the Tier-1 action badge for a stored finding severity."""
    return ACTION_BY_SEVERITY.get((severity or "").lower(), NOTE)


def _pct(v: Any) -> str:
    return f"{float(v):.1%}"


def _count(v: Any) -> str:
    return str(int(v))


def _mins(v: Any) -> str:
    return f"{float(v):.1f}"


def _secs_as_mins(v: Any) -> str:
    return f"{float(v) / 60:.1f}"


def _joined(v: Any) -> str:
    if not isinstance(v, list) or not v:
        raise ValueError("expected a non-empty list")
    return ", ".join(str(x) for x in v)


Formatters = dict[str, Callable[[Any], str]]

# rule_id -> (template, {peer_comparison key: formatter}). `{entity}` is always
# available; every other placeholder must be a key of the finding's stored
# peer_comparison_json.
HEADLINES: dict[str, tuple[str, Formatters]] = {
    "EG01": (
        (
            "{entity_share} of the serious alerts that analysts closed at {entity} were closed in "
            "under {peer_p5_seconds} minutes (faster than 95% of such closures across all assessed "
            "entities), with little or no investigation recorded."
        ),
        {"entity_share": _pct, "peer_p5_seconds": _secs_as_mins},
    ),
    "EG02": (
        (
            "{entity_share} of analyst-closed alerts at {entity} were closed with no recorded "
            "investigation step and almost no closing notes."
        ),
        {"entity_share": _pct},
    ),
    "EG03": (
        (
            "{unescalated_count} confirmed critical threats at {entity} were closed without ever "
            "being escalated to senior responders."
        ),
        {"unescalated_count": _count},
    ),
    "EG04": (
        (
            "{repeat_share} of analyst closing notes at {entity} are copied word-for-word rather "
            "than written for the specific case."
        ),
        {"repeat_share": _pct},
    ),
    "EG05": (
        (
            "{unaddressed_pairs} recurring false alarms at {entity} keep firing on the same "
            "systems, with no record of the underlying cause being fixed."
        ),
        {"unaddressed_pairs": _count},
    ),
    "EG06": (
        (
            "Closure figures at {entity} may be managed to meet targets: {bulk_batches} batch(es) "
            "of alerts closed by one analyst in the same minute, and {hugging_share} of alerts "
            "closed just before their deadline."
        ),
        {"bulk_batches": _count, "hugging_share": _pct},
    ),
    "EG07": (
        (
            "One analyst account at {entity} closed up to {max_closures_per_hour} alerts in a "
            "single hour, more than one person can realistically review."
        ),
        {"max_closures_per_hour": _count},
    ),
    "EG08": (
        (
            "{unack_count} escalations at {entity} were passed to senior responders but never "
            "acknowledged."
        ),
        {"unack_count": _count},
    ),
    "EG09": (
        (
            "{stale_cases} incident cases at {entity} have been open for more than 14 days "
            "without resolution."
        ),
        {"stale_cases": _count},
    ),
    "EG10": (
        (
            "{entity} reports resolving serious alerts in {declared_mttr_mins} minutes on average, "
            "but its own records show {empirical_mttr_mins} minutes, {gap_ratio} longer than "
            "reported."
        ),
        {"declared_mttr_mins": _mins, "empirical_mttr_mins": _mins, "gap_ratio": _pct},
    ),
    "EG11": (
        (
            "{entity} dismissed {fp_rate} of its {total_alerts} alerts as false alarms or harmless, "
            "an unusual pattern that may mean detection is poorly tuned or real threats are being "
            "missed."
        ),
        {"fp_rate": _pct, "total_alerts": _count},
    ),
    "EG12": (
        (
            "{skipped_cases_count} critical incident cases at {entity} were closed without the "
            "required containment step being recorded."
        ),
        {"skipped_cases_count": _count},
    ),
    "NS01": (
        (
            "{silent_assets_count} critical system(s) at {entity} that should be monitored sent no "
            "security logs at all for up to {max_silent_days} days."
        ),
        {"silent_assets_count": _count, "max_silent_days": _count},
    ),
    "NS02": (
        (
            "{entity} reported no alerts at all in categories that most other entities see "
            "regularly: {missing_categories}."
        ),
        {"missing_categories": _joined},
    ),
    "NS03": (
        (
            "Only {night_share} of {entity}'s alerts occur overnight, compared with {peer_average} "
            "on average across assessed entities, which suggests monitoring may lapse outside "
            "business hours."
        ),
        {"night_share": _pct, "peer_average": _pct},
    ),
    "NS04": (
        (
            "{tp_without_case} confirmed serious threats at {entity} have no matching incident "
            "case on record."
        ),
        {"tp_without_case": _count},
    ),
    "NS05": (
        (
            "{dormant_share} of {entity}'s active detection rules ({dormant_rules_count} rules) "
            "never raised a single alert during the review period and may not be working."
        ),
        {"dormant_share": _pct, "dormant_rules_count": _count},
    ),
    "NS06": (
        (
            "{ghost_assets_count} system(s) listed in {entity}'s asset inventory produced no logs "
            "or alerts at all during the review period."
        ),
        {"ghost_assets_count": _count},
    ),
    "NS07": (
        (
            "{unreported_cases_count} critical incident(s) at {entity} have no record of being "
            "reported to NCIIPC / CERT-In (reporting timeliness was not checked)."
        ),
        {"unreported_cases_count": _count},
    ),
    "NS08": (
        (
            "{entity}'s submission covers only {active_months} of the required 6 months of alert "
            "data."
        ),
        {"active_months": _count},
    ),
}


def headline(
    rule_id: str, entity_id: str, peer_comparison: dict[str, Any], fallback_title: str
) -> str:
    """Plain-language one-sentence headline, or the stored title if it can't be filled."""
    spec = HEADLINES.get(rule_id)
    if spec is None:
        return fallback_title
    template, formatters = spec
    try:
        values = {key: fmt(peer_comparison[key]) for key, fmt in formatters.items()}
    except (KeyError, TypeError, ValueError):
        return fallback_title
    return template.format(entity=entity_id, **values)


@dataclass(frozen=True)
class Comparison:
    """Two same-unit values for the paired-bar chart; the gap between them is the finding."""

    title: str
    entity_label: str
    entity_value: float
    baseline_label: str
    baseline_value: float
    unit: str  # "%" or "min"


def paired_comparison(rule_id: str, peer_comparison: dict[str, Any]) -> Comparison | None:
    """Comparison for rules whose stored values share a unit (NS03, EG10), else None."""
    try:
        if rule_id == "NS03":
            return Comparison(
                title="Share of alerts raised overnight (20:00-08:00)",
                entity_label="This entity",
                entity_value=float(peer_comparison["night_share"]) * 100,
                baseline_label="Portfolio average",
                baseline_value=float(peer_comparison["peer_average"]) * 100,
                unit="%",
            )
        if rule_id == "EG10":
            return Comparison(
                title="Mean time to resolve high/critical alerts",
                entity_label="Measured from records",
                entity_value=float(peer_comparison["empirical_mttr_mins"]),
                baseline_label="Reported by entity",
                baseline_value=float(peer_comparison["declared_mttr_mins"]),
                unit="min",
            )
    except (KeyError, TypeError, ValueError):
        return None
    return None
