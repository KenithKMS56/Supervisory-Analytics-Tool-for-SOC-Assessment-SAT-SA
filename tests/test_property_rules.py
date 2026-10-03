"""Property tests for five rules: EG03, EG07, EG09, NS04 and NS07.

Hypothesis generates the records of one entity (plus records of a second entity, which must
never count), loads them into a fresh store, and checks for every generated case:

- the rule flags exactly when its documented criterion holds (docs/analytics_methodology.md
  Section 3), computed here independently from the generated records;
- a finding always cites evidence, the evidence is the offending records, and the count it
  reports is the number of offending records;
- the same records inserted in another order give the same finding and the same evidence, in
  the same order;
- adding one more offending record never removes a finding and never lowers its score.

EG06, NS01 and NS06 get the first three checks only (their evidence lists need data with
several batches or assets, which the seed-42 set does not have), and every rule is run once on
the seed-42 data in shuffled row order.
"""

from __future__ import annotations

import random
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from satsa.rules.registry import RuleRegistry
from satsa.store.duckdb import DuckDBStore

SETTINGS = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
REGISTRY = RuleRegistry()
BASE = datetime(2026, 3, 2, 9, 0)
REFERENCE = datetime(2026, 6, 30, 12, 0)


def param(rule_id: str, name: str) -> Any:
    rule = REGISTRY.get_rule(rule_id)
    assert rule is not None and name in rule.params, (rule_id, name)
    return rule.params[name]


@dataclass
class Scenario:
    rows: dict[str, list[tuple[Any, ...]]]  # table -> rows, in the column order of COLUMNS
    flagged: bool
    count: int  # offending records the finding must report
    evidence: list[str]  # the evidence ids, in the order the finding must list them
    count_key: str
    check: Callable[[Any], None] | None = None  # any further assertion on the finding


COLUMNS = {
    "alert": "entity_id, alert_id, severity_final, disposition, created_at, closed_at, closed_by, closed_by_type",
    "escalation": "entity_id, esc_id, ref_id",
    "case": "entity_id, case_id, severity, status, opened_at",
    "case_alert_link": "entity_id, case_id, alert_id",
    "external_report": "entity_id, incident_id",
    "asset": "entity_id, asset_id, criticality, monitored_flag",
    "log_source_daily": "entity_id, asset_id, date, event_count",
}


def evaluate(rule_id: str, scenario: Scenario, seed: int | None = None) -> tuple[list[Any], list[Any]]:
    """Load the scenario's rows (shuffled by `seed`) into a fresh store and run the rule."""
    rule = REGISTRY.get_rule(rule_id)
    assert rule is not None
    with tempfile.TemporaryDirectory() as tmp:
        store = DuckDBStore(tmp)
        try:
            for table, rows in scenario.rows.items():
                rows = list(rows)
                if seed is not None:
                    random.Random(seed).shuffle(rows)
                if rows:
                    marks = ", ".join("?" for _ in rows[0])
                    store.conn.executemany(f'INSERT INTO "{table}" ({COLUMNS[table]}) VALUES ({marks})', rows)
            rule.reference_date = REFERENCE
            return rule.evaluate("E1", store, [], "RUN")
        finally:
            rule.reference_date = None
            store.close()


def dump(result: tuple[list[Any], list[Any]]) -> tuple[list[dict], list[dict]]:
    findings, evidences = result
    return ([f.model_dump(exclude={"created_at"}) for f in findings], [e.model_dump() for e in evidences])


def check(rule_id: str, scenario: Scenario, seed: int) -> None:
    findings, evidences = evaluate(rule_id, scenario)
    assert len(findings) == (1 if scenario.flagged else 0)
    if scenario.flagged:
        finding = findings[0]
        assert evidences, "a finding without evidence"
        assert {e.finding_id for e in evidences} == {finding.finding_id}
        assert [e.record_id for e in evidences] == scenario.evidence
        assert finding.evidence_ids == scenario.evidence
        assert finding.peer_comparison[scenario.count_key] == scenario.count
        if scenario.check:
            scenario.check(finding)
    else:
        assert evidences == []
    assert dump(evaluate(rule_id, scenario, seed)) == dump((findings, evidences)), "depends on row order"


def score(rule_id: str, scenario: Scenario) -> float | None:
    findings, _ = evaluate(rule_id, scenario)
    return findings[0].score if findings else None


def alert(entity: str, aid: str, severity: str = "high", disposition: str = "false_positive",
          closed_at: datetime | None = None, closed_by: str | None = None, closed_by_type: str = "human") -> tuple:  # fmt: skip
    return (entity, aid, severity, disposition, BASE, closed_at, closed_by, closed_by_type)


# ------------------------------------------------------------------ EG03

EG03_KINDS = st.lists(st.sampled_from(["defect", "escalated", "false_positive", "high_tp", "other_entity"]), max_size=14)


def eg03(kinds: list[str]) -> Scenario:
    alerts, escalations, defects = [], [], []
    for i, kind in enumerate(kinds):
        aid = f"A{(i * 37) % 101:03d}"  # ids not in insertion order
        if kind == "defect":
            alerts.append(alert("E1", aid, "critical", "true_positive"))
            defects.append(aid)
        elif kind == "escalated":
            alerts.append(alert("E1", aid, "critical", "true_positive"))
            escalations.append(("E1", f"X{i}", aid))
        elif kind == "false_positive":
            alerts.append(alert("E1", aid, "critical", "false_positive"))
        elif kind == "high_tp":
            alerts.append(alert("E1", aid, "high", "true_positive"))
        else:
            alerts.append(alert("E2", aid, "critical", "true_positive"))
    return Scenario({"alert": alerts, "escalation": escalations}, bool(defects), len(defects), sorted(defects),
                    "unescalated_count")  # fmt: skip


@SETTINGS
@given(EG03_KINDS, st.integers(0, 10**6))
def test_eg03_flags_every_unescalated_critical_true_positive(kinds, seed):
    check("EG03", eg03(kinds), seed)


@SETTINGS
@given(EG03_KINDS)
def test_eg03_another_unescalated_critical_never_lowers_the_finding(kinds):
    before, after = score("EG03", eg03(kinds)), score("EG03", eg03([*kinds, "defect"]))
    assert after is not None and (before is None or after >= before)


# ------------------------------------------------------------------ EG06 (bulk closures only)

# human closures per (analyst, minute); with no SLA policy loaded, deadline hugging is 0%, so
# only the bulk-closure half of the rule can flag. The seed-42 data has a single bulk batch, so
# only generated data with several batches can show whether their order is stable.
EG06_BUCKETS = st.dictionaries(
    st.tuples(st.sampled_from(["ana", "bob", "cy"]), st.integers(0, 3)), st.integers(0, 12), max_size=10
)


def eg06(buckets: dict[tuple[str, int], int]) -> Scenario:
    limit = int(param("EG06", "min_bulk_closures_per_minute"))
    alerts, first, n = [], {}, 0
    for (who, minute), count in sorted(buckets.items(), key=lambda kv: (-kv[0][1], kv[0][0])):
        for j in range(count):
            aid = f"A{(n * 37) % 997:03d}"  # ids not in time order
            alerts.append(alert("E1", aid, closed_at=BASE + timedelta(minutes=minute, seconds=j * 7 % 60), closed_by=who))
            first[(who, minute)] = min(first.get((who, minute), aid), aid)
            n += 1
    batches = sorted((minute, who) for (who, minute), count in buckets.items() if count >= limit)
    evidence = [first[(who, minute)] for minute, who in batches]
    return Scenario({"alert": alerts}, bool(batches), len(batches), evidence, "bulk_batches")


@SETTINGS
@given(EG06_BUCKETS, st.integers(0, 10**6))
def test_eg06_flags_bulk_closure_batches_in_time_order(buckets, seed):
    check("EG06", eg06(buckets), seed)


# ------------------------------------------------------------------ EG07

# closures per (analyst, clock hour); "soar" closures are automation and never count
EG07_BUCKETS = st.dictionaries(
    st.tuples(st.sampled_from(["ana", "bob", "cy", "soar"]), st.integers(0, 2)), st.integers(0, 40), max_size=8
)


def eg07(buckets: dict[tuple[str, int], int]) -> Scenario:
    limit = int(param("EG07", "min_closures_per_analyst_hour"))
    alerts, n = [], 0
    for (who, hour), count in sorted(buckets.items()):
        for j in range(count):
            closed = BASE + timedelta(hours=hour, seconds=j * 89 % 3600)
            kind = "automation" if who == "soar" else "human"
            alerts.append(alert("E1", f"A{n:05d}", closed_at=closed, closed_by=who, closed_by_type=kind))
            n += 1
    human = {k: v for k, v in buckets.items() if k[0] != "soar"}
    over = {k: v for k, v in human.items() if v >= limit}
    top = max(over.values(), default=0)
    busiest = sorted({who for (who, _), v in over.items() if v == top})
    # evidence: analysts over the limit, busiest hour first, then by name
    best = {who: max(v for (w, _), v in over.items() if w == who) for who, _ in over}
    order = sorted(best, key=lambda who: (-best[who], who))

    def names_the_busiest(finding: Any) -> None:
        assert f"analyst '{busiest[0]}'" in finding.rationale, (finding.rationale, busiest)

    return Scenario({"alert": alerts}, bool(over), top, order, "max_closures_per_hour", names_the_busiest)


@SETTINGS
@given(EG07_BUCKETS, st.integers(0, 10**6))
def test_eg07_flags_an_analyst_hour_over_the_limit_and_names_the_busiest(buckets, seed):
    check("EG07", eg07(buckets), seed)


@SETTINGS
@given(EG07_BUCKETS, st.sampled_from(["ana", "bob", "cy"]), st.integers(0, 2))
def test_eg07_another_closure_never_lowers_the_finding(buckets, who, hour):
    more = {**buckets, (who, hour): buckets.get((who, hour), 0) + 1}
    before, after = score("EG07", eg07(buckets)), score("EG07", eg07(more))
    assert before is None or (after is not None and after >= before)


# ------------------------------------------------------------------ EG09

STALE_SECONDS = int(param("EG09", "stale_case_days")) * 86400
# (status, age in seconds relative to the stale limit): ages cluster around the boundary
EG09_CASES = st.lists(
    st.tuples(st.sampled_from(["open", "closed", "open_other_entity"]), st.integers(-3 * 86400, 3 * 86400)),
    max_size=12,
)


def eg09(cases: list[tuple[str, int]]) -> Scenario:
    rows, stale = [], []
    for i, (status, delta) in enumerate(cases):
        cid = f"C{(i * 7) % 13:02d}{i:02d}"
        opened = REFERENCE - timedelta(seconds=STALE_SECONDS + delta)
        entity = "E2" if status == "open_other_entity" else "E1"
        rows.append((entity, cid, "high", "closed" if status == "closed" else "open", opened))
        if entity == "E1" and status == "open" and STALE_SECONDS + delta > STALE_SECONDS:
            stale.append((opened, cid))
    flagged = len(stale) >= int(param("EG09", "min_stale_cases"))
    return Scenario({"case": rows}, flagged, len(stale), [cid for _, cid in sorted(stale)][:5], "stale_cases")


@SETTINGS
@given(EG09_CASES, st.integers(0, 10**6))
def test_eg09_flags_enough_open_cases_older_than_the_limit(cases, seed):
    check("EG09", eg09(cases), seed)


@SETTINGS
@given(EG09_CASES)
def test_eg09_another_stale_case_never_lowers_the_finding(cases):
    before, after = score("EG09", eg09(cases)), score("EG09", eg09([*cases, ("open", 86400)]))
    assert before is None or (after is not None and after >= before)


# ------------------------------------------------------------------ NS04

NS04_KINDS = st.lists(
    st.sampled_from(["defect_high", "defect_critical", "linked", "false_positive", "medium_tp", "other_entity"]),
    max_size=14,
)


def ns04(kinds: list[str]) -> Scenario:
    alerts, links, defects = [], [], []
    for i, kind in enumerate(kinds):
        aid = f"A{(i * 37) % 101:03d}"
        if kind.startswith("defect"):
            alerts.append(alert("E1", aid, kind.split("_")[1], "true_positive"))
            defects.append(aid)
        elif kind == "linked":
            alerts.append(alert("E1", aid, "critical", "true_positive"))
            links.append(("E1", f"C{i}", aid))
        elif kind == "false_positive":
            alerts.append(alert("E1", aid, "critical", "false_positive"))
        elif kind == "medium_tp":
            alerts.append(alert("E1", aid, "medium", "true_positive"))
        else:
            alerts.append(alert("E2", aid, "critical", "true_positive"))
    flagged = len(defects) >= int(param("NS04", "min_tp_without_case"))
    return Scenario({"alert": alerts, "case_alert_link": links}, flagged, len(defects), sorted(defects)[:5],
                    "tp_without_case")  # fmt: skip


@SETTINGS
@given(NS04_KINDS, st.integers(0, 10**6))
def test_ns04_flags_enough_true_positives_without_a_case(kinds, seed):
    check("NS04", ns04(kinds), seed)


@SETTINGS
@given(NS04_KINDS)
def test_ns04_another_true_positive_without_a_case_never_lowers_the_finding(kinds):
    before, after = score("NS04", ns04(kinds)), score("NS04", ns04([*kinds, "defect_high"]))
    assert before is None or (after is not None and after >= before)


# ------------------------------------------------------------------ NS07

NS07_KINDS = st.lists(st.sampled_from(["defect", "reported", "high_case", "other_entity"]), max_size=12)


def ns07(kinds: list[str]) -> Scenario:
    cases, reports, defects = [], [], []
    for i, kind in enumerate(kinds):
        cid = f"C{(i * 37) % 101:03d}"
        if kind == "defect":
            cases.append(("E1", cid, "critical", "closed", BASE))
            defects.append(cid)
        elif kind == "reported":
            cases.append(("E1", cid, "critical", "closed", BASE))
            reports.append(("E1", cid))
        elif kind == "high_case":
            cases.append(("E1", cid, "high", "closed", BASE))
        else:
            cases.append(("E2", cid, "critical", "closed", BASE))
    return Scenario({"case": cases, "external_report": reports}, bool(defects), len(defects), sorted(defects),
                    "unreported_cases_count")  # fmt: skip


@SETTINGS
@given(NS07_KINDS, st.integers(0, 10**6))
def test_ns07_flags_every_critical_case_without_an_external_report(kinds, seed):
    check("NS07", ns07(kinds), seed)


@SETTINGS
@given(NS07_KINDS)
def test_ns07_another_unreported_critical_case_never_lowers_the_finding(kinds):
    before, after = score("NS07", ns07(kinds)), score("NS07", ns07([*kinds, "defect"]))
    assert after is not None and (before is None or after >= before)


# ------------------------------------------------------------------ NS01 and NS06: asset lists

# per asset: (criticality, monitored, days with zero events, days with events). The seed-42 data
# has too few silent or ghost assets per entity for their order to vary, so this generates more.
ASSETS = st.lists(
    st.tuples(st.integers(1, 4), st.booleans(), st.integers(0, 5), st.integers(0, 2)), min_size=1, max_size=12
)


def asset_rows(assets: list[tuple[int, bool, int, int]]) -> tuple[dict[str, list[tuple[Any, ...]]], list[str]]:
    rows: dict[str, list[tuple[Any, ...]]] = {"asset": [], "log_source_daily": []}
    ids = []
    for i, (criticality, monitored, silent, active) in enumerate(assets):
        aid = f"H{(i * 37) % 101:03d}"  # ids not in insertion order
        ids.append(aid)
        rows["asset"].append(("E1", aid, criticality, monitored))
        for day in range(silent + active):
            rows["log_source_daily"].append(("E1", aid, BASE.date() + timedelta(days=day), 0 if day < silent else 5))
    return rows, ids


def ns01(assets: list[tuple[int, bool, int, int]]) -> Scenario:
    rows, ids = asset_rows(assets)
    silent = sorted(
        aid for aid, (crit, monitored, days, _) in zip(ids, assets, strict=True)
        if crit >= int(param("NS01", "min_asset_criticality")) and monitored and days >= int(param("NS01", "min_silent_days"))
    )  # fmt: skip
    return Scenario(rows, bool(silent), len(silent), silent, "silent_assets_count")


def ns06(assets: list[tuple[int, bool, int, int]]) -> Scenario:
    rows, ids = asset_rows(assets)
    ghosts = sorted(aid for aid, (_, _, _, active) in zip(ids, assets, strict=True) if active == 0)
    flagged = len(ghosts) >= int(param("NS06", "min_ghost_assets"))
    return Scenario(rows, flagged, len(ghosts), ghosts if flagged else [], "ghost_assets_count")


@SETTINGS
@given(ASSETS, st.integers(0, 10**6))
def test_ns01_flags_silent_critical_assets_in_id_order(assets, seed):
    check("NS01", ns01(assets), seed)


@SETTINGS
@given(ASSETS, st.integers(0, 10**6))
def test_ns06_flags_ghost_assets_in_id_order(assets, seed):
    check("NS06", ns06(assets), seed)


# ------------------------------------------------------------------ all 20 rules: row order

def _assess_generated(seed: int | None) -> dict[tuple[str, str], tuple[list[dict], list[dict]]]:
    """Every rule for every entity of a generated portfolio, rows stored in `seed`'s order."""
    import polars as pl

    from satsa.peers.grouping import PeerResolver
    from satsa.synth.generator import SyntheticDataGenerator

    data, _ = SyntheticDataGenerator(seed=42, base_alerts_per_entity=300).generate()
    results: dict[tuple[str, str], tuple[list[dict], list[dict]]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        store = DuckDBStore(tmp)
        try:
            for table, records in data.items():
                frame = pl.DataFrame([r.model_dump() for r in records])
                frame = frame.select([c for c in store.table_columns(table) if c in frame.columns])
                if seed is not None:
                    frame = frame.sample(fraction=1.0, shuffle=True, seed=seed)
                store.conn.register("incoming", frame)
                store.conn.execute(f'INSERT INTO "{table}" BY NAME SELECT * FROM incoming')
                store.conn.unregister("incoming")
            entities = data["entity"]
            as_of = max(a.created_at for a in data["alert"])
            for entity in entities:
                peers, _, _ = PeerResolver().resolve_peers(entity, entities)
                for rule_id, rule in sorted(REGISTRY.rules.items()):
                    rule.reference_date = as_of
                    try:
                        results[(entity.entity_id, rule_id)] = dump(rule.evaluate(entity.entity_id, store, peers, "RUN"))
                    finally:
                        rule.reference_date = None
        finally:
            store.close()
    return results


_UNSHUFFLED: dict[str, Any] = {}


@settings(max_examples=4, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.integers(0, 2**31 - 1))
def test_no_rule_depends_on_the_order_rows_are_stored_in(seed):
    if "results" not in _UNSHUFFLED:
        _UNSHUFFLED["results"] = _assess_generated(None)
    expected = _UNSHUFFLED["results"]
    assert len({rule for _, rule in expected}) == 20
    assert sum(1 for findings, _ in expected.values() if findings) >= 15  # the portfolio has findings to compare
    got = _assess_generated(seed)
    differing = sorted(key for key in expected if got[key] != expected[key])
    assert not differing, differing
