"""Context-aware analytics and defensible comparisons (brief §7, docs/analytics_context.md).

Acceptance: fractional-offset and daylight-saving fixtures behave correctly; maintenance changes
only approved scope and time; missing input is not monitoring silence; sparse peer cohorts are
flagged; anomaly baselines never use later values; each displayed comparison is reproducible
from what the run recorded; exceptions expire and never cover a critical finding.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest
from deploy_utils import copy_deployment

from satsa import context
from satsa.context import EntityContext, MaintenanceWindow, schedule_class
from satsa.models.canonical import Entity
from satsa.peers.anomaly_scan import AnomalyScanner
from satsa.peers.grouping import PeerResolver
from satsa.peers.spc import SPCDetector
from satsa.rules.registry import RuleRegistry
from satsa.rules.systemic import (
    SystemicCorrelationDetector,
    benjamini_hochberg,
    hypergeom_upper_tail,
)
from satsa.scoring.replay import replay_run
from satsa.scoring.runner import AssessmentRunner
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


def _entity(store: DuckDBStore, entity_id: str, tz: str | None, shift: str = "09:00-18:00") -> None:
    store.execute(
        "INSERT INTO entity (entity_id, name, sector, size_band, soc_model, soc_provider, timezone, "
        "declared_shift_hours) VALUES (?, ?, 'power', 'large', 'inhouse', 'internal', ?, ?)",
        [entity_id, entity_id, tz, shift],
    )


def _alerts(store: DuckDBStore, entity_id: str, when: list[dt.datetime]) -> None:
    for i, ts in enumerate(when):
        store.execute(
            "INSERT INTO alert (entity_id, alert_id, rule_id, severity_final, created_at, status) "
            "VALUES (?, ?, 'R1', 'medium', ?, 'open')",
            [entity_id, f"{entity_id}-A{i}", ts],
        )


def _ns03(store: DuckDBStore, entity_id: str, ctx: EntityContext | None = None):
    rule = RuleRegistry().get_rule("NS03")
    rule.context = ctx
    try:
        return rule.evaluate(entity_id, store, [], "RUN-T")
    finally:
        rule.context = None


# --- time zones -----------------------------------------------------------------------------


def test_fractional_offset_moves_alerts_into_the_local_night(tmp_path):
    """16:00 UTC is daytime in UTC but 21:45 in Kathmandu (+05:45): the same alerts are a night
    flatline for a UTC entity and normal night activity for a Kathmandu one."""
    store = DuckDBStore(tmp_path / "pq")
    try:
        when = [dt.datetime(2026, 2, d % 28 + 1, 16, 0) for d in range(150)]
        _entity(store, "UTCE", "UTC")
        _entity(store, "KTM", "Asia/Kathmandu")
        _alerts(store, "UTCE", when)
        _alerts(store, "KTM", when)
        utc_findings, _ = _ns03(store, "UTCE")
        ktm_findings, _ = _ns03(store, "KTM")
        assert utc_findings and utc_findings[0].peer_comparison["timezone"] == "UTC"
        assert "20:00-08:00 UTC" in utc_findings[0].rationale
        assert ktm_findings == []  # every alert is at 21:45 local: 100% night share
        hours = store.query(
            f"WITH {context.ENTITY_TZ_CTE} SELECT DISTINCT {context.local_hour('created_at')} AS h "
            "FROM alert LEFT JOIN _satsa_tz USING (entity_id) WHERE entity_id = 'KTM'"
        )["h"].to_list()
        assert hours == [21]
    finally:
        store.close()


def test_daylight_saving_shifts_the_local_hour_by_season(tmp_path):
    """00:30 UTC is 19:30 in New York in January (EST, -5) and 20:30 in July (EDT, -4)."""
    store = DuckDBStore(tmp_path / "pq")
    try:
        _entity(store, "NYC-W", "America/New_York")
        _entity(store, "NYC-S", "America/New_York")
        _alerts(store, "NYC-W", [dt.datetime(2026, 1, d % 28 + 1, 0, 30) for d in range(150)])
        _alerts(store, "NYC-S", [dt.datetime(2026, 7, d % 28 + 1, 0, 30) for d in range(150)])
        winter, _ = _ns03(store, "NYC-W")
        summer, _ = _ns03(store, "NYC-S")
        assert winter and winter[0].peer_comparison["night_share"] == 0.0  # 19:30: evening, not night
        assert summer == []  # 20:30: night
    finally:
        store.close()


def test_unknown_time_zone_is_read_as_utc_and_said_so(tmp_path):
    store = DuckDBStore(tmp_path / "pq")
    try:
        _entity(store, "BAD", "Mars/Olympus_Mons")
        _alerts(store, "BAD", [dt.datetime(2026, 2, d % 28 + 1, 12, 0) for d in range(150)])
        ctx = context.build_contexts([Entity(entity_id="BAD", name="b", timezone="Mars/Olympus_Mons")], store)["BAD"]
        assert ctx.timezone == "UTC" and ctx.timezone_assumed
        findings, evidence = _ns03(store, "BAD", ctx)
        assert findings and "not a known IANA time zone" in findings[0].rationale
        assert findings[0].peer_comparison["timezone_note"]
        assert {e.details["timezone"] for e in evidence} == {"UTC"}
    finally:
        store.close()


@pytest.mark.parametrize(
    ("declared", "expected"),
    [("09:00-18:00", "business_hours"), ("24x7", "24x7"), ("00:00-24:00", "24x7"), ("00:00-23:59", "24x7"),
     ("22:00-06:00", "business_hours"), ("", "unknown"), (None, "unknown"), ("nights", "unknown"),
     ("25:00-26:00", "unknown")],
)
def test_operating_schedule_is_classified(declared, expected):
    assert schedule_class(declared) == expected


# --- maintenance and effective-dated inventory -------------------------------------------------


def _silence_fixture(store: DuckDBStore) -> None:
    _entity(store, "E1", "UTC")
    for asset in ("A", "B"):
        store.execute(
            "INSERT INTO asset (entity_id, asset_id, asset_type, criticality, monitored_flag) VALUES ('E1', ?, 'server', 4, true)",
            [asset],
        )
        for day in range(1, 11):
            # days 3-6 silent on both assets; day 9 has no row at all (missing submission)
            if day == 9:
                continue
            store.execute(
                "INSERT INTO log_source_daily (entity_id, asset_id, source_type, date, event_count) VALUES ('E1', ?, 'syslog', ?, ?)",
                [asset, dt.date(2026, 3, day), 0 if 3 <= day <= 6 else 500],
            )


def _ns01(store, ctx):
    rule = RuleRegistry().get_rule("NS01")
    rule.context = ctx
    try:
        return rule.evaluate("E1", store, [], "RUN-T")
    finally:
        rule.context = None


def _ctx(*windows: MaintenanceWindow) -> EntityContext:
    return EntityContext("E1", "UTC", "UTC", "24x7", "24x7", "inhouse", tuple(windows))


def test_maintenance_excludes_only_its_own_asset_and_days(tmp_path):
    store = DuckDBStore(tmp_path / "pq")
    try:
        _silence_fixture(store)
        before, _ = _ns01(store, _ctx())
        assert before and sorted(before[0].evidence_ids) == ["A", "B"]
        assert before[0].peer_comparison["max_silent_days"] == 4  # day 9 (no row) is not silence

        window = MaintenanceWindow("MW-1", "E1", "A", dt.date(2026, 3, 3), dt.date(2026, 3, 5), "patching", "x")
        after, _ = _ns01(store, _ctx(window))
        # A keeps 1 silent day (day 6), under the 3-day threshold; B, outside the scope, keeps 4.
        assert after and after[0].evidence_ids == ["B"]
        assert after[0].peer_comparison["maintenance_days_excluded"] == 3
        assert after[0].peer_comparison["max_silent_days"] == 4
        assert "inside approved maintenance (MW-1)" in after[0].rationale

        all_assets = MaintenanceWindow("MW-2", "E1", None, dt.date(2026, 3, 1), dt.date(2026, 3, 10), "outage", "x")
        assert _ns01(store, _ctx(all_assets))[0] == []
    finally:
        store.close()


def test_days_outside_an_assets_in_service_dates_are_not_silence(tmp_path):
    store = DuckDBStore(tmp_path / "pq")
    try:
        _silence_fixture(store)
        store.execute("UPDATE asset SET in_service_to = DATE '2026-03-02' WHERE asset_id = 'A'")
        findings, _ = _ns01(store, _ctx())
        assert findings[0].evidence_ids == ["B"]
        assert findings[0].peer_comparison["out_of_service_days_excluded"] == 4
        # NS06: an asset decommissioned before the telemetry period is not a ghost asset.
        store.execute(
            "INSERT INTO asset (entity_id, asset_id, asset_type, criticality, monitored_flag, in_service_to) "
            "VALUES ('E1', 'OLD1', 'server', 2, true, DATE '2025-12-31'), ('E1', 'OLD2', 'server', 2, true, DATE '2025-12-31')"
        )
        assert RuleRegistry().get_rule("NS06").evaluate("E1", store, [], "RUN-T")[0] == []
        store.execute("UPDATE asset SET in_service_to = NULL WHERE asset_id IN ('OLD1', 'OLD2')")
        ghosts = RuleRegistry().get_rule("NS06").evaluate("E1", store, [], "RUN-T")[0]
        assert ghosts and sorted(ghosts[0].evidence_ids) == ["OLD1", "OLD2"]
    finally:
        store.close()


def test_maintenance_needs_a_different_examiners_approval_and_resolves_as_of(tmp_path):
    store = SQLiteStore(tmp_path / "satsa.db")
    try:
        wid = context.request_maintenance(store, "E1", "2026-03-03", "2026-03-05", "patching", "CHG-1", "ana", "analyst")
        assert context.maintenance_in_force(store) == {}  # not approved yet
        with pytest.raises(context.ContextError, match="only an examiner"):
            context.approve_maintenance(store, wid, "ana2", "analyst")
        with pytest.raises(context.ContextError, match="before the start date"):
            context.request_maintenance(store, "E1", "2026-03-03", "2026-03-02", "x", "y", "ex", "examiner")
        exam_id = context.request_maintenance(store, "E1", "2026-04-01", "2026-04-02", "x", "y", "ex1", "examiner")
        with pytest.raises(context.ContextError, match="other than the requester"):
            context.approve_maintenance(store, exam_id, "ex1", "examiner")
        before_approval = store.conn.execute("SELECT requested_at FROM maintenance_windows WHERE window_id = ?",
                                             (wid,)).fetchone()[0]
        context.approve_maintenance(store, wid, "ex1", "examiner")
        assert [w.window_id for w in context.maintenance_in_force(store)["E1"]] == [wid]
        assert context.maintenance_in_force(store, at=before_approval) == {}
        context.revoke_maintenance(store, wid, "ex2", "examiner", "wrong dates")
        assert context.maintenance_in_force(store) == {}
        actions = [r[0] for r in store.conn.execute("SELECT action FROM audit_log ORDER BY rowid")]
        assert {"maintenance_requested", "maintenance_approved", "maintenance_revoked"} <= set(actions)
        with pytest.raises(context.ContextError, match="at most"):
            context.request_maintenance(store, "E1", "2026-01-01", "2026-12-31", "x", "y", "ana", "analyst")
    finally:
        store.close()


def test_a_rule_exception_needs_reason_evidence_approver_and_a_bounded_expiry(tmp_path):
    store = SQLiteStore(tmp_path / "satsa.db")
    soon = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=30)).isoformat()
    try:
        with pytest.raises(context.ContextError, match="only an examiner"):
            context.request_exception(store, "E1", "NS03", "s", "r", "e", soon, "ana", "analyst")
        with pytest.raises(context.ContextError, match="evidence reference"):
            context.request_exception(store, "E1", "NS03", "s", "r", " ", soon, "ex1", "examiner")
        with pytest.raises(context.ContextError, match="future"):
            context.request_exception(store, "E1", "NS03", "s", "r", "e", "2020-01-01", "ex1", "examiner")
        far = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=400)).isoformat()
        with pytest.raises(context.ContextError, match="renew"):
            context.request_exception(store, "E1", "NS03", "s", "r", "e", far, "ex1", "examiner")
        xid = context.request_exception(store, "E1", "NS03", "8x5 SOC", "board-approved", "MIN-7", soon, "ex1", "examiner")
        assert context.exceptions_in_force(store) == {}
        with pytest.raises(context.ContextError, match="other than the requester"):
            context.approve_exception(store, xid, "ex1", "examiner")
        context.approve_exception(store, xid, "ex2", "examiner")
        assert context.exceptions_in_force(store)[("E1", "NS03")]["exception_id"] == xid
        after_expiry = f"{(dt.date.fromisoformat(soon) + dt.timedelta(days=1)).isoformat()}T00:00:00.000000+00:00"
        assert context.exceptions_in_force(store, at=after_expiry) == {}  # it lapses on its own
        # The database itself refuses a self-approval written around the API.
        with pytest.raises(Exception, match="CHECK"), store.transaction():
            store.conn.execute("UPDATE rule_exceptions SET approved_by = requested_by WHERE exception_id = ?", (xid,))
    finally:
        store.close()


# --- peers ----------------------------------------------------------------------------------


def _ents(n_power: int, n_bank: int, soc_model: str = "inhouse") -> list[Entity]:
    out = [Entity(entity_id=f"P{i}", name="p", sector="power", size_band="large", soc_model=soc_model)
           for i in range(n_power)]
    out += [Entity(entity_id=f"B{i}", name="b", sector="banking", size_band="large") for i in range(n_bank)]
    return out


def test_sparse_cohorts_are_exploratory_and_record_their_exclusions():
    resolver = PeerResolver()
    sparse = resolver.resolve(_ents(4, 3)[0], _ents(4, 3), {"B2": "retired"})
    assert sparse.member_ids == ["P1", "P2", "P3"] and sparse.cohort_label == "power_large"
    assert sparse.strength == "exploratory" and sparse.fallback_level == 1
    assert {"entity_id": "B2", "reason": "retired"} in sparse.excluded
    assert {"entity_id": "B0", "reason": "different sector"} in sparse.excluded
    established = resolver.resolve(_ents(7, 1)[0], _ents(7, 1))
    assert established.strength == "established" and established.denominator == 6
    assert established.attributes == ("sector", "size_band", "soc_model", "schedule")  # enough for the finest
    broad = resolver.resolve(_ents(1, 2)[0], _ents(1, 2))
    assert broad.cohort_label == "all_entities_broad" and broad.strength == "exploratory"
    alone = resolver.resolve(_ents(1, 0)[0], _ents(1, 0))
    assert alone.strength == "none" and alone.member_ids == []


def test_a_small_portfolio_is_not_split_by_soc_model():
    """Four power entities with mixed SOC models: the finest level would leave one or two peers,
    so the cohort falls back to sector and size instead of over-partitioning."""
    ents = _ents(4, 0)
    ents[1] = ents[1].model_copy(update={"soc_model": "mssp"})
    cohort = PeerResolver().resolve(ents[0], ents)
    assert cohort.attributes == ("sector", "size_band") and cohort.member_ids == ["P1", "P2", "P3"]


# --- provider-level leads --------------------------------------------------------------------


def test_hypergeometric_tail_and_bh_values():
    assert hypergeom_upper_tail(3, 3, 3, 10) == pytest.approx(1 / 120)
    assert hypergeom_upper_tail(0, 3, 3, 10) == 1.0
    assert benjamini_hochberg([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.04, 0.04])


def _finding(entity_id: str, rule_id: str = "NS01"):
    from satsa.models.outputs import Finding

    return Finding(finding_id=f"F-{entity_id}", run_id="R", entity_id=entity_id, rule_id=rule_id, rule_version="1",
                   domain="d", level="entity", score=50, confidence=1, severity="high", title="t", rationale="r",
                   examiner_check="c")


def test_provider_leads_report_affected_assessable_group_and_comparison_rate():
    ents = [Entity(entity_id=f"M{i}", name="m", soc_provider="MSSP-X") for i in range(5)]
    ents += [Entity(entity_id=f"O{i}", name="o", soc_provider="other") for i in range(10)]
    findings = [_finding(f"M{i}") for i in range(3)] + [_finding("O0")]
    # M4 could not be assessed for NS01: it is neither affected nor clear.
    results = [{"entity_id": e.entity_id, "rule_id": "NS01", "state": "insufficient_evidence" if e.entity_id == "M4"
                else ("finding" if e.entity_id in {"M0", "M1", "M2", "O0"} else "assessed_clear")} for e in ents]
    [lead] = SystemicCorrelationDetector().evaluate(ents, findings, "R", results)
    assert (lead["entity_count"], lead["assessable_count"], lead["group_size"]) == (3, 4, 5)
    assert (lead["comparison_affected"], lead["comparison_assessable"]) == (1, 10)
    assert 0 < lead["p_value"] < 0.05 and lead["q_value"] == pytest.approx(lead["p_value"])
    assert "3 of 4 assessable clients" in lead["rationale"] and "1 of 10" in lead["rationale"]
    assert "hypothesis" in lead["rationale"] and "not evidence that the provider caused it" in lead["rationale"]


# --- anomaly baselines never use later values -----------------------------------------------


def test_time_shift_baseline_is_fixed_before_the_months_it_judges():
    scanner = AnomalyScanner()
    months = [f"2025-{m:02d}" for m in range(1, 9)]
    base = [0.30, 0.31, 0.29, 0.30, 0.30, 0.10, 0.10, 0.10]
    series = {"night_share": [(m, v, 200) for m, v in zip(months, base, strict=True)]}
    [signal] = scanner._time_shifts("R", "E", series)
    # Change only the last month: the baseline and the reference months do not move.
    later = {"night_share": [*series["night_share"][:-1], (months[-1], 0.90, 200)]}
    changed = scanner._time_shifts("R", "E", later)
    for s in changed:
        assert s.baseline == signal.baseline and s.detail["reference_months"] == signal.detail["reference_months"]
    # And the default control charts take their baseline from the leading values only.
    assert SPCDetector.cusum([2.0] * 5 + [1.0], min_scale=0.1)[2] == [5]
    lead = SPCDetector.ewma([10.0, 10.5, 9.5, 10.0, 10.2, 10.1, 30.0, 30.0])
    assert lead[2] and lead[2][0] >= 6
    assert SPCDetector.ewma([10.0, 10.5, 9.5, 10.0, 10.2, 10.1, 30.0, 30.0])[1][0] == \
        SPCDetector.ewma([10.0, 10.5, 9.5, 10.0, 10.2, 10.1, 99.0, 99.0])[1][0]


# --- the run: peer records, exceptions, replay -----------------------------------------------


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    root = copy_deployment(tmp_path / "deployment")
    monkeypatch.chdir(root)
    return root


def _run(**kwargs):
    duck, lite = DuckDBStore("data"), SQLiteStore("data/satsa.db")
    try:
        return AssessmentRunner(duck, lite).run_assessment(**kwargs)
    finally:
        duck.close()
        lite.close()


def test_a_run_records_each_cohort_and_applies_exceptions_without_hiding_findings(deployment):
    soon = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=60)).isoformat()
    lite = SQLiteStore("data/satsa.db")
    try:
        latest = lite.conn.execute("SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()[0]
        target = lite.conn.execute(
            "SELECT entity_id, rule_id FROM findings WHERE run_id = ? AND severity <> 'critical' "
            "ORDER BY score DESC, finding_id LIMIT 1", (latest,)
        ).fetchone()
        critical = lite.conn.execute(
            "SELECT entity_id, rule_id FROM findings WHERE run_id = ? AND severity = 'critical' "
            "ORDER BY finding_id LIMIT 1", (latest,)
        ).fetchone()
        for ent, rule in (tuple(target), tuple(critical)):
            xid = context.request_exception(lite, ent, rule, "test scope", "test reason", "REF-1", soon, "ex1", "examiner")
            context.approve_exception(lite, xid, "ex2", "examiner")
    finally:
        lite.close()

    res = _run(period=None)
    run_id = res["run_id"]
    lite = SQLiteStore("data/satsa.db")
    try:
        comparisons = lite.conn.execute("SELECT * FROM peer_comparisons WHERE run_id = ?", (run_id,)).fetchall()
        assert len(comparisons) == res["entities_count"]
        one = lite.get_peer_comparison(run_id, target["entity_id"])
        assert one["denominator"] == len(one["member_ids"]) and one["strength"] in ("established", "exploratory")
        manifest = json.loads(lite.conn.execute("SELECT manifest_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0])
        assert sum(manifest["peer_comparisons"].values()) == res["entities_count"]

        kept = lite.conn.execute(
            "SELECT exception_id FROM findings WHERE run_id = ? AND entity_id = ? AND rule_id = ?",
            (run_id, target["entity_id"], target["rule_id"]),
        ).fetchone()
        assert kept is not None and kept["exception_id"].startswith("EXC-")  # recorded and shown, not deleted
        # Not queued: no risk-selected record of the entity cites the excepted rule.
        reasons = [r[0] for r in lite.conn.execute(
            "SELECT selection_reason FROM review_queue WHERE run_id = ? AND entity_id = ? AND NOT is_random",
            (run_id, target["entity_id"]),
        )]
        assert not any(target["rule_id"] in reason for reason in reasons)
        not_covered = lite.conn.execute(
            "SELECT f.exception_id, r.reason FROM findings f JOIN rule_results r USING (run_id, entity_id, rule_id) "
            "WHERE f.run_id = ? AND f.entity_id = ? AND f.rule_id = ?",
            (run_id, critical["entity_id"], critical["rule_id"]),
        ).fetchone()
        assert not_covered["exception_id"] is None and "never covered" in not_covered["reason"]
        selection = json.loads(lite.conn.execute("SELECT selection_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0])
        assert len(selection["rule_exceptions"]) == 2

        # Revoke the exception afterwards: a replay still sees what the run saw.
        xid = kept["exception_id"]
        context.revoke_exception(lite, xid, "ex3", "examiner", "no longer justified")
        replay = replay_run(run_id, "data", lite)
        assert replay["results_match"] and "selection" not in replay["differences"]
    finally:
        lite.close()

    # The next run counts the finding again.
    res2 = _run(period=None)
    lite = SQLiteStore("data/satsa.db")
    try:
        again = lite.conn.execute(
            "SELECT exception_id FROM findings WHERE run_id = ? AND entity_id = ? AND rule_id = ?",
            (res2["run_id"], target["entity_id"], target["rule_id"]),
        ).fetchone()
        assert again is not None and again["exception_id"] is None
    finally:
        lite.close()
