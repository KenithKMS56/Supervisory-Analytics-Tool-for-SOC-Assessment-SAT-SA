"""Test detection rules EG01-EG12 and NS01-NS08 on ingested synthetic data."""

from datetime import datetime

from satsa.rules.registry import RuleRegistry
from satsa.store.duckdb import DuckDBStore


def test_rule_registry_loading():
    registry = RuleRegistry("config/rules.yaml")
    rules = registry.get_all_rules()
    assert len(rules) == 20
    assert registry.get_rule("EG01") is not None
    assert registry.get_rule("NS01") is not None


def test_injected_defects_detection():
    store = DuckDBStore("data")
    store.load_all_tables()
    registry = RuleRegistry("config/rules.yaml")

    run_id = "test-eval-run-01"
    all_peer_ids = [
        "CSE-01",
        "CSE-02",
        "CSE-03",
        "CSE-04",
        "CSE-05",
        "CSE-06",
        "CSE-07",
        "CSE-08",
        "CSE-09",
        "CSE-10",
    ]

    # 1. CSE-03: Fast closure (EG01) and missing escalation (EG03)
    eg01 = registry.get_rule("EG01")
    assert eg01 is not None
    f01, _ = eg01.evaluate("CSE-03", store, all_peer_ids, run_id)
    assert len(f01) == 1
    assert "fast" in f01[0].title.lower()

    eg03 = registry.get_rule("EG03")
    assert eg03 is not None
    f03, _ = eg03.evaluate("CSE-03", store, all_peer_ids, run_id)
    assert len(f03) == 1

    # 2. CSE-07: Template comments (EG04) and metric gaming (EG06)
    eg04 = registry.get_rule("EG04")
    assert eg04 is not None
    f04, _ = eg04.evaluate("CSE-07", store, all_peer_ids, run_id)
    assert len(f04) == 1

    eg06 = registry.get_rule("EG06")
    assert eg06 is not None
    f06, _ = eg06.evaluate("CSE-07", store, all_peer_ids, run_id)
    assert len(f06) == 1

    # 3. CSE-09: Repeat alerts, no root cause (EG05)
    eg05 = registry.get_rule("EG05")
    assert eg05 is not None
    f05, _ = eg05.evaluate("CSE-09", store, all_peer_ids, run_id)
    assert len(f05) == 1

    # 4. CSE-05: Silent critical assets (NS01) and ghost assets (NS06)
    ns01 = registry.get_rule("NS01")
    assert ns01 is not None
    fns01, _ = ns01.evaluate("CSE-05", store, all_peer_ids, run_id)
    assert len(fns01) == 1

    ns06 = registry.get_rule("NS06")
    assert ns06 is not None
    fns06, _ = ns06.evaluate("CSE-05", store, all_peer_ids, run_id)
    assert len(fns06) == 1

    # 5. CSE-08: Missing categories (NS02) and missing records (NS04)
    ns02 = registry.get_rule("NS02")
    assert ns02 is not None
    fns02, _ = ns02.evaluate("CSE-08", store, all_peer_ids, run_id)
    assert len(fns02) == 1

    # 6. CSE-10: Night flatline (NS03)
    ns03 = registry.get_rule("NS03")
    assert ns03 is not None
    fns03, _ = ns03.evaluate("CSE-10", store, all_peer_ids, run_id)
    assert len(fns03) == 1

    # 7. Verify Clean baseline: CSE-01 must not trigger fast closure EG01
    clean_f01, _ = eg01.evaluate("CSE-01", store, all_peer_ids, run_id)
    assert len(clean_f01) == 0

    store.close()


def test_findings_cite_checkable_evidence_not_placeholders():
    """EG10, EG11 and NS08 used to cite invented IDs (KPI-GAP-<entity>, DISP-EXTREME-<entity>,
    MISSING-MONTHS-<entity>). They now cite the declared KPI rows, a sample of the alerts, and
    the actual missing months."""
    store = DuckDBStore("data")
    store.load_all_tables()
    registry = RuleRegistry("config/rules.yaml")
    try:
        eg10, eg10_ev = registry.get_rule("EG10").evaluate("CSE-02", store, [], "RUN-X")
        assert eg10[0].evidence_ids and all(e.startswith("MTTR:") for e in eg10[0].evidence_ids)
        assert [e.record_id for e in eg10_ev] == eg10[0].evidence_ids

        eg11, eg11_ev = registry.get_rule("EG11").evaluate("CSE-07", store, [], "RUN-X")
        alert_ids = set(store.query("SELECT alert_id FROM alert WHERE entity_id = 'CSE-07'")["alert_id"].to_list())
        assert eg11[0].evidence_ids and set(eg11[0].evidence_ids) <= alert_ids
        assert {e.record_type for e in eg11_ev} == {"alert"}

        ns08, _ = registry.get_rule("NS08").evaluate("CSE-10", store, [], "RUN-X")
        assert ns08[0].evidence_ids == ["missing-month:2026-06"]
    finally:
        store.close()


def test_every_finding_carries_evidence_records():
    """NS03, NS05 and NS08 used to return findings with no FindingEvidence rows at all
    (EG11 too, until it began citing sample alerts). Every finding on the demo dataset must
    now carry supporting rows that exist in the stored data."""
    store = DuckDBStore("data")
    store.load_all_tables()
    registry = RuleRegistry("config/rules.yaml")
    entities = store.query("SELECT entity_id FROM entity ORDER BY entity_id")["entity_id"].to_list()
    alert_ids = set(store.query("SELECT alert_id FROM alert")["alert_id"].to_list())
    rule_ids = set(store.query("SELECT rule_id FROM detection_rule")["rule_id"].to_list())
    checked = 0
    try:
        for rule in registry.get_all_rules():
            for entity_id in entities:
                findings, evidences = rule.evaluate(entity_id, store, [], "RUN-X")
                for finding in findings:
                    own = [e for e in evidences if e.finding_id == finding.finding_id]
                    assert own, f"{rule.id} on {entity_id} has no evidence records"
                    checked += 1
                    for e in own:
                        if e.record_type == "alert":
                            assert e.record_id in alert_ids, (rule.id, e.record_id)
                        if e.record_type == "detection_rule":
                            assert e.record_id in rule_ids, (rule.id, e.record_id)
        ns03, ns03_ev = registry.get_rule("NS03").evaluate("CSE-10", store, [], "RUN-X")
        assert ns03 and {e.details["reason"] for e in ns03_ev} == {"Last alert recorded that day"}
        ns08, ns08_ev = registry.get_rule("NS08").evaluate("CSE-10", store, [], "RUN-X")
        assert ns08 and [e.details["reason"] for e in ns08_ev] == ["Last alert before the gap in 2026-06"]
    finally:
        store.close()
    assert checked >= 19


# ------------------------------------------------------------------ closures, not open alerts


def _insert_alert(store, alert_id, *, closed, comment_len=None, investigated=False):
    created = datetime(2026, 2, 1, 9, 0, 0)
    store.execute(
        "INSERT INTO alert (entity_id, alert_id, rule_id, severity_final, created_at, closed_at, closed_by, "
        "closed_by_type, status) VALUES ('E1', ?, 'R1', 'medium', ?, ?, 'ANALYST_1', 'human', ?)",
        [alert_id, created, datetime(2026, 2, 1, 12, 0, 0) if closed else None, "closed" if closed else "open"],
    )
    if comment_len is not None:
        store.execute(
            "INSERT INTO closure (entity_id, ref_id, reason_code, disposition, comment_norm_hash, comment_len) "
            "VALUES ('E1', ?, 'none', 'benign', 'samehash', ?)",
            [alert_id, comment_len],
        )
    if investigated:
        store.execute(
            "INSERT INTO workflow_event (entity_id, ref_type, ref_id, ts, action) VALUES ('E1', 'alert', ?, ?, 'investigate')",
            [alert_id, created],
        )


def test_eg02_and_eg04_judge_closures_not_alerts_still_open(tmp_path):
    """Open alerts have no closure. Counting them made EG02 report them as closed uninvestigated
    and watered down EG04's share. Synthetic data never showed it: there, every alert is closed."""
    store = DuckDBStore(tmp_path / "pq")
    try:
        for i in range(40):  # closed properly: investigated, real comment, each its own text
            _insert_alert(store, f"OK{i}", closed=True, comment_len=80, investigated=True)
            store.execute("UPDATE closure SET comment_norm_hash = ? WHERE ref_id = ?", [f"h{i}", f"OK{i}"])
        for i in range(30):  # still open: nothing recorded yet
            _insert_alert(store, f"OPEN{i}", closed=False)
        registry = RuleRegistry()
        assert registry.get_rule("EG02").evaluate("E1", store, [], "RUN")[0] == []

        for i in range(12):  # closed with one boilerplate comment, uninvestigated
            _insert_alert(store, f"BAD{i}", closed=True, comment_len=10)
        eg02 = registry.get_rule("EG02").evaluate("E1", store, [], "RUN")[0]
        assert eg02 and "12 of 52 alerts" in eg02[0].rationale  # 52 closures; the 30 open alerts are not counted
        eg04 = registry.get_rule("EG04").evaluate("E1", store, [], "RUN")[0]
        assert eg04 == []  # 12 of 52 closures = 23%, under the 25% threshold
        for i in range(12, 16):
            _insert_alert(store, f"BAD{i}", closed=True, comment_len=10)
        assert registry.get_rule("EG04").evaluate("E1", store, [], "RUN")[0]  # 16 of 56 = 29%
    finally:
        store.close()
