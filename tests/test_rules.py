"""Test detection rules EG01-EG12 and NS01-NS08 on ingested synthetic data."""

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
