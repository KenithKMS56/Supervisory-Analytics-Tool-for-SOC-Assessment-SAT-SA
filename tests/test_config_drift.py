"""Config/tuning drift: every tunable threshold in config/rules.yaml must be live.

(a) Structural: every key under rules.<ID>.params is read by that rule class via
    self.params.get("<key>", ...), no rule carries stray top-level keys, and the
    Tuning page offers exactly the params the YAML declares.
(b) Behavioral: changing EG04's max_comment_hash_share through the config makes
    a previously-firing EG04 finding disappear, and the default brings it back --
    proving the config path is actually wired, not just structurally present.
(c) UI round-trip: posting the Tuning form's field names to /tuning/save lands
    in cfg["rules"][RULE]["params"][key] and is picked up by the rule registry.
"""

import inspect
import re
from datetime import datetime
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from satsa.api.routes import TUNABLE_PARAMS, app
from satsa.rules.registry import RuleRegistry
from satsa.store.duckdb import DuckDBStore

CONFIG = Path("config/rules.yaml")
ALLOWED_TOP_LEVEL = {"name", "version", "domain", "level", "min_sample", "severity_weight",
                     "description", "params"}
RULE_CLASSES = {cls.id: cls for cls in RuleRegistry.RULE_CLASSES}
EXPECTED_PARAMS = {
    "EG01": {"fast_share_threshold": 0.15, "min_fast_count": 5},
    "EG02": {"max_uninvestigated_share": 0.15, "min_uninvestigated_count": 5},
    "EG04": {"max_comment_hash_share": 0.25, "min_hash_group_size": 10},
    "EG05": {"min_repeat_count": 8, "min_unaddressed_pairs": 2, "max_chance_pairs": 0.5},
    "EG06": {"min_bulk_closures_per_minute": 8, "max_deadline_hugging_share": 0.25},
    "EG07": {"min_closures_per_analyst_hour": 30},
    "EG08": {"min_unacknowledged_escalations": 3},
    "EG09": {"stale_case_days": 14, "min_stale_cases": 3},
    "EG10": {"mttr_gap_ratio_threshold": 0.60},
    "EG11": {"min_alert_volume": 200, "max_robust_z": 3.5, "min_spread": 0.01, "max_fp_rate": 0.98},
    "EG12": {"min_skipped_cases": 2},
    "NS01": {"min_silent_days": 3, "min_asset_criticality": 3},
    "NS02": {"min_peer_share": 0.6},
    "NS03": {"max_night_share": 0.03, "min_alert_volume": 100, "max_robust_z": 3.5, "min_spread": 0.02},
    "NS04": {"min_tp_without_case": 3},
    "NS05": {"max_dormant_share": 0.40, "min_dormant_rules": 5},
    "NS06": {"min_ghost_assets": 2},
    "NS08": {"review_period_months": 6},
}
# EG03 and NS07 are zero-tolerance (one unescalated critical TP / one unreported critical
# incident is a finding): no knobs.
UNTUNABLE_RULES = {"EG03", "NS07"}


def _cfg() -> dict:
    return yaml.safe_load(CONFIG.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- (a) structural


def test_yaml_params_are_exactly_the_tunable_set():
    declared = {rid: meta.get("params", {}) for rid, meta in _cfg()["rules"].items() if meta.get("params")}
    assert declared == EXPECTED_PARAMS


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_PARAMS))
def test_every_yaml_param_is_read_by_its_rule(rule_id):
    source = inspect.getsource(RULE_CLASSES[rule_id])
    for key in _cfg()["rules"][rule_id]["params"]:
        assert f'self.params.get("{key}"' in source, f"{rule_id} never reads params[{key!r}]"


def test_code_defaults_match_yaml_values():
    """Removing a key from the YAML must not change behaviour (defaults == YAML)."""
    for rule_id, params in EXPECTED_PARAMS.items():
        source = inspect.getsource(RULE_CLASSES[rule_id])
        for key, value in params.items():
            m = re.search(rf'self\.params\.get\("{key}", ([0-9.]+)\)', source)
            assert m, (rule_id, key)
            assert float(m.group(1)) == float(value), (rule_id, key, m.group(1), value)


def test_no_stray_top_level_keys():
    for rule_id, meta in _cfg()["rules"].items():
        stray = set(meta) - ALLOWED_TOP_LEVEL
        assert not stray, f"{rule_id} has keys no code reads: {stray}"


def test_every_rule_in_yaml_exists():
    assert set(_cfg()["rules"]) == set(RULE_CLASSES)


def test_every_rule_is_tunable_or_deliberately_knob_free():
    """A hardcoded threshold can't be tuned or covered by the threshold-sensitivity sweep."""
    assert set(EXPECTED_PARAMS) | UNTUNABLE_RULES == set(RULE_CLASSES)
    assert not set(EXPECTED_PARAMS) & UNTUNABLE_RULES


def test_tuning_page_offers_exactly_the_yaml_params():
    offered = {(p["rule"], p["key"]) for p in TUNABLE_PARAMS}
    declared = {(rid, key) for rid, params in EXPECTED_PARAMS.items() for key in params}
    assert offered == declared


def test_no_fake_ns07_window_knob():
    assert "params" not in _cfg()["rules"]["NS07"]
    assert "6 hours" not in inspect.getsource(RULE_CLASSES["NS07"])
    assert not any(p["rule"] == "NS07" for p in TUNABLE_PARAMS)


# ---------------------------------------------------------------- (b) behavioral


def _write_config(tmp_path: Path, **eg04_params) -> Path:
    cfg = _cfg()
    cfg["rules"]["EG04"]["params"].update(eg04_params)
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.dump(cfg, sort_keys=False), encoding="utf-8")
    return path


@pytest.fixture
def eg04_fixture_store(tmp_path):
    """40 human-closed alerts; 20 share one normalized comment hash (share 0.50)."""
    store = DuckDBStore(tmp_path / "store")
    for i in range(40):
        store.execute(
            "INSERT INTO alert (entity_id, alert_id, closed_by_type) VALUES (?, ?, 'human')",
            ["EG4-ENT", f"A{i:03d}"],
        )
        comment_hash = "BOILERPLATE" if i < 20 else f"UNIQUE-{i}"
        store.execute(
            "INSERT INTO closure (entity_id, ref_id, comment_norm_hash) VALUES (?, ?, ?)",
            ["EG4-ENT", f"A{i:03d}", comment_hash],
        )
    yield store
    store.close()


def test_eg04_threshold_is_live_on_fixture(tmp_path, eg04_fixture_store):
    default_rule = RuleRegistry(_write_config(tmp_path)).get_rule("EG04")
    findings, _ = default_rule.evaluate("EG4-ENT", eg04_fixture_store, [], "RUN-X")
    assert len(findings) == 1

    raised_rule = RuleRegistry(_write_config(tmp_path, max_comment_hash_share=0.99)).get_rule("EG04")
    findings, _ = raised_rule.evaluate("EG4-ENT", eg04_fixture_store, [], "RUN-X")
    assert findings == []

    # min_hash_group_size is live too: groups of 20 no longer qualify at 21.
    big_group_rule = RuleRegistry(_write_config(tmp_path, min_hash_group_size=21)).get_rule("EG04")
    findings, _ = big_group_rule.evaluate("EG4-ENT", eg04_fixture_store, [], "RUN-X")
    assert findings == []


def test_eg04_threshold_is_live_on_demo_dataset(tmp_path):
    """The real demo finding (CSE-07) disappears at 0.99 and returns at the default."""
    store = DuckDBStore("data")
    store.load_all_tables()
    try:
        default_rule = RuleRegistry(_write_config(tmp_path)).get_rule("EG04")
        assert default_rule.evaluate("CSE-07", store, [], "RUN-X")[0], "expected demo EG04 finding"

        raised_rule = RuleRegistry(_write_config(tmp_path, max_comment_hash_share=0.99)).get_rule("EG04")
        assert raised_rule.evaluate("CSE-07", store, [], "RUN-X")[0] == []

        restored_rule = RuleRegistry(_write_config(tmp_path, max_comment_hash_share=0.25)).get_rule("EG04")
        assert restored_rule.evaluate("CSE-07", store, [], "RUN-X")[0]
    finally:
        store.close()


# ---------------------------------------------------------------- (c) UI round trip


@pytest.fixture
def analyst_client():
    original = CONFIG.read_bytes()
    c = TestClient(app)
    r = c.post(
        "/login",
        data={"username": "analyst", "password": "ChangeMe-Analyst#2026"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    yield c
    CONFIG.write_bytes(original)


def test_tuning_page_renders_real_labels(analyst_client):
    html = analyst_client.get("/tuning").text
    assert "EG01 - min share of closures faster than peer p5" in html
    assert 'name="EG04__max_comment_hash_share"' in html
    assert 'value="0.25"' in html
    assert "NS07 Statutory Reporting Window" not in html


def test_tuning_save_round_trips_into_running_config(analyst_client):
    resp = analyst_client.post(
        "/tuning/save",
        data={"EG04__max_comment_hash_share": "0.3", "NS01__min_silent_days": "4"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    cfg = _cfg()
    assert cfg["rules"]["EG04"]["params"]["max_comment_hash_share"] == 0.3
    assert cfg["rules"]["NS01"]["params"]["min_silent_days"] == 4
    # Untouched params keep their values; no stray top-level keys are written.
    assert cfg["rules"]["EG04"]["params"]["min_hash_group_size"] == 10
    assert set(cfg["rules"]["EG04"]) <= ALLOWED_TOP_LEVEL
    # The header comment survives the rewrite.
    assert CONFIG.read_text(encoding="utf-8").startswith("# SAT-SA rule configuration.")

    registry = RuleRegistry(CONFIG)
    assert registry.get_rule("EG04").params["max_comment_hash_share"] == 0.3
    assert registry.get_rule("NS01").params["min_silent_days"] == 4


@pytest.mark.parametrize("bad", ["abc", "-1", "2.5"])
def test_tuning_save_rejects_invalid_values(analyst_client, bad):
    before = CONFIG.read_bytes()
    resp = analyst_client.post("/tuning/save", data={"EG04__max_comment_hash_share": bad})
    assert resp.status_code == 422
    assert CONFIG.read_bytes() == before


# ---------------------------------------------------------------- (d) preview and period


def _state(store_path: str = "data/satsa.db") -> tuple[int, int, int, bytes]:
    from satsa.store.sqlite import SQLiteStore

    store = SQLiteStore(store_path)
    counts = tuple(
        store.conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
        for t in ("runs", "findings", "audit_log")
    )
    store.close()
    return (*counts, CONFIG.read_bytes())


def test_tuning_preview_shows_the_effect_and_persists_nothing(analyst_client):
    before = _state()
    resp = analyst_client.post("/tuning/preview", data={"EG04__max_comment_hash_share": "0.99"})
    assert resp.status_code == 200
    html = resp.text
    assert "Preview only" in html and "CSE-07 / EG04" in html  # the demo EG04 finding would disappear
    assert 'value="0.99"' in html  # the form keeps the proposed value
    # No config write, no run, no findings, no audit entry.
    assert _state() == before


def test_tuning_preview_rejects_invalid_values_like_save(analyst_client):
    before = _state()
    assert analyst_client.post("/tuning/preview", data={"EG04__max_comment_hash_share": "7"}).status_code == 422
    assert analyst_client.post("/tuning/preview", data={"period": "next quarter"}).status_code == 422
    assert _state() == before


def test_tuning_save_reruns_the_selected_period_not_a_hardcoded_one(analyst_client):
    from satsa.store.sqlite import SQLiteStore

    def latest() -> tuple[str, str]:
        store = SQLiteStore("data/satsa.db")
        row = store.conn.execute("SELECT run_id, period FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
        store.close()
        return row["run_id"], row["period"]

    created: list[str] = []
    try:
        resp = analyst_client.post("/tuning/save", data={"period": "2026-H1"}, follow_redirects=False)
        assert resp.status_code == 303
        run_id, period = latest()
        created.append(run_id)
        assert period == "2026-H1"
        # With no period given, the latest run's period is kept (it used to snap back to 2026-Q1).
        resp = analyst_client.post("/tuning/save", data={}, follow_redirects=False)
        assert resp.status_code == 303
        run_id, period = latest()
        created.append(run_id)
        assert period == "2026-H1"
    finally:
        from satsa.store.sqlite import SQLiteStore as _Store

        store = _Store("data/satsa.db")
        for rid in created:
            for table in ("runs", "entity_scores", "domain_scores", "findings", "review_queue"):
                store.conn.execute(f"DELETE FROM {table} WHERE run_id = ?", (rid,))
        store.conn.commit()
        store.close()


# ---------------------------------------------------------------- NS08 review period


def _ns08_store(tmp_path, months_by_entity):
    store = DuckDBStore(tmp_path / "ns08")
    n = 0
    for entity, months in months_by_entity.items():
        for month in months:
            n += 1
            store.execute(
                "INSERT INTO alert (entity_id, alert_id, created_at) VALUES (?, ?, ?)",
                [entity, f"A{n}", datetime(2026, month, 10, 9, 0, 0)],
            )
    return store


def test_ns08_review_period_comes_from_config(tmp_path):
    """A lone entity with 4 months of alerts: short of a 6-month period, complete for a 4-month one."""
    from satsa.rules.negative_space import NS08SubmissionCompleteness

    store = _ns08_store(tmp_path, {"SOLO": [1, 2, 3, 4]})
    try:
        default = NS08SubmissionCompleteness()
        findings, _ = default.evaluate("SOLO", store, [], "RUN-X")
        assert findings and findings[0].peer_comparison == {"active_months": 4, "expected_months": 6}

        four = NS08SubmissionCompleteness({"params": {"review_period_months": 4}})
        assert four.evaluate("SOLO", store, [], "RUN-X")[0] == []

        twelve = NS08SubmissionCompleteness({"params": {"review_period_months": 12}})
        findings, _ = twelve.evaluate("SOLO", store, [], "RUN-X")
        assert findings[0].peer_comparison["expected_months"] == 12
        assert "12-month supervisory review period" in findings[0].rationale
    finally:
        store.close()


@pytest.mark.parametrize("bad", [0, -3, 25, 600, 6.5, "6", True, None])
def test_ns08_review_period_out_of_range_is_rejected(bad):
    from satsa.rules.negative_space import NS08SubmissionCompleteness

    with pytest.raises(ValueError, match="review_period_months must be a whole number of months between 1 and 24"):
        NS08SubmissionCompleteness({"params": {"review_period_months": bad}})


def test_out_of_range_review_period_in_rules_yaml_stops_the_registry(tmp_path):
    cfg = _cfg()
    cfg["rules"]["NS08"]["params"]["review_period_months"] = 99
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.dump(cfg, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="review_period_months"):
        RuleRegistry(path)


def test_tuning_form_rejects_an_out_of_range_review_period():
    from fastapi import HTTPException

    from satsa.api.routes import _apply_tuning_form

    with pytest.raises(HTTPException) as exc:
        _apply_tuning_form({"NS08__review_period_months": "30"}, _cfg())
    assert exc.value.status_code == 422
    cfg, changes = _apply_tuning_form({"NS08__review_period_months": "3"}, _cfg())
    assert cfg["rules"]["NS08"]["params"]["review_period_months"] == 3
    assert changes == {"NS08__review_period_months": {"old": 6, "new": 3}}
