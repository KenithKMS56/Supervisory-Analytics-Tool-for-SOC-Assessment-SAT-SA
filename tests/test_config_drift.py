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
    "EG04": {"max_comment_hash_share": 0.25, "min_hash_group_size": 10},
    "EG05": {"min_repeat_count": 8, "min_unaddressed_pairs": 2},
    "EG10": {"mttr_gap_ratio_threshold": 0.60},
    "NS01": {"min_silent_days": 3, "min_asset_criticality": 3},
    "NS02": {"min_peer_entity_count": 6},
    "NS03": {"max_night_share": 0.03, "min_alert_volume": 100},
}


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
