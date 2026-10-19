"""Independent pilot evaluation from blinded reviews (satsa.validate.pilot; docs/product_brief.md
section 14).

A small, fully known deployment: ten entities with set bands, one blind sample reviewed by two
examiners, and a third who adjudicates. Every expected figure below follows from the judgements
the test records, so the evaluation is checked against independent arithmetic, not against itself.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest
from case_fixtures import make_store
from typer.testing import CliRunner

from satsa.cases import blind
from satsa.cases.workflow import CaseForbidden, CaseInvalid
from satsa.deployment import DEMO, mode
from satsa.validate import pilot

RUN = "RUN-PILOT-1"
OTHER_RUN = "RUN-PILOT-2"
BANDS = {f"E-{i:02d}": ("High" if i <= 3 else "Moderate" if i <= 6 else "Low") for i in range(1, 11)}


def _add_run(store, run_id: str, config_hash: str) -> None:
    with store.transaction():
        store.conn.execute(
            "INSERT INTO runs (run_id, period, created_at, config_hash, code_version, status) "
            "VALUES (?, '2026-Q1', ?, ?, 'test', 'completed')", (run_id, dt.datetime.now(dt.UTC).isoformat(), config_hash))
        for i, (entity, band) in enumerate(sorted(BANDS.items())):
            store.conn.execute(
                "INSERT INTO entity_scores (run_id, entity_id, risk_index, risk_band, distinct_rules_triggered, "
                "classification_status) VALUES (?, ?, ?, ?, 0, 'assessable')", (run_id, entity, 90 - 8 * i, band))


@pytest.fixture
def store(tmp_path):
    s = make_store(tmp_path)
    for name, role in (("analyst", "analyst"), ("examiner", "examiner")):
        if not s.conn.execute("SELECT 1 FROM identities WHERE username = ?", (name,)).fetchone():
            s.create_user(name, role, "Pilot-Test-Passphrase#2026")
    _add_run(s, RUN, "cfgA")
    yield s
    s.close()


def _kinds(store, sample_id: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {"flagged": [], "random": [], "control": []}
    for r in store.conn.execute("SELECT * FROM blind_tasks WHERE sample_id = ? ORDER BY position", (sample_id,)):
        out[r["sample_kind"]].append(dict(r))
    for tasks in out.values():
        tasks.sort(key=lambda t: (json.loads(t["provenance_json"]).get("rank") or 0, t["entity_id"]))
    return out


def _judge(store, sample_id: str, reviewer: str, labels: dict[str, str | None]) -> None:
    """Open and submit the reviewer's task for each entity; None leaves it unanswered."""
    for t in store.conn.execute("SELECT task_id, entity_id FROM blind_tasks WHERE sample_id = ?", (sample_id,)).fetchall():
        concern = labels[t["entity_id"]]
        pilot.open_task(store, t["task_id"], reviewer)
        if concern is None:
            continue
        blind.submit(store, t["task_id"], reviewer, "examiner", concern, "P3", "Advisory", "Reviewed the raw signals.")
        # A fixed two minutes of review, so the time figures are known.
        store.conn.execute("UPDATE blind_tasks SET opened_at = ? WHERE task_id = ?",
                           ((dt.datetime.fromisoformat(store.conn.execute(
                               "SELECT submitted_at FROM blind_tasks WHERE task_id = ?", (t["task_id"],)).fetchone()[0])
                             - dt.timedelta(seconds=120)).isoformat(), t["task_id"]))


@pytest.fixture
def reviewed(store):
    """Protocol frozen first; then a sample, a replica, and both examiners' judgements."""
    proto = pilot.freeze_protocol(store, "pilot-1", RUN, "analyst", "analyst", seed=11, calibration_fraction=0.0,
                                  budget=2)
    sample = blind.create_sample(store, RUN, "analyst", "analyst", "examiner", 3, 2, 2, seed=5)
    replica = pilot.replicate_sample(store, sample["sample_id"], "examiner2", "analyst", "analyst")
    k = _kinds(store, sample["sample_id"])
    f1, f2, f3 = (t["entity_id"] for t in k["flagged"])
    c1, c2 = (t["entity_id"] for t in k["control"])
    r1, r2 = (t["entity_id"] for t in k["random"])
    first = {f1: "Elevated", f2: "Critical", f3: "Low", c1: "Critical", c2: "Low", r1: "Low", r2: "Moderate"}
    second = {**first, f1: "Moderate", r1: None}  # disagrees on f1, leaves r1 unanswered
    _judge(store, sample["sample_id"], "examiner", first)
    _judge(store, replica["sample_id"], "examiner2", second)
    return {"protocol": proto["protocol_id"], "sample": sample, "replica": replica,
            "f": (f1, f2, f3), "c": (c1, c2), "r": (r1, r2)}


# ---------------------------------------------------------------- statistics


def test_cohens_kappa_matches_the_textbook_value():
    pairs = [(0, 0)] * 20 + [(0, 1)] * 5 + [(1, 0)] * 10 + [(1, 1)] * 15
    assert pilot.cohens_kappa(pairs, 2) == pytest.approx(0.4)  # p_o 0.70, p_e 0.50
    assert pilot.cohens_kappa([(1, 1), (0, 0)], 2) == pytest.approx(1.0)
    assert pilot.cohens_kappa([], 2) is None
    assert pilot.cohens_kappa([(1, 1), (1, 1)], 2) is None  # chance agreement is total: undefined
    # Linear weights give partial credit to a near miss on the four levels.
    assert pilot.cohens_kappa([(0, 1), (1, 2), (2, 3), (3, 3), (0, 0)], 4, weighted=True) > \
        pilot.cohens_kappa([(0, 1), (1, 2), (2, 3), (3, 3), (0, 0)], 4)


def test_the_entity_cluster_interval_is_wider_than_one_that_ignores_clustering():
    # Two entities, each with many perfectly correlated units: in effect two observations.
    units = [("A", True)] * 20 + [("B", False)] * 20
    ci = pilot.cluster_bootstrap_ci(units, seed=1)
    assert ci is not None and ci[0] <= 0.05 and ci[1] >= 0.95
    assert pilot.cluster_bootstrap_ci([("A", True)] * 5, seed=1) is None
    assert pilot.cluster_bootstrap_ci(units, seed=1) == pilot.cluster_bootstrap_ci(units, seed=1)  # reproducible


def test_the_split_is_seeded_and_keeps_its_share():
    entities = [f"E-{i:02d}" for i in range(1, 21)]
    a = pilot.split_entities(entities, 7, 0.3)
    assert a == pilot.split_entities(list(reversed(entities)), 7, 0.3)
    assert sum(v == "calibration" for v in a.values()) == 6
    assert a != pilot.split_entities(entities, 8, 0.3)
    with pytest.raises(CaseInvalid):
        pilot.split_entities(entities, 7, 1.0)


# ---------------------------------------------------------------- protocol and reviewers


def test_a_protocol_is_frozen_once_by_an_analyst(store):
    res = pilot.freeze_protocol(store, "p", RUN, "analyst", "analyst", seed=3, calibration_fraction=0.3)
    assert res["config_hash"] == "cfgA" and len(res["calibration"]) == 3 and len(res["held_out"]) == 7
    with pytest.raises(CaseInvalid):
        pilot.freeze_protocol(store, "p", RUN, "analyst", "analyst")
    with pytest.raises(CaseForbidden):
        pilot.freeze_protocol(store, "q", RUN, "examiner", "examiner")
    audit = [r[0] for r in store.conn.execute("SELECT action FROM audit_log")]
    assert "pilot_protocol_frozen" in audit


def test_a_replica_has_the_same_entities_in_its_own_order_for_another_examiner(store):
    sample = blind.create_sample(store, RUN, "analyst", "analyst", "examiner", 3, 3, 3, seed=9)
    replica = pilot.replicate_sample(store, sample["sample_id"], "examiner2", "analyst", "analyst")

    def tasks(sid):
        return [(r["entity_id"], r["sample_kind"]) for r in store.conn.execute(
            "SELECT entity_id, sample_kind FROM blind_tasks WHERE sample_id = ? ORDER BY position", (sid,))]

    a, b = tasks(sample["sample_id"]), tasks(replica["sample_id"])
    assert sorted(a) == sorted(b) and a != b, "same entities and kinds, another order"
    with pytest.raises(CaseInvalid):  # the first reviewer cannot be the second
        pilot.replicate_sample(store, sample["sample_id"], "examiner", "analyst", "analyst")
    with pytest.raises(CaseInvalid):  # nor can a reviewer of an existing replica
        pilot.replicate_sample(store, sample["sample_id"], "examiner2", "analyst", "analyst")
    with pytest.raises(CaseInvalid):
        pilot.replicate_sample(store, replica["sample_id"], "examiner3", "analyst", "analyst")
    with pytest.raises(CaseForbidden):
        pilot.replicate_sample(store, sample["sample_id"], "examiner3", "examiner", "examiner")


def test_opening_a_task_starts_the_review_time_once(store):
    sample = blind.create_sample(store, RUN, "analyst", "analyst", "examiner", 1, 0, 0, seed=1)
    task = store.conn.execute("SELECT task_id FROM blind_tasks WHERE sample_id = ?", (sample["sample_id"],)).fetchone()[0]
    pilot.open_task(store, task, "examiner2")  # not theirs: nothing recorded
    assert store.conn.execute("SELECT opened_at FROM blind_tasks WHERE task_id = ?", (task,)).fetchone()[0] is None
    pilot.open_task(store, task, "examiner")
    first = store.conn.execute("SELECT opened_at FROM blind_tasks WHERE task_id = ?", (task,)).fetchone()[0]
    pilot.open_task(store, task, "examiner")
    assert first and store.conn.execute("SELECT opened_at FROM blind_tasks WHERE task_id = ?", (task,)).fetchone()[0] == first


# ---------------------------------------------------------------- evaluation


def test_the_evaluation_follows_from_the_recorded_judgements(store, reviewed):
    res = pilot.evaluate(store, reviewed["protocol"])
    held = res["held_out"]
    # The test deployment is a demonstration one, so the figures are labelled synthetic.
    assert res["synthetic"] is (mode(store) == DEMO) and res["runs_evaluated"] == [RUN]
    assert held["units"] == 7
    # f1 is an unresolved disagreement: left out, and not counted as a negative.
    assert held["unresolved_disagreements"] == 1 and held["labelled"] == 6 and held["unanswered"] == 0
    assert held["arms"]["flagged"]["n"] == 2 and held["arms"]["flagged"]["positive"] == 1   # f2 yes, f3 no
    assert held["arms"]["control"]["n"] == 2 and held["arms"]["control"]["positive"] == 1   # c1
    assert held["arms"]["random"]["n"] == 2 and held["arms"]["random"]["positive"] == 0
    assert held["arms"]["flagged"]["budget"] == {"reviewed": 2, "important": 1}
    assert held["false_positives"] == {"n": 2, "not_important": 1}
    assert [m["entity_id"] for m in held["missed_important"]] == [reviewed["c"][0]]
    assert held["arms"]["flagged"]["wilson_95"] is not None
    # Six entities were reviewed twice; they agree on five (important or not).
    assert res["agreement"]["pairs"] == 6 and res["agreement"]["observed_binary"] == pytest.approx(5 / 6, abs=1e-4)
    assert res["agreement"]["kappa_binary"] is not None
    assert res["review_time"]["all"] == {"n": 13, "median_s": 120.0, "p90_s": 120.0}
    assert set(res["review_time"]["by_reviewer"]) == {"examiner", "examiner2"}
    assert [d["entity_id"] for d in res["disagreements"]] == [reviewed["f"][0]]


def test_a_third_examiner_settles_a_disagreement(store, reviewed):
    f1, f2, _ = reviewed["f"]
    with pytest.raises(CaseForbidden):  # a reviewer of the entity cannot adjudicate it
        pilot.adjudicate(store, reviewed["protocol"], RUN, f1, "Elevated", "examiner", "examiner", "why")
    with pytest.raises(CaseInvalid):  # only a disagreement is adjudicated
        pilot.adjudicate(store, reviewed["protocol"], RUN, f2, "Low", "examiner3", "examiner", "why")
    with pytest.raises(CaseInvalid):
        pilot.adjudicate(store, reviewed["protocol"], RUN, f1, "Severe", "examiner3", "examiner", "why")
    pilot.adjudicate(store, reviewed["protocol"], RUN, f1, "Elevated", "examiner3", "examiner",
                     "The off-hours closures are not explained.")
    with pytest.raises(CaseInvalid):
        pilot.adjudicate(store, reviewed["protocol"], RUN, f1, "Low", "examiner3", "examiner", "again")
    held = pilot.evaluate(store, reviewed["protocol"])["held_out"]
    assert held["unresolved_disagreements"] == 0 and held["adjudicated"] == 1
    assert held["arms"]["flagged"]["n"] == 3 and held["arms"]["flagged"]["positive"] == 2


def test_a_run_under_other_thresholds_is_left_out(store, reviewed):
    _add_run(store, OTHER_RUN, "cfgB")
    other = blind.create_sample(store, OTHER_RUN, "analyst", "analyst", "examiner", 2, 0, 0, seed=2)
    _judge(store, other["sample_id"], "examiner", dict.fromkeys(BANDS, "Critical"))
    res = pilot.evaluate(store, reviewed["protocol"])
    assert res["runs_excluded_config_changed"] == [OTHER_RUN] and res["runs_evaluated"] == [RUN]
    assert res["held_out"]["units"] == 7
    report = pilot.evaluation_markdown(res)
    assert OTHER_RUN in report and "left out" in report.lower()


def test_calibration_entities_are_reported_apart(store):
    proto = pilot.freeze_protocol(store, "split", RUN, "analyst", "analyst", seed=4, calibration_fraction=0.5)
    sample = blind.create_sample(store, RUN, "analyst", "analyst", "examiner", 3, 3, 3, seed=6)
    _judge(store, sample["sample_id"], "examiner", dict.fromkeys(BANDS, "Moderate"))
    res = pilot.evaluate(store, proto["protocol_id"])
    split = pilot.protocol(store, proto["protocol_id"])["split"]
    sampled = {r[0] for r in store.conn.execute("SELECT entity_id FROM blind_tasks WHERE sample_id = ?",
                                                (sample["sample_id"],))}
    assert res["held_out"]["units"] == sum(split[e] == "held_out" for e in sampled)
    assert res["calibration"]["units"] == sum(split[e] == "calibration" for e in sampled)


def test_the_report_states_a_synthetic_check_and_every_exclusion(store, reviewed):
    res = pilot.evaluate(store, reviewed["protocol"])
    real = pilot.evaluation_markdown({**res, "synthetic": False})
    assert "Synthetic implementation check" not in real
    assert "not counted as negatives" in real and "1 unresolved" in real
    assert "Synthetic implementation check" in pilot.evaluation_markdown({**res, "synthetic": True})


def test_the_cli_evaluates_a_protocol(store, reviewed, tmp_path, monkeypatch):
    from satsa.cli import app

    monkeypatch.chdir(tmp_path)  # make_store put the deployment's data/ here
    out, raw = tmp_path / "pilot.md", tmp_path / "pilot.json"
    result = CliRunner().invoke(app, ["pilot", "evaluate", "--protocol", reviewed["protocol"], "--out", str(out),
                                      "--json", str(raw)])
    assert result.exit_code == 0, result.output
    assert "Held-out entities" in out.read_text(encoding="utf-8")
    assert json.loads(raw.read_text(encoding="utf-8"))["held_out"]["units"] == 7
    refused = CliRunner().invoke(app, ["pilot", "freeze", "--name", "x", "--run", RUN, "--actor", "examiner"])
    assert refused.exit_code == 1
