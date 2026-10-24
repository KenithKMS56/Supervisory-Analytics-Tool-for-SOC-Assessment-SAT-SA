"""Replay a recorded assessment run and say whether it reproduces.

A run records its full configuration (`run_config_snapshots`), its selection (mode, window,
source snapshot, reference date) and its analytical fingerprint (scoring.fingerprint). A replay
re-evaluates the same published data, as of the same source snapshot, with the recorded
configuration -- not the current one -- and compares:

- the fingerprint, component by component (configuration, data, selection, environment), so a
  mismatch says *why* (e.g. the code revision changed, a published file was altered);
- the results: every entity's risk index and band, and every finding's entity, rule and score.

Nothing is written: the replay is a dry run. Runs recorded before snapshots existed cannot be
replayed and are reported as such.
"""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from satsa.scoring.fingerprint import environment_identity
from satsa.scoring.runner import AssessmentRunner
from satsa.scoring.selection import AssessmentWindow
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

_FILES = {
    "rules": "rules.yaml",
    "scoring": "scoring.yaml",
    "peers": "peers.yaml",
    "systemic": "systemic.yaml",
    "anomaly": "anomaly.yaml",
    "taxonomy": "taxonomy.yaml",
    "expected": "expected.yaml",
}


class ReplayError(RuntimeError):
    """The run cannot be replayed (unknown, or recorded without what a replay needs)."""


def _window(selection: dict[str, Any]) -> AssessmentWindow:
    def ts(value: str | None) -> datetime | None:
        return datetime.fromisoformat(value) if value else None

    return AssessmentWindow(
        mode=selection["mode"],
        start=ts(selection.get("start")),
        end=ts(selection.get("end_exclusive")),
        max_pub_seq=selection.get("max_pub_seq"),
        label=selection.get("label"),
    )


def _context_time(created_at: Any) -> str:
    """The run's start in the store's timestamp format (utc_now_iso), for "in force as of"."""
    when = created_at if isinstance(created_at, datetime) else datetime.fromisoformat(str(created_at))
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when.astimezone(UTC).isoformat(timespec="microseconds")


def replay_run(run_id: str, data_dir: Path | str, sqlite_store: SQLiteStore) -> dict[str, Any]:
    row = sqlite_store.conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise ReplayError(f"no run {run_id!r}")
    if not row["fingerprint"] or not row["selection_json"]:
        raise ReplayError(
            f"run {run_id} was recorded before runs stored their configuration and selection; it cannot be replayed"
        )
    snapshot = sqlite_store.get_config_snapshot(run_id)
    if "rules" not in snapshot:
        raise ReplayError(f"run {run_id} has no configuration snapshot")
    selection = json.loads(row["selection_json"])

    with tempfile.TemporaryDirectory(prefix="satsa-replay-") as tmp:
        cfg = Path(tmp)
        (cfg / "mappings").mkdir()
        for key, entry in snapshot.items():
            if entry["content"] is None:
                continue  # the file did not exist when the run read it
            name = _FILES.get(key) or (f"mappings/{key.split(':', 1)[1]}.yaml" if key.startswith("mapping:") else None)
            if name:
                # Bytes, not text: write_text would translate newlines on Windows and change the hash.
                (cfg / name).write_bytes(entry["content"].encode("utf-8"))
        duck = DuckDBStore(data_dir)
        try:
            runner = AssessmentRunner(
                duck,
                sqlite_store,
                rules_config_path=cfg / "rules.yaml",
                scoring_config_path=cfg / "scoring.yaml",
                peers_config_path=cfg / "peers.yaml",
                systemic_config_path=cfg / "systemic.yaml",
                anomaly_config_path=cfg / "anomaly.yaml",
            )
            ref = selection.get("reference_date")
            res = runner.run_assessment(
                period=row["period"],
                code_version=row["code_version"],
                dry_run=True,
                window=_window(selection),
                reference_date=datetime.fromisoformat(ref) if ref else None,
                record_data_gaps=False,
                excluded_entities=selection.get("retired_entities", []),
                # Applicability decisions, maintenance and exceptions as they stood for the run.
                context_at=_context_time(row["created_at"]),
            )
        finally:
            duck.close()
    if res.get("status") != "success":
        raise ReplayError(f"the replay could not run: {res.get('message')}")

    recorded_scores = {
        r["entity_id"]: (round(float(r["risk_index"]), 6), r["risk_band"])
        for r in sqlite_store.conn.execute(
            "SELECT entity_id, risk_index, risk_band FROM entity_scores WHERE run_id = ?", (run_id,)
        )
    }
    replay_scores = {
        e: (round(float(v["risk_index"]), 6), v["risk_band"]) for e, v in res["entity_scores"].items()
    }
    recorded_findings = sorted(
        (r["entity_id"], r["rule_id"], round(float(r["score"]), 6))
        for r in sqlite_store.conn.execute("SELECT entity_id, rule_id, score FROM findings WHERE run_id = ?", (run_id,))
    )
    replay_findings = sorted((f["entity_id"], f["rule_id"], round(float(f["score"]), 6)) for f in res["findings"])

    recorded_env = json.loads(row["environment_json"] or "{}")
    recorded_data = json.loads(row["data_fingerprint_json"] or "{}")
    recorded_selection = {k: v for k, v in selection.items() if k != "description"}
    replay_selection = {k: v for k, v in res["selection"].items() if k != "description"}
    current_env = environment_identity()
    differences: dict[str, Any] = {}
    changed_tables = sorted(t for t in set(recorded_data) | set(res["data_fingerprint"])
                            if recorded_data.get(t) != res["data_fingerprint"].get(t))
    if changed_tables:
        differences["data"] = changed_tables
    if res["config_hash"] != row["config_hash"]:
        differences["configuration"] = {"recorded": row["config_hash"], "replay": res["config_hash"]}
    if recorded_selection != replay_selection:
        differences["selection"] = {"recorded": recorded_selection, "replay": replay_selection}
    env_changes = {
        k: {"recorded": recorded_env.get(k), "now": current_env.get(k)}
        for k in sorted(set(recorded_env) | set(current_env))
        if recorded_env.get(k) != current_env.get(k)
    }
    if env_changes:
        differences["environment"] = env_changes

    score_diffs = {
        e: {"recorded": recorded_scores.get(e), "replay": replay_scores.get(e)}
        for e in sorted(set(recorded_scores) | set(replay_scores))
        if recorded_scores.get(e) != replay_scores.get(e)
    }
    return {
        "run_id": run_id,
        "fingerprint_recorded": row["fingerprint"],
        "fingerprint_replay": res["fingerprint"],
        "fingerprint_match": row["fingerprint"] == res["fingerprint"],
        "differences": differences,
        "results_match": not score_diffs and recorded_findings == replay_findings,
        "score_differences": score_diffs,
        "findings_recorded": len(recorded_findings),
        "findings_replay": len(replay_findings),
        "findings_only_recorded": [list(f) for f in recorded_findings if f not in replay_findings][:50],
        "findings_only_replay": [list(f) for f in replay_findings if f not in recorded_findings][:50],
    }
