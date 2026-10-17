"""Assessment runner orchestrating rule evaluation, scoring, queue ranking, and audit persistence."""

import hashlib
import json
import logging
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from satsa.models.canonical import Entity
from satsa.models.outputs import (
    DomainScore,
    DQIssue,
    EntityScore,
    Finding,
    FindingEvidence,
    ReviewQueueItem,
    Run,
)
from satsa.peers.anomaly_scan import AnomalyScanner
from satsa.peers.grouping import PeerResolver
from satsa.rules.base import data_reference_date
from satsa.rules.contracts import (
    ASSESSED_CLEAR,
    DEGRADED,
    FINDING,
    INSUFFICIENT_EVIDENCE,
    NOT_APPLICABLE,
    RuleContract,
    contract_for,
    evaluated_population,
    unusable_alert_fields,
)
from satsa.rules.registry import RuleRegistry
from satsa.rules.systemic import SystemicCorrelationDetector
from satsa.scoring.fingerprint import (
    analytical_fingerprint,
    config_hash,
    config_snapshot,
    data_fingerprint,
    environment_identity,
)
from satsa.scoring.prioritiser import ReviewPrioritiser
from satsa.scoring.scorer import ScoringEngine
from satsa.scoring.selection import ALL_SUBMITTED, AssessmentWindow, apply_window, window_for_period
from satsa.security import is_valid_entity_id, is_valid_run_id
from satsa.store.catalog import DECLARED_EMPTY, REJECTED
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

logger = logging.getLogger(__name__)

# Label of an assessment that names no review period: every submitted record, no period filter.
ALL_SUBMITTED_LABEL = "ALL-SUBMITTED"

# How each table an entity's rules read stands in the assessed selection.
PRESENT = "present"  # rows in the selection
TABLE_DECLARED_EMPTY = "declared_empty"  # submitted for the selection, with no rows: absence is a signal
OMITTED = "omitted"  # never submitted
TABLE_REJECTED = "rejected"  # submitted but could not be stored
STALE = "stale"  # submitted only for other periods: nothing is known about this one
UNUSABLE_TABLE_STATES = frozenset({OMITTED, TABLE_REJECTED, STALE})

_STATUS_WORDS = {
    OMITTED: "was not submitted",
    TABLE_REJECTED: "was submitted but could not be stored",
    STALE: "has no records for the assessed period and was not submitted for it",
}


class AssessmentRunner:
    """Executes a supervisory assessment across all entities, computing scores, findings, and queue."""

    def __init__(
        self,
        duckdb_store: DuckDBStore,
        sqlite_store: SQLiteStore,
        rules_config_path: Path | str = "config/rules.yaml",
        scoring_config_path: Path | str = "config/scoring.yaml",
        peers_config_path: Path | str = "config/peers.yaml",
        systemic_config_path: Path | str = "config/systemic.yaml",
        anomaly_config_path: Path | str = "config/anomaly.yaml",
    ):
        self.duckdb_store = duckdb_store
        self.sqlite_store = sqlite_store
        self.registry = RuleRegistry(rules_config_path)
        self.scorer = ScoringEngine(scoring_config_path)
        self.peer_resolver = PeerResolver(peers_config_path)
        queue_cfg = self.scorer.config.get("review_queue", {})
        self.prioritiser = ReviewPrioritiser(
            top_ratio=float(queue_cfg.get("top_risk_ratio", 0.70)),
            seed=int(queue_cfg.get("random_seed", 42)),
        )
        self.queue_size_per_entity = int(queue_cfg.get("queue_size_per_entity", 30))
        self.systemic_detector = SystemicCorrelationDetector(systemic_config_path)
        self.anomaly_scanner = AnomalyScanner(anomaly_config_path)
        # Every file whose content changes results (scoring.fingerprint). Taxonomy, expected
        # values and source mappings shape what ingestion stored; they are snapshotted with the
        # run so a replay can tell whether they differ.
        config_dir = Path(rules_config_path).parent
        self.config_paths: dict[str, Path] = {
            "rules": Path(rules_config_path),
            "scoring": Path(scoring_config_path),
            "peers": Path(peers_config_path),
            "systemic": Path(systemic_config_path),
            "anomaly": Path(anomaly_config_path),
            "taxonomy": config_dir / "taxonomy.yaml",
            "expected": config_dir / "expected.yaml",
        }
        self.mapping_dirs = tuple(d for d in (config_dir / "mappings",) if d.is_dir())

    # --- evidence -------------------------------------------------------------------------------

    def _table_status(
        self, entity_ids: list[str], tables: set[str], window: AssessmentWindow
    ) -> dict[str, dict[str, str]]:
        """entity -> table -> PRESENT / TABLE_DECLARED_EMPTY / OMITTED / TABLE_REJECTED / STALE.

        - rows in the selection: present;
        - no rows, and a published batch declared the table for this entity (with no rows, or
          with rows outside a windowed selection while the batch's period covers the window):
          declared empty, so absence is a real signal;
        - no rows, submitted only for other periods (a windowed selection): stale;
        - every submission of it was rejected: rejected;
        - otherwise: omitted.

        Data stored before the catalog existed is described by the operational store's
        manifest (`submitted_tables`), which is used for batches the catalog does not know.
        """
        snapshot = window.max_pub_seq
        catalog = self.duckdb_store.catalog
        declared = catalog.submitted_tables(snapshot)
        known_batches = catalog.batch_ids()
        # Declarations made before the catalog existed carry no period: like any undated batch
        # they describe a complete export and count for every period.
        undated_legacy: dict[str, set[str]] = {}
        for ent, tbl_batches in self.sqlite_store.get_submitted_table_batches().items():
            for table, batch_id in tbl_batches.items():
                if batch_id in known_batches:
                    continue  # the catalog already says how that batch declared it
                declared.setdefault(ent, {}).setdefault(table, DECLARED_EMPTY)
                undated_legacy.setdefault(ent, set()).add(table)

        present: dict[str, set[str]] = {}
        for table in sorted(tables):
            df = self.duckdb_store.query(f'SELECT DISTINCT entity_id FROM "{table}" WHERE entity_id IS NOT NULL')
            for ent in df["entity_id"].to_list() if not df.is_empty() else []:
                present.setdefault(str(ent), set()).add(table)

        windowed = window.mode != ALL_SUBMITTED
        out: dict[str, dict[str, str]] = {}
        for ent in entity_ids:
            statuses: dict[str, str] = {}
            ent_declared = declared.get(ent, {})
            covering: set[str] | None = None
            for table in sorted(tables):
                if table in present.get(ent, set()):
                    statuses[table] = PRESENT
                    continue
                how = ent_declared.get(table)
                if how is None:
                    statuses[table] = OMITTED
                elif how == REJECTED:
                    statuses[table] = TABLE_REJECTED
                elif how == DECLARED_EMPTY and not windowed:
                    statuses[table] = TABLE_DECLARED_EMPTY
                elif not windowed:
                    # Rows were published but none selected: only possible for rows the window
                    # cannot place, which an all-submitted selection keeps. Treat as declared.
                    statuses[table] = TABLE_DECLARED_EMPTY
                elif table in undated_legacy.get(ent, set()):
                    statuses[table] = TABLE_DECLARED_EMPTY
                else:
                    if covering is None:
                        covering = self._tables_submitted_for_window(ent, window)
                    statuses[table] = TABLE_DECLARED_EMPTY if table in covering else STALE
            out[ent] = statuses
        return out

    def _tables_submitted_for_window(self, entity_id: str, window: AssessmentWindow) -> set[str]:
        assert window.end is not None
        start = (window.start or datetime(1, 1, 1)).isoformat()
        return self.duckdb_store.catalog.tables_submitted_for_period(
            entity_id, start, window.end.isoformat(), window.max_pub_seq
        )

    def _rule_result(
        self,
        rule: Any,
        contract: RuleContract,
        ent_id: str,
        statuses: dict[str, str],
        decision: dict[str, Any] | None,
        unusable: set[str],
        population_cache: dict[str, int],
        run_id: str,
        peers: list[Any],
    ) -> tuple[dict[str, Any], list[Finding], list[FindingEvidence]]:
        base = {
            "run_id": run_id,
            "entity_id": ent_id,
            "rule_id": rule.id,
            "rule_version": rule.version,
            "domain": rule.domain,
            "min_sample": contract.min_sample,
            "missing_inputs": [],
            "population": None,
            "findings_count": 0,
        }
        if decision is not None:
            return (
                {
                    **base,
                    "state": NOT_APPLICABLE,
                    "reason": f"Not applicable by decision {decision['decision_id']} of {decision['decided_by']}: "
                    f"{decision['reason']}",
                },
                [],
                [],
            )
        missing = [t for t in contract.required_tables if statuses.get(t) in UNUSABLE_TABLE_STATES]
        if missing:
            why = "; ".join(f"'{t}' {_STATUS_WORDS[statuses[t]]}" for t in missing)
            return (
                {
                    **base,
                    "state": INSUFFICIENT_EVIDENCE,
                    "missing_inputs": missing,
                    "reason": f"Not assessed: {why}. Neither a finding nor a clean result.",
                },
                [],
                [],
            )
        findings, evidences = rule.evaluate(ent_id, self.duckdb_store, peers, run_id)
        if contract.population_table not in population_cache:
            population_cache[contract.population_table] = evaluated_population(contract, self.duckdb_store, ent_id)
        population = population_cache[contract.population_table]
        base["population"] = population
        if findings:
            return (
                {**base, "state": FINDING, "findings_count": len(findings), "reason": f"{len(findings)} finding(s)."},
                findings,
                evidences,
            )
        blind = sorted(f for f in contract.alert_fields if f in unusable)
        if blind:
            return (
                {
                    **base,
                    "state": DEGRADED,
                    "missing_inputs": [f"alert.{f}" for f in blind],
                    "reason": f"Ran, but {', '.join('alert.' + f for f in blind)} holds no usable value, so it "
                    "cannot fire: no finding is not evidence that the control works.",
                },
                [],
                [],
            )
        if population < contract.min_sample:
            return (
                {
                    **base,
                    "state": INSUFFICIENT_EVIDENCE,
                    "reason": f"No finding, but only {population} {contract.population_table} record(s) were "
                    f"evaluated; at least {contract.min_sample} are needed to call the control clear.",
                },
                [],
                [],
            )
        return (
            {
                **base,
                "state": ASSESSED_CLEAR,
                "reason": f"Assessed over {population} {contract.population_table} record(s); no finding.",
            },
            [],
            [],
        )

    def _dependency_issues(
        self, statuses: dict[str, dict[str, str]], results: list[dict[str, Any]]
    ) -> list[DQIssue]:
        """The DQ view's data-gap entries for the current submission (unchanged check names)."""
        issues: list[DQIssue] = []
        rules_by_table: dict[str, list[str]] = {}
        for rule in self.registry.get_all_rules():
            for table in contract_for(rule).required_tables:
                rules_by_table.setdefault(table, []).append(rule.id)
        for ent_id, ent_status in sorted(statuses.items()):
            for table, status in sorted(ent_status.items()):
                if status != TABLE_DECLARED_EMPTY:
                    continue
                rule_ids = rules_by_table.get(table, [])
                verb = "depends" if len(rule_ids) == 1 else "depend"
                issues.append(
                    DQIssue(
                        issue_id=f"DQ-DEPENDENCY-{ent_id}-{table}",
                        entity_id=ent_id,
                        check_name="rule_dependency_empty",
                        severity="warning",
                        count=len(rule_ids),
                        sample_records=rule_ids,
                        details=(
                            f"'{table}' was submitted for this entity but holds no records for it. "
                            f"{', '.join(rule_ids)} {verb} on that table and treat the absence as the SOC's "
                            "behaviour; confirm with the entity that the empty table is complete."
                        ),
                    )
                )
        for r in results:
            if r["state"] != INSUFFICIENT_EVIDENCE or not r["missing_inputs"]:
                continue
            missing = sorted(r["missing_inputs"])
            ent_status = statuses[r["entity_id"]]
            if all(ent_status[t] == OMITTED for t in missing):
                why = f"its submission does not include {', '.join(repr(t) for t in missing)}"
            else:
                why = "; ".join(f"{t!r} {_STATUS_WORDS[ent_status[t]]}" for t in missing)
            issues.append(
                DQIssue(
                    issue_id=f"DQ-NOT-ASSESSED-{r['entity_id']}-{r['rule_id']}",
                    entity_id=r["entity_id"],
                    check_name="rule_not_assessed",
                    severity="warning",
                    count=len(missing),
                    sample_records=missing,
                    details=(
                        f"{r['rule_id']} was not assessed for this entity: {why}. This is neither a finding "
                        "nor a clean result; request the table to assess this control."
                    ),
                )
            )
        return issues

    # --- the run --------------------------------------------------------------------------------

    def run_assessment(
        self,
        period: str | None = None,
        code_version: str | None = None,
        actor: str = "system",
        refresh_tables: bool = True,
        record_data_gaps: bool = True,
        dry_run: bool = False,
        reference_date: datetime | None = None,
        window: AssessmentWindow | None = None,
        max_pub_seq: int | None = None,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Run full evaluation pipeline.

        `run_id` makes the run idempotent (satsa.jobs): if a run with that id was already
        published, it is returned instead of being assessed again.

        What is assessed (satsa.scoring.selection): `window` if given, else the window the
        `period` label names (`2026`, `2026-Q1`, `2026-H1`, `2026-03`). A label that names no
        period (or none at all) assesses every submitted record, and the run says so. The
        source snapshot is the catalog's publication sequence `max_pub_seq` (default: all
        published data now); both are recorded in the run so it can be replayed.

        `reference_date` is the date the assessment is "as of" for time-dependent rules
        (EG09's case age). It defaults to the latest timestamp in the selected data, never
        the wall clock, and is recorded in the run manifest.

        `dry_run=True` evaluates and scores exactly as a real run would but persists nothing:
        no run row, findings, scores, queue, audit entry or DQ changes. The result carries
        the findings themselves (`findings`) so a caller can preview a configuration.

        `refresh_tables=False` assesses the store exactly as the caller prepared it instead
        of reloading and selecting from the published data (the selection is then recorded as
        prepared by the caller). `record_data_gaps=False` keeps such a run from rewriting the
        DQ view's missing-table entries, which describe the current submission.

        Everything the run writes is published in one SQLite transaction: a failure leaves no
        partial run (and is recorded in the audit log as `run_failed`).
        """
        label = period or ALL_SUBMITTED_LABEL
        if run_id is not None and not dry_run:
            if not is_valid_run_id(run_id):
                raise ValueError(f"invalid run id {run_id!r}")
            done = self.sqlite_store.conn.execute(
                "SELECT run_id, (SELECT count(*) FROM findings f WHERE f.run_id = r.run_id) AS n "
                "FROM runs r WHERE run_id = ?", (run_id,)
            ).fetchone()
            if done is not None:
                return {"status": "success", "run_id": done["run_id"], "findings_count": done["n"],
                        "already_published": True}
        if window is None:
            window = window_for_period(period, max_pub_seq)
        selection_report: dict[str, Any] = {}
        if refresh_tables:
            self.duckdb_store.load_all_tables(window.max_pub_seq if window.max_pub_seq is not None else max_pub_seq)
            window = replace(window, max_pub_seq=self.duckdb_store.source_snapshot)
            selection_report = apply_window(self.duckdb_store, window)
        else:
            window = replace(window, max_pub_seq=self.duckdb_store.source_snapshot)
            selection_report = {"mode": window.mode, "prepared_by_caller": True}

        # Query all entities
        df_entities = self.duckdb_store.query("SELECT * FROM entity")
        if df_entities.is_empty():
            return {"status": "error", "message": "No entities found in storage."}

        # Defense in depth: an entity whose ID fails satsa.security.ENTITY_ID_RE
        # is never handed to any rule (rules bind entity_id as a query parameter,
        # but a malformed ID must not reach a query at all).
        all_entities = [Entity(**row) for row in df_entities.iter_rows(named=True)]
        entities = [e for e in all_entities if is_valid_entity_id(e.entity_id)]
        skipped_entity_ids = sorted(
            repr(e.entity_id) for e in all_entities if not is_valid_entity_id(e.entity_id)
        )
        if not entities:
            return {"status": "error", "message": "No entities with valid IDs found in storage."}

        snapshot = config_snapshot(self.config_paths, self.mapping_dirs)
        cfg_hash = config_hash(snapshot)
        environment = environment_identity()
        code_version = code_version or str(environment["code_revision"])
        now = datetime.now(UTC)
        # Microsecond precision (plus the period label folded into the hash
        # suffix) keeps run_id unique even across rapid successive calls in
        # the same wall-clock second, e.g. when seeding several historical
        # periods back-to-back (see satsa.scoring.history).
        uniq_suffix = hashlib.sha256(f"{cfg_hash}:{label}:{now.isoformat()}".encode()).hexdigest()[:8]
        run_id = run_id or f"RUN-{now.strftime('%Y%m%d%H%M%S%f')}-{uniq_suffix}"

        all_findings: list[Finding] = []
        all_evidences: list[FindingEvidence] = []
        all_domain_scores: list[DomainScore] = []
        all_entity_scores: list[EntityScore] = []
        all_queue_items: list[ReviewQueueItem] = []
        all_results: list[dict[str, Any]] = []

        all_rules = self.registry.get_all_rules()
        rule_contracts = {rule.id: contract_for(rule) for rule in all_rules}
        needed_tables = {t for c in rule_contracts.values() for t in c.required_tables}
        entity_ids = [e.entity_id for e in entities]
        statuses = self._table_status(entity_ids, needed_tables, window)
        decisions = self.sqlite_store.active_applicability_decisions()
        all_alert_fields = {f for c in rule_contracts.values() for f in c.alert_fields}

        as_of = reference_date or data_reference_date(self.duckdb_store)
        for rule in all_rules:
            rule.reference_date = as_of
        for entity in entities:
            ent_id = entity.entity_id
            peers, _cohort_label, _is_weak = self.peer_resolver.resolve_peers(entity, entities)

            ent_findings: list[Finding] = []
            ent_evidences: list[FindingEvidence] = []
            unusable = unusable_alert_fields(self.duckdb_store, ent_id, all_alert_fields)
            population_cache: dict[str, int] = {}
            ent_results: list[dict[str, Any]] = []
            for rule in all_rules:
                rule_result, findings, evidences = self._rule_result(
                    rule,
                    rule_contracts[rule.id],
                    ent_id,
                    statuses[ent_id],
                    decisions.get((ent_id, rule.id)),
                    unusable,
                    population_cache,
                    run_id,
                    peers,
                )
                ent_results.append(rule_result)
                ent_findings.extend(findings)
                ent_evidences.extend(evidences)

            all_findings.extend(ent_findings)
            all_evidences.extend(ent_evidences)
            all_results.extend(ent_results)

            # Evidence coverage, then domain and entity scores that know what was assessed.
            states = {r["rule_id"]: r["state"] for r in ent_results}
            missing_by_rule = {
                r["rule_id"]: r["missing_inputs"]
                for r in ent_results
                if r["state"] in (INSUFFICIENT_EVIDENCE, DEGRADED) and r["missing_inputs"]
            }
            coverage = self.scorer.classify_coverage(states, missing_by_rule)
            dom_scores = self.scorer.compute_domain_scores(
                ent_id, run_id, ent_findings, {r["rule_id"]: (r["domain"], r["state"]) for r in ent_results}
            )
            ent_score = self.scorer.compute_entity_score(ent_id, run_id, dom_scores, ent_findings, coverage)
            all_domain_scores.extend(dom_scores)
            all_entity_scores.append(ent_score)

            # Build Review Queue
            q_items = self.prioritiser.build_queue(
                run_id=run_id,
                entity_id=ent_id,
                findings=ent_findings,
                evidences=ent_evidences,
                store=self.duckdb_store,
                total_size=self.queue_size_per_entity,
            )
            all_queue_items.extend(q_items)

        # The run's complete identity (scoring.fingerprint): configuration, selected data,
        # selection, applicability decisions in force, and environment.
        data_fp = data_fingerprint(self.duckdb_store)
        selection = {
            **window.as_dict(),
            "reference_date": as_of.isoformat() if as_of else None,
            "applicability_decisions": sorted(d["decision_id"] for d in decisions.values()),
        }
        fingerprint = analytical_fingerprint(snapshot, data_fp, selection, environment)

        # Build Run record
        coverage_summary: dict[str, int] = {}
        for es in all_entity_scores:
            key = es.classification_status or "unknown"
            coverage_summary[key] = coverage_summary.get(key, 0) + 1
        manifest_dict = {
            "run_id": run_id,
            "period": label,
            "timestamp": now.isoformat(),
            "config_hash": cfg_hash,
            "fingerprint": fingerprint,
            "code_version": code_version,
            "reference_date": as_of.isoformat() if as_of else None,
            "selection": selection,
            "selection_report": selection_report,
            "source_snapshot": window.max_pub_seq,
            "entities_evaluated": entity_ids,
            "entities_skipped_invalid_id": skipped_entity_ids,
            "classification_summary": coverage_summary,
            "total_findings": len(all_findings),
            "total_queue_items": len(all_queue_items),
            "anomaly_config_hash": self.anomaly_scanner.config_hash,
        }

        # Cross-entity ("systemic") correlation: looks ACROSS the per-entity
        # findings just computed, not within any single entity's data.
        systemic_findings = self.systemic_detector.evaluate(entities, all_findings, run_id)

        # Exploratory scan for indicators no rule tests: leads for the examiner, kept out of
        # the scores and the queue (satsa.peers.anomaly_scan). A table counts as submitted when
        # it holds rows or was declared for the selection.
        submitted = {
            ent: {t for t, st in tables.items() if st in (PRESENT, TABLE_DECLARED_EMPTY)}
            for ent, tables in statuses.items()
        }
        anomaly = self.anomaly_scanner.scan(run_id, entities, self.duckdb_store, self.peer_resolver, submitted)
        manifest_dict["anomaly_signals"] = len(anomaly["signals"])
        run_obj = Run(
            run_id=run_id,
            period=label,
            created_at=now,
            config_hash=cfg_hash,
            code_version=code_version,
            status="completed",
            manifest_json=json.dumps(manifest_dict),
            fingerprint=fingerprint,
            selection_json=json.dumps(selection),
            source_snapshot=window.max_pub_seq,
            data_fingerprint_json=json.dumps(data_fp, sort_keys=True),
            environment_json=json.dumps(environment, sort_keys=True),
        )

        result: dict[str, Any] = {
            "status": "success",
            "run_id": run_id,
            "period": label,
            "config_hash": cfg_hash,
            "fingerprint": fingerprint,
            "selection": selection,
            "data_fingerprint": data_fp,
            "source_snapshot": window.max_pub_seq,
            "reference_date": as_of.isoformat() if as_of else None,
            "entities_count": len(entities),
            "findings_count": len(all_findings),
            "queue_count": len(all_queue_items),
            "systemic_findings_count": len(systemic_findings),
            "anomaly_signals_count": len(anomaly["signals"]),
            "entity_scores": {
                es.entity_id: {
                    "risk_index": es.risk_index,
                    "risk_band": es.risk_band,
                    "classification_status": es.classification_status,
                    "coverage": es.coverage,
                }
                for es in all_entity_scores
            },
        }
        if dry_run:
            result["dry_run"] = True
            result["findings"] = [
                {"entity_id": f.entity_id, "rule_id": f.rule_id, "score": f.score, "severity": f.severity, "title": f.title}
                for f in all_findings
            ]
            result["rule_results"] = all_results
            return result

        dependency_issues = (
            self._dependency_issues(statuses, all_results) if record_data_gaps else []
        )
        audit_details = {
            "run_id": run_id,
            "period": label,
            "config_hash": cfg_hash,
            "fingerprint": fingerprint,
            "selection": window.describe(),
            "source_snapshot": window.max_pub_seq,
            "findings_count": len(all_findings),
            "entities_count": len(entities),
            "systemic_findings_count": len(systemic_findings),
            "anomaly_signals_count": len(anomaly["signals"]),
            "anomaly_config_hash": self.anomaly_scanner.config_hash,
        }
        store = self.sqlite_store
        try:
            with store.audited_transaction():
                if record_data_gaps:
                    store.conn.execute(
                        "DELETE FROM dq_issues WHERE check_name IN ('rule_dependency_empty', 'rule_not_assessed')"
                    )
                    for issue in dependency_issues:
                        store.save_dq_issue(issue)
                store.save_run(run_obj)
                store.save_findings(all_findings, all_evidences)
                store.save_scores(all_domain_scores, all_entity_scores)
                store.save_rule_results(all_results)
                store.save_review_queue(all_queue_items)
                if systemic_findings:
                    store.save_systemic_findings(systemic_findings)
                store.save_anomaly_signals(anomaly["signals"])
                store.save_metric_values(run_id, anomaly["metric_values"])
                store.save_config_snapshot(run_id, snapshot)
                # Append to Audit Log with hash chaining (same transaction: no run without its entry)
                store.append_audit(action="run", actor=actor, details=audit_details)
        except Exception as exc:
            logger.exception("Assessment run %s failed to publish; nothing of it was kept", run_id)
            try:
                store.append_audit(
                    action="run_failed",
                    actor=actor,
                    details={"run_id": run_id, "period": label, "error": f"{type(exc).__name__}: {exc}"[:500]},
                )
            except Exception:
                logger.exception("Could not record the failed run %s in the audit log", run_id)
            raise

        return result
