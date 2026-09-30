"""Assessment runner orchestrating rule evaluation, scoring, queue ranking, and audit persistence."""

import hashlib
import json
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
from satsa.peers.grouping import PeerResolver
from satsa.rules.base import data_reference_date
from satsa.rules.registry import RULE_DEPENDENCIES, RuleRegistry
from satsa.rules.systemic import SystemicCorrelationDetector
from satsa.scoring.prioritiser import ReviewPrioritiser
from satsa.scoring.scorer import ScoringEngine
from satsa.security import is_valid_entity_id
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


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

    def _report_empty_dependencies(
        self, entity_ids: list[str], submitted: dict[str, set[str]], record: bool = True
    ) -> dict[str, dict[str, list[str]]]:
        """Decide, per entity, which rules cannot be assessed, and report data gaps on the DQ view.

        A rule such as EG03 reads "no escalation rows" as "never escalated". What that means
        depends on the entity's submission manifest (tables it has ever submitted):

        - table **not in the manifest**: the entity never sent it, so the rule is *not assessed*
          for that entity (returned here, reported as `rule_not_assessed`);
        - table **in the manifest but with no rows**: the entity submitted an empty table, so
          absence is a real signal; the rule runs and `rule_dependency_empty` notes the basis;
        - entity with **no manifest at all** (data stored before manifests existed): the rule
          runs and `rule_dependency_empty` warns that the finding may be an artifact.

        Returns entity_id -> {rule_id: [missing tables]} for the rules to skip. With
        `record=False` the DQ view is left untouched (used for historical-window runs).
        """
        if record:
            with self.sqlite_store.conn:
                self.sqlite_store.conn.execute(
                    "DELETE FROM dq_issues WHERE check_name IN ('rule_dependency_empty', 'rule_not_assessed')"
                )
        rules_by_table: dict[str, list[str]] = {}
        for rule_id, tables in sorted(RULE_DEPENDENCIES.items()):
            for table in tables:
                rules_by_table.setdefault(table, []).append(rule_id)

        not_assessed: dict[str, dict[str, list[str]]] = {}
        for table, rule_ids in sorted(rules_by_table.items()):
            df = self.duckdb_store.query(f'SELECT DISTINCT entity_id FROM "{table}"')
            present = set(df["entity_id"].to_list()) if not df.is_empty() else set()
            for entity_id in entity_ids:
                if entity_id in present:
                    continue
                manifest = submitted.get(entity_id)
                if manifest is not None and table not in manifest:
                    for rule_id in rule_ids:
                        not_assessed.setdefault(entity_id, {}).setdefault(rule_id, []).append(table)
                    continue
                if not record:
                    continue
                verb = "depends" if len(rule_ids) == 1 else "depend"
                if manifest is None:
                    basis = (
                        f"No '{table}' records for this entity, and no record of what it submitted. "
                        f"{', '.join(rule_ids)} {verb} on that table: any finding from them may mean the table "
                        "was not submitted rather than a SOC defect, and a missing finding does not mean the "
                        "control works. Confirm what was submitted."
                    )
                else:
                    basis = (
                        f"'{table}' was submitted for this entity but holds no records for it. "
                        f"{', '.join(rule_ids)} {verb} on that table and treat the absence as the SOC's "
                        "behaviour; confirm with the entity that the empty table is complete."
                    )
                self.sqlite_store.save_dq_issue(
                    DQIssue(
                        issue_id=f"DQ-DEPENDENCY-{entity_id}-{table}",
                        entity_id=entity_id,
                        check_name="rule_dependency_empty",
                        severity="warning",
                        count=len(rule_ids),
                        sample_records=rule_ids,
                        details=basis,
                    )
                )

        for entity_id, rules in sorted(not_assessed.items()) if record else []:
            for rule_id, missing in sorted(rules.items()):
                self.sqlite_store.save_dq_issue(
                    DQIssue(
                        issue_id=f"DQ-NOT-ASSESSED-{entity_id}-{rule_id}",
                        entity_id=entity_id,
                        check_name="rule_not_assessed",
                        severity="warning",
                        count=len(missing),
                        sample_records=sorted(missing),
                        details=(
                            f"{rule_id} was not assessed for this entity: its submission does not include "
                            f"{', '.join(repr(t) for t in sorted(missing))}. This is neither a finding nor a clean "
                            "result; request the table to assess this control."
                        ),
                    )
                )
        return not_assessed

    def run_assessment(
        self,
        period: str = "2026-Q1",
        code_version: str = "0.1.0",
        actor: str = "system",
        refresh_tables: bool = True,
        record_data_gaps: bool = True,
        dry_run: bool = False,
        reference_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Run full evaluation pipeline.

        `reference_date` is the date the assessment is "as of" for time-dependent rules
        (EG09's case age). It defaults to the latest timestamp in the submitted data, never
        the wall clock, and is recorded in the run manifest.

        `dry_run=True` evaluates and scores exactly as a real run would but persists nothing:
        no run row, findings, scores, queue, audit entry or DQ changes. The result carries
        the findings themselves (`findings`) so a caller can preview a configuration.

        `refresh_tables=False` assesses the store exactly as the caller prepared it instead
        of reloading every table from Parquet. satsa.scoring.history relies on this: it
        truncates the tables to a past window first, and a reload would silently restore the
        full dataset. `record_data_gaps=False` keeps such a run from rewriting the DQ view's
        missing-table entries, which describe the current submission.
        """
        if refresh_tables:
            self.duckdb_store.load_all_tables()

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
        config_hash = hashlib.sha256(self.registry.config_path.read_bytes()).hexdigest()[:16]
        now = datetime.now(UTC)
        # Microsecond precision (plus the period label folded into the hash
        # suffix) keeps run_id unique even across rapid successive calls in
        # the same wall-clock second, e.g. when seeding several historical
        # periods back-to-back (see satsa.scoring.history).
        uniq_suffix = hashlib.sha256(f"{config_hash}:{period}:{now.isoformat()}".encode()).hexdigest()[:8]
        run_id = f"RUN-{now.strftime('%Y%m%d%H%M%S%f')}-{uniq_suffix}"

        all_findings: list[Finding] = []
        all_evidences: list[FindingEvidence] = []
        all_domain_scores: list[DomainScore] = []
        all_entity_scores: list[EntityScore] = []
        all_queue_items: list[ReviewQueueItem] = []

        not_assessed = self._report_empty_dependencies(
            [e.entity_id for e in entities],
            self.sqlite_store.get_submitted_tables(),
            record=record_data_gaps and not dry_run,
        )

        # Evaluate rules per entity
        all_rules = self.registry.get_all_rules()
        as_of = reference_date or data_reference_date(self.duckdb_store)
        for rule in all_rules:
            rule.reference_date = as_of
        for entity in entities:
            ent_id = entity.entity_id
            peers, _cohort_label, _is_weak = self.peer_resolver.resolve_peers(entity, entities)

            ent_findings: list[Finding] = []
            ent_evidences: list[FindingEvidence] = []

            skipped = not_assessed.get(ent_id, {})
            for rule in all_rules:
                if rule.id in skipped:
                    continue  # a table it depends on was never submitted: see rule_not_assessed
                findings, evidences = rule.evaluate(ent_id, self.duckdb_store, peers, run_id)
                ent_findings.extend(findings)
                ent_evidences.extend(evidences)

            all_findings.extend(ent_findings)
            all_evidences.extend(ent_evidences)

            # Compute Domain Scores and Entity Score
            dom_scores = self.scorer.compute_domain_scores(ent_id, run_id, ent_findings)
            ent_score = self.scorer.compute_entity_score(ent_id, run_id, dom_scores, ent_findings)
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

        # Build Run record
        manifest_dict = {
            "run_id": run_id,
            "period": period,
            "timestamp": now.isoformat(),
            "config_hash": config_hash,
            "code_version": code_version,
            "reference_date": as_of.isoformat() if as_of else None,
            "entities_evaluated": [e.entity_id for e in entities],
            "entities_skipped_invalid_id": skipped_entity_ids,
            "total_findings": len(all_findings),
            "total_queue_items": len(all_queue_items),
        }
        run_obj = Run(
            run_id=run_id,
            period=period,
            created_at=now,
            config_hash=config_hash,
            code_version=code_version,
            status="completed",
            manifest_json=json.dumps(manifest_dict),
        )

        # Cross-entity ("systemic") correlation: looks ACROSS the per-entity
        # findings just computed, not within any single entity's data.
        systemic_findings = self.systemic_detector.evaluate(entities, all_findings, run_id)

        result: dict[str, Any] = {
            "status": "success",
            "run_id": run_id,
            "period": period,
            "config_hash": config_hash,
            "reference_date": as_of.isoformat() if as_of else None,
            "entities_count": len(entities),
            "findings_count": len(all_findings),
            "queue_count": len(all_queue_items),
            "systemic_findings_count": len(systemic_findings),
            "entity_scores": {
                es.entity_id: {"risk_index": es.risk_index, "risk_band": es.risk_band}
                for es in all_entity_scores
            },
        }
        if dry_run:
            result["dry_run"] = True
            result["findings"] = [
                {"entity_id": f.entity_id, "rule_id": f.rule_id, "score": f.score, "severity": f.severity, "title": f.title}
                for f in all_findings
            ]
            return result

        # Save to SQLite
        self.sqlite_store.save_run(run_obj)
        self.sqlite_store.save_findings(all_findings, all_evidences)
        self.sqlite_store.save_scores(all_domain_scores, all_entity_scores)
        self.sqlite_store.save_review_queue(all_queue_items)
        if systemic_findings:
            self.sqlite_store.save_systemic_findings(systemic_findings)

        # Append to Audit Log with hash chaining
        self.sqlite_store.append_audit(
            action="run",
            actor=actor,
            details={
                "run_id": run_id,
                "period": period,
                "config_hash": config_hash,
                "findings_count": len(all_findings),
                "entities_count": len(entities),
                "systemic_findings_count": len(systemic_findings),
            },
        )

        return result
