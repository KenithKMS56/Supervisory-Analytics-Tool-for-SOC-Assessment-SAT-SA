"""Assessment runner orchestrating rule evaluation, scoring, queue ranking, and audit persistence."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from satsa.models.canonical import Entity
from satsa.models.outputs import (
    DomainScore,
    EntityScore,
    Finding,
    FindingEvidence,
    ReviewQueueItem,
    Run,
)
from satsa.peers.grouping import PeerResolver
from satsa.rules.registry import RuleRegistry
from satsa.rules.systemic import SystemicCorrelationDetector
from satsa.scoring.prioritiser import ReviewPrioritiser
from satsa.scoring.scorer import ScoringEngine
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
        self.prioritiser = ReviewPrioritiser()
        self.systemic_detector = SystemicCorrelationDetector(systemic_config_path)

    def run_assessment(
        self,
        period: str = "2026-Q1",
        code_version: str = "0.1.0",
        actor: str = "system",
    ) -> dict[str, Any]:
        """Run full evaluation pipeline."""
        # Refresh DuckDB tables from Parquet
        self.duckdb_store.load_all_tables()

        # Query all entities
        df_entities = self.duckdb_store.query("SELECT * FROM entity")
        if df_entities.is_empty():
            return {"status": "error", "message": "No entities found in storage."}

        entities = [Entity(**row) for row in df_entities.iter_rows(named=True)]
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

        # Evaluate rules per entity
        all_rules = self.registry.get_all_rules()
        for entity in entities:
            ent_id = entity.entity_id
            peers, _cohort_label, _is_weak = self.peer_resolver.resolve_peers(entity, entities)

            ent_findings: list[Finding] = []
            ent_evidences: list[FindingEvidence] = []

            for rule in all_rules:
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
                total_size=30,
            )
            all_queue_items.extend(q_items)

        # Build Run record
        manifest_dict = {
            "run_id": run_id,
            "period": period,
            "timestamp": now.isoformat(),
            "config_hash": config_hash,
            "code_version": code_version,
            "entities_evaluated": [e.entity_id for e in entities],
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

        return {
            "status": "success",
            "run_id": run_id,
            "config_hash": config_hash,
            "entities_count": len(entities),
            "findings_count": len(all_findings),
            "queue_count": len(all_queue_items),
            "systemic_findings_count": len(systemic_findings),
            "entity_scores": {
                es.entity_id: {"risk_index": es.risk_index, "risk_band": es.risk_band}
                for es in all_entity_scores
            },
        }
