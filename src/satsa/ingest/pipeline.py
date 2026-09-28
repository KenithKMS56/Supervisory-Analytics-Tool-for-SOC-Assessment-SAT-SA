"""End-to-end ingestion pipeline orchestrator with intelligent canonical schema mapping."""

from pathlib import Path
from typing import Any

import polars as pl

from satsa.ingest.adapters import SourceAdapter
from satsa.ingest.dq_checks import DQValidator
from satsa.ingest.manifest import ManifestBuilder
from satsa.ingest.normaliser import TaxonomyNormaliser
from satsa.ingest.pseudonymise import Pseudonymiser
from satsa.ingest.redact import Redactor
from satsa.models.outputs import DQIssue
from satsa.security import is_valid_entity_id, require_entity_id
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore


class IngestionPipeline:
    """Orchestrates ingestion, data hygiene, DQ validation, Parquet persistence, and audit logging."""

    CANONICAL_TABLES = {
        "alert",
        "case_record",
        "case",
        "escalation",
        "closure",
        "workflow_event",
        "asset",
        "log_source_daily",
        "declared_kpi",
        "entity",
        "detection_rule",
        "case_alert_link",
        "sla_policy",
        "external_report",
        "remediation",
    }

    # Flexible column mappings from various SIEMs (Splunk, ServiceNow, Sentinel, QRadar, TheHive)
    COLUMN_ALIASES: dict[str, dict[str, list[str]]] = {
        "alert": {
            "alert_id": [
                "alert_id",
                "id",
                "notable_id",
                "incident_id",
                "alertid",
                "event_id",
                "ticket_id",
            ],
            "entity_id": [
                "entity_id",
                "entity",
                "cse_id",
                "org_id",
                "organization",
                "tenant",
                "tenant_id",
            ],
            "rule_id": [
                "rule_id",
                "rule_name",
                "correlation_search_name",
                "rule",
                "signature",
                "detector",
                "name",
            ],
            "category": [
                "category",
                "security_domain",
                "type",
                "mitre_tactic",
                "tactic",
                "threat_category",
            ],
            "severity_orig": [
                "severity_orig",
                "orig_severity",
                "initial_severity",
                "urgency",
                "priority",
            ],
            "severity_final": [
                "severity_final",
                "severity",
                "urgency",
                "priority",
                "final_severity",
                "level",
            ],
            "asset_id": [
                "asset_id",
                "dest_host",
                "host",
                "hostname",
                "dest_ip",
                "ip",
                "asset",
                "system",
                "device",
            ],
            "created_at": [
                "created_at",
                "time",
                "timestamp",
                "alert_time",
                "start_time",
                "date_created",
                "date",
                "event_time",
            ],
            "acknowledged_at": [
                "acknowledged_at",
                "ack_time",
                "review_time",
                "triage_time",
                "first_seen",
            ],
            "first_touch_at": ["first_touch_at", "first_comment_time", "investigate_time"],
            "closed_at": ["closed_at", "close_time", "resolved_at", "end_time", "closed_time"],
            "closed_by": ["closed_by", "owner", "analyst", "user", "assignee", "investigator"],
            "closed_by_type": [
                "closed_by_type",
                "actor_type",
                "closure_type",
                "closure_actor_type",
            ],
            "playbook_id": ["playbook_id", "soar_playbook", "playbook", "automation_id"],
            "disposition": [
                "disposition",
                "status_label",
                "resolution",
                "outcome",
                "verdict",
                "closing_disposition",
            ],
            "status": ["status", "status_code", "state", "alert_status"],
        },
        "case_record": {
            "case_id": ["case_id", "id", "ticket_id", "incident_id", "incident_number", "number"],
            "entity_id": ["entity_id", "entity", "cse_id", "org_id", "tenant"],
            "severity": ["severity", "priority", "urgency", "impact"],
            "status": ["status", "state", "case_status"],
            "owner": ["owner", "lead_analyst_id", "assignee", "analyst"],
            "opened_at": ["opened_at", "created_at", "open_time", "start_time"],
            "closed_at": ["closed_at", "resolved_at", "resolve_time", "end_time"],
        },
        "escalation": {
            "esc_id": ["esc_id", "escalation_id", "id"],
            "ref_id": ["ref_id", "alert_id", "case_id", "incident_id"],
            "entity_id": ["entity_id", "entity", "cse_id"],
            "from_role": ["from_role", "from_tier", "tier_source"],
            "to_role": ["to_role", "to_tier", "escalated_to"],
            "escalated_at": ["escalated_at", "timestamp", "time"],
            "acknowledged_at": ["acknowledged_at", "ack_time"],
            "outcome": ["outcome", "status"],
        },
        "closure": {
            "ref_id": ["ref_id", "record_id", "alert_id", "case_id", "ticket_id"],
            "entity_id": ["entity_id", "entity", "cse_id"],
            "reason_code": ["reason_code", "resolution"],
            "disposition": ["disposition", "status", "verdict"],
            "comment_norm_hash": ["comment_norm_hash", "hash"],
            "comment_len": ["comment_len", "length"],
            "comment_shingles": ["comment_shingles", "shingles"],
        },
        "workflow_event": {
            "entity_id": ["entity_id", "entity", "cse_id"],
            "ref_type": ["ref_type", "type"],
            "ref_id": ["ref_id", "case_id", "alert_id", "ticket_id"],
            "ts": ["ts", "performed_at", "timestamp", "time", "date"],
            "actor": ["actor", "user", "performed_by", "analyst"],
            "action": ["action", "step_name", "activity", "stage"],
            "from_status": ["from_status", "old_status", "previous_status"],
            "to_status": ["to_status", "new_status", "status"],
            "note_len": ["note_len", "comment_length", "len"],
        },
        "asset": {
            "asset_id": [
                "asset_id",
                "id",
                "hostname",
                "host",
                "system",
                "device_name",
                "ip",
                "ci_name",
            ],
            "entity_id": ["entity_id", "entity", "cse_id"],
            "asset_type": ["asset_type", "type", "category", "class"],
            "criticality": ["criticality", "priority", "tier", "business_value"],
            "monitored_flag": ["monitored_flag", "is_monitored", "monitored", "active_monitoring"],
            "owner_unit": ["owner_unit", "owner", "unit", "department"],
        },
        "log_source_daily": {
            "entity_id": ["entity_id", "entity", "cse_id"],
            "asset_id": ["asset_id", "host", "hostname", "system"],
            "source_type": ["source_type", "log_source_type", "type", "log_type"],
            "date": ["date", "day", "event_date"],
            "event_count": ["event_count", "count", "events", "volume"],
        },
        "declared_kpi": {
            "entity_id": ["entity_id", "entity", "cse_id"],
            "period": ["period", "quarter", "month"],
            "metric": ["metric", "kpi_name", "metric_name", "kpi"],
            "severity": ["severity", "level"],
            "value": ["value", "declared_value", "target"],
        },
        "entity": {
            "entity_id": ["entity_id", "id", "cse_id", "org_id"],
            "name": ["name", "organization_name", "org_name", "entity_name"],
            "sector": ["sector", "industry", "domain"],
            "size_band": ["size_band", "size", "tier", "scale"],
        },
    }

    def __init__(
        self,
        duckdb_store: DuckDBStore,
        sqlite_store: SQLiteStore,
        taxonomy_path: Path | str = "config/taxonomy.yaml",
        salt_file: Path | str = ".satsa_salt",
    ):
        self.duckdb_store = duckdb_store
        self.sqlite_store = sqlite_store
        self.normaliser = TaxonomyNormaliser(taxonomy_path)
        self.pseudonymiser = Pseudonymiser(salt_file)
        self.redactor = Redactor()

    @classmethod
    def resolve_canonical_table(cls, stem: str, headers: list[str]) -> str:
        s = stem.lower().strip()

        # Exact stem match first
        if s in cls.CANONICAL_TABLES:
            return s
        if s == "case":
            return "case_record"

        # Filename matching (specific before general)
        mapping_rules = [
            ("case_alert_link", "case_alert_link"),
            ("workflow_event", "workflow_event"),
            ("workflow", "workflow_event"),
            ("lifecycle", "workflow_event"),
            ("detection_rule", "detection_rule"),
            ("detection", "detection_rule"),
            ("sla_policy", "sla_policy"),
            ("sla", "sla_policy"),
            ("external_report", "external_report"),
            ("log_source_daily", "log_source_daily"),
            ("log_source", "log_source_daily"),
            ("declared_kpi", "declared_kpi"),
            ("escalat", "escalation"),
            ("closur", "closure"),
            ("case", "case_record"),
            ("incident", "case_record"),
            ("ticket", "case_record"),
            ("alert", "alert"),
            ("notable", "alert"),
            ("asset", "asset"),
            ("host", "asset"),
            ("inventory", "asset"),
            ("telemetry", "log_source_daily"),
            ("kpi", "declared_kpi"),
            ("metric", "declared_kpi"),
            ("entity", "entity"),
            ("cse", "entity"),
            ("organization", "entity"),
            ("event", "alert"),
        ]
        for pattern, table in mapping_rules:
            if pattern in s:
                return table

        # Header inspection matching
        lower_headers = {h.lower().strip() for h in headers}
        if any(h in lower_headers for h in ["alert_id", "notable_id", "alertid"]):
            return "alert"
        if any(h in lower_headers for h in ["case_id", "incident_number", "ticket_id"]):
            return "case_record"
        if any(h in lower_headers for h in ["escalation_id", "from_tier", "to_tier"]):
            return "escalation"
        if any(h in lower_headers for h in ["closure_id", "comment", "duration_seconds"]):
            return "closure"
        if any(h in lower_headers for h in ["step_name", "step_order", "activity"]):
            return "workflow_event"
        if any(h in lower_headers for h in ["asset_id", "criticality", "hostname"]):
            return "asset"
        if any(h in lower_headers for h in ["event_count", "log_source_type"]):
            return "log_source_daily"
        if any(h in lower_headers for h in ["declared_value", "metric", "metric_name"]):
            return "declared_kpi"
        if any(h in lower_headers for h in ["sector", "size_band"]):
            return "entity"

        return "alert"  # Default fallback

    @classmethod
    def normalize_row_columns(cls, row: dict[str, Any], target_table: str) -> dict[str, Any]:
        """Map alternative column names and lowercase keys to canonical fields."""
        norm: dict[str, Any] = {}
        # Clean row keys
        lower_row = {k.lower().strip(): v for k, v in row.items()}
        table_aliases = cls.COLUMN_ALIASES.get(target_table, {})

        for canonical_col, aliases in table_aliases.items():
            for alias in aliases:
                if (
                    alias in lower_row
                    and lower_row[alias] is not None
                    and str(lower_row[alias]).strip() != ""
                ):
                    norm[canonical_col] = lower_row[alias]
                    break

        # Copy any remaining unmapped keys as-is. Previously this only copied a
        # key when it was already one of `target_table`'s CANONICAL column
        # names (`k in table_aliases`, since table_aliases' keys are the
        # canonical names) -- for any table with no COLUMN_ALIASES entry at
        # all (e.g. "detection_rule"), table_aliases is `{}`, so this check
        # was always False and EVERY column of EVERY row was silently
        # dropped, producing empty records for that table on every ingest.
        # Canonical models use `extra="ignore"`, so passing through raw
        # column names that don't happen to be recognized is always safe.
        for k, v in lower_row.items():
            if k not in norm:
                norm[k] = v

        return norm

    def ingest_directory(
        self, input_dir: Path | str, default_entity_id: str | None = None
    ) -> dict[str, Any]:
        """Ingest all CSV and JSON tables from directory, validate DQ, and store as Parquet.

        Rows whose `entity_id` fails satsa.security.ENTITY_ID_RE are dropped
        (never written, never evaluated) and reported as an `invalid_entity_id`
        DQ issue, so a malformed ID can't reach a query or a partition path.
        """
        if default_entity_id is not None:
            require_entity_id(default_entity_id)
        dir_path = Path(input_dir)
        raw_files = (
            list(dir_path.rglob("*.csv"))
            + list(dir_path.rglob("*.json"))
            + list(dir_path.rglob("*.ndjson"))
        )
        if not raw_files:
            return {"status": "empty", "message": f"No supported data files found in {input_dir}"}

        tables_data: dict[str, list[dict[str, Any]]] = {}
        row_counts: dict[str, int] = {}
        processed_files: list[Path] = []
        # table -> sample of rejected (invalid) entity_id values
        rejected_ids: dict[str, list[str]] = {}

        for f in raw_files:
            try:
                if f.suffix.lower() == ".csv":
                    raw_rows = SourceAdapter.read_csv(f)
                else:
                    raw_rows = SourceAdapter.read_json(f)

                if not raw_rows:
                    continue

                processed_files.append(f)
                headers = list(raw_rows[0].keys())
                canonical_table = self.resolve_canonical_table(f.stem, headers)

                normalized_rows = []
                for r in raw_rows:
                    clean_r = self.normalize_row_columns(r, canonical_table)
                    # Apply default entity if missing
                    if default_entity_id and not clean_r.get("entity_id"):
                        clean_r["entity_id"] = default_entity_id
                    eid = clean_r.get("entity_id")
                    if eid is not None and str(eid).strip() and not is_valid_entity_id(str(eid)):
                        rejected_ids.setdefault(canonical_table, []).append(str(eid))
                        continue
                    normalized_rows.append(clean_r)

                tables_data.setdefault(canonical_table, []).extend(normalized_rows)
                row_counts[canonical_table] = row_counts.get(canonical_table, 0) + len(
                    normalized_rows
                )
            except Exception:  # noqa: BLE001, S112
                continue

        if not tables_data:
            return {"status": "error", "message": "Failed to parse records from uploaded files."}

        # Determine entities involved
        entities_present: set[str] = set()
        for tbl in ["entity", "alert", "case_record", "asset", "declared_kpi"]:
            if tbl in tables_data:
                for r in tables_data[tbl]:
                    val = r.get("entity_id")
                    if val and str(val).strip():
                        entities_present.add(str(val).strip())

        if default_entity_id:
            entities_present.add(default_entity_id)

        primary_entity = min(entities_present) if entities_present else "ALL_CSE"

        # Apply Pseudonymisation, Normalization, and Redaction
        if "alert" in tables_data:
            for r in tables_data["alert"]:
                if r.get("closed_by_type") == "human" and r.get("closed_by"):
                    r["closed_by"] = self.pseudonymiser.pseudonymise(
                        r["closed_by"], prefix="ANALYST"
                    )
                # Defaults
                if not r.get("closed_by_type"):
                    r["closed_by_type"] = "human"
                if r.get("severity_orig"):
                    r["severity_orig"] = self.normaliser.normalise_severity(r["severity_orig"])
                if r.get("severity_final"):
                    r["severity_final"] = self.normaliser.normalise_severity(r["severity_final"])
                elif r.get("severity"):
                    r["severity_final"] = self.normaliser.normalise_severity(r["severity"])
                if r.get("status"):
                    r["status"] = self.normaliser.normalise_status(r["status"])
                if r.get("disposition"):
                    r["disposition"] = self.normaliser.normalise_disposition(r["disposition"])

        if "workflow_event" in tables_data:
            for r in tables_data["workflow_event"]:
                if r.get("actor"):
                    r["actor"] = self.pseudonymiser.pseudonymise(r["actor"], prefix="ACTOR")

        if "closure" in tables_data:
            for r in tables_data["closure"]:
                raw_c = r.get("comment", "")
                if raw_c:
                    redacted = self.redactor.redact_text(str(raw_c))
                    r["comment_norm_hash"] = self.redactor.compute_norm_hash(redacted)
                    r["comment_len"] = len(redacted)
                    shingles = self.redactor.generate_shingles(redacted)
                    r["comment_shingles"] = ",".join(shingles[:10])

        # Auto-register newly discovered entities into the entity table
        self.duckdb_store.load_table_from_parquet("entity")
        df_existing_entities = self.duckdb_store.query("SELECT entity_id FROM entity")
        existing_eids = (
            {row["entity_id"] for row in df_existing_entities.iter_rows(named=True)}
            if not df_existing_entities.is_empty()
            else set()
        )

        new_entities_to_add: list[dict[str, Any]] = []
        for eid in entities_present:
            if eid not in existing_eids:
                new_ent_record = {
                    "entity_id": eid,
                    "name": f"{eid} Operations",
                    "sector": "General Infrastructure",
                    "size_band": "Medium",
                    "soc_model": "inhouse",
                    "timezone": "UTC",
                    "declared_shift_hours": "09:00-18:00",
                }
                new_entities_to_add.append(new_ent_record)
                existing_eids.add(eid)

        if new_entities_to_add:
            tables_data.setdefault("entity", []).extend(new_entities_to_add)
            row_counts["entity"] = row_counts.get("entity", 0) + len(new_entities_to_add)

        # Run Data Quality checks per entity
        all_dq_issues = []
        for tbl, bad_ids in sorted(rejected_ids.items()):
            all_dq_issues.append(
                DQIssue(
                    issue_id=f"DQ-INVALID-ENTITY-ID-{primary_entity}-{tbl}",
                    entity_id=primary_entity,
                    check_name="invalid_entity_id",
                    severity="error",
                    count=len(bad_ids),
                    sample_records=[repr(b)[:80] for b in bad_ids[:5]],
                    details=(
                        f"{len(bad_ids)} '{tbl}' rows rejected: entity_id does not match "
                        "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ (rows were not stored or evaluated)."
                    ),
                )
            )
        for ent_id in sorted(entities_present):
            ent_alerts = [a for a in tables_data.get("alert", []) if a.get("entity_id") == ent_id]
            if ent_alerts:
                req_issues = DQValidator.check_required_fields(
                    ent_alerts,
                    ["alert_id", "entity_id", "created_at", "severity_final"],
                    ent_id,
                    "alert",
                )
                all_dq_issues.extend(req_issues)

                ts_issues = DQValidator.check_timestamp_logic(ent_alerts, ent_id)
                all_dq_issues.extend(ts_issues)

                dup_issues = DQValidator.check_duplicate_ids(
                    ent_alerts, "alert_id", ent_id, "alert"
                )
                all_dq_issues.extend(dup_issues)

                gap_issues = DQValidator.check_id_sequence_gaps(ent_alerts, "alert_id", ent_id)
                all_dq_issues.extend(gap_issues)

                null_issues = DQValidator.check_null_rates(
                    ent_alerts, ["rule_id", "asset_id", "closed_by", "disposition"], ent_id, "alert"
                )
                all_dq_issues.extend(null_issues)

            ent_assets: set[str] = {
                str(a.get("asset_id"))
                for a in tables_data.get("asset", [])
                if a.get("entity_id") == ent_id and a.get("asset_id")
            }
            if ent_assets and ent_alerts:
                orphan_issues = DQValidator.check_orphan_references(
                    ent_alerts, ent_assets, "asset_id", ent_id, "alert", "asset"
                )
                all_dq_issues.extend(orphan_issues)

        # Save DQ issues to SQLite
        for dq in all_dq_issues:
            self.sqlite_store.save_dq_issue(dq)

        # Write to partitioned Parquet via DuckDBStore
        for table_name, rows in tables_data.items():
            if rows:
                try:
                    df = pl.DataFrame(rows)
                    # Canonical table names: map 'case_record' to 'case' if DuckDB DDL requires
                    duck_tbl = "case" if table_name == "case_record" else table_name
                    self.duckdb_store.write_partitioned_parquet(duck_tbl, df)
                except Exception:  # noqa: BLE001, S112
                    continue

        # Build manifest and append to audit log
        batch, _manifest_dict = ManifestBuilder.build_manifest(
            entity_id=primary_entity, files=processed_files, row_counts=row_counts
        )
        self.sqlite_store.append_audit(
            action="ingest",
            actor="pipeline",
            details={
                "batch_id": batch.batch_id,
                "entity_id": primary_entity,
                "files_count": len(processed_files),
                "row_counts": row_counts,
                "entities_detected": list(entities_present),
                "dq_issues_found": len(all_dq_issues),
            },
        )

        return {
            "status": "success",
            "batch_id": batch.batch_id,
            "entities": list(entities_present),
            "row_counts": row_counts,
            "dq_issues": len(all_dq_issues),
        }
