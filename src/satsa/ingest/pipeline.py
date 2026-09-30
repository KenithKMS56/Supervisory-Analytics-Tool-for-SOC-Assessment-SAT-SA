"""End-to-end ingestion pipeline orchestrator with intelligent canonical schema mapping."""

import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import polars as pl

from satsa.ingest.adapters import SourceAdapter
from satsa.ingest.dq_checks import DQValidator
from satsa.ingest.manifest import ManifestBuilder
from satsa.ingest.mapper import SourceMapping
from satsa.ingest.normaliser import TaxonomyNormaliser
from satsa.ingest.pseudonymise import Pseudonymiser
from satsa.ingest.redact import Redactor
from satsa.models.outputs import DQIssue
from satsa.rules.registry import RULE_ALERT_FIELDS, rule_coverage
from satsa.security import is_valid_entity_id, require_entity_id
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

logger = logging.getLogger(__name__)

# Child tables whose rows must reference an alert in the same submission:
# (table, foreign-key column, which rows the check applies to).
_ALERT_CHILD_TABLES: list[tuple[str, str, Callable[[dict[str, Any]], bool]]] = [
    ("closure", "ref_id", lambda r: True),
    ("workflow_event", "ref_id", lambda r: str(r.get("ref_type", "alert")) == "alert"),
    ("escalation", "ref_id", lambda r: True),
    ("case_alert_link", "alert_id", lambda r: True),
]


# Values that say "no verdict recorded": a disposition column holding only these is empty.
_NO_VALUE = frozenset({"", "unknown", "unmapped", "none", "null"})


# Rows normalised at a time. Bounds the memory held as Python objects during ingestion.
CHUNK_ROWS = 100_000


def _usable_count(series: pl.Series) -> int:
    """Number of values in a column that say something: not null, not blank, not "unknown"."""
    if series.dtype == pl.Null:
        return 0
    if series.dtype == pl.String:
        blank = series.str.strip_chars().str.to_lowercase().is_in(list(_NO_VALUE))
        return int((series.is_not_null() & ~blank).sum())
    return int(series.is_not_null().sum())


def _frame_from_rows(rows: list[dict[str, Any]]) -> pl.DataFrame:
    try:
        return pl.DataFrame(rows, infer_schema_length=None)
    except (pl.exceptions.PolarsError, TypeError, ValueError):
        # A column holding mixed types in one chunk: keep every value, as text. The store
        # casts each column to its canonical type when it loads the table.
        return pl.DataFrame(
            [{k: None if v is None else str(v) for k, v in r.items()} for r in rows], infer_schema_length=None
        )


def _concat_frames(frames: list[pl.DataFrame]) -> pl.DataFrame:
    if len(frames) == 1:
        return frames[0]
    try:
        return pl.concat(frames, how="diagonal_relaxed")
    except pl.exceptions.PolarsError:
        return pl.concat([f.cast(pl.String) for f in frames], how="diagonal_relaxed")


def _partition_by_entity(frame: pl.DataFrame) -> dict[str, pl.DataFrame]:
    if "entity_id" not in frame.columns or frame.height == 0:
        return {}
    return {str(part["entity_id"][0]): part for part in frame.partition_by("entity_id", maintain_order=True)}


def _store_table(canonical_table: str) -> str:
    """Name a table is stored and queried under (`case_record` is stored as `case`)."""
    return "case" if canonical_table == "case_record" else canonical_table


def default_entity_record(entity_id: str) -> dict[str, Any]:
    """Registry record for a CSE first seen in submitted data rather than onboarded via /upload/add-entity."""
    return {
        "entity_id": entity_id,
        "name": f"{entity_id} Operations",
        "sector": "General Infrastructure",
        "size_band": "Medium",
        "soc_model": "inhouse",
        "timezone": "UTC",
        "declared_shift_hours": "09:00-18:00",
    }


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
    def table_for_empty_file(cls, path: Path) -> str | None:
        """Table a file with no data rows stands for, or None if it cannot be identified.

        A header-only file declares "this table is submitted and empty" (see the submission
        manifest). resolve_canonical_table defaults to `alert` for anything it does not
        recognise, which is fine for rows but would record an unrelated empty file as the
        alert table, so that default is accepted only when the name or headers really say alert.
        """
        headers: list[str] = []
        if path.suffix.lower() == ".csv":
            first_line = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()[:1]
            headers = [h.strip().strip('"') for h in first_line[0].split(",")] if first_line else []
        table = cls.resolve_canonical_table(path.stem, headers)
        if table != "alert":
            return table
        stem = path.stem.lower()
        named_alert = any(k in stem for k in ("alert", "notable", "event"))
        alert_headers = {h.lower() for h in headers} & {"alert_id", "notable_id", "alertid"}
        return "alert" if named_alert or alert_headers else None

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

    def _apply_row_hygiene(self, table: str, rows: list[dict[str, Any]]) -> None:
        """Pseudonymise people, normalise taxonomy values and reduce free text, in place."""
        if table == "alert":
            for r in rows:
                # The default comes first: a source with no closer-type column is all human,
                # and its analysts' names must be pseudonymised like any other.
                if not r.get("closed_by_type"):
                    r["closed_by_type"] = "human"
                if r.get("closed_by_type") == "human" and r.get("closed_by"):
                    r["closed_by"] = self.pseudonymiser.pseudonymise(str(r["closed_by"]), prefix="ANALYST")
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
        elif table == "workflow_event":
            for r in rows:
                if r.get("actor"):
                    r["actor"] = self.pseudonymiser.pseudonymise(str(r["actor"]), prefix="ACTOR")
        elif table in ("case_record", "case"):
            # Case owners are people too: pseudonymised like alert closers and workflow actors.
            for r in rows:
                if r.get("owner"):
                    r["owner"] = self.pseudonymiser.pseudonymise(str(r["owner"]), prefix="OWNER")
        elif table == "closure":
            for r in rows:
                # The free text itself is never stored: only its redacted hash, length and shingles.
                raw_c = r.pop("comment", "")
                if raw_c:
                    redacted = self.redactor.redact_text(str(raw_c))
                    r["comment_norm_hash"] = self.redactor.compute_norm_hash(redacted)
                    r["comment_len"] = len(redacted)
                    shingles = self.redactor.hash_shingles(self.redactor.generate_shingles(redacted))
                    r["comment_shingles"] = ",".join(shingles[:10])

    def ingest_directory(
        self,
        input_dir: Path | str,
        default_entity_id: str | None = None,
        mapping: SourceMapping | None = None,
    ) -> dict[str, Any]:
        """Ingest all CSV and JSON tables from directory, validate DQ, and store as Parquet.

        Rows whose `entity_id` fails satsa.security.ENTITY_ID_RE are dropped
        (never written, never evaluated) and reported as an `invalid_entity_id`
        DQ issue, so a malformed ID can't reach a query or a partition path.

        With `mapping` (a product export mapping from config/mappings/), files are not in
        the canonical layout: each is translated by the mapping, every row belongs to
        `default_entity_id` (else the mapping's own entity), and a file the mapping does
        not describe is reported instead of being guessed at.

        The result says what the submission lets each rule do (`rule_coverage`) and how
        complete each stored column is (`field_coverage`).
        """
        if mapping is not None:
            default_entity_id = default_entity_id or mapping.entity_id
            if not default_entity_id:
                return {
                    "status": "error",
                    "message": "A source mapping needs a target entity (--entity, or entity_id in the mapping).",
                }
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

        # Rows are held as columnar frames, one list of chunks per table. A row is a Python
        # dict only while its chunk is being normalised, so memory follows the chunk size and
        # not the size of the submission.
        buffers: dict[str, list[pl.DataFrame]] = {}
        row_counts: dict[str, int] = {}
        processed_files: list[Path] = []
        # table -> sample of rejected (invalid) entity_id values
        rejected_ids: dict[str, list[str]] = {}
        # table -> number of rows with no entity_id (and no default entity given)
        unattributed: dict[str, int] = {}
        # Only the canonical columns are stored. A source column the model does not know
        # (a free-text note, a user name, an e-mail address) would otherwise sit unredacted
        # in the Parquet files even though no rule can read it.
        dropped: dict[str, set[str]] = {}
        canonical_columns: dict[str, list[str]] = {}

        # Tables this submission includes, whether or not they hold rows: a header-only file
        # says "we submit this table and it is empty", which is different from not sending it.
        declared_tables: set[str] = set()
        unreadable_files: list[str] = []
        unmapped_files: list[str] = []
        unused_source_columns: dict[str, list[str]] = {}

        def store_rows(table: str, rows: list[dict[str, Any]]) -> None:
            """Hygiene, canonical columns only, then into the table's columnar buffer."""
            if not rows:
                return
            self._apply_row_hygiene(table, rows)
            if table not in canonical_columns:
                canonical_columns[table] = self.duckdb_store.table_columns(_store_table(table))
            columns = canonical_columns[table]
            if columns:
                present = set().union(*(r.keys() for r in rows))
                extra = present - set(columns)
                if extra:
                    dropped.setdefault(_store_table(table), set()).update(extra)
                keep = [c for c in columns if c in present]
                rows = [{c: r.get(c) for c in keep} for r in rows]
            buffers.setdefault(table, []).append(_frame_from_rows(rows))
            row_counts[table] = row_counts.get(table, 0) + len(rows)

        def normalise_chunk(table: str, raw_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            kept = []
            for r in raw_rows:
                clean_r = self.normalize_row_columns(r, table)
                # Apply default entity if missing
                if default_entity_id and not clean_r.get("entity_id"):
                    clean_r["entity_id"] = default_entity_id
                eid = clean_r.get("entity_id")
                if eid is None or not str(eid).strip():
                    # Every canonical table is partitioned by entity: a row
                    # attributable to no CSE can't be assessed, and storing it
                    # would land outside the entity partitions.
                    unattributed[table] = unattributed.get(table, 0) + 1
                    continue
                if not is_valid_entity_id(str(eid)):
                    rejected_ids.setdefault(table, []).append(str(eid))
                    continue
                kept.append(clean_r)
            return kept

        def read(path: Path) -> pl.DataFrame | list[dict[str, Any]]:
            if path.suffix.lower() == ".csv":
                return SourceAdapter.read_csv_frame(path)
            return SourceAdapter.read_json(path)

        def chunks(data: pl.DataFrame | list[dict[str, Any]]) -> Iterator[list[dict[str, Any]]]:
            if isinstance(data, pl.DataFrame):
                for piece in data.iter_slices(CHUNK_ROWS):
                    yield piece.to_dicts()
            else:
                for i in range(0, len(data), CHUNK_ROWS):
                    yield data[i : i + CHUNK_ROWS]

        # A product export is read up front: one file may be needed to translate ids in
        # another. The canonical layout is read one file at a time.
        preloaded: dict[Path, list[dict[str, Any]]] = {}
        if mapping is not None:
            for f in raw_files:
                try:
                    data = read(f)
                    preloaded[f] = data.to_dicts() if isinstance(data, pl.DataFrame) else data
                except Exception:
                    logger.exception("Could not read submission file %s", f.name)
                    unreadable_files.append(f.name)
            mapping.build_lookups({f.stem: rows for f, rows in preloaded.items()})

        for f in raw_files:
            if f.name in unreadable_files:
                continue
            try:
                if mapping is not None:
                    raw_rows = preloaded.pop(f)
                    specs = mapping.specs_for_file(f.stem)
                    if not specs:
                        unmapped_files.append(f.name)
                        continue
                    assert default_entity_id is not None
                    if raw_rows:
                        processed_files.append(f)
                        used = set().union(*(spec.source_columns() for spec in specs))
                        unused = sorted(set(raw_rows[0]) - used)
                        if unused:
                            unused_source_columns[f.name] = unused
                    for spec in specs:
                        declared_tables.add(_store_table(spec.table))
                        store_rows(spec.table, mapping.map_rows(raw_rows, spec, default_entity_id).rows)
                    continue

                data = read(f)
                if len(data) == 0:
                    empty_table = self.table_for_empty_file(f)
                    if empty_table:
                        declared_tables.add(_store_table(empty_table))
                    continue

                processed_files.append(f)
                headers = data.columns if isinstance(data, pl.DataFrame) else list(data[0].keys())
                canonical_table = self.resolve_canonical_table(f.stem, headers)
                declared_tables.add(_store_table(canonical_table))
                row_counts.setdefault(canonical_table, 0)
                for raw_rows in chunks(data):
                    store_rows(canonical_table, normalise_chunk(canonical_table, raw_rows))
            except Exception:
                # Reported below as a DQ error: a file dropped without trace would make
                # its table look absent, and rules would read that as a SOC defect.
                logger.exception("Could not read submission file %s", f.name)
                unreadable_files.append(f.name)

        if unattributed and not buffers:
            counts = ", ".join(f"{n} {t}" for t, n in sorted(unattributed.items()))
            return {
                "status": "error",
                "message": (
                    f"No rows stored: {counts} row(s) have no entity_id. Add an entity_id "
                    "column or choose a target entity for the upload."
                ),
            }
        if not buffers and not row_counts:
            return {"status": "error", "message": "Failed to parse records from uploaded files."}

        tables: dict[str, pl.DataFrame] = {name: _concat_frames(parts) for name, parts in buffers.items()}
        buffers.clear()

        # Determine entities involved
        entities_present: set[str] = set()
        for tbl in ["entity", "alert", "case_record", "case", "asset", "declared_kpi"]:
            if tbl in tables:
                for val in tables[tbl]["entity_id"].unique().to_list():
                    if val and str(val).strip():
                        entities_present.add(str(val).strip())

        if default_entity_id:
            entities_present.add(default_entity_id)

        primary_entity = min(entities_present) if entities_present else "ALL_CSE"

        # Auto-register newly discovered entities into the entity table
        self.duckdb_store.load_table_from_parquet("entity")
        df_existing_entities = self.duckdb_store.query("SELECT entity_id FROM entity")
        existing_eids = (
            {row["entity_id"] for row in df_existing_entities.iter_rows(named=True)}
            if not df_existing_entities.is_empty()
            else set()
        )

        new_entities_to_add: list[dict[str, Any]] = []
        for eid in sorted(entities_present):
            if eid not in existing_eids:
                new_entities_to_add.append(default_entity_record(eid))
                existing_eids.add(eid)

        if new_entities_to_add:
            parts = [tables["entity"]] if "entity" in tables else []
            tables["entity"] = _concat_frames([*parts, _frame_from_rows(new_entities_to_add)])
            row_counts["entity"] = row_counts.get("entity", 0) + len(new_entities_to_add)

        # Each table split by entity once; an entity's rows become dicts only while its
        # checks run.
        by_entity: dict[str, dict[str, pl.DataFrame]] = {
            name: _partition_by_entity(frame) for name, frame in tables.items()
        }

        def entity_rows(table: str, ent_id: str) -> list[dict[str, Any]]:
            frame = by_entity.get(table, {}).get(ent_id)
            return frame.to_dicts() if frame is not None else []

        # Run Data Quality checks per entity
        all_dq_issues = []
        if unreadable_files:
            all_dq_issues.append(
                DQIssue(
                    issue_id=f"DQ-UNREADABLE-{primary_entity}-{'-'.join(sorted(unreadable_files))[:80]}",
                    entity_id=primary_entity,
                    check_name="file_unreadable",
                    severity="error",
                    count=len(unreadable_files),
                    sample_records=sorted(unreadable_files)[:5],
                    details=(
                        f"{len(unreadable_files)} submitted file(s) could not be read and were not ingested: "
                        f"{', '.join(sorted(unreadable_files))}. Rules that depend on their tables are unreliable "
                        "until the files are fixed and re-submitted."
                    ),
                )
            )
        if unmapped_files:
            all_dq_issues.append(
                DQIssue(
                    issue_id=f"DQ-UNMAPPED-FILE-{primary_entity}-{'-'.join(sorted(unmapped_files))[:80]}",
                    entity_id=primary_entity,
                    check_name="file_not_mapped",
                    severity="warning",
                    count=len(unmapped_files),
                    sample_records=sorted(unmapped_files)[:5],
                    details=(
                        f"{len(unmapped_files)} file(s) are not described by the source mapping and were not "
                        f"ingested: {', '.join(sorted(unmapped_files))}."
                    ),
                )
            )
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
        for tbl, n in sorted(unattributed.items()):
            all_dq_issues.append(
                DQIssue(
                    issue_id=f"DQ-MISSING-ENTITY-ID-{primary_entity}-{tbl}",
                    entity_id=primary_entity,
                    check_name="missing_entity_id",
                    severity="error",
                    count=n,
                    sample_records=[],
                    details=(
                        f"{n} '{tbl}' rows rejected: no entity_id and no target entity "
                        "selected (rows were not stored or evaluated)."
                    ),
                )
            )
        for ent_id in sorted(entities_present):
            ent_alerts = entity_rows("alert", ent_id)
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

                # Only meaningful where alert ids are a running counter; a mapping for a product
                # whose ids are GUIDs or storage keys says `sequential_ids: false`.
                if mapping is None or mapping.config.get("sequential_ids", True):
                    gap_issues = DQValidator.check_id_sequence_gaps(ent_alerts, "alert_id", ent_id)
                    all_dq_issues.extend(gap_issues)

                null_issues = DQValidator.check_null_rates(
                    ent_alerts, ["rule_id", "asset_id", "closed_by", "disposition"], ent_id, "alert"
                )
                all_dq_issues.extend(null_issues)

            ent_assets: set[str] = {
                str(a.get("asset_id")) for a in entity_rows("asset", ent_id) if a.get("asset_id")
            }
            if ent_assets and ent_alerts:
                orphan_issues = DQValidator.check_orphan_references(
                    ent_alerts, ent_assets, "asset_id", ent_id, "alert", "asset"
                )
                all_dq_issues.extend(orphan_issues)

            # Child records must point at an alert (or case) that is in the submission.
            # A closure, workflow event, escalation or case link whose parent is missing
            # makes EG02/EG03/NS04 read "no investigation / no escalation / no case" for
            # the wrong reason, and can itself indicate withheld records.
            ent_alert_ids = {str(a.get("alert_id")) for a in ent_alerts if a.get("alert_id")}
            del ent_alerts
            if ent_alert_ids:
                for child_table, fk_col, keep in _ALERT_CHILD_TABLES:
                    children = [r for r in entity_rows(child_table, ent_id) if keep(r)]
                    if children:
                        all_dq_issues.extend(
                            DQValidator.check_orphan_references(
                                children, ent_alert_ids, fk_col, ent_id, child_table, "alert"
                            )
                        )
            ent_case_ids = {
                str(c.get("case_id"))
                for tbl in ("case", "case_record")
                for c in entity_rows(tbl, ent_id)
                if c.get("case_id")
            }
            ent_links = entity_rows("case_alert_link", ent_id)
            if ent_case_ids and ent_links:
                all_dq_issues.extend(
                    DQValidator.check_orphan_references(
                        ent_links, ent_case_ids, "case_id", ent_id, "case_alert_link", "case"
                    )
                )

        field_coverage: dict[str, dict[str, Any]] = {
            _store_table(name): {
                "rows": frame.height,
                "filled": {
                    c: (_usable_count(frame[c]) if c in frame.columns else 0)
                    for c in canonical_columns.get(name) or self.duckdb_store.table_columns(_store_table(name))
                    if c != "entity_id"
                },
            }
            for name, frame in tables.items()
            if frame.height
        }
        dropped_columns = {table: sorted(columns) for table, columns in sorted(dropped.items())}

        # Write to partitioned Parquet via DuckDBStore. A table that fails to store must
        # not vanish quietly: rules would then read its absence as a SOC defect.
        failed_tables: list[str] = []
        for table_name, df in tables.items():
            if df.height:
                try:
                    # Canonical table names: map 'case_record' to 'case' if DuckDB DDL requires
                    duck_tbl = "case" if table_name == "case_record" else table_name
                    self.duckdb_store.write_partitioned_parquet(duck_tbl, df)
                except Exception as exc:
                    logger.exception("Failed to store table %r (%d rows)", table_name, df.height)
                    failed_tables.append(table_name)
                    all_dq_issues.append(
                        DQIssue(
                            issue_id=f"DQ-WRITE-FAILED-{primary_entity}-{table_name}",
                            entity_id=primary_entity,
                            check_name="table_write_failed",
                            severity="error",
                            count=df.height,
                            sample_records=[],
                            details=(
                                f"Table '{table_name}' ({df.height} rows) could not be stored "
                                f"({type(exc).__name__}). Findings that depend on it are unreliable "
                                "until the submission is re-ingested."
                            ),
                        )
                    )

        # Build manifest and append to audit log
        batch, _manifest_dict = ManifestBuilder.build_manifest(
            entity_id=primary_entity, files=processed_files, row_counts=row_counts
        )
        # Submission manifest: every entity in this batch submitted these tables. A table whose
        # file failed to store is not counted, so its rules are not assessed on missing data.
        manifest_tables = declared_tables - {_store_table(t) for t in failed_tables}
        self.sqlite_store.record_submitted_tables(entities_present, manifest_tables, batch.batch_id)

        # What this leaves each rule able to do, per entity: skipped for want of a table, or
        # running on an alert column the source could not fill.
        submitted = self.sqlite_store.get_submitted_tables()
        coverage: dict[str, dict[str, dict[str, list[str]]]] = {}
        for ent_id in sorted(entities_present):
            alert_frame = by_entity.get("alert", {}).get(ent_id)
            alert_count = alert_frame.height if alert_frame is not None else 0
            empty_fields = {
                column
                for columns in RULE_ALERT_FIELDS.values()
                for column in columns
                if alert_frame is not None
                and (column not in alert_frame.columns or _usable_count(alert_frame[column]) == 0)
            }
            coverage[ent_id] = rule_coverage(submitted.get(ent_id, set()), empty_fields)
            rules_by_column: dict[str, list[str]] = {}
            for rule_id, columns in coverage[ent_id]["degraded"].items():
                for column in columns:
                    rules_by_column.setdefault(column, []).append(rule_id)
            for column, rule_ids in sorted(rules_by_column.items()):
                all_dq_issues.append(
                    DQIssue(
                        issue_id=f"DQ-RULE-INPUT-{ent_id}-alert-{column}",
                        entity_id=ent_id,
                        check_name="rule_input_missing",
                        severity="warning",
                        count=alert_count,
                        sample_records=sorted(rule_ids),
                        details=(
                            f"alert.{column} holds no usable value in any of this entity's {alert_count} "
                            f"submitted alerts. {', '.join(sorted(rule_ids))} read it and cannot fire without "
                            "it: no finding from them is not evidence that the control works."
                        ),
                    )
                )

        # Save DQ issues to SQLite
        for dq in all_dq_issues:
            self.sqlite_store.save_dq_issue(dq)

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
                "failed_tables": failed_tables,
            },
        )

        return {
            "status": "partial" if failed_tables else "success",
            "batch_id": batch.batch_id,
            "entities": list(entities_present),
            "row_counts": row_counts,
            "failed_tables": failed_tables,
            "unreadable_files": sorted(unreadable_files),
            "submitted_tables": sorted(manifest_tables),
            "dq_issues": len(all_dq_issues),
            "unattributed_rows": unattributed,
            "rule_coverage": coverage,
            "field_coverage": field_coverage,
            "dropped_columns": dropped_columns,
            "source": mapping.source if mapping is not None else None,
            "unmapped_files": sorted(unmapped_files),
            "unused_source_columns": unused_source_columns,
        }
