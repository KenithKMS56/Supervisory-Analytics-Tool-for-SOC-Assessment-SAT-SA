"""End-to-end ingestion pipeline orchestrator with intelligent canonical schema mapping."""

import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import polars as pl

from satsa.ingest.adapters import SourceAdapter
from satsa.ingest.columnar import ColumnarResult, normalise_frame
from satsa.ingest.dq_checks import FrameDQ
from satsa.ingest.ledger import ROW_SAMPLE, FileLedger, Rejected
from satsa.ingest.manifest import ManifestBuilder
from satsa.ingest.mapper import MappingError, SourceMapping
from satsa.ingest.normaliser import TaxonomyNormaliser
from satsa.ingest.pseudonymise import Pseudonymiser
from satsa.ingest.redact import Redactor
from satsa.ingest.sanitise import (
    EXCEL_SUFFIXES,
    SUPPORTED_SUFFIXES,
    TABULAR_SUFFIXES,
    UnreadableFile,
    collect_reports,
    collected,
    header_key,
    read_header,
    report_for,
)
from satsa.models.outputs import DQIssue
from satsa.rules.registry import RULE_ALERT_FIELDS, rule_coverage
from satsa.security import is_valid_entity_id, require_entity_id
from satsa.store.duckdb import DuckDBStore
from satsa.store.sqlite import SQLiteStore

logger = logging.getLogger(__name__)

def _alert_refs(frame: pl.DataFrame) -> pl.DataFrame:
    """Workflow events that refer to an alert: `str(row.get("ref_type", "alert")) == "alert"`."""
    if "ref_type" not in frame.columns:
        return frame
    if frame["ref_type"].dtype == pl.String:
        return frame.filter(pl.col("ref_type").fill_null("None") == "alert")
    return frame.filter(pl.Series([str(v) == "alert" for v in frame["ref_type"].to_list()], dtype=pl.Boolean))


# Database exports: every table inside is read as if it were a file named after the table.
DATABASE_SUFFIXES = (".db", ".sqlite", ".sqlite3")


FILE_ORDER = (".csv", ".json", ".ndjson", ".tsv", ".xlsx")
assert set(FILE_ORDER) == set(SUPPORTED_SUFFIXES)


# Why a canonical row is set aside. Each reason also has its own DQ check
# (missing_entity_id, invalid_entity_id); every other reason is reported as rows_rejected.
NO_ENTITY = "no entity_id"
BAD_ENTITY = "invalid entity_id"


def _why(exc: Exception) -> str:
    """Why a file could not be read, in words that do not quote its content."""
    if isinstance(exc, UnreadableFile):
        return str(exc)
    if isinstance(exc, OSError):
        return f"could not be opened ({type(exc).__name__})"
    return f"could not be parsed ({type(exc).__name__})"


def _is_submission_file(path: Path) -> bool:
    """A data file to read: not an Excel lock file, macOS resource fork or `__MACOSX` copy."""
    if path.name.startswith(("~$", "._")) or "__MACOSX" in path.parts:
        return False
    return path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES


def _file_headers(path: Path) -> list[str]:
    """A delimited or Excel file's clean header, without reading its rows (empty otherwise)."""
    if path.suffix.lower() not in TABULAR_SUFFIXES + EXCEL_SUFFIXES:
        return []
    try:
        return read_header(path)
    except (OSError, UnicodeError):
        return []


def detect_source_mapping(input_dir: Path | str, mappings_dir: Path | str) -> SourceMapping | None:
    """The product mapping a submission's own columns identify, or None.

    A mapping is chosen when exactly one qualifies: one of its tables lists `headers:` that a
    submitted file has, and every submitted file is described by it (by name or columns). It is
    an exact match on column names the mapping declares, not a guess: a canonical submission has
    no product's identifying columns, and a mixed one is left to the canonical layout.
    """
    files = sorted(f for f in Path(input_dir).rglob("*") if _is_submission_file(f))
    if not files:
        return None
    headers = {f: _file_headers(f) for f in files}
    found = []
    for path in sorted(Path(mappings_dir).glob("*.yaml")):
        try:
            mapping = SourceMapping(path)
        except MappingError:
            continue  # not a pipeline mapping (cse_api_ticketing.yaml is a single-record one)
        if not any(spec.headers for spec in mapping.tables):
            continue
        if any(mapping.identifies(h) for h in headers.values()) and all(
            mapping.specs_for_file(f.stem, h) for f, h in headers.items()
        ):
            found.append(mapping)
    return found[0] if len(found) == 1 else None


@dataclass(frozen=True)
class DatabaseTable:
    """One table of a SQLite database export, standing in for a file named after the table."""

    db_path: Path
    table: str

    @property
    def name(self) -> str:
        return f"{self.db_path.name}:{self.table}"

    @property
    def stem(self) -> str:
        return self.table

    @property
    def suffix(self) -> str:
        return ".table"

# Child tables whose rows must reference an alert in the same submission:
# (table, foreign-key column, which rows the check applies to).
_ALERT_CHILD_TABLES: list[tuple[str, str, Callable[[pl.DataFrame], pl.DataFrame]]] = [
    ("closure", "ref_id", lambda f: f),
    ("workflow_event", "ref_id", _alert_refs),
    ("escalation", "ref_id", lambda f: f),
    ("case_alert_link", "alert_id", lambda f: f),
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


def _usable_counts(frame: pl.DataFrame, columns: list[str], slice_rows: int = 500_000) -> dict[str, int]:
    """_usable_count for several columns of a frame (absent columns count 0).

    The columns are counted together, a slice of rows at a time: together is faster, and
    slicing bounds the memory the trimmed, lower-cased copies of the text take.
    """
    exprs = []
    for column in columns:
        if column not in frame.columns or frame.schema[column] == pl.Null:
            continue
        usable = pl.col(column).is_not_null()
        if frame.schema[column] == pl.String:
            usable = usable & ~pl.col(column).str.strip_chars().str.to_lowercase().is_in(list(_NO_VALUE))
        exprs.append(usable.sum().alias(column))
    totals = dict.fromkeys(columns, 0)
    if exprs:
        for piece in frame.iter_slices(slice_rows):
            for column, count in piece.select(exprs).row(0, named=True).items():
                totals[column] += int(count or 0)
    return totals


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


def _rows_per_entity(frame: pl.DataFrame) -> dict[str, int]:
    """Row count per entity_id (normalised as the batch's entities are); {} without the column."""
    if "entity_id" not in frame.columns or frame.height == 0:
        return {}
    counts: dict[str, int] = {}
    for value, n in frame.group_by("entity_id").len().iter_rows():
        if value is not None and str(value).strip():
            key = str(value).strip()
            counts[key] = counts.get(key, 0) + n
    return counts


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


# Read the largest CSV of a canonical submission first (see ingest_directory); a switch only so
# tests can compare with the plain order.
READ_LARGEST_FIRST = True

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
        """The table a file stands for, `alert` when nothing identifies it (see recognise_table)."""
        return cls.recognise_table(stem, headers) or "alert"

    @classmethod
    def recognise_table(cls, stem: str, headers: list[str]) -> str | None:
        """The canonical table a file's name or key columns identify, or None if neither does.

        A file nothing identifies is not ingested: storing it as alerts (as ingest used to)
        would count rows of an unknown kind as alerts and let rules read their columns.
        """
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
        lower_headers = {header_key(h) for h in headers}
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

        return None

    @classmethod
    def table_for_empty_file(cls, path: Path | DatabaseTable) -> str | None:
        """Table a file with no data rows stands for, or None if it cannot be identified.

        A header-only file declares "this table is submitted and empty" (see the submission
        manifest). An unrelated empty file must not be recorded as some table, so only a file
        whose name or headers identify one counts (recognise_table).
        """
        headers: list[str] = []
        if isinstance(path, Path) and path.suffix.lower() in TABULAR_SUFFIXES + EXCEL_SUFFIXES:
            headers = read_header(path)
        return cls.recognise_table(path.stem, headers)

    @classmethod
    def normalize_row_columns(cls, row: dict[str, Any], target_table: str) -> dict[str, Any]:
        """Map alternative column names and lowercase keys to canonical fields."""
        norm: dict[str, Any] = {}
        # Clean row keys: "Alert ID", "alert_id" and "ALERT-ID" are the same column.
        lower_row = {header_key(k): v for k, v in row.items()}
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
        """Ingest a directory (see `_ingest_directory`), reporting how each file had to be read."""
        with collect_reports():
            result = self._ingest_directory(input_dir, default_entity_id, mapping)
            result["file_sanitising"] = [r.as_dict() for r in collected() if r.noteworthy]
        return result

    def _ingest_directory(
        self,
        input_dir: Path | str,
        default_entity_id: str | None = None,
        mapping: SourceMapping | None = None,
    ) -> dict[str, Any]:
        """Ingest all CSV, TSV, Excel and JSON tables from directory, validate DQ, and store as Parquet.

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
        # Suffixes are matched case-insensitively ("ALERTS.CSV" is a CSV on every platform).
        # Files are taken in the order they always were (CSV, then JSON, then NDJSON), with
        # the newer formats after them.
        found = [f for f in dir_path.rglob("*") if _is_submission_file(f)]
        raw_files: list[Path | DatabaseTable] = [
            f for suffix in FILE_ORDER for f in found if f.suffix.lower() == suffix
        ]
        unreadable_files: list[str] = []
        # What became of each file and its rows (ledger.py), in the order files were taken.
        ledgers: dict[Path | DatabaseTable, FileLedger] = {}

        def ledger(f: Path | DatabaseTable) -> FileLedger:
            if f not in ledgers:
                report = report_for(f) if isinstance(f, Path) else None
                ledgers[f] = FileLedger(file=f.name, row_label=report.row_label if report else "record")
            return ledgers[f]

        def file_rows(f: Path | DatabaseTable, positions: list[int]) -> list[int]:
            """The file's own numbers (spreadsheet row, JSON record) for positions in what was read."""
            report = report_for(f) if isinstance(f, Path) else None
            return report.source_rows(positions) if report else [p + 1 for p in sorted(positions)]

        def unreadable(f: Path | DatabaseTable, exc: Exception) -> None:
            unreadable_files.append(f.name)
            book = ledger(f)
            book.status, book.note = "unreadable", _why(exc)

        for db_file in sorted(f for f in dir_path.rglob("*") if f.suffix.lower() in DATABASE_SUFFIXES):
            try:
                raw_files.extend(DatabaseTable(db_file, t) for t in SourceAdapter.list_sqlite_tables(db_file))
            except Exception as exc:
                logger.exception("Could not open database export %s", db_file.name)
                unreadable(db_file, exc)
        if not raw_files and not unreadable_files:
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
        unmapped_files: list[str] = []
        unrecognised_files: list[str] = []
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

        def normalise_chunk(
            table: str,
            raw_rows: list[dict[str, Any]],
            set_aside: dict[str, Rejected] | None = None,
            offset: int = 0,
        ) -> list[dict[str, Any]]:
            kept = []
            for i, r in enumerate(raw_rows):
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
                    if set_aside is not None:
                        set_aside.setdefault(NO_ENTITY, Rejected()).add(1, [offset + i])
                    continue
                if not is_valid_entity_id(str(eid)):
                    rejected_ids.setdefault(table, []).append(str(eid))
                    if set_aside is not None:
                        set_aside.setdefault(BAD_ENTITY, Rejected()).add(1, [offset + i])
                    continue
                kept.append(clean_r)
            return kept

        def store_frame(table: str, frame: pl.DataFrame) -> ColumnarResult | None:
            """The columnar equivalent of normalise_chunk + store_rows; None if it does not apply."""
            if table not in canonical_columns:
                canonical_columns[table] = self.duckdb_store.table_columns(_store_table(table))
            done = normalise_frame(frame, table, self, default_entity_id, canonical_columns[table])
            if done is None:
                return None
            if done.unattributed:
                unattributed[table] = unattributed.get(table, 0) + done.unattributed
            if done.rejected:
                rejected_ids.setdefault(table, []).extend(done.rejected)
            if done.frame.height:
                if done.dropped:
                    dropped.setdefault(_store_table(table), set()).update(done.dropped)
                buffers.setdefault(table, []).append(done.frame)
                row_counts[table] = row_counts.get(table, 0) + done.frame.height
            return done

        def read(path: Path | DatabaseTable) -> pl.DataFrame | list[dict[str, Any]]:
            if isinstance(path, DatabaseTable):
                return SourceAdapter.read_sqlite(path.db_path, path.table)
            suffix = path.suffix.lower()
            if suffix in TABULAR_SUFFIXES:
                return SourceAdapter.read_csv_frame(path)
            if suffix in EXCEL_SUFFIXES:
                return SourceAdapter.read_excel_frame(path)
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
        preloaded: dict[Path | DatabaseTable, list[dict[str, Any]]] = {}
        if mapping is not None:
            for f in raw_files:
                try:
                    data = read(f)
                    preloaded[f] = data.to_dicts() if isinstance(data, pl.DataFrame) else data
                except Exception as exc:
                    logger.exception("Could not read submission file %s", f.name)
                    unreadable(f, exc)
            mapping.build_lookups({f.stem: rows for f, rows in preloaded.items()})

        # The largest CSV of a canonical submission is read before the others, while nothing
        # else is held: reading a file briefly needs a few times its size, and at 5,000,000
        # alerts that read on top of the tables already held set the ingest's peak memory.
        # Files are still processed in their usual order, so nothing else changes.
        read_early: dict[Path | DatabaseTable, pl.DataFrame | Exception] = {}
        csv_files = [f for f in raw_files if isinstance(f, Path) and f.suffix.lower() == ".csv"]
        if READ_LARGEST_FIRST and mapping is None and len(csv_files) > 1:
            largest = max(csv_files, key=lambda f: f.stat().st_size)
            try:
                read_early[largest] = SourceAdapter.read_csv_frame(largest)
            except Exception as exc:  # noqa: BLE001 - raised again, and reported, in the file's turn
                read_early[largest] = exc

        for f in raw_files:
            if f.name in unreadable_files:
                continue
            try:
                if mapping is not None:
                    raw_rows = preloaded.pop(f)
                    book = ledger(f)
                    book.rows_read = len(raw_rows)
                    columns = (
                        list(raw_rows[0]) if raw_rows else _file_headers(f) if isinstance(f, Path) else []
                    )
                    specs = mapping.specs_for_file(f.stem, columns)
                    if not specs:
                        unmapped_files.append(f.name)
                        book.status, book.note = "not mapped", "no table of the source mapping names this file"
                        continue
                    assert default_entity_id is not None
                    if raw_rows:
                        processed_files.append(f.db_path if isinstance(f, DatabaseTable) else f)
                        used = set().union(*(spec.source_columns() for spec in specs))
                        unused = sorted(set(raw_rows[0]) - used)
                        if unused:
                            unused_source_columns[f.name] = unused
                    # A row one table cannot take is lost only if no other table took it: an
                    # alert export feeds `alert` with every alert and `case_alert_link` only
                    # with the alerts that have a case.
                    stored_somewhere: set[int] = set()
                    outcomes: list[tuple[str, int, int, dict[str, list[int]]]] = []
                    for spec in specs:
                        target = _store_table(spec.table)
                        declared_tables.add(target)
                        mapped = mapping.map_rows(raw_rows, spec, default_entity_id)
                        stored_somewhere.update(mapped.positions)
                        outcomes.append((target, len(mapped.rows), mapped.skipped_by_filter, mapped.rejected))
                        store_rows(spec.table, mapped.rows)
                    # A row no table took is reported once, under the first table that wanted it.
                    reported: set[int] = set()
                    for target, stored, not_for_table, missing in outcomes:
                        book.store(target, stored)
                        for reason, positions in missing.items():
                            lost = [p for p in positions if p not in stored_somewhere]
                            not_for_table += len(positions) - len(lost)
                            fresh = [p for p in lost if p not in reported]
                            reported.update(fresh)
                            book.reject(f"{reason} for {target}", len(fresh), file_rows(f, fresh[:ROW_SAMPLE]))
                        book.filtered[target] = book.filtered.get(target, 0) + not_for_table
                    continue

                early = read_early.pop(f, None)
                if isinstance(early, Exception):
                    raise early
                data = early if early is not None else read(f)
                book = ledger(f)
                book.rows_read = len(data)
                if len(data) == 0:
                    empty_table = self.table_for_empty_file(f)
                    if empty_table:
                        declared_tables.add(_store_table(empty_table))
                    continue

                headers = data.columns if isinstance(data, pl.DataFrame) else list(data[0].keys())
                recognised = self.recognise_table(f.stem, headers)
                if recognised is None:
                    unrecognised_files.append(f.name)
                    book.status = "not recognised"
                    book.note = "neither its name nor its key columns match a table of the template"
                    del data
                    continue
                canonical_table = recognised
                target = _store_table(canonical_table)
                processed_files.append(f.db_path if isinstance(f, DatabaseTable) else f)
                declared_tables.add(target)
                row_counts.setdefault(canonical_table, 0)
                done = store_frame(canonical_table, data) if isinstance(data, pl.DataFrame) else None
                if done is not None:
                    del data  # the file as read is no longer needed
                    book.store(target, done.frame.height)
                    book.reject(NO_ENTITY, done.unattributed, file_rows(f, done.unattributed_at))
                    book.reject(BAD_ENTITY, len(done.rejected), file_rows(f, done.rejected_at))
                    continue
                set_aside: dict[str, Rejected] = {}
                offset = 0
                for raw_rows in chunks(data):
                    kept = normalise_chunk(canonical_table, raw_rows, set_aside, offset)
                    offset += len(raw_rows)
                    book.store(target, len(kept))
                    store_rows(canonical_table, kept)
                del data
                for reason, rejected in set_aside.items():
                    book.reject(reason, rejected.count, file_rows(f, rejected.rows))
            except Exception as exc:
                # Reported below as a DQ error: a file dropped without trace would make
                # its table look absent, and rules would read that as a SOC defect.
                logger.exception("Could not read submission file %s", f.name)
                unreadable(f, exc)

        for book in ledgers.values():
            book.settle()
        file_coverage = [book.as_dict() for book in ledgers.values()]
        if unattributed and not buffers:
            counts = ", ".join(f"{n} {t}" for t, n in sorted(unattributed.items()))
            return {
                "status": "error",
                "message": (
                    f"No rows stored: {counts} row(s) have no entity_id. Add an entity_id "
                    "column or choose a target entity for the upload."
                ),
                "file_coverage": file_coverage,
            }
        if not buffers and not row_counts:
            why = "; ".join(book.summary() for book in ledgers.values())
            return {
                "status": "error",
                "message": "No rows could be stored from the submitted files" + (f": {why}" if why else "."),
                "file_coverage": file_coverage,
            }

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

        # A batch with several entities is owned by none of them: its batch id and audit entry
        # say MULTI_CSE. (They used to name the alphabetically first entity, and file every
        # batch-level DQ issue under it.)
        batch_entities = sorted(entities_present) or ["ALL_CSE"]
        batch_owner = batch_entities[0] if len(batch_entities) == 1 else "MULTI_CSE"

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
            # Defaults go FIRST: the entity table keeps the newest non-null value per column
            # (store.duckdb._upsert_entity_row), so the submission's own name, sector, size band
            # and SOC model win and a default only fills a column the submission left empty.
            # (They used to go last, which replaced every submitted profile with
            # "General Infrastructure" / "Medium" on a fresh store and put every entity in one
            # peer cohort.)
            parts = [tables["entity"]] if "entity" in tables else []
            tables["entity"] = _concat_frames([_frame_from_rows(new_entities_to_add), *parts])
            row_counts["entity"] = row_counts.get("entity", 0) + len(new_entities_to_add)

        # An entity's rows of a table, selected when its checks run (None if it has none).
        # Tables are not copied per entity up front: that doubled ingest's peak memory.
        partitions: dict[str, dict[str, pl.DataFrame]] = {}
        row_positions: dict[str, tuple[dict[str, int], pl.Series]] = {}

        def entity_frame(table: str, ent_id: str) -> pl.DataFrame | None:
            frame = tables.get(table)
            if frame is None or frame.height == 0 or "entity_id" not in frame.columns:
                return None
            if frame["entity_id"].dtype == pl.String:
                if table not in row_positions:  # each entity's row positions, in row order
                    grouped = (
                        frame.select("entity_id").with_row_index("row")
                        .group_by("entity_id", maintain_order=True).agg(pl.col("row"))
                    )  # fmt: skip
                    index = {e: i for i, e in enumerate(grouped["entity_id"].to_list()) if e is not None}
                    row_positions[table] = (index, grouped["row"])
                index, positions = row_positions[table]
                if ent_id not in index:
                    return None
                return frame[positions[index[ent_id]]]
            if table not in partitions:  # a non-text entity_id: grouped as str(value), as before
                partitions[table] = _partition_by_entity(frame)
            return partitions[table].get(ent_id)

        # Run Data Quality checks per entity
        all_dq_issues = []

        # A file that could not be read or mapped, or a row with no usable entity_id, belongs
        # to no known entity: each entity in the batch gets the issue, since any of its rules
        # may depend on what was lost.
        shared_note = (
            f" Submitted in a batch shared by {len(batch_entities)} entities ({', '.join(batch_entities)})."
            if len(batch_entities) > 1
            else ""
        )

        def batch_issues(prefix: str, suffix: str, details: str, **fields: Any) -> list[DQIssue]:
            return [
                DQIssue(issue_id=f"{prefix}-{ent}-{suffix}", entity_id=ent, details=details + shared_note, **fields)
                for ent in batch_entities
            ]

        if unreadable_files:
            all_dq_issues.extend(
                batch_issues(
                    "DQ-UNREADABLE",
                    "-".join(sorted(unreadable_files))[:80],
                    f"{len(unreadable_files)} submitted file(s) could not be read and were not ingested: "
                    f"{', '.join(sorted(unreadable_files))}. Rules that depend on their tables are unreliable "
                    "until the files are fixed and re-submitted.",
                    check_name="file_unreadable",
                    severity="error",
                    count=len(unreadable_files),
                    sample_records=sorted(unreadable_files)[:5],
                )
            )
        lossy = [r for r in collected() if r.data_lost]
        if lossy:
            all_dq_issues.extend(
                batch_issues(
                    "DQ-SANITISED",
                    "-".join(sorted(r.file for r in lossy))[:80],
                    "Part of these files could not be read and was left out: "
                    + "; ".join(f"{r.file}: {', '.join(n for n in r.notes() if 'not read' in n or 'skipped' in n)}" for r in lossy)
                    + ". Counts from these files may be understated.",
                    check_name="file_partly_read",
                    severity="warning",
                    count=sum(r.long_rows_truncated + r.records_skipped for r in lossy),
                    sample_records=sorted(r.file for r in lossy)[:5],
                )
            )
        if unmapped_files:
            all_dq_issues.extend(
                batch_issues(
                    "DQ-UNMAPPED-FILE",
                    "-".join(sorted(unmapped_files))[:80],
                    f"{len(unmapped_files)} file(s) are not described by the source mapping and were not "
                    f"ingested: {', '.join(sorted(unmapped_files))}.",
                    check_name="file_not_mapped",
                    severity="warning",
                    count=len(unmapped_files),
                    sample_records=sorted(unmapped_files)[:5],
                )
            )
        if unrecognised_files:
            all_dq_issues.extend(
                batch_issues(
                    "DQ-UNRECOGNISED-FILE",
                    "-".join(sorted(unrecognised_files))[:80],
                    f"{len(unrecognised_files)} file(s) were not ingested because neither the file name "
                    f"nor any key column matches a table of the submission template: "
                    f"{', '.join(sorted(unrecognised_files))}. Describe the export with a source mapping, "
                    "or use the template's column names.",
                    check_name="file_not_recognised",
                    severity="warning",
                    count=len(unrecognised_files),
                    sample_records=sorted(unrecognised_files)[:5],
                )
            )
        # Rows a source mapping could not fill (the entity checks below report their own).
        left_out = [
            (book, {r: rej for r, rej in book.rejected.items() if r not in (NO_ENTITY, BAD_ENTITY)})
            for book in ledgers.values()
        ]
        left_out = [(book, reasons) for book, reasons in left_out if reasons]
        if left_out:
            per_file: list[str] = []
            for book, reasons in left_out:
                reason_notes: list[str] = []
                for reason, rej in reasons.items():
                    where = rej.where(book.row_label)
                    reason_notes.append(f"{rej.count} {reason}" + (f" ({where})" if where else ""))
                per_file.append(f"{book.file}: {', '.join(reason_notes)}")
            # Losing half a file or more is not a detail: its tables would mislead every rule.
            severe = any(
                2 * sum(rej.count for rej in reasons.values()) >= max(book.rows_read, 1)
                for book, reasons in left_out
            )
            all_dq_issues.extend(
                batch_issues(
                    "DQ-ROWS-REJECTED",
                    "-".join(sorted(book.file for book, _ in left_out))[:80],
                    "Rows were not stored because a field the source mapping requires is empty or "
                    "could not be read: " + "; ".join(per_file) + ". Counts from these files are "
                    "understated until the export (or its mapping) is corrected and submitted again.",
                    check_name="rows_rejected",
                    severity="error" if severe else "warning",
                    count=sum(rej.count for _, reasons in left_out for rej in reasons.values()),
                    sample_records=[
                        f"{book.file} {book.row_label} {n}"
                        for book, reasons in left_out
                        for rej in reasons.values()
                        for n in rej.rows[:5]
                    ][:5],
                )
            )
        for tbl, bad_ids in sorted(rejected_ids.items()):
            all_dq_issues.extend(
                batch_issues(
                    "DQ-INVALID-ENTITY-ID",
                    tbl,
                    f"{len(bad_ids)} '{tbl}' rows rejected: entity_id does not match "
                    "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ (rows were not stored or evaluated).",
                    check_name="invalid_entity_id",
                    severity="error",
                    count=len(bad_ids),
                    sample_records=[repr(b)[:80] for b in bad_ids[:5]],
                )
            )
        for tbl, n in sorted(unattributed.items()):
            all_dq_issues.extend(
                batch_issues(
                    "DQ-MISSING-ENTITY-ID",
                    tbl,
                    f"{n} '{tbl}' rows rejected: no entity_id and no target entity "
                    "selected (rows were not stored or evaluated).",
                    check_name="missing_entity_id",
                    severity="error",
                    count=n,
                    sample_records=[],
                )
            )
        no_ids = pl.Series([], dtype=pl.String)
        for ent_id in sorted(entities_present):
            ent_alerts = entity_frame("alert", ent_id)
            if ent_alerts is not None:
                req_issues = FrameDQ.check_required_fields(
                    ent_alerts,
                    ["alert_id", "entity_id", "created_at", "severity_final"],
                    ent_id,
                    "alert",
                )
                all_dq_issues.extend(req_issues)

                ts_issues = FrameDQ.check_timestamp_logic(ent_alerts, ent_id)
                all_dq_issues.extend(ts_issues)

                dup_issues = FrameDQ.check_duplicate_ids(ent_alerts, "alert_id", ent_id, "alert")
                all_dq_issues.extend(dup_issues)

                # Only meaningful where alert ids are a running counter; a mapping for a product
                # whose ids are GUIDs or storage keys says `sequential_ids: false`.
                if mapping is None or mapping.config.get("sequential_ids", True):
                    gap_issues = FrameDQ.check_id_sequence_gaps(ent_alerts, "alert_id", ent_id)
                    all_dq_issues.extend(gap_issues)

                null_issues = FrameDQ.check_null_rates(
                    ent_alerts, ["rule_id", "asset_id", "closed_by", "disposition"], ent_id, "alert"
                )
                all_dq_issues.extend(null_issues)

            ent_asset_frame = entity_frame("asset", ent_id)
            ent_assets = FrameDQ.truthy_ids(ent_asset_frame, "asset_id") if ent_asset_frame is not None else no_ids
            if ent_assets.len() and ent_alerts is not None:
                orphan_issues = FrameDQ.check_orphan_references(
                    ent_alerts, ent_assets, "asset_id", ent_id, "alert", "asset"
                )
                all_dq_issues.extend(orphan_issues)

            # Child records must point at an alert (or case) that is in the submission.
            # A closure, workflow event, escalation or case link whose parent is missing
            # makes EG02/EG03/NS04 read "no investigation / no escalation / no case" for
            # the wrong reason, and can itself indicate withheld records.
            ent_alert_ids = FrameDQ.truthy_ids(ent_alerts, "alert_id") if ent_alerts is not None else no_ids
            del ent_alerts
            if ent_alert_ids.len():
                for child_table, fk_col, keep in _ALERT_CHILD_TABLES:
                    child_frame = entity_frame(child_table, ent_id)
                    children = keep(child_frame) if child_frame is not None else None
                    if children is not None and children.height:
                        all_dq_issues.extend(
                            FrameDQ.check_orphan_references(
                                children, ent_alert_ids, fk_col, ent_id, child_table, "alert"
                            )
                        )
            case_frames = [cf for tbl in ("case", "case_record") if (cf := entity_frame(tbl, ent_id)) is not None]
            ent_case_ids = (
                pl.concat([FrameDQ.truthy_ids(cf, "case_id") for cf in case_frames]).unique() if case_frames else no_ids
            )
            ent_links = entity_frame("case_alert_link", ent_id)
            if ent_case_ids.len() and ent_links is not None:
                all_dq_issues.extend(
                    FrameDQ.check_orphan_references(
                        ent_links, ent_case_ids, "case_id", ent_id, "case_alert_link", "case"
                    )
                )

        field_coverage: dict[str, dict[str, Any]] = {
            _store_table(name): {
                "rows": frame.height,
                "filled": _usable_counts(
                    frame,
                    [
                        c
                        for c in canonical_columns.get(name) or self.duckdb_store.table_columns(_store_table(name))
                        if c != "entity_id"
                    ],
                ),
            }
            for name, frame in tables.items()
            if frame.height
        }
        dropped_columns = {table: sorted(columns) for table, columns in sorted(dropped.items())}

        # Per entity, while the alert frame is still held: its alert count and the alert
        # columns that hold no usable value (read by the rule coverage below).
        alert_profile: dict[str, tuple[int, set[str]]] = {}
        rule_columns = sorted({column for columns in RULE_ALERT_FIELDS.values() for column in columns})
        for ent_id in sorted(entities_present):
            alert_frame = entity_frame("alert", ent_id)
            if alert_frame is None:
                alert_profile[ent_id] = (0, set())
                continue
            usable = _usable_counts(alert_frame, rule_columns)
            alert_profile[ent_id] = (alert_frame.height, {column for column in rule_columns if usable[column] == 0})
        partitions.clear()
        row_positions.clear()

        # Write to partitioned Parquet via DuckDBStore. A table that fails to store must
        # not vanish quietly: rules would then read its absence as a SOC defect. Each table's
        # frame is released once written, and the written tables are reloaded into DuckDB
        # only after all are written, so the submission is not held as frames and as DuckDB
        # tables at the same time. A reload that fails counts as a failed store, as it did
        # when the reload was part of each write.
        # A failed table is filed under the entities whose rows it held, each with its own row
        # count; those counts are taken while the frame is held, for a reload that fails later.
        failures: dict[str, tuple[int, dict[str, int], str]] = {}
        written: list[tuple[str, int, dict[str, int]]] = []
        table_order = list(tables)
        with self.duckdb_store.deferred_reload():
            for table_name in table_order:
                df = tables.pop(table_name)
                if df.height:
                    entity_rows = _rows_per_entity(df)
                    try:
                        self.duckdb_store.write_partitioned_parquet(_store_table(table_name), df)
                        written.append((table_name, df.height, entity_rows))
                    except Exception as exc:
                        logger.exception("Failed to store table %r (%d rows)", table_name, df.height)
                        failures[table_name] = (df.height, entity_rows, type(exc).__name__)
                del df
        for table_name, height, entity_rows in written:
            try:
                self.duckdb_store.load_table_from_parquet(_store_table(table_name))
            except Exception as exc:
                logger.exception("Failed to store table %r (%d rows)", table_name, height)
                failures[table_name] = (height, entity_rows, type(exc).__name__)
        failed_tables: list[str] = [t for t in table_order if t in failures]
        for table_name in failed_tables:
            height, entity_rows, error = failures[table_name]
            for ent_id, ent_rows in sorted(entity_rows.items()) or [(ent, height) for ent in batch_entities]:
                all_dq_issues.append(
                    DQIssue(
                        issue_id=f"DQ-WRITE-FAILED-{ent_id}-{table_name}",
                        entity_id=ent_id,
                        check_name="table_write_failed",
                        severity="error",
                        count=ent_rows,
                        sample_records=[],
                        details=(
                            f"Table '{table_name}' ({ent_rows} rows) could not be stored "
                            f"({error}). Findings that depend on it are unreliable "
                            "until the submission is re-ingested."
                        ),
                    )
                )

        # Build manifest and append to audit log
        batch, _manifest_dict = ManifestBuilder.build_manifest(
            entity_id=batch_owner, files=list(dict.fromkeys(processed_files)), row_counts=row_counts
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
            alert_count, empty_fields = alert_profile[ent_id]
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
                "entity_id": batch_owner,
                "files_count": len(set(processed_files)),
                "row_counts": row_counts,
                "entities_detected": sorted(entities_present),
                "dq_issues_found": len(all_dq_issues),
                "failed_tables": failed_tables,
            },
        )

        return {
            "status": "partial" if failed_tables else "success",
            "batch_id": batch.batch_id,
            "entities": sorted(entities_present),
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
            "unrecognised_files": sorted(unrecognised_files),
            "unused_source_columns": unused_source_columns,
            "file_coverage": file_coverage,
        }
