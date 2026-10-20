"""DuckDB columnar storage interface for SAT-SA."""

import logging
import os
import threading
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import duckdb
import polars as pl

from satsa.store.catalog import (
    SEQ_COLUMN,
    VERSION_KEYS,
    BatchWriter,
    Catalog,
    PublishedFile,
    published_sequence,
)

logger = logging.getLogger(__name__)

# Tables holding one record per entity (keyed by entity_id) rather than an
# append-only stream of events.
KEYED_BY_ENTITY = frozenset({"entity"})

# Every canonical table, in load order.
CANONICAL_TABLES: tuple[str, ...] = (
    "entity",
    "asset",
    "log_source_daily",
    "detection_rule",
    "alert",
    "case",
    "case_alert_link",
    "workflow_event",
    "escalation",
    "closure",
    "remediation",
    "external_report",
    "declared_kpi",
    "sla_policy",
    "submission_batch",
)


# A text timestamp ending in a UTC offset: "Z", "+05:30", "+0530" or "+05" after a time of day.
_OFFSET_SUFFIX = r"[0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]+)?)?(Z|z|[+-][0-9]{2}(:?[0-9]{2})?)$"


def _quoted(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _file_list(files: list[PublishedFile]) -> str:
    return ", ".join("'" + f.path.as_posix().replace("'", "''") + "'" for f in files)


def text_timestamp_sql(column: str) -> str:
    """SQL reading the text column `column` (a quoted identifier) as a naive UTC TIMESTAMP.

    Canonical timestamps are UTC (docs/data_requirements.md). Text that carries an offset is
    converted to UTC with that offset; a plain `TRY_CAST(... AS TIMESTAMP)` drops the offset
    and keeps the wall-clock time. Text without an offset is read exactly as before (as UTC,
    never by the session time zone), and text DuckDB cannot read becomes NULL.
    """
    return (
        f"CASE WHEN regexp_matches({column}, '{_OFFSET_SUFFIX}') "
        f"THEN timezone('UTC', TRY_CAST({column} AS TIMESTAMPTZ)) "
        f"ELSE TRY_CAST({column} AS TIMESTAMP) END"
    )


class DuckDBStore:
    """Manages DuckDB queries and partitioned Parquet files for analytics."""

    def __init__(self, data_dir: Path | str = "data"):
        self.data_dir = Path(data_dir)
        self.parquet_dir = self.data_dir / "parquet"
        self.parquet_dir.mkdir(parents=True, exist_ok=True)
        self._catalog: Catalog | None = None
        self._active_batch: BatchWriter | None = None
        self._defer_reload = False
        self._memo: dict[Any, Any] = {}
        # Tables published since they were loaded, reloaded before anything next reads (mark_stale).
        self._stale: set[str] = set()
        # Publication sequence the loaded tables reflect (the source snapshot); None until loaded.
        self.source_snapshot: int | None = None
        self.conn = duckdb.connect(":memory:")
        # Force single-threaded execution. DuckDB's default multi-threaded
        # vectorized execution combines parallel partial aggregates (SUM/AVG
        # over floating-point columns) in a run-dependent order, which is not
        # associative in floating-point arithmetic and can flip a rule's
        # threshold comparison (e.g. share > 0.25) by a few ULPs between two
        # runs on IDENTICAL input data. That silently contradicts the
        # byte-identical reproducibility guarantee in DECISIONS.md ADR-002/
        # ADR-003, so determinism is pinned explicitly rather than left to
        # incidental single-threaded scheduling.
        self.conn.execute("PRAGMA threads=1")
        # No external file cache. Published files are never rewritten now, but a restore or a
        # manual repair can put different bytes at a path; the cache, checked by path and
        # modification time, could then serve the previous file (on Linux CI that read once
        # failed with "ZSTD Decompression failure" and loaded an empty table). Every table is
        # copied into memory on load, so the cache saves nothing here.
        self.conn.execute("SET enable_external_file_cache = false")
        self._init_schemas()

    def _init_schemas(self) -> None:
        """Initialize empty tables and views in DuckDB."""
        # Initialize DuckDB tables for all canonical datasets
        ddl_statements = [
            """
            CREATE TABLE IF NOT EXISTS entity (
                entity_id VARCHAR PRIMARY KEY,
                name VARCHAR,
                sector VARCHAR,
                size_band VARCHAR,
                soc_model VARCHAR,
                soc_provider VARCHAR,
                timezone VARCHAR,
                declared_shift_hours VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS asset (
                entity_id VARCHAR,
                asset_id VARCHAR,
                asset_type VARCHAR,
                criticality INTEGER,
                monitored_flag BOOLEAN,
                owner_unit VARCHAR,
                in_service_from DATE,
                in_service_to DATE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS log_source_daily (
                entity_id VARCHAR,
                asset_id VARCHAR,
                source_type VARCHAR,
                date DATE,
                event_count INTEGER
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS detection_rule (
                entity_id VARCHAR,
                rule_id VARCHAR,
                category VARCHAR,
                mitre_tactic VARCHAR,
                mitre_technique VARCHAR,
                enabled BOOLEAN,
                last_fired TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS alert (
                entity_id VARCHAR,
                alert_id VARCHAR,
                rule_id VARCHAR,
                category VARCHAR,
                severity_orig VARCHAR,
                severity_final VARCHAR,
                asset_id VARCHAR,
                created_at TIMESTAMP,
                acknowledged_at TIMESTAMP,
                first_touch_at TIMESTAMP,
                closed_at TIMESTAMP,
                closed_by VARCHAR,
                closed_by_type VARCHAR,
                playbook_id VARCHAR,
                disposition VARCHAR,
                status VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS "case" (
                entity_id VARCHAR,
                case_id VARCHAR,
                severity VARCHAR,
                status VARCHAR,
                owner VARCHAR,
                opened_at TIMESTAMP,
                closed_at TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS case_alert_link (
                entity_id VARCHAR,
                case_id VARCHAR,
                alert_id VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS workflow_event (
                entity_id VARCHAR,
                ref_type VARCHAR,
                ref_id VARCHAR,
                ts TIMESTAMP,
                actor VARCHAR,
                action VARCHAR,
                from_status VARCHAR,
                to_status VARCHAR,
                note_len INTEGER
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS escalation (
                entity_id VARCHAR,
                esc_id VARCHAR,
                ref_id VARCHAR,
                escalated_at TIMESTAMP,
                from_role VARCHAR,
                to_role VARCHAR,
                acknowledged_at TIMESTAMP,
                outcome VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS closure (
                entity_id VARCHAR,
                ref_id VARCHAR,
                reason_code VARCHAR,
                disposition VARCHAR,
                comment_norm_hash VARCHAR,
                comment_len INTEGER,
                comment_shingles VARCHAR
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS remediation (
                entity_id VARCHAR,
                ticket_id VARCHAR,
                linked_asset_id VARCHAR,
                linked_rule_id VARCHAR,
                type VARCHAR,
                created_at TIMESTAMP,
                closed_at TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS external_report (
                entity_id VARCHAR,
                incident_id VARCHAR,
                reported_to VARCHAR,
                reported_at TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS declared_kpi (
                entity_id VARCHAR,
                period VARCHAR,
                metric VARCHAR,
                severity VARCHAR,
                value DOUBLE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sla_policy (
                entity_id VARCHAR,
                severity VARCHAR,
                ack_minutes INTEGER,
                resolve_minutes INTEGER
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS submission_batch (
                batch_id VARCHAR PRIMARY KEY,
                entity_id VARCHAR,
                period_start TIMESTAMP,
                period_end TIMESTAMP,
                file_name VARCHAR,
                sha256 VARCHAR,
                row_counts VARCHAR
            )
            """,
        ]
        for stmt in ddl_statements:
            self.conn.execute(stmt)

    @property
    def conn(self) -> duckdb.DuckDBPyConnection:
        """The DuckDB connection; tables marked stale are reloaded first, so every read sees them."""
        if self._stale:
            self._reload_stale()
        return self._conn

    @conn.setter
    def conn(self, value: duckdb.DuckDBPyConnection) -> None:
        self._conn = value

    def mark_stale(self, tables: Iterable[str]) -> None:
        """Reload `tables` before the next read instead of now.

        An ingest publishes and then usually ends: the CLI and the import job each use their own
        store, and an assessment reloads every table itself. Reloading at publication (version
        selection over every published file) was most of an ingest's time at scale and was then
        thrown away; a caller that does read the store afterwards still sees the published rows.
        """
        self._memo.clear()
        self._stale.update(tables)

    def _reload_stale(self) -> None:
        pending = sorted(self._stale)
        self._stale.clear()
        for done, table in enumerate(pending):
            try:
                self.load_table_from_parquet(table)
            except BaseException:
                self._stale.update(pending[done:])
                raise

    @contextmanager
    def deferred_reload(self) -> Iterator[None]:
        """Within the block, write_partitioned_parquet does not reload the table into DuckDB.

        For a caller writing several tables (ingest), which reloads them itself once all are
        written, so a submission is not held as frames and as DuckDB tables at the same time.
        """
        self._defer_reload = True
        try:
            yield
        finally:
            self._defer_reload = False

    @property
    def catalog(self) -> Catalog:
        """The publication catalog of this data directory (opened on first use)."""
        if self._catalog is None:
            self._catalog = Catalog(self.data_dir)
        return self._catalog

    @contextmanager
    def publication(self, **batch_meta: Any) -> Iterator[BatchWriter]:
        """One batch: every write_partitioned_parquet inside the block is staged into it.

        Nothing is visible to readers until the caller calls `publish()` on the yielded writer
        (or `hold()`s it for review); leaving the block otherwise discards the staged files.
        Reloading the written tables after publishing is the caller's job.
        """
        if self._active_batch is not None:
            raise RuntimeError("a publication is already open on this store")
        with self.catalog.open_batch(**batch_meta) as writer:
            self._active_batch = writer
            try:
                yield writer
            finally:
                self._active_batch = None

    def memo(self, key: Any, compute: Any) -> Any:
        """`compute()`, computed once per key while the loaded tables stay as they are.

        For results every entity of an assessment asks for in the same form (a portfolio-wide
        aggregate): the first rule evaluation computes it, the others reuse it. Loading,
        writing or executing anything on this store forgets every memo."""
        if key not in self._memo:
            self._memo[key] = compute()
        return self._memo[key]

    def write_partitioned_parquet(self, table_name: str, df: pl.DataFrame) -> None:
        """Store rows of a canonical table as a new, immutable batch file per entity.

        Inside `publication()` the rows join that batch. Otherwise they are published at once
        as a one-table batch (transport `direct`) and the table is reloaded (unless inside
        `deferred_reload`). Existing files are never rewritten: an updated record is a new
        version, and the loader selects the latest one (see `load_table_from_parquet`).
        """
        self._memo.clear()
        if df.is_empty():
            return
        if self._active_batch is not None:
            self._active_batch.add_table(table_name, df)
            return
        with self.catalog.open_batch(transport="direct") as writer:
            writer.add_table(table_name, df)
            writer.publish()
        if not self._defer_reload:
            self.load_table_from_parquet(table_name)

    def table_columns(self, table_name: str) -> list[str]:
        """Column names of a canonical table, in schema order (empty for an unknown table)."""
        rows = self.conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = ? ORDER BY ordinal_position",
            [table_name],
        ).fetchall()
        return [r[0] for r in rows]

    def load_table_from_parquet(self, table_name: str, max_pub_seq: int | None = None) -> None:
        """Load the current version of every published record of a table into DuckDB.

        Reads the files of published batches only (up to `max_pub_seq`, the source snapshot;
        default: everything published now). Per business key (`catalog.VERSION_KEYS`, within one
        source system) the rows of the latest batch that published that key are current: a
        correction replaces the earlier version instead of being counted beside it. Rows of one
        batch that share a key are all kept, as submitted (ingestion reports them as duplicate
        ids). Identical rows are kept once, and a table without a business key keeps each
        distinct row once. The `entity` table keeps, per column, the newest non-null value, so a
        thinner later record never blanks out an attribute submitted earlier.

        Only the table's own columns are read, with TRY_CAST, so a pass-through source column
        or an unparseable value in one file cannot fail the load; text timestamps go through
        text_timestamp_sql, which applies a UTC offset instead of dropping it. A published file
        that is missing or unreadable is skipped with a warning, never silently.
        """
        self._memo.clear()
        self._stale.discard(table_name)
        catalog = self.catalog
        catalog.adopt_legacy_files(table_name)
        snapshot = catalog.max_pub_seq() if max_pub_seq is None else max_pub_seq
        self.source_snapshot = snapshot if self.source_snapshot is None else max(self.source_snapshot, snapshot)
        table_types = {
            row[0]: row[1]
            for row in self.conn.execute(
                "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = ?",
                [table_name],
            ).fetchall()
        }
        if not table_types:
            return
        listed = catalog.published_files(table_name, snapshot)
        if not listed:
            # Nothing was ever published for the table: what is in memory (rows a caller
            # inserted directly) is left as it is, as before the catalog existed.
            return
        escaped = _quoted(table_name)
        self.conn.execute(f"DELETE FROM {escaped}")

        files = []
        for f in listed:
            if f.path.exists():
                files.append(f)
            else:
                logger.warning("Published file of table %r is missing: %s (batch %s)", table_name, f.path, f.batch_id)
        files = self._readable(table_name, files) if files else []
        if not files:
            return

        mapping = pl.DataFrame(
            {
                "filename": [f.path.as_posix() for f in files],
                "pub": [f.pub_seq for f in files],
                "src": [f.source for f in files],
                "ent": [f.entity_id or None for f in files],
            },
            schema={"filename": pl.String, "pub": pl.Int64, "src": pl.String, "ent": pl.String},
        )
        source = (
            f"read_parquet([{_file_list(files)}], filename='_satsa_file', union_by_name=true, hive_partitioning=false)"
        )
        view = f"_satsa_files_{uuid.uuid4().hex[:8]}"
        self.conn.register(view, mapping)
        try:
            source_types = {r[0]: r[1] for r in self.conn.execute(f"DESCRIBE SELECT * FROM {source}").fetchall()}
            cols = [c for c in table_types if c in source_types or c == "entity_id"]

            def typed(c: str) -> str:
                if c == "entity_id":
                    raw = "TRY_CAST(s.entity_id AS VARCHAR)" if "entity_id" in source_types else "NULL"
                    return f"coalesce(NULLIF({raw}, ''), m.ent) AS entity_id"
                if table_types[c] == "TIMESTAMP" and source_types[c] == "VARCHAR":
                    return f"{text_timestamp_sql('s.' + _quoted(c))} AS {_quoted(c)}"
                return f"TRY_CAST(s.{_quoted(c)} AS {table_types[c]}) AS {_quoted(c)}"

            seq = f"s.{SEQ_COLUMN}" if SEQ_COLUMN in source_types else "NULL"
            rows = (
                f"SELECT {', '.join(typed(c) for c in cols)}, m.pub AS _satsa_pub, m.src AS _satsa_src, "
                f"TRY_CAST({seq} AS BIGINT) AS _satsa_seq, row_number() OVER () AS _satsa_row "
                f"FROM {source} s JOIN {view} m ON s._satsa_file = m.filename"
            )
            out = ", ".join(_quoted(c) for c in cols)
            if table_name in KEYED_BY_ENTITY:
                order = "(_satsa_pub * 4294967296 + coalesce(_satsa_seq, 0))"
                merged = ", ".join(
                    f"arg_max({_quoted(c)}, {order}) FILTER (WHERE {_quoted(c)} IS NOT NULL) AS {_quoted(c)}"
                    for c in cols
                    if c != "entity_id"
                )
                sql = (
                    f"INSERT INTO {escaped} BY NAME SELECT entity_id{', ' + merged if merged else ''} "
                    f"FROM ({rows}) WHERE entity_id IS NOT NULL GROUP BY entity_id"
                )
            else:
                keys = VERSION_KEYS.get(table_name)
                if keys is not None and all(k in cols for k in keys):
                    # A record missing part of its key cannot be matched to another version of it.
                    null_key = " OR ".join(f"{_quoted(k)} IS NULL" for k in keys)
                    partition = (
                        f"_satsa_src, {', '.join(_quoted(k) for k in keys)}, CASE WHEN {null_key} THEN _satsa_row END"
                    )
                    current = (
                        f"SELECT * FROM ({rows}) QUALIFY rank() OVER (PARTITION BY {partition} "
                        "ORDER BY _satsa_pub DESC) = 1"
                    )
                else:
                    current = rows  # no business key: a row's full content is its identity
                # Stored in entity order. Version selection and DISTINCT return rows in hash order;
                # stored that way, every per-entity query (each rule, for each entity) scans the
                # whole table, because no row group's min/max of entity_id excludes the entity. In
                # entity order DuckDB skips the row groups of other entities. Which rows are
                # stored is unchanged.
                sql = f"INSERT INTO {escaped} BY NAME SELECT DISTINCT {out} FROM ({current}) ORDER BY entity_id"
            self.conn.execute(sql)
        finally:
            self.conn.unregister(view)

    def _readable(self, table_name: str, files: list[PublishedFile]) -> list[PublishedFile]:
        """`files` without those DuckDB cannot read; each one dropped is logged."""

        def probe(group: list[PublishedFile]) -> bool:
            try:
                self.conn.execute(f"SELECT count(*) FROM read_parquet([{_file_list(group)}], union_by_name=true)")
                return True
            except duckdb.Error:
                return False

        if probe(files):
            return files
        good = []
        for f in files:
            if probe([f]):
                good.append(f)
            else:
                logger.warning(
                    "Could not read published file of table %r: %s (batch %s); its rows are not loaded",
                    table_name, f.path, f.batch_id,
                )
        return good

    def load_all_tables(self, max_pub_seq: int | None = None) -> None:
        """Reload every canonical table from the published batches, as of one source snapshot."""
        self._stale.clear()
        catalog = self.catalog
        catalog.adopt_legacy_files()
        snapshot = catalog.max_pub_seq() if max_pub_seq is None else max_pub_seq
        self.source_snapshot = snapshot
        for t in CANONICAL_TABLES:
            self.load_table_from_parquet(t, snapshot)
        self.source_snapshot = snapshot

    def query(self, sql: str, params: list[Any] | None = None) -> pl.DataFrame:
        """Execute query and return Polars DataFrame."""
        if params:
            return self.conn.execute(sql, params).pl()
        return self.conn.execute(sql).pl()

    def execute(self, sql: str, params: list[Any] | None = None) -> None:
        """Execute raw DDL or modification statement."""
        self._memo.clear()
        if params:
            self.conn.execute(sql, params)
        else:
            self.conn.execute(sql)

    def close(self) -> None:
        """Close the DuckDB connection and the catalog (stale tables are not reloaded first)."""
        self._stale.clear()
        self._conn.close()
        if self._catalog is not None:
            self._catalog.close()
            self._catalog = None


class ReadOnlyStoreError(RuntimeError):
    """A shared read view was asked to change data; mutating handlers use their own store."""


class SharedDuckDBView(DuckDBStore):
    """One request's read-only handle on the process-wide analytics store.

    It has its own DuckDB cursor on the shared in-memory database, so it can be used from any
    thread, and closing it closes only that cursor.
    """

    def __init__(self, shared: DuckDBStore):
        self.data_dir = shared.data_dir
        self.parquet_dir = shared.parquet_dir
        self._catalog = None
        self._active_batch = None
        self._defer_reload = False
        self._memo = {}
        self._stale = set()
        self.source_snapshot = shared.source_snapshot
        self.conn = shared.conn.cursor()

    def write_partitioned_parquet(self, table_name: str, df: pl.DataFrame) -> None:
        raise ReadOnlyStoreError("write_partitioned_parquet on a shared read view")

    def load_table_from_parquet(self, table_name: str, max_pub_seq: int | None = None) -> None:
        raise ReadOnlyStoreError("load_table_from_parquet on a shared read view")

    def load_all_tables(self, max_pub_seq: int | None = None) -> None:
        raise ReadOnlyStoreError("load_all_tables on a shared read view")

    def close(self) -> None:
        self._conn.close()


def parquet_fingerprint(parquet_dir: Path) -> tuple[int, int, int]:
    """(file count, total bytes, newest mtime in ns) of the Parquet store: changes when data does."""
    count = size = newest = 0
    stack = [str(parquet_dir)]
    while stack:
        try:
            entries = list(os.scandir(stack.pop()))
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                stack.append(entry.path)
            elif entry.name.endswith(".parquet"):
                stat = entry.stat()
                count += 1
                size += stat.st_size
                newest = max(newest, stat.st_mtime_ns)
    return count, size, newest


class AnalyticsCache:
    """Keeps the canonical tables loaded between requests instead of re-reading every Parquet
    file on each one.

    The loaded store is reused for as long as its key is unchanged. The key is the latest
    assessment run, the catalog's publication sequence and a fingerprint of the Parquet store,
    so the cache is rebuilt when a new run completes and when data is published, removed or
    changed by any process (this web app, the Admin Portal, or the CLI) -- including a batch
    that only declares tables empty and so adds no file.
    """

    # The Parquet fingerprint walks every file; it is taken at most this often per data directory.
    # Publication through the catalog changes the publication sequence, which is read on every
    # request, so this delay applies only to files changed outside the catalog.
    FINGERPRINT_SECONDS = 2.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stores: dict[Path, tuple[tuple[Any, ...], DuckDBStore]] = {}
        self._fingerprints: dict[Path, tuple[float, int, tuple[int, int, int]]] = {}
        self.loads = 0  # how many times the tables were (re)loaded; read by tests and benchmarks

    def _fingerprint(self, root: Path, sequence: int) -> tuple[int, int, int]:
        """The Parquet fingerprint, taken again when the interval has passed or anything was
        published since (so a fingerprint is never paired with a newer publication)."""
        now = time.monotonic()
        taken = self._fingerprints.get(root)
        if taken is None or taken[1] != sequence or now - taken[0] >= self.FINGERPRINT_SECONDS:
            taken = (now, sequence, parquet_fingerprint(root / "parquet"))
            self._fingerprints[root] = taken
        return taken[2]

    def view(self, data_dir: Path | str, run_marker: str | None) -> SharedDuckDBView:
        root = Path(data_dir).resolve()
        sequence = published_sequence(root)
        key = (run_marker, sequence, *self._fingerprint(root, sequence))
        with self._lock:
            cached = self._stores.get(root)
            if cached is None or cached[0] != key:
                store = DuckDBStore(root)
                store.load_all_tables()
                self.loads += 1
                # The previous store is dropped, not closed: a request on another thread may
                # still hold a cursor on it. DuckDB frees it with its last cursor.
                self._stores[root] = cached = (key, store)
            return SharedDuckDBView(cached[1])

    def clear(self) -> None:
        with self._lock:
            self._stores.clear()
            self._fingerprints.clear()


analytics_cache = AnalyticsCache()
