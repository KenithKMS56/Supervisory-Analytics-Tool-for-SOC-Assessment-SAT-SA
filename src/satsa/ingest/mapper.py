"""Source-to-canonical mapping.

`SourceMapping` reads a `config/mappings/*.yaml` file that describes how a product's native
export (Splunk ES, ServiceNow SIR, TheHive, ...) feeds the canonical tables, and is what the
ingestion pipeline uses. `CSEMapper` is the older single-record mapper for flat mappings.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

from satsa.ingest.normaliser import TaxonomyNormaliser
from satsa.ingest.sanitise import (
    header_key,
    parse_bool,
    parse_datetime_text,
    parse_literal,
    parse_number,
)

TIMESTAMP_FIELDS = frozenset(
    {
        "created_at",
        "acknowledged_at",
        "first_touch_at",
        "closed_at",
        "opened_at",
        "escalated_at",
        "reported_at",
        "last_fired",
        "ts",
    }
)
# Canonical fields normalised through value_mappings.<kind>, then config/taxonomy.yaml.
TAXONOMY_KIND = {
    "severity": "severity",
    "severity_orig": "severity",
    "severity_final": "severity",
    "status": "status",
    "disposition": "disposition",
}


# Value transforms a mapping column may name (`transform: <name>`).
TRANSFORMS = frozenset({"length", "boolean", "number"})


class MappingError(ValueError):
    """The mapping file is unusable. Raised when it is loaded, before any row is read."""


def _parse_utc_offset(text: str) -> timezone:
    raw = str(text).strip()
    try:
        sign = -1 if raw.startswith("-") else 1
        hours, _, minutes = raw.lstrip("+-").partition(":")
        delta = timedelta(hours=int(hours), minutes=int(minutes or 0))
    except ValueError:
        raise MappingError(f"utc_offset must look like '+05:30', got {text!r}") from None
    if delta > timedelta(hours=14):
        raise MappingError(f"utc_offset out of range: {text!r}")
    return timezone(sign * delta)


def parse_source_timestamp(val: Any, ts_format: str, source_tz: timezone = UTC) -> datetime | None:
    """Parse a source timestamp into a naive UTC datetime (what the stores hold).

    `ts_format` is `epoch_ms`, `epoch_s`, `iso`, or a strptime pattern. A value that does not
    match it is tried against the common written forms (`sanitise.parse_datetime_text`:
    "Oct 1st 2026 22:53:09", "1 Oct 2026", ...); an ambiguous numeric date such as 03/04/2026
    still gives None unless the pattern states the order. A value that carries no offset of its
    own is read as local time in `source_tz`. Unparseable values give None.
    """
    if val is None or val == "":
        return None
    parsed: datetime | None = None
    if isinstance(val, datetime):
        parsed = val
    elif ts_format in ("epoch_ms", "epoch_s"):
        try:
            seconds = float(val) / (1000.0 if ts_format == "epoch_ms" else 1.0)
            parsed = datetime.fromtimestamp(seconds, tz=UTC)
        except (ValueError, TypeError, OverflowError, OSError):
            return None
    else:
        text = str(val).strip()
        if ts_format != "iso":
            try:
                parsed = datetime.strptime(text, ts_format)
            except ValueError:
                parsed = None
        if parsed is None:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                parsed = parse_datetime_text(text)
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=source_tz)
    return parsed.astimezone(UTC).replace(tzinfo=None)


def _lookup(record: dict[str, Any], path: str | list[str]) -> Any:
    """Value at `path` in a raw record; `a.b` descends into nested objects (JSON exports).

    A list of paths gives the first one that holds a value.
    """
    if isinstance(path, list):
        for candidate in path:
            value = _lookup(record, candidate)
            if not _blank(value):
                return value
        return None
    if path in record:
        return record[path]
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


@dataclass
class TableSpec:
    """How one kind of export file feeds one canonical table."""

    table: str
    files: list[str]
    columns: dict[str, dict[str, Any]]
    required: list[str] = field(default_factory=list)
    where: dict[str, list[str]] = field(default_factory=dict)
    # Columns that identify the export whatever the file is called (compared by header_key).
    headers: list[str] = field(default_factory=list)

    def matches(self, file_stem: str, headers: list[str] | None = None) -> bool:
        return self.matches_name(file_stem) or self.matches_headers(headers or [])

    def matches_name(self, file_stem: str) -> bool:
        return any(fnmatch(file_stem.lower(), pattern.lower()) for pattern in self.files)

    def matches_headers(self, headers: list[str]) -> bool:
        present = {header_key(h) for h in headers}
        return bool(self.headers) and all(header_key(h) in present for h in self.headers)

    def source_columns(self) -> set[str]:
        """Raw columns this spec reads (mapped columns and the ones its conditions look at)."""
        used = set(self.where)
        for spec in self.columns.values():
            if "column" in spec:
                used.update(_as_list(spec["column"]))
            used.update(spec.get("when", {}))
        return used


@dataclass
class MappedTable:
    """Rows produced for one canonical table from one file, and how complete they are."""

    table: str
    rows: list[dict[str, Any]]
    source_rows: int
    skipped_by_filter: int
    dropped_missing_required: int
    filled: dict[str, int]
    # "missing created_at" -> positions in the file's rows of the rows dropped for it
    rejected: dict[str, list[int]] = field(default_factory=dict)
    positions: list[int] = field(default_factory=list)  # of each row in `rows`


class SourceMapping:
    """A product export mapping with one or more target tables (`tables:` in the YAML)."""

    def __init__(self, mapping_path: Path | str, normaliser: TaxonomyNormaliser | None = None):
        self.path = Path(mapping_path)
        if not self.path.is_file():
            raise MappingError(f"Mapping file not found: {self.path}")
        with open(self.path, encoding="utf-8") as f:
            self.config: dict[str, Any] = yaml.safe_load(f) or {}
        self.normaliser = normaliser or TaxonomyNormaliser()
        self.source: str = str(self.config.get("source") or self.path.stem)
        self.entity_id: str | None = self.config.get("entity_id")
        self.ts_format: str = str(self.config.get("timestamp_format", "iso"))
        self.source_tz = self._source_timezone()
        self.value_maps: dict[str, dict[str, str]] = {
            kind: {str(k): str(v) for k, v in (values or {}).items()}
            for kind, values in (self.config.get("value_mappings") or {}).items()
        }
        self.tables = self._table_specs()

    def _source_timezone(self) -> timezone:
        """Zone of timestamps that carry no offset. A fixed `utc_offset` needs no tz database."""
        if "utc_offset" in self.config:
            return _parse_utc_offset(self.config["utc_offset"])
        name = str(self.config.get("timezone", "UTC"))
        if name.upper() in ("UTC", "Z", "GMT"):
            return UTC
        raise MappingError(
            f"{self.path.name}: timezone {name!r} needs a time-zone database, which an air-gapped "
            "host may not have. Give the fixed offset instead, e.g. utc_offset: '+05:30'."
        )

    def _table_specs(self) -> list[TableSpec]:
        raw_tables = self.config.get("tables")
        if not isinstance(raw_tables, list) or not raw_tables:
            raise MappingError(
                f"{self.path.name} has no `tables:` section. The ingestion pipeline needs one entry "
                "per canonical table the export feeds (see config/mappings/cse_splunk.yaml)."
            )
        specs = []
        for entry in raw_tables:
            table = entry.get("table")
            files = entry.get("files") or []
            columns = entry.get("columns") or {}
            if not table or not (files or entry.get("headers")) or not columns:
                raise MappingError(
                    f"{self.path.name}: every table needs `table`, `files` and `columns` (`headers` can stand in for `files`)."
                )
            normalised: dict[str, dict[str, Any]] = {}
            for canonical, spec in columns.items():
                spec = {"column": spec} if isinstance(spec, str | list) else dict(spec or {})
                if "column" not in spec and "const" not in spec:
                    raise MappingError(
                        f"{self.path.name}: {table}.{canonical} needs a source `column` or a `const`."
                    )
                transform = spec.get("transform")
                if transform is not None and transform not in TRANSFORMS:
                    raise MappingError(
                        f"{self.path.name}: {table}.{canonical} transform {transform!r} is not one of "
                        f"{', '.join(sorted(TRANSFORMS))}."
                    )
                values = spec.get("values")
                if values is not None and values not in self.value_maps:
                    raise MappingError(f"{self.path.name}: value_mappings.{values} is not defined.")
                spec["when"] = {k: [str(x) for x in _as_list(v)] for k, v in (spec.get("when") or {}).items()}
                lookup = spec.get("lookup")
                if lookup is not None and not {"files", "key", "value"} <= set(lookup):
                    raise MappingError(
                        f"{self.path.name}: {table}.{canonical} lookup needs `files`, `key` and `value`."
                    )
                normalised[canonical] = spec
            specs.append(
                TableSpec(
                    table=table,
                    files=[str(p) for p in _as_list(files)],
                    columns=normalised,
                    required=list(entry.get("required") or []),
                    where={k: [str(x) for x in _as_list(v)] for k, v in (entry.get("where") or {}).items()},
                    headers=[str(h) for h in _as_list(entry.get("headers") or [])],
                )
            )
        return specs

    def specs_for_file(self, file_stem: str, headers: list[str] | None = None) -> list[TableSpec]:
        """Tables a file feeds: by its name, or by the columns a table lists under `headers:`."""
        return [spec for spec in self.tables if spec.matches(file_stem, headers)]

    def identifies(self, headers: list[str]) -> bool:
        """True if these columns are the export a table of this mapping lists under `headers:`."""
        return any(spec.matches_headers(headers) for spec in self.tables)

    def build_lookups(self, files: dict[str, list[dict[str, Any]]]) -> None:
        """Index the batch's files for columns that translate an id through another export.

        ServiceNow's audit trail names a record by `sys_id` while the incident export is known
        by its `number`: `lookup: {files: "sn_si_incident*", key: sys_id, value: number}`.
        """
        self._lookups: dict[tuple[str, str, str], dict[str, Any]] = {}
        for spec in self.tables:
            for col_spec in spec.columns.values():
                lookup = col_spec.get("lookup")
                if not lookup:
                    continue
                ident = (str(lookup["files"]), str(lookup["key"]), str(lookup["value"]))
                index = self._lookups.setdefault(ident, {})
                for stem, rows in files.items():
                    if not fnmatch(stem.lower(), ident[0].lower()):
                        continue
                    for row in rows:
                        key = _lookup(row, ident[1])
                        if not _blank(key):
                            index[str(key).strip()] = _lookup(row, ident[2])

    def _convert(self, canonical: str, spec: dict[str, Any], raw: Any) -> Any:
        if spec.get("transform") == "length":
            return 0 if _blank(raw) else len(str(raw))
        if "extract" in spec:
            raw = _extract(raw, spec["extract"])
        if _blank(raw):
            return spec.get("default")
        if spec.get("transform") == "boolean":
            flag = parse_bool(raw)
            return spec.get("default") if flag is None else flag
        if spec.get("transform") == "number":
            number = parse_number(raw)
            return spec.get("default") if number is None else number
        lookup = spec.get("lookup")
        if lookup:
            ident = (str(lookup["files"]), str(lookup["key"]), str(lookup["value"]))
            raw = getattr(self, "_lookups", {}).get(ident, {}).get(str(raw).strip())
            if _blank(raw):
                return spec.get("default")
        if canonical in TIMESTAMP_FIELDS:
            return parse_source_timestamp(raw, str(spec.get("format", self.ts_format)), self.source_tz)
        kind = spec.get("values") or TAXONOMY_KIND.get(canonical)
        text = str(raw).strip()
        if kind and text in self.value_maps.get(kind, {}):
            return self.value_maps[kind][text]
        if "values" in spec:
            # An explicit value map with no entry for this value: the declared default, or
            # nothing. Passing the raw product value through would store an unknown code.
            return spec.get("default")
        if canonical in TAXONOMY_KIND:
            normalise = getattr(self.normaliser, f"normalise_{TAXONOMY_KIND[canonical]}")
            return normalise(text)
        # Identifiers are text in every canonical table, even where an export's ids look like
        # numbers (XSIAM case 241806): a numeric id would clash with the same table's text ids.
        return text if isinstance(raw, str) or canonical.endswith("_id") else raw

    def map_rows(self, raw_rows: list[dict[str, Any]], spec: TableSpec, entity_id: str) -> MappedTable:
        """Canonical rows for `spec.table`. Only mapped fields are emitted: no raw column passes through."""
        rows: list[dict[str, Any]] = []
        filled = dict.fromkeys(spec.columns, 0)
        skipped = dropped = 0
        rejected: dict[str, list[int]] = {}
        positions: list[int] = []
        for position, raw in enumerate(raw_rows):
            if any(str(_lookup(raw, col)).strip() not in allowed for col, allowed in spec.where.items()):
                skipped += 1
                continue
            row: dict[str, Any] = {"entity_id": entity_id}
            for canonical, col_spec in spec.columns.items():
                if any(
                    str(_lookup(raw, col)).strip() not in allowed for col, allowed in col_spec["when"].items()
                ):
                    row[canonical] = None
                elif "const" in col_spec:
                    row[canonical] = col_spec["const"]
                else:
                    row[canonical] = self._convert(canonical, col_spec, _lookup(raw, col_spec["column"]))
            missing = [name for name in spec.required if _blank(row.get(name))]
            if missing:
                dropped += 1
                rejected.setdefault(f"missing {', '.join(missing)}", []).append(position)
                continue
            for canonical in spec.columns:
                if not _blank(row.get(canonical)):
                    filled[canonical] += 1
            rows.append(row)
            positions.append(position)
        return MappedTable(
            table=spec.table,
            rows=rows,
            source_rows=len(raw_rows),
            skipped_by_filter=skipped,
            dropped_missing_required=dropped,
            filled=filled,
            rejected=rejected,
            positions=positions,
        )


def _extract(raw: Any, path: Any) -> Any:
    """Value inside a cell that holds a dict/list literal: `extract: total_duration` or `a.0.b`.

    `{'total_duration': 1295, 'status': 'ended'}` (a Python repr, as some exports write it) and
    JSON are both read; a cell that is not such a literal, or lacks the key, gives None.
    """
    current = parse_literal(raw) if isinstance(raw, str) else raw
    for part in str(path).split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.lstrip("-").isdigit():
            index = int(part)
            current = current[index] if -len(current) <= index < len(current) else None
        else:
            return None
    return current


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list | tuple) else [value]


class CSEMapper:
    """Applies per-CSE schema mappings and timezone conversions to raw records."""

    def __init__(self, mapping_path: Path | str, normaliser: TaxonomyNormaliser | None = None):
        self.mapping_path = Path(mapping_path)
        self.mapping = self._load_mapping()
        self.normaliser = normaliser or TaxonomyNormaliser()
        self.entity_id: str = self.mapping.get("entity_id", "UNKNOWN")
        self.col_map: dict[str, str] = self.mapping.get("column_mappings", {})
        self.val_map: dict[str, dict[str, str]] = self.mapping.get("value_mappings", {})
        self.tz_str: str = self.mapping.get("timezone", "UTC")
        self.ts_format: str = self.mapping.get("timestamp_format", "%Y-%m-%d %H:%M:%S")

    def _load_mapping(self) -> dict[str, Any]:
        with open(self.mapping_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def parse_timestamp(self, val: Any) -> datetime | None:
        """Parse source timestamp into UTC datetime."""
        parsed = parse_source_timestamp(val, self.ts_format)
        return parsed.replace(tzinfo=UTC) if parsed else None

    def map_record(self, raw_record: dict[str, Any], table_type: str = "alert") -> dict[str, Any]:
        """Transform a raw dictionary into canonical field values."""
        canonical: dict[str, Any] = {"entity_id": self.entity_id}

        # Apply column mappings
        for can_field, src_col in self.col_map.items():
            if src_col in raw_record:
                canonical[can_field] = raw_record[src_col]

        # Normalize taxonomy fields if present
        if "severity" in canonical or "severity_orig" in canonical:
            raw_sev = str(canonical.get("severity_orig", canonical.get("severity", "")))
            if "severity" in self.val_map and raw_sev in self.val_map["severity"]:
                norm_sev = self.val_map["severity"][raw_sev]
            else:
                norm_sev = self.normaliser.normalise_severity(raw_sev)
            canonical["severity"] = norm_sev
            canonical["severity_orig"] = norm_sev
            canonical["severity_final"] = norm_sev

        if "status" in canonical:
            raw_stat = str(canonical["status"])
            if "status" in self.val_map and raw_stat in self.val_map["status"]:
                canonical["status"] = self.val_map["status"][raw_stat]
            else:
                canonical["status"] = self.normaliser.normalise_status(raw_stat)

        if "disposition" in canonical:
            raw_disp = str(canonical["disposition"])
            if "disposition" in self.val_map and raw_disp in self.val_map["disposition"]:
                canonical["disposition"] = self.val_map["disposition"][raw_disp]
            else:
                canonical["disposition"] = self.normaliser.normalise_disposition(raw_disp)

        # Normalize timestamp fields
        for ts_col in [
            "created_at",
            "acknowledged_at",
            "first_touch_at",
            "closed_at",
            "opened_at",
            "escalated_at",
            "ts",
        ]:
            if ts_col in canonical:
                canonical[ts_col] = self.parse_timestamp(canonical[ts_col])

        return canonical
