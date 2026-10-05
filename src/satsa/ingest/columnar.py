"""Columnar ingest of one submitted CSV table: the row-wise result, computed per column.

`IngestionPipeline` normalises a submission row by row (`normalize_row_columns`, the entity
checks in `normalise_chunk`, `_apply_row_hygiene`, the canonical-column filter), turning every
row into a Python dict. `normalise_frame` produces the same frame with Polars expressions.
Functions with per-value logic (pseudonymisation, taxonomy, redaction, the entity-ID check) are
the same Python functions, called once per distinct value instead of once per row.

It covers what a canonical CSV contains. For anything where equivalence is not certain, it
returns None and the caller uses the row-wise path. That happens when:
- two columns have the same name once compared by `header_key` ("Alert ID" / "alert_id");
- a column is not text, integer, float, boolean or empty;
- two alias columns of one canonical column are both present (the row path picks per row);
- a column the hygiene step rewrites, or the entity ID, is not text.

tests/test_golden_findings.py and tests/test_columnar_ingest.py check the equivalence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import polars as pl

from satsa.ingest.ledger import ROW_SAMPLE
from satsa.ingest.sanitise import header_key
from satsa.security import is_valid_entity_id

if TYPE_CHECKING:
    from satsa.ingest.pipeline import IngestionPipeline

# Python's str.strip() whitespace, which is wider than the regex engine's \s.
_PY_WHITESPACE = "".join(chr(c) for c in range(0x110000) if chr(c).isspace())
_BLANK = "^[" + "".join(f"\\x{{{ord(c):x}}}" for c in _PY_WHITESPACE) + "]*$"

_PLAIN = (pl.String, pl.Int64, pl.Float64, pl.Boolean, pl.Null)
_TEXT = (pl.String, pl.Null)

# Columns a table's hygiene step reads or rewrites: they must be text (or wholly empty).
_HYGIENE_TEXT: dict[str, tuple[str, ...]] = {
    "alert": ("closed_by_type", "closed_by", "severity_orig", "severity_final", "severity", "status", "disposition"),
    "workflow_event": ("actor",),
    "case_record": ("owner",),
    "case": ("owner",),
    "closure": ("comment", "comment_norm_hash", "comment_shingles"),
}


@dataclass
class ColumnarResult:
    """What the row path would have produced for one file."""

    frame: pl.DataFrame
    unattributed: int = 0
    rejected: list[str] = field(default_factory=list)
    dropped: set[str] = field(default_factory=set)
    # Positions in the file of the first ROW_SAMPLE rows set aside, for the file ledger.
    unattributed_at: list[int] = field(default_factory=list)
    rejected_at: list[int] = field(default_factory=list)


def _is(dtype: pl.DataType, kinds: tuple[Any, ...]) -> bool:
    return any(dtype == kind for kind in kinds)


def _truthy(frame: pl.DataFrame, column: str) -> pl.Expr:
    """`bool(value)` for a text column: not null and not the empty string."""
    if column not in frame.columns or frame.schema[column] == pl.Null:
        return pl.lit(False)
    return pl.col(column).is_not_null() & (pl.col(column) != "")


def _mapped(frame: pl.DataFrame, column: str, function: Any) -> pl.Expr:
    """The column with `function` applied to every truthy value (others unchanged)."""
    values = frame.filter(_truthy(frame, column))[column].unique().to_list()
    return pl.col(column).replace({v: function(v) for v in values})


def normalise_frame(
    frame: pl.DataFrame,
    table: str,
    pipeline: IngestionPipeline,
    default_entity_id: str | None,
    columns: list[str],
) -> ColumnarResult | None:
    """The frame the row path would buffer for `frame`, or None where equivalence is not certain."""
    names = [header_key(c) for c in frame.columns]
    if len(set(names)) != len(names):
        return None
    if not all(_is(dtype, _PLAIN) for dtype in frame.dtypes):
        return None
    frame = frame.rename(dict(zip(frame.columns, names, strict=True)))
    present = set(names)

    # normalize_row_columns: each canonical column takes its first non-blank alias.
    additions: list[pl.Expr] = []
    for canonical, aliases in pipeline.COLUMN_ALIASES.get(table, {}).items():
        found = [a for a in aliases if a in present]
        if len(found) > 1:
            return None
        if not found or found[0] == canonical:
            continue  # absent, or present under its own name (kept as submitted)
        alias = found[0]
        dtype = frame.schema[alias]
        if dtype == pl.Null:
            continue  # never non-blank: the canonical column stays absent
        usable = pl.col(alias).is_not_null()
        if dtype == pl.String:
            usable = usable & ~pl.col(alias).str.contains(_BLANK)
        additions.append(pl.when(usable).then(pl.col(alias)).otherwise(None).alias(canonical))
    if additions:
        frame = frame.with_columns(additions)

    for column in _HYGIENE_TEXT.get(table, ()) + ("entity_id",):
        if column in frame.columns and not _is(frame.schema[column], _TEXT):
            return None
    if table == "closure" and "comment_len" in frame.columns and not _is(frame.schema["comment_len"], (pl.Int64, pl.Null)):
        return None

    # normalise_chunk: the default entity, then rows without a valid entity are set aside.
    if "entity_id" not in frame.columns:
        frame = frame.with_columns(pl.lit(default_entity_id, dtype=pl.String).alias("entity_id"))
    elif default_entity_id:
        frame = frame.with_columns(
            pl.when(_truthy(frame, "entity_id")).then(pl.col("entity_id")).otherwise(pl.lit(default_entity_id))
            .cast(pl.String).alias("entity_id")
        )  # fmt: skip
    status = {}
    for value in frame["entity_id"].unique().to_list():
        if value is None or not str(value).strip():
            status[value] = "unattributed"
        elif not is_valid_entity_id(str(value)):
            status[value] = "rejected"
        else:
            status[value] = "kept"
    known = {k: v for k, v in status.items() if k is not None}
    verdict = (
        frame["entity_id"].cast(pl.String).replace_strict(known, default="unattributed", return_dtype=pl.String)
        if known
        else pl.Series("entity_id", ["unattributed"] * frame.height, dtype=pl.String)
    )
    result = ColumnarResult(frame=frame)
    result.unattributed = int((verdict == "unattributed").sum())
    if result.unattributed:
        result.unattributed_at = (verdict == "unattributed").arg_true().head(ROW_SAMPLE).to_list()
    if (verdict == "rejected").any():
        result.rejected = [str(v) for v in frame.filter(verdict == "rejected")["entity_id"].to_list()]
        result.rejected_at = (verdict == "rejected").arg_true().head(ROW_SAMPLE).to_list()
    frame = frame.filter(verdict == "kept")
    if frame.height == 0:
        result.frame = frame.clear()
        return result

    frame = _hygiene(frame, table, pipeline)

    # store_rows: only the table's canonical columns are kept.
    if columns:
        result.dropped = set(frame.columns) - set(columns)
        frame = frame.select([c for c in columns if c in frame.columns])
    result.frame = frame
    return result


def _hygiene(frame: pl.DataFrame, table: str, pipeline: IngestionPipeline) -> pl.DataFrame:
    """_apply_row_hygiene, per column."""
    pseudo = pipeline.pseudonymiser.pseudonymise
    norm = pipeline.normaliser
    if table == "alert":
        if "closed_by_type" in frame.columns:
            frame = frame.with_columns(
                pl.when(_truthy(frame, "closed_by_type")).then(pl.col("closed_by_type")).otherwise(pl.lit("human"))
                .cast(pl.String).alias("closed_by_type")
            )  # fmt: skip
        else:
            frame = frame.with_columns(pl.lit("human", dtype=pl.String).alias("closed_by_type"))
        updates: list[pl.Expr] = []
        if "closed_by" in frame.columns:
            human = (pl.col("closed_by_type") == "human") & _truthy(frame, "closed_by")
            values = frame.filter(human)["closed_by"].unique().to_list()
            mapping = {v: pseudo(str(v), prefix="ANALYST") for v in values}
            updates.append(
                pl.when(human).then(pl.col("closed_by").replace(mapping)).otherwise(pl.col("closed_by")).alias("closed_by")
            )
        if "severity_orig" in frame.columns:
            updates.append(_mapped(frame, "severity_orig", norm.normalise_severity))
        if "severity_final" in frame.columns or "severity" in frame.columns:
            final = _truthy(frame, "severity_final")
            fallback = _truthy(frame, "severity")
            from_final = _mapped(frame, "severity_final", norm.normalise_severity) if "severity_final" in frame.columns else None
            from_severity = (
                pl.col("severity").replace(
                    {v: norm.normalise_severity(v) for v in frame.filter(~final & fallback)["severity"].unique().to_list()}
                )
                if "severity" in frame.columns
                else None
            )
            current = pl.col("severity_final") if "severity_final" in frame.columns else pl.lit(None, dtype=pl.String)
            first = from_final if from_final is not None else current
            expr = (
                pl.when(final).then(first).when(fallback).then(from_severity).otherwise(current)
                if from_severity is not None
                else pl.when(final).then(first).otherwise(current)
            )
            updates.append(expr.cast(pl.String).alias("severity_final"))
        if "status" in frame.columns:
            updates.append(_mapped(frame, "status", norm.normalise_status))
        if "disposition" in frame.columns:
            updates.append(_mapped(frame, "disposition", norm.normalise_disposition))
        if updates:
            frame = frame.with_columns(updates)
    elif table == "workflow_event" and "actor" in frame.columns:
        frame = frame.with_columns(_mapped(frame, "actor", lambda v: pseudo(str(v), prefix="ACTOR")))
    elif table in ("case_record", "case") and "owner" in frame.columns:
        frame = frame.with_columns(_mapped(frame, "owner", lambda v: pseudo(str(v), prefix="OWNER")))
    elif table == "closure" and "comment" in frame.columns:
        redactor = pipeline.redactor
        has_comment = _truthy(frame, "comment")
        derived: dict[str, tuple[str, int, str]] = {}
        for text in frame.filter(has_comment)["comment"].unique().to_list():
            redacted = redactor.redact_text(str(text))
            shingles = redactor.hash_shingles(redactor.generate_shingles(redacted))
            derived[text] = (redactor.compute_norm_hash(redacted), len(redacted), ",".join(shingles[:10]))
        texts = list(derived)

        def part(index: int, dtype: Any) -> pl.Expr:
            return pl.col("comment").replace_strict(texts, [derived[t][index] for t in texts], default=None, return_dtype=dtype)

        def keep(column: str, dtype: Any) -> pl.Expr:
            return pl.col(column) if column in frame.columns else pl.lit(None, dtype=dtype)

        frame = frame.with_columns(
            pl.when(has_comment).then(part(0, pl.String)).otherwise(keep("comment_norm_hash", pl.String))
            .cast(pl.String).alias("comment_norm_hash"),
            pl.when(has_comment).then(part(1, pl.Int64)).otherwise(keep("comment_len", pl.Int64))
            .cast(pl.Int64).alias("comment_len"),
            pl.when(has_comment).then(part(2, pl.String)).otherwise(keep("comment_shingles", pl.String))
            .cast(pl.String).alias("comment_shingles"),
        ).drop("comment")  # fmt: skip
    return frame
