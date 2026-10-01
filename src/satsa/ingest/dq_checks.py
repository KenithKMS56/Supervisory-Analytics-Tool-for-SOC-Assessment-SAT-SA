"""Data Quality (DQ) validation checks and issue reporting."""

import re
from collections import Counter
from datetime import datetime
from typing import Any

import polars as pl

from satsa.models.outputs import DQIssue


class DQValidator:
    """Executes data quality checks and flags anomalies, sequence gaps, and corrupted records."""

    @staticmethod
    def check_required_fields(
        records: list[dict[str, Any]], required_fields: list[str], entity_id: str, table_name: str
    ) -> list[DQIssue]:
        """Check for missing or null required fields."""
        issues: list[DQIssue] = []
        for field in required_fields:
            missing_samples: list[str] = []
            for r in records:
                val = r.get(field)
                if val is None or val == "":
                    rec_id = str(r.get(f"{table_name}_id", r.get("id", "unknown")))
                    missing_samples.append(rec_id)
            if missing_samples:
                issues.append(
                    DQIssue(
                        issue_id=f"DQ-REQ-{entity_id}-{table_name}-{field}",
                        entity_id=entity_id,
                        check_name="missing_required_field",
                        severity="error",
                        count=len(missing_samples),
                        sample_records=missing_samples[:5],
                        details=f"Field '{field}' missing or empty in {len(missing_samples)} records of '{table_name}'.",
                    )
                )
        return issues

    @staticmethod
    def check_timestamp_logic(records: list[dict[str, Any]], entity_id: str) -> list[DQIssue]:
        """Ensure closed_at >= created_at and acknowledged_at >= created_at."""
        issues: list[DQIssue] = []
        inverted_close: list[str] = []
        for r in records:
            c_at = r.get("created_at")
            cl_at = r.get("closed_at")
            if isinstance(c_at, datetime) and isinstance(cl_at, datetime) and cl_at < c_at:
                inverted_close.append(str(r.get("alert_id", "unknown")))

        if inverted_close:
            issues.append(
                DQIssue(
                    issue_id=f"DQ-TS-INVERT-{entity_id}",
                    entity_id=entity_id,
                    check_name="close_before_create",
                    severity="error",
                    count=len(inverted_close),
                    sample_records=inverted_close[:5],
                    details=f"{len(inverted_close)} records exhibit close timestamp preceding create timestamp.",
                )
            )
        return issues

    @staticmethod
    def check_duplicate_ids(
        records: list[dict[str, Any]], id_col: str, entity_id: str, table_name: str
    ) -> list[DQIssue]:
        """Check for duplicate primary key identifiers."""
        issues: list[DQIssue] = []
        ids = [str(r.get(id_col)) for r in records if r.get(id_col)]
        counts = Counter(ids)
        duplicates = [item for item, cnt in counts.items() if cnt > 1]

        if duplicates:
            issues.append(
                DQIssue(
                    issue_id=f"DQ-DUP-{entity_id}-{table_name}",
                    entity_id=entity_id,
                    check_name="duplicate_primary_keys",
                    severity="error",
                    count=len(duplicates),
                    sample_records=duplicates[:5],
                    details=f"Found {len(duplicates)} duplicated IDs in '{table_name}'.",
                )
            )
        return issues

    @staticmethod
    def check_id_sequence_gaps(
        records: list[dict[str, Any]], id_col: str, entity_id: str
    ) -> list[DQIssue]:
        """Detect unexpected gaps in incremental ID sequences."""
        issues: list[DQIssue] = []
        seq_nums: list[int] = []

        pattern = re.compile(r"(\d+)$")
        for r in records:
            val = str(r.get(id_col, ""))
            match = pattern.search(val)
            if match:
                seq_nums.append(int(match.group(1)))

        if len(seq_nums) > 20:
            seq_nums.sort()
            large_gaps = []
            for i in range(len(seq_nums) - 1):
                diff = seq_nums[i + 1] - seq_nums[i]
                if diff > 50:  # Gap of >50 missing sequence numbers
                    large_gaps.append(f"{seq_nums[i]}->{seq_nums[i + 1]} (diff={diff})")

            if large_gaps:
                issues.append(
                    DQIssue(
                        issue_id=f"DQ-GAP-{entity_id}",
                        entity_id=entity_id,
                        check_name="id_sequence_gap",
                        severity="warning",
                        count=len(large_gaps),
                        sample_records=large_gaps[:5],
                        details=f"Detected {len(large_gaps)} material sequence jumps in '{id_col}'.",
                    )
                )
        return issues

    @staticmethod
    def check_orphan_references(
        child_records: list[dict[str, Any]],
        parent_ids: set[str],
        fk_col: str,
        entity_id: str,
        child_table: str,
        parent_table: str,
    ) -> list[DQIssue]:
        """Verify referential integrity."""
        issues: list[DQIssue] = []
        orphans: list[str] = []

        for r in child_records:
            val = str(r.get(fk_col, ""))
            if val and val not in parent_ids:
                orphans.append(str(r.get(f"{child_table}_id", val)))

        if orphans:
            issues.append(
                DQIssue(
                    issue_id=f"DQ-ORPHAN-{entity_id}-{child_table}-{parent_table}",
                    entity_id=entity_id,
                    check_name="orphan_foreign_keys",
                    severity="error",
                    count=len(orphans),
                    sample_records=orphans[:5],
                    details=f"{len(orphans)} records in '{child_table}' reference non-existent {parent_table} IDs.",
                )
            )
        return issues

    @staticmethod
    def check_null_rates(
        records: list[dict[str, Any]],
        key_fields: list[str],
        entity_id: str,
        table_name: str,
        max_rate: float = 0.15,
    ) -> list[DQIssue]:
        """Verify null rates do not exceed acceptable supervisory thresholds."""
        issues: list[DQIssue] = []
        total = len(records)
        if total == 0:
            return issues

        for field in key_fields:
            nulls = sum(1 for r in records if r.get(field) is None or r.get(field) == "")
            rate = nulls / total
            if rate > max_rate:
                issues.append(
                    DQIssue(
                        issue_id=f"DQ-NULLRATE-{entity_id}-{table_name}-{field}",
                        entity_id=entity_id,
                        check_name="high_null_rate",
                        severity="warning",
                        count=nulls,
                        sample_records=[],
                        details=f"High null rate in '{table_name}.{field}': {rate:.1%} exceeds tolerance threshold ({max_rate:.1%}).",
                    )
                )
        return issues


class FrameDQ:
    """DQValidator's checks on a columnar frame, with the same issues and the same samples.

    Ingest used to turn every entity's rows into dicts for these checks. Each method here gives
    exactly what the DQValidator method of the same name gives for `frame.to_dicts()`: the
    same counts, the same samples in the same (row) order and the same text. Text columns are
    checked with Polars expressions; any other column type goes through the dict-based logic,
    one column at a time.
    """

    @staticmethod
    def _missing(frame: pl.DataFrame, column: str) -> pl.Series:
        """`value is None or value == ""` per row (an absent column is missing everywhere)."""
        if column not in frame.columns:
            return pl.Series([True] * frame.height, dtype=pl.Boolean)
        series = frame[column]
        missing = series.is_null()
        if series.dtype == pl.String:
            missing = missing | (series == "")
        return missing.fill_null(True)

    @staticmethod
    def _ids(frame: pl.DataFrame, mask: pl.Series, column: str | None, fallback: str, limit: int = 5) -> list[str]:
        """str(r.get(column, fallback)) for the first `limit` rows where `mask` holds."""
        rows = frame.filter(mask).head(limit)
        if column is not None and column in frame.columns:
            return [str(v) for v in rows[column].to_list()]
        return [fallback] * rows.height

    @staticmethod
    def check_required_fields(
        frame: pl.DataFrame, required_fields: list[str], entity_id: str, table_name: str
    ) -> list[DQIssue]:
        issues: list[DQIssue] = []
        id_column = f"{table_name}_id" if f"{table_name}_id" in frame.columns else ("id" if "id" in frame.columns else None)
        for fld in required_fields:
            missing = FrameDQ._missing(frame, fld)
            count = int(missing.sum())
            if count:
                issues.append(
                    DQIssue(
                        issue_id=f"DQ-REQ-{entity_id}-{table_name}-{fld}",
                        entity_id=entity_id,
                        check_name="missing_required_field",
                        severity="error",
                        count=count,
                        sample_records=FrameDQ._ids(frame, missing, id_column, "unknown"),
                        details=f"Field '{fld}' missing or empty in {count} records of '{table_name}'.",
                    )
                )
        return issues

    @staticmethod
    def check_timestamp_logic(frame: pl.DataFrame, entity_id: str) -> list[DQIssue]:
        if "created_at" not in frame.columns or "closed_at" not in frame.columns:
            return []
        created, closed = frame["created_at"], frame["closed_at"]
        if isinstance(created.dtype, pl.Datetime) and created.dtype == closed.dtype:
            inverted = (closed < created).fill_null(False)
        elif created.dtype == pl.Object or closed.dtype == pl.Object or (
            isinstance(created.dtype, pl.Datetime) and isinstance(closed.dtype, pl.Datetime)
        ):
            ids = frame["alert_id"].to_list() if "alert_id" in frame.columns else ["unknown"] * frame.height
            records = [
                {"created_at": c, "closed_at": d, "alert_id": i}
                for c, d, i in zip(created.to_list(), closed.to_list(), ids, strict=True)
            ]
            return DQValidator.check_timestamp_logic(records, entity_id)
        else:
            return []  # neither column holds datetime values, so no row can be compared
        count = int(inverted.sum())
        if not count:
            return []
        return [
            DQIssue(
                issue_id=f"DQ-TS-INVERT-{entity_id}",
                entity_id=entity_id,
                check_name="close_before_create",
                severity="error",
                count=count,
                sample_records=FrameDQ._ids(frame, inverted, "alert_id", "unknown"),
                details=f"{count} records exhibit close timestamp preceding create timestamp.",
            )
        ]

    @staticmethod
    def check_duplicate_ids(frame: pl.DataFrame, id_col: str, entity_id: str, table_name: str) -> list[DQIssue]:
        if id_col not in frame.columns:
            return []
        series = frame[id_col]
        if series.dtype != pl.String:
            return DQValidator.check_duplicate_ids(
                [{id_col: v} for v in series.to_list()], id_col, entity_id, table_name
            )
        ids = series.filter(series.is_not_null() & (series != ""))
        counts = ids.to_frame("id").group_by("id", maintain_order=True).len()
        duplicates = counts.filter(pl.col("len") > 1)["id"].to_list()
        if not duplicates:
            return []
        return [
            DQIssue(
                issue_id=f"DQ-DUP-{entity_id}-{table_name}",
                entity_id=entity_id,
                check_name="duplicate_primary_keys",
                severity="error",
                count=len(duplicates),
                sample_records=duplicates[:5],
                details=f"Found {len(duplicates)} duplicated IDs in '{table_name}'.",
            )
        ]

    @staticmethod
    def check_id_sequence_gaps(frame: pl.DataFrame, id_col: str, entity_id: str) -> list[DQIssue]:
        if id_col not in frame.columns:
            return []
        series = frame[id_col]
        # Python's \d and $ differ from the regex engine's for non-ASCII digits and a trailing
        # newline; such values, and numbers too long for 64 bits, take the dict-based path.
        plain = series.dtype == pl.String and not bool(
            series.str.contains(r"[^\x00-\x7F]|\n").fill_null(False).any()
        )
        digits = series.str.extract(r"([0-9]+)$", 1) if plain else None
        if digits is None or bool((digits.str.len_chars() > 18).fill_null(False).any()):
            return DQValidator.check_id_sequence_gaps([{id_col: v} for v in series.to_list()], id_col, entity_id)
        numbers = digits.drop_nulls().cast(pl.Int64).sort()
        if numbers.len() <= 20:
            return []
        gaps = pl.DataFrame({"a": numbers[:-1], "b": numbers[1:]}).with_columns(d=pl.col("b") - pl.col("a"))
        gaps = gaps.filter(pl.col("d") > 50)
        if gaps.height == 0:
            return []
        samples = [f"{a}->{b} (diff={d})" for a, b, d in gaps.head(5).iter_rows()]
        return [
            DQIssue(
                issue_id=f"DQ-GAP-{entity_id}",
                entity_id=entity_id,
                check_name="id_sequence_gap",
                severity="warning",
                count=gaps.height,
                sample_records=samples,
                details=f"Detected {gaps.height} material sequence jumps in '{id_col}'.",
            )
        ]

    @staticmethod
    def truthy_ids(frame: pl.DataFrame, column: str) -> pl.Series:
        """{str(v) for v in column if v}, as a Series of distinct text values."""
        if column not in frame.columns:
            return pl.Series(column, [], dtype=pl.String)
        series = frame[column]
        if series.dtype == pl.String:
            return series.filter(series.is_not_null() & (series != "")).unique()
        return pl.Series(column, sorted({str(v) for v in series.to_list() if v}), dtype=pl.String)

    @staticmethod
    def check_orphan_references(
        child: pl.DataFrame,
        parent_ids: pl.Series,
        fk_col: str,
        entity_id: str,
        child_table: str,
        parent_table: str,
    ) -> list[DQIssue]:
        if child.height == 0 or fk_col not in child.columns:
            return []  # r.get(fk_col, "") is "" for every row: nothing to check
        fk = child[fk_col]
        id_column = f"{child_table}_id"
        if fk.dtype not in (pl.String, pl.Null) or (id_column in child.columns and child[id_column].dtype != pl.String):
            records: list[dict[str, Any]] = [{fk_col: v} for v in fk.to_list()]
            if id_column in child.columns:
                for record, value in zip(records, child[id_column].to_list(), strict=True):
                    record[id_column] = value
            return DQValidator.check_orphan_references(
                records, set(parent_ids.to_list()), fk_col, entity_id, child_table, parent_table
            )
        text = fk.cast(pl.String).fill_null("None")  # str(None) is "None", a non-empty value
        orphan = (text != "") & ~text.is_in(parent_ids.cast(pl.String).implode())
        count = int(orphan.sum())
        if not count:
            return []
        if id_column in child.columns:
            samples = [str(v) for v in child.filter(orphan).head(5)[id_column].to_list()]
        else:
            samples = text.filter(orphan).head(5).to_list()
        return [
            DQIssue(
                issue_id=f"DQ-ORPHAN-{entity_id}-{child_table}-{parent_table}",
                entity_id=entity_id,
                check_name="orphan_foreign_keys",
                severity="error",
                count=count,
                sample_records=samples,
                details=f"{count} records in '{child_table}' reference non-existent {parent_table} IDs.",
            )
        ]

    @staticmethod
    def check_null_rates(
        frame: pl.DataFrame, key_fields: list[str], entity_id: str, table_name: str, max_rate: float = 0.15
    ) -> list[DQIssue]:
        issues: list[DQIssue] = []
        total = frame.height
        if total == 0:
            return issues
        for fld in key_fields:
            nulls = int(FrameDQ._missing(frame, fld).sum())
            rate = nulls / total
            if rate > max_rate:
                issues.append(
                    DQIssue(
                        issue_id=f"DQ-NULLRATE-{entity_id}-{table_name}-{fld}",
                        entity_id=entity_id,
                        check_name="high_null_rate",
                        severity="warning",
                        count=nulls,
                        sample_records=[],
                        details=f"High null rate in '{table_name}.{fld}': {rate:.1%} exceeds tolerance threshold ({max_rate:.1%}).",
                    )
                )
        return issues
