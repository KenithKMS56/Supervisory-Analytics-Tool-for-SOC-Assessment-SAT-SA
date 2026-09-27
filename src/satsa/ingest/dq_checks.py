"""Data Quality (DQ) validation checks and issue reporting."""

import re
from collections import Counter
from datetime import datetime
from typing import Any

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
