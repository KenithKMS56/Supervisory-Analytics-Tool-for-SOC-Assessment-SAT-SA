"""Per-CSE configuration mapper for source-to-canonical transformation."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from satsa.ingest.normaliser import TaxonomyNormaliser


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
        if val is None or val == "":
            return None
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=UTC)
        if self.ts_format == "epoch_ms":
            try:
                return datetime.fromtimestamp(float(val) / 1000.0, tz=UTC)
            except (ValueError, TypeError):
                return None
        if self.ts_format == "epoch_s":
            try:
                return datetime.fromtimestamp(float(val), tz=UTC)
            except (ValueError, TypeError):
                return None

        # Parse string timestamp
        try:
            dt = datetime.strptime(str(val).strip(), self.ts_format)
            # Default to UTC if not timezone specified
            return dt.replace(tzinfo=UTC)
        except ValueError:
            # Fallback ISO parser
            try:
                dt = datetime.fromisoformat(str(val).strip().replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
            except ValueError:
                return None

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
