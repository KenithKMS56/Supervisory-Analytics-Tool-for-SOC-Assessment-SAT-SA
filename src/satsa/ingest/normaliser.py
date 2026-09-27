"""Taxonomy normaliser mapping source values to canonical representations."""

from pathlib import Path
from typing import Any

import yaml


class TaxonomyNormaliser:
    """Normalises severity, status, and disposition using taxonomy.yaml."""

    def __init__(self, config_path: Path | str = "config/taxonomy.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.severity_map: dict[str, str] = {}
        self.status_map: dict[str, str] = {}
        self.disposition_map: dict[str, str] = {}
        self._build_lookup_tables()

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _build_lookup_tables(self) -> None:
        # Build reverse lookup for severities
        for canonical, aliases in self.config.get("severities", {}).items():
            for alias in aliases:
                self.severity_map[str(alias).lower().strip()] = canonical
            self.severity_map[canonical.lower().strip()] = canonical

        # Build reverse lookup for statuses
        for canonical, aliases in self.config.get("statuses", {}).items():
            for alias in aliases:
                self.status_map[str(alias).lower().strip()] = canonical
            self.status_map[canonical.lower().strip()] = canonical

        # Build reverse lookup for dispositions
        for canonical, aliases in self.config.get("dispositions", {}).items():
            for alias in aliases:
                self.disposition_map[str(alias).lower().strip()] = canonical
            self.disposition_map[canonical.lower().strip()] = canonical

    def normalise_severity(self, raw_val: Any) -> str:
        if raw_val is None:
            return "unmapped"
        key = str(raw_val).lower().strip()
        return self.severity_map.get(key, "unmapped")

    def normalise_status(self, raw_val: Any) -> str:
        if raw_val is None:
            return "unmapped"
        key = str(raw_val).lower().strip()
        return self.status_map.get(key, "unmapped")

    def normalise_disposition(self, raw_val: Any) -> str:
        if raw_val is None:
            return "unmapped"
        key = str(raw_val).lower().strip()
        return self.disposition_map.get(key, "unmapped")
