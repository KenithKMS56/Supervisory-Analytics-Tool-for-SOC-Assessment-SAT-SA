"""Peer group resolution and cohort fallback handling."""

from pathlib import Path
from typing import Any

import yaml

from satsa.models.canonical import Entity


class PeerResolver:
    """Finds comparable peer entities using hierarchical cohort matching with fallback."""

    def __init__(self, config_path: Path | str = "config/peers.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.min_peers = self.config.get("peer_groups", {}).get("min_peers", 3)

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def resolve_peers(
        self, target_entity: Entity, all_entities: list[Entity]
    ) -> tuple[list[str], str, bool]:
        """
        Resolve cohort of peer entity IDs for target entity.
        Returns: (peer_ids, cohort_label, is_weak_peer_group).
        """
        other_entities = [e for e in all_entities if e.entity_id != target_entity.entity_id]
        if not other_entities:
            return [], "none", True

        # Level 1: Same Sector AND Same Size Band
        cohort_lvl1 = [
            e.entity_id
            for e in other_entities
            if e.sector == target_entity.sector and e.size_band == target_entity.size_band
        ]
        if len(cohort_lvl1) >= self.min_peers:
            return cohort_lvl1, f"{target_entity.sector}_{target_entity.size_band}", False

        # Level 2: Same Sector
        cohort_lvl2 = [e.entity_id for e in other_entities if e.sector == target_entity.sector]
        if len(cohort_lvl2) >= self.min_peers:
            return cohort_lvl2, f"{target_entity.sector}_all_sizes", True

        # Level 3: Same Size Band
        cohort_lvl3 = [
            e.entity_id for e in other_entities if e.size_band == target_entity.size_band
        ]
        if len(cohort_lvl3) >= self.min_peers:
            return cohort_lvl3, f"all_sectors_{target_entity.size_band}", True

        # Level 4: All Entities fallback
        all_ids = [e.entity_id for e in other_entities]
        return all_ids, "all_entities_broad", True
