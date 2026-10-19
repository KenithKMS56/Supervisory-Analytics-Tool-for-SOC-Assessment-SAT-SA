"""Peer cohorts: who an entity is compared with, and how much that comparison can bear.

The cohort is the first level of `peer_groups.hierarchy` (config/peers.yaml) that has enough
members, most specific first: sector, size, SOC model and operating schedule together where the
portfolio is large enough, then sector and size, sector, size, and finally every entity. A level
is used only when it has at least its `min_members` (default `min_peers`), so a small portfolio
is not split into cohorts of one or two.

Every comparison is recorded (`PeerComparison`, stored per run in `peer_comparisons`): the
members, the entities left out and why, the fallback level, the denominator and the minimum
support. A comparison is **established** when it has at least `min_support` members and is not
the all-entities fallback; otherwise it is **exploratory** (shown, but not as an authoritative
peer judgement), or **none** when there is nobody to compare with.

Supported attributes: sector, size_band, soc_model, schedule (satsa.context.schedule_class of
the declared operating hours), soc_provider, and `all`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from satsa.config_cache import load_yaml
from satsa.context import schedule_class
from satsa.models.canonical import Entity

ESTABLISHED, EXPLORATORY, NONE = "established", "exploratory", "none"
ATTRIBUTES = ("sector", "size_band", "soc_model", "schedule", "soc_provider")
_DEFAULT_HIERARCHY: list[dict[str, Any]] = [
    {"attributes": ["sector", "size_band"]},
    {"attributes": ["sector"]},
    {"attributes": ["size_band"]},
    {"attributes": ["all"]},
]


def attribute(entity: Entity, name: str) -> str:
    if name == "schedule":
        return schedule_class(entity.declared_shift_hours)
    return str(getattr(entity, name, "") or "")


@dataclass(frozen=True)
class PeerComparison:
    entity_id: str
    member_ids: list[str]
    cohort_label: str
    attributes: tuple[str, ...]
    fallback_level: int  # 0: the most specific level of the hierarchy
    excluded: list[dict[str, str]] = field(default_factory=list)
    min_support: int = 5
    strength: str = NONE
    reason: str = ""

    @property
    def denominator(self) -> int:
        return len(self.member_ids)

    @property
    def is_weak(self) -> bool:
        return self.strength != ESTABLISHED

    def describe(self) -> str:
        return f"{self.cohort_label} ({self.denominator} peers, {self.strength})"

    def as_row(self, run_id: str) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "entity_id": self.entity_id,
            "cohort_label": self.cohort_label,
            "attributes": list(self.attributes),
            "fallback_level": self.fallback_level,
            "member_ids": self.member_ids,
            "excluded": self.excluded,
            "denominator": self.denominator,
            "min_support": self.min_support,
            "strength": self.strength,
            "reason": self.reason,
        }


class PeerResolver:
    """Finds comparable peer entities using hierarchical cohort matching with fallback."""

    def __init__(self, config_path: Path | str = "config/peers.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        groups = self.config.get("peer_groups", {}) or {}
        self.min_peers = int(groups.get("min_peers", 3))
        self.min_support = int(groups.get("min_support", 5))
        self.hierarchy = self._levels(groups.get("hierarchy"))

    def _load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        return load_yaml(self.config_path) or {}

    def _levels(self, raw: Any) -> list[dict[str, Any]]:
        levels = []
        for item in raw or _DEFAULT_HIERARCHY:
            attrs = item.get("attributes") if isinstance(item, dict) else item
            attrs = [str(a) for a in (attrs or [])]
            unknown = [a for a in attrs if a != "all" and a not in ATTRIBUTES]
            if not attrs or unknown:
                raise ValueError(f"peers.yaml: unknown peer attribute(s) {unknown or attrs}")
            min_members = int(item.get("min_members", self.min_peers)) if isinstance(item, dict) else self.min_peers
            levels.append({"attributes": attrs, "min_members": min_members})
        if levels[-1]["attributes"] != ["all"]:
            levels.append({"attributes": ["all"], "min_members": 1})
        return levels

    @staticmethod
    def _label(target: Entity, attrs: list[str]) -> str:
        # The labels of the original four levels are kept, so earlier runs and reports read the same.
        if attrs == ["sector", "size_band"]:
            return f"{target.sector}_{target.size_band}"
        if attrs == ["sector"]:
            return f"{target.sector}_all_sizes"
        if attrs == ["size_band"]:
            return f"all_sectors_{target.size_band}"
        if attrs == ["all"]:
            return "all_entities_broad"
        return "_".join(attribute(target, a) for a in attrs)

    def resolve(
        self, target: Entity, all_entities: list[Entity], left_out: dict[str, str] | None = None
    ) -> PeerComparison:
        """The cohort for `target`. `left_out` maps entities that may not be peers at all
        (retired, invalid id) to the reason; they are recorded as excluded."""
        left_out = left_out or {}
        excluded = [{"entity_id": e, "reason": r} for e, r in sorted(left_out.items()) if e != target.entity_id]
        pool = [e for e in all_entities if e.entity_id != target.entity_id and e.entity_id not in left_out]
        if not pool:
            return PeerComparison(
                target.entity_id, [], "none", (), len(self.hierarchy) - 1, excluded, self.min_support, NONE,
                "No other entity to compare with.",
            )
        for level, spec in enumerate(self.hierarchy):
            attrs = spec["attributes"]
            members = (
                [e for e in pool if all(attribute(e, a) == attribute(target, a) for a in attrs)]
                if attrs != ["all"] else list(pool)
            )
            if len(members) < spec["min_members"] and attrs != ["all"]:
                continue
            member_ids = sorted(e.entity_id for e in members)
            chosen = set(member_ids)
            for e in sorted(pool, key=lambda x: x.entity_id):
                if e.entity_id not in chosen:
                    differs = next(a for a in attrs if attribute(e, a) != attribute(target, a))
                    excluded.append({"entity_id": e.entity_id, "reason": f"different {differs}"})
            broad = attrs == ["all"]
            strength = ESTABLISHED if len(member_ids) >= self.min_support and not broad else EXPLORATORY
            if strength == ESTABLISHED:
                reason = f"{len(member_ids)} peers share {', '.join(attrs)} (at least {self.min_support} needed)."
            elif broad:
                reason = (f"No cohort sharing {', '.join(self.hierarchy[0]['attributes'])} or a fallback had "
                          f"enough members; compared with every other entity ({len(member_ids)}). Exploratory only.")
            else:
                reason = (f"Only {len(member_ids)} peers share {', '.join(attrs)}; at least {self.min_support} are "
                          "needed for an established comparison. Exploratory only.")
            if level > 0:
                reason += f" Fallback level {level} of the cohort hierarchy."
            return PeerComparison(
                target.entity_id, member_ids, self._label(target, attrs), tuple(attrs), level, excluded,
                self.min_support, strength, reason,
            )
        raise AssertionError("the hierarchy always ends with 'all'")  # pragma: no cover

    def resolve_peers(self, target_entity: Entity, all_entities: list[Entity]) -> tuple[list[str], str, bool]:
        """(peer_ids, cohort_label, is_weak) -- the older interface, for callers that need no record."""
        comparison = self.resolve(target_entity, all_entities)
        if comparison.strength == NONE:
            return [], "none", True
        return comparison.member_ids, comparison.cohort_label, comparison.fallback_level > 0 or comparison.is_weak
