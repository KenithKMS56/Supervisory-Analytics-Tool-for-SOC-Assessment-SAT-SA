"""Entity context for the analytics: time zone, operating schedule, approved maintenance and
documented rule exceptions (docs/analytics_context.md).

What each piece changes, and nothing more:

- **Time zone.** Time-of-day rules (NS03, the anomaly scan's night share) read hours in the
  entity's own time zone, from its submitted `entity.timezone` (an IANA name such as
  `Asia/Kolkata`). Timestamps are stored in UTC; the conversion is per timestamp, so daylight
  saving and fractional offsets (+05:30, +05:45) are exact. A missing or unknown zone is read
  as UTC and the finding says so.
- **Operating schedule.** `entity.declared_shift_hours` ("09:00-18:00", "24x7") is classified
  as `24x7`, `business_hours` or `unknown`. It is a peer-cohort attribute (satsa.peers.grouping)
  and is stated in time-of-day findings; it never suppresses a finding by itself.
- **Maintenance windows.** Approved maintenance for all of an entity's assets, or one asset,
  over inclusive dates. A day inside an approved window is not counted as silence (NS01) for
  that scope; outside its scope or dates it changes nothing. Requested by one person, approved
  by a different examiner, revocable; every step is audited.
- **Rule exceptions.** A documented, time-limited exception for one entity and rule: reason,
  scope, evidence reference, a different examiner's approval and a mandatory expiry (at most
  `MAX_EXCEPTION_DAYS`). While in force, the rule still runs and its finding is still recorded
  and shown, marked with the exception; it is left out of the entity's score and the review
  queue. A critical finding is never covered. After expiry or revocation it counts again, so an
  exception cannot hide a future concern permanently.

The in-force sets are resolved *as of* a time: a replay of an old run uses what was in force
when the run was recorded, not what is in force today.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from satsa.admin.rbac import is_analyst, is_examiner
from satsa.store.sqlite import SQLiteStore, utc_now_iso

MAX_EXCEPTION_DAYS = 366
MAX_MAINTENANCE_DAYS = 92
MAX_TEXT = 2000
SCHEDULES = ("24x7", "business_hours", "unknown")
_SHIFT_RE = re.compile(r"^\s*(\d{1,2}):(\d{2})\s*-\s*(\d{1,2}):(\d{2})\s*$")
_ROUND_THE_CLOCK = {"24x7", "24/7", "24*7", "24x7x365", "always"}


class ContextError(ValueError):
    """A context change the rules refuse (missing reason, wrong approver, bad dates...)."""


def schedule_class(shift_hours: str | None) -> str:
    """`24x7`, `business_hours` or `unknown` for a declared shift such as "09:00-18:00"."""
    text = (shift_hours or "").strip().lower()
    if text in _ROUND_THE_CLOCK:
        return "24x7"
    m = _SHIFT_RE.match(text)
    if not m:
        return "unknown"
    h1, m1, h2, m2 = (int(g) for g in m.groups())
    if h1 > 24 or h2 > 24 or m1 > 59 or m2 > 59:
        return "unknown"
    start, end = h1 * 60 + m1, h2 * 60 + m2
    covered = (end - start) % (24 * 60)
    if covered == 0 or covered >= 24 * 60 - 1:  # 00:00-24:00, 00:00-00:00, 00:00-23:59
        return "24x7"
    return "business_hours"


@dataclass(frozen=True)
class MaintenanceWindow:
    window_id: str
    entity_id: str
    asset_id: str | None  # None: every asset of the entity
    starts_on: _dt.date
    ends_on: _dt.date  # inclusive
    reason: str
    approved_by: str

    def covers(self, asset_id: str | None, day: _dt.date) -> bool:
        return (self.asset_id is None or self.asset_id == asset_id) and self.starts_on <= day <= self.ends_on

    def as_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "asset_id": self.asset_id,
            "starts_on": self.starts_on.isoformat(),
            "ends_on": self.ends_on.isoformat(),
            "reason": self.reason,
            "approved_by": self.approved_by,
        }


@dataclass(frozen=True)
class EntityContext:
    entity_id: str
    timezone: str  # the zone actually used
    declared_timezone: str | None
    shift_hours: str | None
    schedule: str
    soc_model: str | None
    maintenance: tuple[MaintenanceWindow, ...] = field(default_factory=tuple)

    @property
    def timezone_assumed(self) -> bool:
        return self.declared_timezone != self.timezone

    def notes(self) -> list[str]:
        out = []
        if self.timezone_assumed:
            declared = f"'{self.declared_timezone}'" if self.declared_timezone else "no time zone"
            out.append(f"The entity declared {declared}, which is not a known IANA time zone; hours are read as UTC.")
        if self.schedule == "unknown":
            out.append(f"The declared operating hours ({self.shift_hours or 'none'}) could not be read.")
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "timezone": self.timezone,
            "declared_timezone": self.declared_timezone,
            "shift_hours": self.shift_hours,
            "schedule": self.schedule,
            "soc_model": self.soc_model,
            "maintenance_windows": [w.as_dict() for w in self.maintenance],
        }


def known_timezones(duck: Any) -> set[str]:
    """IANA zone names the analytics engine (DuckDB with ICU, bundled, offline) can convert to."""
    return {r[0] for r in duck.conn.execute("SELECT name FROM pg_timezone_names()").fetchall()}


def build_contexts(
    entities: Iterable[Any], duck: Any, maintenance: dict[str, list[MaintenanceWindow]] | None = None
) -> dict[str, EntityContext]:
    zones = known_timezones(duck)
    out = {}
    for e in entities:
        declared = (getattr(e, "timezone", None) or "").strip() or None
        shift = getattr(e, "declared_shift_hours", None)
        out[e.entity_id] = EntityContext(
            entity_id=e.entity_id,
            timezone=declared if declared in zones else "UTC",
            declared_timezone=declared,
            shift_hours=shift,
            schedule=schedule_class(shift),
            soc_model=getattr(e, "soc_model", None),
            maintenance=tuple((maintenance or {}).get(e.entity_id, [])),
        )
    return out


# SQL: hours in each entity's own zone. `tz` is a CTE over the entity table that falls back to UTC
# for a missing or unknown zone; join it on entity_id and pass its alias to `local_hour`.
ENTITY_TZ_CTE = (
    "_satsa_tz AS (SELECT e.entity_id, coalesce(z.name, 'UTC') AS tz FROM entity e "
    "LEFT JOIN (SELECT name FROM pg_timezone_names()) z ON z.name = e.timezone)"
)


def local_hour(column: str, tz_alias: str = "_satsa_tz") -> str:
    """Hour of day (0-23) of a UTC TIMESTAMP column in the entity's own time zone."""
    return f"extract(hour FROM timezone(coalesce({tz_alias}.tz, 'UTC'), {column} AT TIME ZONE 'UTC'))"


# --- persistence (audited) ---------------------------------------------------------------------


def _text(value: str | None, what: str) -> str:
    text = (value or "").strip()
    if not text:
        raise ContextError(f"{what} is required")
    if len(text) > MAX_TEXT:
        raise ContextError(f"{what} is longer than {MAX_TEXT} characters")
    return text


def parse_date(value: str | _dt.date, what: str) -> _dt.date:
    if isinstance(value, _dt.date):
        return value
    try:
        return _dt.date.fromisoformat(str(value).strip())
    except ValueError:
        raise ContextError(f"{what} must be a date (YYYY-MM-DD)") from None


def _new_id(prefix: str, *parts: str) -> str:
    seed = ":".join([*parts, utc_now_iso()])
    return f"{prefix}-" + hashlib.sha256(seed.encode()).hexdigest()[:12].upper()


def request_maintenance(
    store: SQLiteStore,
    entity_id: str,
    starts_on: str | _dt.date,
    ends_on: str | _dt.date,
    reason: str,
    evidence_ref: str,
    actor: str,
    role: str,
    asset_id: str | None = None,
) -> str:
    if not (is_analyst(role) or is_examiner(role)):
        raise ContextError("only supervisory staff record maintenance windows")
    start, end = parse_date(starts_on, "start date"), parse_date(ends_on, "end date")
    if end < start:
        raise ContextError("the end date is before the start date")
    if (end - start).days + 1 > MAX_MAINTENANCE_DAYS:
        raise ContextError(f"a maintenance window covers at most {MAX_MAINTENANCE_DAYS} days")
    reason, evidence_ref = _text(reason, "a reason"), _text(evidence_ref, "an evidence reference")
    asset = (asset_id or "").strip() or None
    window_id = _new_id("MW", entity_id, asset or "*", start.isoformat())
    with store.audited_transaction():
        store.conn.execute(
            "INSERT INTO maintenance_windows (window_id, entity_id, asset_id, starts_on, ends_on, reason, "
            "evidence_ref, requested_by, requested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (window_id, entity_id, asset, start.isoformat(), end.isoformat(), reason, evidence_ref, actor,
             utc_now_iso()),
        )
        store.append_audit(
            "maintenance_requested", actor,
            {"window_id": window_id, "entity_id": entity_id, "asset_id": asset, "starts_on": start.isoformat(),
             "ends_on": end.isoformat(), "reason": reason, "evidence_ref": evidence_ref},
        )
    return window_id


def _approve(store: SQLiteStore, table: str, key: str, item_id: str, actor: str, role: str, event: str) -> None:
    if not is_examiner(role):
        raise ContextError("only an examiner approves")
    with store.audited_transaction():
        row = store.conn.execute(f"SELECT * FROM {table} WHERE {key} = ?", (item_id,)).fetchone()
        if row is None:
            raise ContextError(f"no {item_id}")
        if row["approved_by"] is not None or row["revoked_at"] is not None:
            raise ContextError(f"{item_id} has already been approved or revoked")
        if row["requested_by"] == actor:
            raise ContextError("the approver must be someone other than the requester")
        if table == "rule_exceptions" and row["expires_at"] <= utc_now_iso():
            raise ContextError(f"{item_id} has already expired")
        store.conn.execute(
            f"UPDATE {table} SET approved_by = ?, approved_at = ? WHERE {key} = ?", (actor, utc_now_iso(), item_id)
        )
        store.append_audit(event, actor, {key: item_id, "entity_id": row["entity_id"]})


def _revoke(store: SQLiteStore, table: str, key: str, item_id: str, actor: str, role: str, reason: str,
            event: str) -> None:
    if not is_examiner(role):
        raise ContextError("only an examiner revokes")
    reason = _text(reason, "a reason")
    with store.audited_transaction():
        changed = store.conn.execute(
            f"UPDATE {table} SET revoked_by = ?, revoked_at = ?, revoke_reason = ? "
            f"WHERE {key} = ? AND revoked_at IS NULL",
            (actor, utc_now_iso(), reason, item_id),
        ).rowcount
        if not changed:
            raise ContextError(f"{item_id} does not exist or is already revoked")
        store.append_audit(event, actor, {key: item_id, "reason": reason})


def approve_maintenance(store: SQLiteStore, window_id: str, actor: str, role: str) -> None:
    _approve(store, "maintenance_windows", "window_id", window_id, actor, role, "maintenance_approved")


def revoke_maintenance(store: SQLiteStore, window_id: str, actor: str, role: str, reason: str) -> None:
    _revoke(store, "maintenance_windows", "window_id", window_id, actor, role, reason, "maintenance_revoked")


def maintenance_in_force(store: SQLiteStore, at: str | None = None) -> dict[str, list[MaintenanceWindow]]:
    """Approved windows not revoked as of `at` (default now), by entity."""
    when = at or utc_now_iso()
    out: dict[str, list[MaintenanceWindow]] = {}
    for r in store.conn.execute(
        "SELECT * FROM maintenance_windows WHERE approved_at IS NOT NULL AND approved_at <= ? "
        "AND (revoked_at IS NULL OR revoked_at > ?) ORDER BY entity_id, starts_on, window_id",
        (when, when),
    ):
        out.setdefault(r["entity_id"], []).append(
            MaintenanceWindow(
                window_id=r["window_id"], entity_id=r["entity_id"], asset_id=r["asset_id"],
                starts_on=_dt.date.fromisoformat(r["starts_on"]), ends_on=_dt.date.fromisoformat(r["ends_on"]),
                reason=r["reason"], approved_by=r["approved_by"],
            )
        )
    return out


def request_exception(
    store: SQLiteStore,
    entity_id: str,
    rule_id: str,
    scope: str,
    reason: str,
    evidence_ref: str,
    expires_on: str | _dt.date,
    actor: str,
    role: str,
) -> str:
    if not is_examiner(role):
        raise ContextError("only an examiner requests a rule exception")
    scope, reason = _text(scope, "a scope"), _text(reason, "a reason")
    evidence_ref = _text(evidence_ref, "an evidence reference")
    expires = parse_date(expires_on, "expiry date")
    today = _dt.datetime.now(_dt.UTC).date()
    if expires <= today:
        raise ContextError("the expiry date must be in the future")
    if (expires - today).days > MAX_EXCEPTION_DAYS:
        raise ContextError(f"an exception expires within {MAX_EXCEPTION_DAYS} days; renew it to extend it")
    exception_id = _new_id("EXC", entity_id, rule_id)
    expires_at = f"{expires.isoformat()}T00:00:00.000000+00:00"
    with store.audited_transaction():
        store.conn.execute(
            "INSERT INTO rule_exceptions (exception_id, entity_id, rule_id, scope, reason, evidence_ref, "
            "requested_by, requested_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (exception_id, entity_id, rule_id, scope, reason, evidence_ref, actor, utc_now_iso(), expires_at),
        )
        store.append_audit(
            "rule_exception_requested", actor,
            {"exception_id": exception_id, "entity_id": entity_id, "rule_id": rule_id, "scope": scope,
             "reason": reason, "evidence_ref": evidence_ref, "expires_at": expires_at},
        )
    return exception_id


def approve_exception(store: SQLiteStore, exception_id: str, actor: str, role: str) -> None:
    _approve(store, "rule_exceptions", "exception_id", exception_id, actor, role, "rule_exception_approved")


def revoke_exception(store: SQLiteStore, exception_id: str, actor: str, role: str, reason: str) -> None:
    _revoke(store, "rule_exceptions", "exception_id", exception_id, actor, role, reason, "rule_exception_revoked")


def exceptions_in_force(store: SQLiteStore, at: str | None = None) -> dict[tuple[str, str], dict[str, Any]]:
    """(entity_id, rule_id) -> approved exception neither revoked nor expired as of `at`."""
    when = at or utc_now_iso()
    return {
        (r["entity_id"], r["rule_id"]): dict(r)
        for r in store.conn.execute(
            "SELECT * FROM rule_exceptions WHERE approved_at IS NOT NULL AND approved_at <= ? "
            "AND (revoked_at IS NULL OR revoked_at > ?) AND expires_at > ? ORDER BY approved_at, exception_id",
            (when, when, when),
        )
    }


def entity_context_records(store: SQLiteStore, entity_id: str) -> dict[str, list[dict[str, Any]]]:
    """Every maintenance window, rule exception and applicability decision recorded for the
    entity, newest first, with its status now."""
    now = utc_now_iso()

    def status(r: Any, expires: str | None = None, needs_approval: bool = True) -> str:
        if r["revoked_at"] is not None:
            return "revoked"
        if expires is not None and expires <= now:
            return "expired"
        if needs_approval and r["approved_at"] is None:
            return "awaiting approval"
        return "in force"

    windows = [
        {**dict(r), "status": status(r)}
        for r in store.conn.execute(
            "SELECT * FROM maintenance_windows WHERE entity_id = ? ORDER BY requested_at DESC", (entity_id,)
        )
    ]
    exceptions = [
        {**dict(r), "status": status(r, r["expires_at"])}
        for r in store.conn.execute(
            "SELECT * FROM rule_exceptions WHERE entity_id = ? ORDER BY requested_at DESC", (entity_id,)
        )
    ]
    decisions = [
        {**dict(r), "status": status(r, r["expires_at"], needs_approval=False)}
        for r in store.conn.execute(
            "SELECT * FROM applicability_decisions WHERE entity_id = ? ORDER BY decided_at DESC", (entity_id,)
        )
    ]
    return {"maintenance": windows, "exceptions": exceptions, "applicability": decisions}
