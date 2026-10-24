"""Rule-configuration lifecycle: draft -> approved -> active -> retired (docs/rule_governance.md).

`config/rules.yaml` holds the thresholds every assessment uses. A change to it is a *version*:

- **draft**: proposed on the Tuning page (or `propose`), with what changed and the version it was
  based on. A draft changes nothing; its effect can be previewed (a dry-run assessment).
- **approved**: accepted by an analyst or examiner who is not its author (enforced here and by a
  database CHECK). The author can never approve their own change.
- **active**: written to `config/rules.yaml` (atomically) by an analyst. Only a draft based on the
  version in force can be activated, so two drafts cannot silently overwrite each other; the
  previous active version becomes **retired**. A re-assessment is queued by the caller.
- **rejected**: declined by a reviewer, with a reason.

In a *demonstration* deployment a saved change is activated at once, without a second person,
and recorded as such ("activated without a second approval"). A signed rule pack imported from
the issuing authority is recorded as active with its verified signature as the approval.

Every run still stores its complete configuration (run_config_snapshots), so a version's effect
on past runs is always reproducible by `satsa replay`.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from satsa.admin.rbac import is_analyst, is_examiner
from satsa.cases.workflow import CaseForbidden, CaseInvalid, CaseNotFound, InvalidTransition
from satsa.store.sqlite import SQLiteStore, utc_now_iso

RULES_PATH = Path("config/rules.yaml")
DEMO_ACTIVATION_NOTE = "demonstration deployment: activated without a second approval"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _row(store: SQLiteStore, version_no: int) -> dict[str, Any]:
    row = store.conn.execute("SELECT * FROM rule_pack_versions WHERE version_no = ?", (version_no,)).fetchone()
    if row is None:
        raise CaseNotFound(f"No rule configuration version {version_no}")
    return dict(row, changes=json.loads(row["changes_json"]))


def versions(store: SQLiteStore, limit: int = 50) -> list[dict[str, Any]]:
    return [dict(r, changes=json.loads(r["changes_json"])) for r in store.conn.execute(
        "SELECT * FROM rule_pack_versions ORDER BY version_no DESC LIMIT ?", (limit,))]


def _active_row(store: SQLiteStore) -> dict[str, Any] | None:
    row = store.conn.execute("SELECT * FROM rule_pack_versions WHERE state = 'active'").fetchone()
    return dict(row, changes=json.loads(row["changes_json"])) if row is not None else None


def _on_disk(rules_path: Path) -> str:
    return rules_path.read_text(encoding="utf-8") if rules_path.exists() else ""


def active(store: SQLiteStore, rules_path: Path = RULES_PATH) -> dict[str, Any]:
    """The version in force, as it is on disk.

    The first time, the configuration on disk is adopted as version 1. If `config/rules.yaml` was
    changed outside the lifecycle (by hand, or by a restore), what is on disk is what assessments
    use, so it is recorded as a new active version ("external_edit") and the change is audited;
    the Tuning page says that it happened (`drift`)."""
    current = _active_row(store)
    text = _on_disk(rules_path)
    if current is not None and current["sha256"] == _sha(text):
        return current
    with store.audited_transaction():
        current = _active_row(store)
        if current is None or current["sha256"] != _sha(text):
            n = _next_no(store)
            now = utc_now_iso()
            source, note = (("adopted", "the configuration in force when versioning began") if current is None else
                            ("external_edit", (f"config/rules.yaml was changed outside the lifecycle; recorded as found "
                                              f"(was version {current['version_no']})")))
            store.conn.execute("UPDATE rule_pack_versions SET state = 'retired', retired_at = ? WHERE state = 'active'",
                               (now,))
            store.conn.execute(
                "INSERT INTO rule_pack_versions (version_no, state, rules_yaml, sha256, base_version_no, source, "
                "created_by, created_at, activated_by, activated_at, note) "
                "VALUES (?, 'active', ?, ?, ?, ?, 'system', ?, 'system', ?, ?)",
                (n, text, _sha(text), current["version_no"] if current else None, source, now, now, note),
            )
            store.append_audit("rule_version_adopted" if current is None else "rule_version_external_edit", "system",
                               {"version_no": n, "sha256": _sha(text)})
    row = _active_row(store)
    assert row is not None
    return row


def drift(store: SQLiteStore, rules_path: Path = RULES_PATH) -> str | None:
    """A warning when config/rules.yaml no longer matches the active version (read before
    `active` records the edit)."""
    current = _active_row(store)
    if current is None:
        return None
    on_disk = _on_disk(rules_path)
    if _sha(on_disk) != current["sha256"]:
        return (f"config/rules.yaml was changed outside the rule-change lifecycle (it no longer matches version "
                f"{current['version_no']}); it has been recorded as a new version marked \"external edit\".")
    return None


def _next_no(store: SQLiteStore) -> int:
    return int(store.conn.execute("SELECT coalesce(max(version_no), 0) + 1 FROM rule_pack_versions").fetchone()[0])


def propose(store: SQLiteStore, rules_yaml: str, changes: list[dict[str, Any]], author: str, role: str,
            source: str = "tuning", note: str = "", rules_path: Path = RULES_PATH) -> dict[str, Any]:
    """A draft based on the version in force. Nothing on disk changes."""
    if not is_analyst(role):
        raise CaseForbidden("Rule changes are proposed by an analyst.")
    base = active(store, rules_path)
    if _sha(rules_yaml) == base["sha256"]:
        raise CaseInvalid("The proposed configuration is the one already in force.")
    with store.audited_transaction():
        n = _next_no(store)
        store.conn.execute(
            "INSERT INTO rule_pack_versions (version_no, state, rules_yaml, sha256, base_version_no, changes_json, "
            "source, created_by, created_at, note) VALUES (?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?)",
            (n, rules_yaml, _sha(rules_yaml), base["version_no"], json.dumps(changes), source, author, utc_now_iso(),
             note.strip()[:2000] or None),
        )
        store.append_audit("rule_version_proposed", author,
                           {"version_no": n, "base_version_no": base["version_no"], "changes": changes})
    return _row(store, n)


def approve(store: SQLiteStore, version_no: int, actor: str, role: str, note: str = "") -> dict[str, Any]:
    if not (is_analyst(role) or is_examiner(role)):
        raise CaseForbidden("A rule change is approved by an analyst or an examiner.")
    with store.audited_transaction():
        v = _row(store, version_no)
        if v["state"] != "draft":
            raise InvalidTransition(f"Version {version_no} is {v['state']}; only a draft is approved.")
        if v["created_by"] == actor:
            raise CaseForbidden("The author of a rule change cannot approve it; another person must.")
        store.conn.execute(
            "UPDATE rule_pack_versions SET state = 'approved', approved_by = ?, approved_at = ?, approval_note = ? "
            "WHERE version_no = ? AND state = 'draft'", (actor, utc_now_iso(), note.strip()[:2000] or None, version_no))
        store.append_audit("rule_version_approved", actor, {"version_no": version_no})
    return _row(store, version_no)


def reject(store: SQLiteStore, version_no: int, actor: str, role: str, reason: str) -> dict[str, Any]:
    if not (is_analyst(role) or is_examiner(role)):
        raise CaseForbidden("A rule change is rejected by an analyst or an examiner.")
    reason = (reason or "").strip()
    if not reason:
        raise CaseInvalid("Say why the change is rejected.")
    with store.audited_transaction():
        v = _row(store, version_no)
        if v["state"] not in ("draft", "approved"):
            raise InvalidTransition(f"Version {version_no} is {v['state']}; it cannot be rejected.")
        store.conn.execute(
            "UPDATE rule_pack_versions SET state = 'rejected', rejected_by = ?, rejected_at = ?, note = ? "
            "WHERE version_no = ?", (actor, utc_now_iso(), reason[:2000], version_no))
        store.append_audit("rule_version_rejected", actor, {"version_no": version_no, "reason": reason[:500]})
    return _row(store, version_no)


def _write_atomically(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".rules-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def activate(store: SQLiteStore, version_no: int, actor: str, role: str, rules_path: Path = RULES_PATH,
             *, demo: bool = False) -> dict[str, Any]:
    """Put an approved version in force: write config/rules.yaml, retire the previous one.

    `demo=True` (demonstration deployments only) activates a draft without a second approval
    and records that it did."""
    if not is_analyst(role):
        raise CaseForbidden("A rule change is put in force by an analyst.")
    current = active(store, rules_path)
    with store.audited_transaction():
        v = _row(store, version_no)
        allowed = ("approved", "draft") if demo else ("approved",)
        if v["state"] not in allowed:
            raise InvalidTransition(
                f"Version {version_no} is {v['state']}; only an approved version is put in force.")
        if v["base_version_no"] != current["version_no"]:
            raise InvalidTransition(
                f"Version {version_no} was based on version {v['base_version_no']}, but version "
                f"{current['version_no']} is now in force: propose it again from the current configuration.")
        _write_atomically(rules_path, v["rules_yaml"])
        now = utc_now_iso()
        store.conn.execute("UPDATE rule_pack_versions SET state = 'retired', retired_at = ? WHERE state = 'active'",
                           (now,))
        note = DEMO_ACTIVATION_NOTE if demo and v["state"] == "draft" else v["note"]
        store.conn.execute(
            "UPDATE rule_pack_versions SET state = 'active', activated_by = ?, activated_at = ?, note = ? "
            "WHERE version_no = ?", (actor, now, note, version_no))
        store.append_audit("rule_version_activated", actor, {
            "version_no": version_no, "retired": current["version_no"], "sha256": v["sha256"],
            "without_second_approval": bool(demo and v["state"] == "draft"),
        })
    return _row(store, version_no)


def record_signed_pack(store: SQLiteStore, rules_path: Path, actor: str, pack_version: str | None,
                       signature: str) -> dict[str, Any] | None:
    """After a verified signed rule pack was installed: record its rules as the active version,
    approved by the signature. None if the pack left the rules unchanged."""
    current = _active_row(store)
    text = _on_disk(rules_path)
    if current is not None and current["sha256"] == _sha(text):
        return None
    with store.audited_transaction():
        n = _next_no(store)
        now = utc_now_iso()
        store.conn.execute("UPDATE rule_pack_versions SET state = 'retired', retired_at = ? WHERE state = 'active'",
                           (now,))
        store.conn.execute(
            "INSERT INTO rule_pack_versions (version_no, state, rules_yaml, sha256, base_version_no, source, "
            "created_by, created_at, approved_by, approved_at, activated_by, activated_at, note) "
            "VALUES (?, 'active', ?, ?, ?, 'signed_pack', ?, ?, ?, ?, ?, ?, ?)",
            (n, text, _sha(text), current["version_no"] if current else None, actor, now,
             f"signature:{signature[:12]}", now, actor, now, f"signed rule pack {pack_version or ''}".strip()),
        )
        store.append_audit("rule_version_activated", actor, {"version_no": n, "source": "signed_pack",
                                                            "pack_version": pack_version})
    return _row(store, n)
