"""Deployment identity, mode and first-run setup (docs/first_run_setup.md).

A deployment is either **production** or **demo**, decided once, when its database is created:
demo only if `SATSA_DEMO=1` was set at that moment. The mode lives in the database
(`deployment_settings`, migration v4), so it cannot flip because an environment variable changed
later.

- **Production** starts empty: no accounts with published passphrases and no demonstration data.
  The first administrator is created by first-run setup, which needs a one-time token. The token
  is written to `data/secrets/setup_token` (readable only by whoever can read the data volume) and
  printed on the platform console. Setup also records the deployment's name, time zone and
  retention, and then deletes the token.
- **Demo** seeds the published demonstration accounts, loads synthetic data through a job and
  shows a banner on every page. A demo process refuses to start against a production database
  (`DemoIsolationError`), so demonstration data cannot mix with real evidence.

Databases created before modes existed are recorded as production, with `mode_origin` saying
so. Their accounts already exist, so no setup is pending.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import re
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from satsa.keys import secrets_dir, write_private

if TYPE_CHECKING:
    from satsa.store.sqlite import SQLiteStore

DEMO, PRODUCTION = "demo", "production"
SETUP_TOKEN_FILE = "setup_token"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
SETUP_ADMIN_ROLE = "NCIIPC Super Administrator"
DEFAULT_RETENTION_DAYS = {"job_inputs_days": 30, "backups_keep": 7}


class SetupError(ValueError):
    """First-run setup refused; the message says why and is safe to show."""


class DemoIsolationError(RuntimeError):
    """A demo process was pointed at a production deployment's data."""


def env_wants_demo() -> bool:
    return os.environ.get("SATSA_DEMO", "").strip().lower() in ("1", "true", "yes")


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def settings(store: SQLiteStore) -> dict[str, str]:
    rows = store.conn.execute("SELECT key, value FROM deployment_settings").fetchall()
    return {r["key"]: r["value"] for r in rows}


def set_settings(store: SQLiteStore, values: dict[str, Any], actor: str) -> None:
    now = _now()
    with store.transaction():
        store.conn.executemany(
            "INSERT INTO deployment_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, "
            "updated_by = excluded.updated_by",
            [(k, str(v), now, actor) for k, v in values.items()],
        )


def mode(store: SQLiteStore) -> str:
    row = store.conn.execute("SELECT value FROM deployment_settings WHERE key = 'mode'").fetchone()
    return row["value"] if row else PRODUCTION


def is_demo(store: SQLiteStore) -> bool:
    return mode(store) == DEMO


def settle_mode(store: SQLiteStore, fresh: bool) -> str:
    """Record the mode the first time the database is opened by a release that knows modes."""
    current = settings(store)
    if "mode" in current:
        return current["mode"]
    if fresh:
        chosen = DEMO if env_wants_demo() else PRODUCTION
        set_settings(store, {"mode": chosen, "mode_origin": f"chosen when the database was created ({_now()})",
                             "created_at": _now()}, actor="system")
    else:
        chosen = PRODUCTION
        set_settings(store, {"mode": chosen, "mode_origin": "deployment existed before deployment modes; "
                             "recorded as production", "setup_completed_at": "before deployment modes"},
                     actor="system")
    return chosen


def check_demo_isolation(store: SQLiteStore) -> None:
    """A process started in demo mode must not run against a production database."""
    if env_wants_demo() and mode(store) == PRODUCTION:
        raise DemoIsolationError(
            "SATSA_DEMO is set, but this data directory belongs to a production deployment. Demo mode "
            "only runs on its own data directory (e.g. SATSA_DATA_DIR=./demo-data with Compose); "
            "it never adds demonstration data or published passphrases to production."
        )


def _admin_exists(store: SQLiteStore) -> bool:
    from satsa.admin.rbac import ADMIN_PORTAL_ROLES

    marks = ",".join("?" for _ in ADMIN_PORTAL_ROLES)
    row = store.conn.execute(
        f"SELECT 1 FROM identities WHERE role IN ({marks}) AND COALESCE(is_blocked, 0) = 0 "
        "AND COALESCE(status, 'ACTIVE') != 'BLOCKED' LIMIT 1",
        tuple(ADMIN_PORTAL_ROLES),
    ).fetchone()
    return row is not None


def setup_pending(store: SQLiteStore) -> bool:
    """Production, never set up, and no usable administrator account."""
    return mode(store) == PRODUCTION and "setup_completed_at" not in settings(store) and not _admin_exists(store)


def _token_path(data_dir: Path | str) -> Path:
    return secrets_dir(data_dir) / SETUP_TOKEN_FILE


def issue_setup_token(store: SQLiteStore, data_dir: Path | str) -> tuple[str, Path] | None:
    """The one-time setup token (created if needed) and its file, or None if no setup is pending."""
    if not setup_pending(store):
        return None
    path = _token_path(data_dir)
    known = settings(store).get("setup_token_sha256")
    if path.exists() and known:
        token = path.read_text(encoding="utf-8").strip()
        if hashlib.sha256(token.encode()).hexdigest() == known:
            return token, path
    token = secrets.token_urlsafe(24)
    write_private(path, token.encode("utf-8"))
    set_settings(store, {"setup_token_sha256": hashlib.sha256(token.encode()).hexdigest()}, actor="system")
    return token, path


def complete_setup(
    store: SQLiteStore,
    data_dir: Path | str,
    *,
    token: str | None,
    admin_username: str,
    passphrase: str,
    confirm: str,
    deployment_name: str,
    timezone: str,
    job_inputs_days: int = DEFAULT_RETENTION_DAYS["job_inputs_days"],
    backups_keep: int = DEFAULT_RETENTION_DAYS["backups_keep"],
    actor: str = "setup",
    require_token: bool = True,
) -> None:
    """Create the first administrator and record the deployment settings; consume the token.

    `require_token=False` is for `satsa setup`, run by someone with shell access to the data
    directory (who could read the token anyway)."""
    from satsa.auth.identities import SEEDED_DEFAULT_PASSPHRASES, passphrase_policy_error

    if not setup_pending(store):
        raise SetupError("This deployment is already set up.")
    known = settings(store).get("setup_token_sha256")
    if require_token and (
        not token or not known
        or not secrets.compare_digest(hashlib.sha256(token.strip().encode()).hexdigest(), known)
    ):
        raise SetupError("The setup token is not valid. It is in data/secrets/setup_token on the server.")
    username = admin_username.strip()
    if not USERNAME_RE.match(username):
        raise SetupError("The administrator name must be 3-64 letters, digits, '.', '_' or '-'.")
    if username in SEEDED_DEFAULT_PASSPHRASES:
        raise SetupError("Choose an administrator name other than the demonstration accounts' names.")
    problem = passphrase_policy_error(passphrase, confirm, current="")
    if problem:
        raise SetupError(problem)
    name = deployment_name.strip()
    if not 2 <= len(name) <= 120:
        raise SetupError("Give the deployment a name of 2-120 characters.")
    try:
        ZoneInfo(timezone.strip())
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise SetupError(f"Unknown time zone {timezone!r}; use an IANA name such as Asia/Kolkata.") from exc
    if not 1 <= int(job_inputs_days) <= 3650 or not 1 <= int(backups_keep) <= 1000:
        raise SetupError("Retention must be 1-3650 days for job inputs and keep 1-1000 backups.")

    store.seed_default_organisations_and_cses()
    store.create_user(username, SETUP_ADMIN_ROLE, passphrase, org_id="ORG-NCIIPC", is_admin_user=1)
    set_settings(store, {
        "deployment_name": name,
        "timezone": timezone.strip(),
        "retention_job_inputs_days": int(job_inputs_days),
        "retention_backups_keep": int(backups_keep),
        "setup_completed_at": _now(),
        "setup_completed_by": username,
    }, actor=actor)
    with store.transaction():
        store.conn.execute("DELETE FROM deployment_settings WHERE key = 'setup_token_sha256'")
    _token_path(data_dir).unlink(missing_ok=True)
    store.append_audit(action="first_run_setup_completed", actor=actor,
                       details={"administrator": username, "deployment_name": name, "timezone": timezone.strip()})


def prepare_deployment(data_dir: Path | str = "data") -> list[str]:
    """What the platform does at start, before the portals and the worker launch.

    Returns console lines. Raises DemoIsolationError if a demo process meets production data."""
    from satsa.jobs.queue import JobQueue
    from satsa.store.sqlite import SQLiteStore

    lines: list[str] = []
    store = SQLiteStore(Path(data_dir) / "satsa.db")
    try:
        check_demo_isolation(store)
        current = mode(store)
        store.seed_default_organisations_and_cses()
        if current == DEMO:
            store.seed_default_admin()
            for username in store.flag_unrotated_default_accounts():
                lines.append(f"[!] Account '{username}' still uses its published default passphrase: "
                             "a new one must be set at first login.")
            lines.append("[+] DEMONSTRATION deployment: synthetic data and published passphrases.")
            has_findings = store.conn.execute("SELECT 1 FROM findings LIMIT 1").fetchone() is not None
            pending = store.conn.execute(
                "SELECT 1 FROM jobs WHERE kind = 'demo_seed' AND state IN ('queued', 'running')"
            ).fetchone()
            if not has_findings and pending is None:
                job = JobQueue(store).enqueue("demo_seed", {"role": "system"}, "system", max_attempts=1)
                lines.append(f"[+] Demonstration data queued as job {job['job_id']} (the worker loads it).")
        else:
            issued = issue_setup_token(store, data_dir)
            if issued is not None:
                token, path = issued
                lines += [
                    "[+] PRODUCTION deployment, not set up yet. Open the Admin Portal (:8000) and use",
                    f"    this one-time setup token (also in {path}):",
                    f"    {token}",
                ]
            else:
                lines.append(f"[+] Production deployment: {settings(store).get('deployment_name', 'unnamed')}.")
        lines.append(f"[+] Shared identity and assessment database verified: {store.db_path}")
    finally:
        store.close()
    return lines
