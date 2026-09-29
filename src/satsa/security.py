"""Shared input-validation helpers for externally supplied identifiers and paths.

Every externally supplied ID that reaches a query or a filesystem path is
checked here, so the rules engine, ingestion pipeline, REST routes and admin
portal all apply the same definition of "valid" instead of ad-hoc checks.
Parameterized queries remain the primary defense against SQL injection; these
checks are defense in depth (a bad ID is rejected before it can reach a query
or be used to build a path, even if a parameterization fix is missed).
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

# Entity IDs: alphanumeric first char, then alphanumerics / '_' / '.' / '-', max 64.
# Excludes quotes, whitespace, '*', '/', '\\' and anything else that could alter
# a query or a path. '..' is additionally rejected by is_valid_entity_id().
ENTITY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

# Usernames: same rule the admin portal already enforces on user creation.
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{3,32}$")

# Assessment run IDs, e.g. RUN-20260929081306814098-612ed014 (scoring/runner.py).
RUN_ID_RE = re.compile(r"^RUN-[A-Za-z0-9_-]{1,64}$")

# Finding IDs, e.g. FND-EG01-<entity_id>-<run_id> (rules/*.py).
FINDING_ID_RE = re.compile(r"^FND-[A-Za-z0-9][A-Za-z0-9_.-]{0,190}$")


def is_valid_entity_id(value: object) -> bool:
    """Return True if `value` is a string matching ENTITY_ID_RE (and contains no '..')."""
    return isinstance(value, str) and bool(ENTITY_ID_RE.match(value)) and ".." not in value


def require_entity_id(value: object) -> str:
    """Return `value` unchanged if it is a valid entity ID, else raise ValueError."""
    if not is_valid_entity_id(value):
        raise ValueError(f"Invalid entity_id: {value!r}")
    return str(value)


def is_valid_run_id(value: object) -> bool:
    """Return True if `value` is a string matching RUN_ID_RE."""
    return isinstance(value, str) and bool(RUN_ID_RE.match(value))


def is_valid_finding_id(value: object) -> bool:
    """Return True if `value` is a string matching FINDING_ID_RE (and contains no '..')."""
    return isinstance(value, str) and bool(FINDING_ID_RE.match(value)) and ".." not in value


def is_valid_username(value: object) -> bool:
    """Return True if `value` is a string matching USERNAME_RE (and contains no '..')."""
    return isinstance(value, str) and bool(USERNAME_RE.match(value)) and ".." not in value


def safe_archive_member(name: str) -> PurePosixPath:
    """Validate an archive entry name and return it as a relative POSIX path.

    Rejects absolute paths, drive letters, backslashes, empty names and any
    '..' component, i.e. anything that could escape the extraction directory.
    """
    if not name or "\\" in name or "\x00" in name:
        raise ValueError(f"Unsafe archive member name: {name!r}")
    p = PurePosixPath(name)
    if p.is_absolute() or (p.parts and ":" in p.parts[0]):
        raise ValueError(f"Unsafe archive member name: {name!r}")
    if any(part == ".." for part in p.parts):
        raise ValueError(f"Unsafe archive member name: {name!r}")
    return p


def safe_join(base: Path | str, rel: str | PurePosixPath) -> Path:
    """Join `rel` onto `base` and guarantee the result stays inside `base`."""
    base_resolved = Path(base).resolve()
    target = (base_resolved / str(rel)).resolve()
    if target != base_resolved and base_resolved not in target.parents:
        raise ValueError(f"Path {rel!s} escapes base directory {base_resolved}")
    return target
