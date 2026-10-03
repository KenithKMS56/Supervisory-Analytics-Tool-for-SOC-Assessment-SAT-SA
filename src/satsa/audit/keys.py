"""Key files for signed audit checkpoints: generation with owner-only permissions, and a refusal
to sign with a private key that other accounts can read.

POSIX: the private key is created with mode 0600 (`O_EXCL`, so an existing key is never
overwritten without `force`), and a key with any group or other permission bit is refused.

Windows: file mode bits do not describe access, so the key's ACL is used. `icacls` removes
inherited entries and grants Full Control to the current user only. The check reads the ACL
through PowerShell `Get-Acl` and translates every entry to its SID, so it does not depend on
the display language: a key is refused if an Allow entry grants read access to Everyone
(S-1-1-0), Anonymous (S-1-5-7), Authenticated Users (S-1-5-11), BUILTIN\\Users (S-1-5-32-545)
or BUILTIN\\Guests (S-1-5-32-546). Administrators and SYSTEM can read any file on the machine
regardless, which is one reason the private key belongs on removable media held by the
examiner, not on the supervisory host (DECISIONS.md ADR-008).
"""

from __future__ import annotations

import getpass
import os
import stat
import subprocess
from pathlib import Path

from satsa.audit.signing import DEFAULT_ALGORITHM, get_backend

PRIVATE_KEY_NAME = "satsa_audit_{alg}.key"
PUBLIC_KEY_NAME = "satsa_audit_{alg}.pub"

# Well-known SIDs whose read access makes a key readable by other accounts.
BROAD_READ_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
}
# FileSystemRights / generic bits that include reading the file's data.
_READ_BITS = 0x1 | 0x80000000 | 0x10000000  # ReadData, GENERIC_READ, GENERIC_ALL


class KeyPermissionError(PermissionError):
    """The private key can be read by accounts other than its owner."""


def _restrict_windows(path: Path) -> None:
    user = os.environ.get("USERNAME") or getpass.getuser()
    domain = os.environ.get("USERDOMAIN")
    principal = f"{domain}\\{user}" if domain else user
    subprocess.run(
        ["icacls", str(path), "/inheritance:r", "/grant:r", f"{principal}:(F)"],
        check=True, capture_output=True,
    )


def _windows_broad_readers(path: Path) -> list[str]:
    literal = str(path).replace("'", "''")
    script = (
        f"(Get-Acl -LiteralPath '{literal}').Access | ForEach-Object {{ "
        "$sid = try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } "
        "catch { $_.IdentityReference.Value }; "
        "'{0}|{1}|{2}' -f $sid, [int64]$_.FileSystemRights, $_.AccessControlType }"
    )
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=True, capture_output=True, text=True,
    ).stdout
    readers = []
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        sid, rights, kind = parts
        if kind.strip() == "Allow" and sid in BROAD_READ_SIDS and int(rights) & _READ_BITS:
            readers.append(BROAD_READ_SIDS[sid])
    return sorted(set(readers))


def other_readers(path: Path | str) -> list[str]:
    """Who besides the owner (and, on Windows, Administrators/SYSTEM) can read `path`."""
    p = Path(path)
    if os.name == "nt":
        return _windows_broad_readers(p)
    mode = stat.S_IMODE(p.stat().st_mode)
    who = []
    if mode & 0o070:
        who.append("group")
    if mode & 0o007:
        who.append("others")
    return who


def check_private_key_permissions(path: Path | str) -> None:
    """Raise KeyPermissionError if `path` is readable by other accounts."""
    readers = other_readers(path)
    if readers:
        fix = (
            f'icacls "{path}" /inheritance:r /grant:r "%USERNAME%:(F)"'
            if os.name == "nt"
            else f"chmod 600 {path}"
        )
        raise KeyPermissionError(
            f"Refusing to use private key {path}: readable by {', '.join(readers)}. "
            f"Restrict it to its owner first ({fix})."
        )


def write_private_key(path: Path, pem: bytes, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; pass force to replace it.")
    if os.name == "nt":
        path.write_bytes(pem)
        _restrict_windows(path)
    else:
        if path.exists():
            path.unlink()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        os.chmod(path, 0o600)  # some filesystems ignore the mode passed to os.open
    check_private_key_permissions(path)


def generate_keypair(
    out_dir: Path | str, algorithm: str = DEFAULT_ALGORITHM, force: bool = False
) -> tuple[Path, Path]:
    """Write a new key pair into `out_dir`; returns (private key path, public key path)."""
    backend = get_backend(algorithm)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    private_path = out / PRIVATE_KEY_NAME.format(alg=backend.algorithm)
    public_path = out / PUBLIC_KEY_NAME.format(alg=backend.algorithm)
    if not force and (private_path.exists() or public_path.exists()):
        raise FileExistsError(f"{private_path} or {public_path} already exists; pass force to replace them.")
    private_pem, public_pem = backend.generate()
    write_private_key(private_path, private_pem, force=force)
    public_path.write_bytes(public_pem)
    return private_path, public_path


def load_signer(private_key_path: Path | str, algorithm: str = DEFAULT_ALGORITHM):
    """Load a signer, refusing a private key that other accounts can read."""
    path = Path(private_key_path)
    check_private_key_permissions(path)
    return get_backend(algorithm).load_signer(path.read_bytes())


def load_verifier(public_key_path: Path | str, algorithm: str = DEFAULT_ALGORITHM):
    return get_backend(algorithm).load_verifier(Path(public_key_path).read_bytes())
