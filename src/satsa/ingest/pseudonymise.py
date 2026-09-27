"""HMAC-SHA256 pseudonymisation for actors and asset identifiers."""

import hashlib
import hmac
import os
from pathlib import Path


class Pseudonymiser:
    """Deterministic HMAC-SHA256 pseudonymisation with a secure local salt."""

    def __init__(self, salt_file: Path | str = ".satsa_salt"):
        self.salt_path = Path(salt_file)
        self.salt = self._load_or_create_salt()

    def _load_or_create_salt(self) -> bytes:
        if self.salt_path.exists():
            return self.salt_path.read_bytes()
        # Generate random 32-byte salt
        salt = os.urandom(32)
        self.salt_path.parent.mkdir(parents=True, exist_ok=True)
        self.salt_path.write_bytes(salt)
        return salt

    def pseudonymise(self, value: str | None, prefix: str = "PSEUDO") -> str | None:
        """Pseudonymise a value deterministically using HMAC-SHA256."""
        if not value:
            return None
        h = hmac.new(self.salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
        return f"{prefix}_{h}"
