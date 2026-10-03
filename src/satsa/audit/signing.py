"""Signature algorithms for audit checkpoints, behind one small interface.

A checkpoint (satsa.audit.checkpoint) is signed by a `Signer` and checked by a `Verifier`; both
are obtained from the registry here by algorithm name, so another algorithm can be added
without touching the checkpoint format or the CLI:

* ``ed25519`` -- implemented, with the `cryptography` library (offline; no key server, no
  network).
* ``ml-dsa-44`` / ``ml-dsa-65`` / ``ml-dsa-87`` -- **reserved** names for a post-quantum signer
  (FIPS 204). Not implemented: asking for one raises `AlgorithmUnavailableError`. Adding it
  means one `SignatureBackend` subclass registered in `_BACKENDS`; the `cryptography` version
  this project pins (50.0.2) already provides ML-DSA keys
  (`cryptography.hazmat.primitives.asymmetric.mldsa`), so no new dependency is needed.
* Any other name raises `UnknownAlgorithmError`.
"""

from __future__ import annotations

from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DEFAULT_ALGORITHM = "ed25519"
RESERVED_ALGORITHMS = frozenset({"ml-dsa-44", "ml-dsa-65", "ml-dsa-87"})


class UnknownAlgorithmError(ValueError):
    """The named signature algorithm is not one SAT-SA knows."""


class AlgorithmUnavailableError(ValueError):
    """The algorithm name is reserved for a future signer that is not installed."""


class KeyFormatError(ValueError):
    """A key file is not a key of the expected algorithm."""


class Signer(Protocol):
    algorithm: str

    def sign(self, data: bytes) -> bytes: ...

    def public_key_bytes(self) -> bytes: ...


class Verifier(Protocol):
    algorithm: str

    def verify(self, signature: bytes, data: bytes) -> bool: ...

    def public_key_bytes(self) -> bytes: ...


class SignatureBackend:
    """Key generation and loading for one algorithm."""

    algorithm: str = ""

    def generate(self) -> tuple[bytes, bytes]:
        """Return (private key PEM, public key PEM)."""
        raise NotImplementedError

    def load_signer(self, private_pem: bytes) -> Signer:
        raise NotImplementedError

    def load_verifier(self, public_pem: bytes) -> Verifier:
        raise NotImplementedError


class _Ed25519Signer:
    algorithm = "ed25519"

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


class _Ed25519Verifier:
    algorithm = "ed25519"

    def __init__(self, key: Ed25519PublicKey) -> None:
        self._key = key

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self._key.verify(signature, data)
        except InvalidSignature:
            return False
        return True

    def public_key_bytes(self) -> bytes:
        return self._key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Ed25519Backend(SignatureBackend):
    algorithm = "ed25519"

    def generate(self) -> tuple[bytes, bytes]:
        key = Ed25519PrivateKey.generate()
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    def load_signer(self, private_pem: bytes) -> Signer:
        try:
            key = serialization.load_pem_private_key(private_pem, password=None)
        except (ValueError, TypeError) as exc:
            raise KeyFormatError(f"not a readable unencrypted PEM private key: {exc}") from None
        if not isinstance(key, Ed25519PrivateKey):
            raise KeyFormatError("the private key is not an Ed25519 key")
        return _Ed25519Signer(key)

    def load_verifier(self, public_pem: bytes) -> Verifier:
        try:
            key = serialization.load_pem_public_key(public_pem)
        except (ValueError, TypeError) as exc:
            raise KeyFormatError(f"not a readable PEM public key: {exc}") from None
        if not isinstance(key, Ed25519PublicKey):
            raise KeyFormatError("the public key is not an Ed25519 key")
        return _Ed25519Verifier(key)


_BACKENDS: dict[str, type[SignatureBackend]] = {"ed25519": Ed25519Backend}


def available_algorithms() -> list[str]:
    return sorted(_BACKENDS)


def get_backend(algorithm: str) -> SignatureBackend:
    """The backend for `algorithm`; reserved and unknown names are refused, never guessed."""
    name = (algorithm or "").strip().lower()
    if name in _BACKENDS:
        return _BACKENDS[name]()
    if name in RESERVED_ALGORITHMS:
        raise AlgorithmUnavailableError(
            f"{name!r} is reserved for a post-quantum (ML-DSA) signer, which is not implemented "
            f"in this version. Available: {available_algorithms()}."
        )
    raise UnknownAlgorithmError(
        f"unknown signature algorithm {algorithm!r}; available: {available_algorithms()}"
    )
