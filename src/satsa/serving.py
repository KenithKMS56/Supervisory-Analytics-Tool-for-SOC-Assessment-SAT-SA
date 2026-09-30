"""How the two portals are served: bind address, optional TLS, offline certificate generation.

Defaults are the closed ones: loopback only, and plain HTTP only there. Listening on another
address and serving TLS are both explicit choices made through the environment (or the CLI
flags that mirror it). Nothing here touches the network beyond opening the listening socket.
"""

import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

LOOPBACK_HOST = "127.0.0.1"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

ENV_HOST = "SATSA_HOST"
ENV_TLS_CERT = "SATSA_TLS_CERT"
ENV_TLS_KEY = "SATSA_TLS_KEY"
ENV_COOKIE_SECURE = "SATSA_COOKIE_SECURE"

CERT_FILENAME = "satsa-cert.pem"
KEY_FILENAME = "satsa-key.pem"
MIN_CERT_DAYS, MAX_CERT_DAYS = 1, 825


class ServingConfigError(ValueError):
    """The serving configuration is unusable; the portals must not start on a guess."""


@dataclass(frozen=True)
class ServingConfig:
    host: str
    certfile: str | None = None
    keyfile: str | None = None

    @property
    def tls(self) -> bool:
        return self.certfile is not None

    @property
    def scheme(self) -> str:
        return "https" if self.tls else "http"

    @property
    def external(self) -> bool:
        """True when the portals listen beyond this machine's loopback interface."""
        return self.host not in LOOPBACK_HOSTS

    def uvicorn_args(self, app: str, port: int) -> list[str]:
        """Arguments for `python -m uvicorn`."""
        args = [app, "--host", self.host, "--port", str(port), "--log-level", "info"]
        if self.certfile and self.keyfile:
            args += ["--ssl-certfile", self.certfile, "--ssl-keyfile", self.keyfile]
        return args

    def child_env(self, env: Mapping[str, str]) -> dict[str, str]:
        """Environment for the portal processes: over TLS, session cookies are marked Secure."""
        out = dict(env)
        if self.tls:
            out.setdefault(ENV_COOKIE_SECURE, "1")
        return out


def serving_config(
    env: Mapping[str, str] | None = None,
    host: str | None = None,
    certfile: str | None = None,
    keyfile: str | None = None,
) -> ServingConfig:
    """Resolve bind address and TLS files from explicit arguments, then the environment.

    The host defaults to loopback. TLS needs both the certificate and the key, and both must
    exist: half a TLS configuration is an error, never a silent fall back to plain HTTP.
    """
    env = os.environ if env is None else env
    resolved_host = (host or env.get(ENV_HOST) or LOOPBACK_HOST).strip()
    cert = (certfile or env.get(ENV_TLS_CERT) or "").strip()
    key = (keyfile or env.get(ENV_TLS_KEY) or "").strip()
    if bool(cert) != bool(key):
        raise ServingConfigError(
            f"TLS needs both a certificate and a key: set {ENV_TLS_CERT} and {ENV_TLS_KEY} together "
            "(or neither, for plain HTTP)."
        )
    for label, path in (("certificate", cert), ("key", key)):
        if path and not Path(path).is_file():
            raise ServingConfigError(f"TLS {label} file not found: {path}")
    return ServingConfig(host=resolved_host, certfile=cert or None, keyfile=key or None)


def exposure_warning(config: ServingConfig) -> str | None:
    """What to tell the operator when the portals are reachable from other machines."""
    if not config.external:
        return None
    if config.tls:
        return f"Listening on {config.host}: reachable from other machines (TLS on)."
    return (
        f"Listening on {config.host} over plain HTTP: passphrases and session cookies cross the "
        f"network unencrypted. Set {ENV_TLS_CERT} and {ENV_TLS_KEY} (see docs/deployment_ops.md)."
    )


def generate_self_signed_cert(
    out_dir: Path | str,
    hostnames: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    days: int = 365,
    force: bool = False,
) -> tuple[Path, Path]:
    """Create a self-signed certificate and private key with the local `openssl` binary.

    Fully offline: no certificate authority, no network. Returns (certificate, key). Existing
    files are kept unless `force` is set, so a working deployment is never re-keyed by accident.
    """
    hostnames = hostnames or ["localhost"]
    ip_addresses = ip_addresses if ip_addresses is not None else ["127.0.0.1"]
    if not MIN_CERT_DAYS <= days <= MAX_CERT_DAYS:
        raise ServingConfigError(f"Certificate validity must be {MIN_CERT_DAYS} to {MAX_CERT_DAYS} days.")
    openssl = shutil.which("openssl")
    if openssl is None:
        raise ServingConfigError(
            "The `openssl` command was not found. Install OpenSSL, or create the certificate on "
            "another machine and copy the two .pem files here."
        )
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cert, key = out / CERT_FILENAME, out / KEY_FILENAME
    if not force and (cert.exists() or key.exists()):
        raise ServingConfigError(f"{cert} or {key} already exists; pass force to replace them.")

    san = ",".join([f"DNS:{h}" for h in hostnames] + [f"IP:{ip}" for ip in ip_addresses])
    command = [
        openssl, "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
        "-days", str(days),
        "-subj", f"/CN={hostnames[0]}/O=SAT-SA self-signed",
        "-addext", f"subjectAltName={san}",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-keyout", str(key), "-out", str(cert),
    ]  # fmt: skip
    # MSYS (Git Bash) would rewrite "/CN=..." as a Windows path.
    env = {**os.environ, "MSYS_NO_PATHCONV": "1", "MSYS2_ARG_CONV_EXCL": "*"}
    result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
    if result.returncode != 0 or not cert.is_file() or not key.is_file():
        raise ServingConfigError(f"openssl failed: {result.stderr.strip() or result.stdout.strip()}")
    key.chmod(0o600)
    return cert, key
