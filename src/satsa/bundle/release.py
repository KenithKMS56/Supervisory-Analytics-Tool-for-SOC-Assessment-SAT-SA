"""Release metadata for the offline bundle: SBOM, licence notices, checksums and signature
(docs/offline_install.md, "Verifying a bundle").

- `sbom.cdx.json`: a CycloneDX 1.5 SBOM of the **runtime** dependency closure locked in
  `uv.lock` (development tools such as pytest and Playwright are excluded). It gives each
  package's version, purl and the SHA-256 hashes the lock pins.
- `THIRD_PARTY_LICENSES.txt`: the licence declared by each runtime package and the licence files
  it ships, read from the installed distributions. A package whose metadata is not installed
  here is listed as such, never guessed. Vendored browser assets are listed too.
- `SHA256SUMS`: the hash of every file in the bundle.
- `SHA256SUMS.sig`: optionally, an Ed25519 signature over `SHA256SUMS` with the release key.

Verification (`satsa release verify`) needs the release **public key obtained separately**, for
example from the release notes or a fingerprint read out by phone. A key shipped inside the
bundle would prove nothing. Verification checks the signature, every file's hash, and that no
file was added.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import tomllib
import uuid
from importlib import metadata
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SUMS_FILE = "SHA256SUMS"
SIG_FILE = "SHA256SUMS.sig"
VENDORED_ASSETS = (
    ("swagger-ui-dist", "5.17.14", "Apache-2.0", "src/satsa/ui/static/vendor/swagger-ui/LICENSE"),
    ("Apache ECharts", "(vendored echarts.min.js)", "Apache-2.0", None),
)


class ReleaseVerificationError(RuntimeError):
    """The bundle does not match its manifest or signature."""


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def runtime_packages(lock_path: Path | str, root_name: str = "satsa") -> list[dict[str, Any]]:
    """The packages `root_name` needs at run time, from uv.lock (all platform markers included)."""
    lock = tomllib.loads(Path(lock_path).read_text(encoding="utf-8"))
    by_name = {_normalise(p["name"]): p for p in lock["package"]}
    root = by_name[_normalise(root_name)]
    seen: dict[str, dict[str, Any]] = {}
    pending = [_normalise(d["name"]) for d in root.get("dependencies", [])]
    while pending:
        name = pending.pop()
        if name in seen or name not in by_name:
            continue
        seen[name] = by_name[name]
        pending.extend(_normalise(d["name"]) for d in by_name[name].get("dependencies", []))
    return [seen[n] for n in sorted(seen)]


def _hashes(package: dict[str, Any]) -> list[str]:
    found = [w["hash"] for w in package.get("wheels", []) if "hash" in w]
    if "sdist" in package and "hash" in package["sdist"]:
        found.append(package["sdist"]["hash"])
    return sorted({h.split(":", 1)[1] for h in found if h.startswith("sha256:")})


def _declared_licence(name: str) -> str | None:
    try:
        meta: Any = metadata.metadata(name)  # an email.message.Message underneath
    except metadata.PackageNotFoundError:
        return None
    expression = meta.get("License-Expression")
    if expression:
        return str(expression)
    classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    licence = meta.get("License")
    if licence and len(licence) < 100:
        return str(licence)
    return "; ".join(classifiers) or (licence[:100] + "..." if licence else None)


def sbom(lock_path: Path | str, version: str) -> dict[str, Any]:
    packages = runtime_packages(lock_path)
    components = []
    for p in packages:
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{_normalise(p['name'])}@{p['version']}",
            "name": p["name"],
            "version": p["version"],
            "purl": f"pkg:pypi/{_normalise(p['name'])}@{p['version']}",
            "hashes": [{"alg": "SHA-256", "content": h} for h in _hashes(p)],
        }
        licence = _declared_licence(p["name"])
        if licence:
            component["licenses"] = [{"license": {"name": licence}}]
        components.append(component)
    deps = [{"ref": f"pkg:pypi/{_normalise(p['name'])}@{p['version']}",
             "dependsOn": [f"pkg:pypi/{_normalise(d['name'])}@{next(q['version'] for q in packages if _normalise(q['name']) == _normalise(d['name']))}"
                           for d in p.get("dependencies", []) if any(_normalise(q["name"]) == _normalise(d["name"]) for q in packages)]}
            for p in packages]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
            "component": {"type": "application", "name": "satsa", "version": version,
                          "bom-ref": f"pkg:pypi/satsa@{version}"},
        },
        "components": components,
        "dependencies": deps,
    }


def licence_notices(lock_path: Path | str, root_dir: Path | str = ".") -> str:
    out = ["Third-party software in this SAT-SA release", "=" * 44, ""]
    for p in runtime_packages(lock_path):
        out.append(f"{p['name']} {p['version']}")
        licence = _declared_licence(p["name"])
        out.append(f"  Declared licence: {licence or 'metadata not installed in the build environment; see the wheel'}")
        try:
            files = metadata.files(p["name"]) or []
        except metadata.PackageNotFoundError:
            files = []
        for f in files:
            if re.match(r"^(LICEN[CS]E|COPYING|NOTICE)", Path(str(f)).name, re.IGNORECASE):
                try:
                    text = Path(str(f.locate())).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                out += [f"  --- {Path(str(f)).name} ---", *("  " + line for line in text.strip().splitlines()), ""]
        out.append("")
    out += ["Vendored browser assets", "-" * 23]
    for name, version, licence, path in VENDORED_ASSETS:
        out.append(f"{name} {version}: {licence}")
        if path and (Path(root_dir) / path).exists():
            out += ["  " + line for line in (Path(root_dir) / path).read_text(encoding="utf-8").strip().splitlines()]
        out.append("")
    return "\n".join(out) + "\n"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(bundle_dir: Path | str) -> Path:
    bundle = Path(bundle_dir)
    lines = [
        f"{_sha256(p)}  {p.relative_to(bundle).as_posix()}"
        for p in sorted(bundle.rglob("*"))
        if p.is_file() and p.name not in (SUMS_FILE, SIG_FILE)
    ]
    path = bundle / SUMS_FILE
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


def generate_keypair(out_dir: Path | str) -> tuple[Path, Path]:
    """An Ed25519 release key pair: keep the private key offline; publish the public key."""
    from satsa.keys import write_private

    out = Path(out_dir)
    key = Ed25519PrivateKey.generate()
    private = out / "release_signing_key.pem"
    public = out / "release_public_key.pem"
    if private.exists():
        raise FileExistsError(f"{private} already exists")
    write_private(private, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, public


def public_key_fingerprint(public_key_pem: bytes) -> str:
    key = serialization.load_pem_public_key(public_key_pem)
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:32]


def sign(bundle_dir: Path | str, private_key_path: Path | str) -> Path:
    key = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("the release signing key must be an Ed25519 key (satsa release keygen)")
    bundle = Path(bundle_dir)
    signature = key.sign((bundle / SUMS_FILE).read_bytes())
    path = bundle / SIG_FILE
    path.write_bytes(signature)
    return path


def verify(bundle_dir: Path | str, public_key_path: Path | str | None) -> dict[str, Any]:
    """Check the signature (if a public key is given), every hash, and that no file was added."""
    bundle = Path(bundle_dir)
    sums_path = bundle / SUMS_FILE
    if not sums_path.exists():
        raise ReleaseVerificationError(f"{SUMS_FILE} is missing")
    sums = sums_path.read_bytes()
    signed = False
    if public_key_path is not None:
        sig_path = bundle / SIG_FILE
        if not sig_path.exists():
            raise ReleaseVerificationError("the bundle is not signed")
        key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ReleaseVerificationError("the public key is not an Ed25519 key")
        try:
            key.verify(sig_path.read_bytes(), sums)
        except InvalidSignature as exc:
            raise ReleaseVerificationError("the signature does not match this public key and SHA256SUMS") from exc
        signed = True
    listed: dict[str, str] = {}
    for line in sums.decode("utf-8").splitlines():
        digest, rel = line.split("  ", 1)
        listed[rel] = digest
    present = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*")
               if p.is_file() and p.name not in (SUMS_FILE, SIG_FILE)}
    if present - set(listed):
        raise ReleaseVerificationError(f"files not in {SUMS_FILE}: {sorted(present - set(listed))[:10]}")
    if set(listed) - present:
        raise ReleaseVerificationError(f"files missing: {sorted(set(listed) - present)[:10]}")
    for rel, digest in listed.items():
        if _sha256(bundle / rel) != digest:
            raise ReleaseVerificationError(f"{rel} does not match {SUMS_FILE}")
    return {"files": len(listed), "signature_verified": signed}


def write_release_metadata(bundle_dir: Path | str, root_dir: Path | str, version: str) -> list[Path]:
    """SBOM, licence notices, release facts and local docs; called before checksums."""
    from satsa.scoring.fingerprint import environment_identity

    bundle, root = Path(bundle_dir), Path(root_dir)
    written = []
    lock = root / "uv.lock"
    if lock.exists():
        (bundle / "sbom.cdx.json").write_text(json.dumps(sbom(lock, version), indent=2), encoding="utf-8")
        (bundle / "THIRD_PARTY_LICENSES.txt").write_text(licence_notices(lock, root), encoding="utf-8")
        written += [bundle / "sbom.cdx.json", bundle / "THIRD_PARTY_LICENSES.txt"]
    env = environment_identity()
    facts = {
        "version": version,
        "code_revision": env.get("code_revision"),
        "lockfile_sha256": env.get("lockfile_sha256"),
        "built_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "built_with": env.get("runtime"),
        # Only what this release was actually run on; nothing is advertised beyond it.
        "tested_targets": [
            "Windows 11 x86_64, CPython 3.13, native install (full automated suite and browser tests)",
        ],
        "untested_targets": [
            "Linux container from the bundled Containerfile (not built or run for this release)",
            "Any other OS, architecture or Python version",
        ],
        "migrations": "applied by `satsa migrate` (docs/migrations.md); the scripts are part of the package",
    }
    (bundle / "RELEASE.json").write_text(json.dumps(facts, indent=2), encoding="utf-8")
    written.append(bundle / "RELEASE.json")
    if (root / "docs").is_dir():
        import shutil

        shutil.copytree(root / "docs", bundle / "docs",
                        ignore=shutil.ignore_patterns("*.html", "usability", "__pycache__"), dirs_exist_ok=True)
    return written
