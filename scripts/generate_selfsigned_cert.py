"""Create a self-signed TLS certificate for the SAT-SA portals, fully offline.

    python scripts/generate_selfsigned_cert.py --out certs --hostname satsa.internal --ip 10.0.0.5

Writes certs/satsa-cert.pem and certs/satsa-key.pem using the local `openssl` command: no
certificate authority and no network. Same as `satsa tls-cert`. See docs/deployment_ops.md.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from satsa.serving import (
    ENV_TLS_CERT,
    ENV_TLS_KEY,
    ServingConfigError,
    generate_self_signed_cert,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a self-signed TLS certificate, offline.")
    parser.add_argument("--out", default="certs", help="directory for the certificate and key")
    parser.add_argument("--hostname", action="append", help="DNS name the portals are reached by (repeatable)")
    parser.add_argument("--ip", action="append", help="IP address the portals are reached by (repeatable)")
    parser.add_argument("--days", type=int, default=365, help="validity in days (1-825)")
    parser.add_argument("--force", action="store_true", help="replace an existing certificate and key")
    args = parser.parse_args()
    try:
        cert, key = generate_self_signed_cert(
            args.out, args.hostname, args.ip, days=args.days, force=args.force
        )
    except ServingConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"certificate: {cert}")
    print(f"private key: {key}")
    print(f"Serve with TLS: set {ENV_TLS_CERT}={cert} and {ENV_TLS_KEY}={key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
