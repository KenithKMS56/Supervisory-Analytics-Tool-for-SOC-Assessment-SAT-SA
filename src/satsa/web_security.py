"""Same-origin checks against cross-site request forgery (docs/security/threat_model.md, T3).

Both portals authenticate browsers with a session cookie. A page on another site could make a
victim's browser send a form POST that carries that cookie. SameSite=Lax/Strict cookies already
block most of this; as the second layer, every state-changing request (POST, PUT, PATCH, DELETE)
and every WebSocket handshake must come from the portal's own origin:

- `Sec-Fetch-Site: cross-site` is refused;
- an `Origin` header must equal the portal's origin (`null`, sent by sandboxed frames and data:
  URLs, is refused);
- without `Origin`, a `Referer` must be same-origin if present.

Modern browsers send `Origin` on every POST, so a forged request is always identifiable. A client
that sends neither header is not a browser acting for a user (curl, a script with a service
credential) and is not subject to CSRF. Requests authenticated by an `Authorization` header
alone, with no cookie, carry no ambient credential and are not checked.

Behind a reverse proxy that rewrites `Host`, list the public origin(s) in
`SATSA_ALLOWED_ORIGINS` (comma-separated, e.g. `https://satsa.example.org`).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import urlsplit

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def normalise_origin(url: str) -> str | None:
    """`scheme://host[:port]` in lower case with default ports dropped, or None if not a URL."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    scheme = {"ws": "http", "wss": "https"}.get(parts.scheme.lower(), parts.scheme.lower())
    try:
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}" + (f":{port}" if port and port != _DEFAULT_PORTS.get(scheme) else "")


def allowed_origins(own_origin: str) -> set[str]:
    extra = {normalise_origin(o) for o in os.environ.get("SATSA_ALLOWED_ORIGINS", "").split(",") if o.strip()}
    own = normalise_origin(own_origin)
    return {o for o in (own, *extra) if o}


def cross_site_reason(method: str, headers: Mapping[str, str], own_origin: str, *, websocket: bool = False) -> str | None:
    """Why this request looks cross-site, or None if it may proceed."""
    if not websocket:
        if method.upper() not in UNSAFE_METHODS:
            return None
        if headers.get("authorization") and not headers.get("cookie"):
            return None
    allowed = allowed_origins(own_origin)
    if (headers.get("sec-fetch-site") or "").lower() == "cross-site":
        return "the browser marked the request cross-site"
    origin = headers.get("origin")
    if origin is not None:
        if normalise_origin(origin) not in allowed:
            return f"origin {origin!r} is not this portal's"
        return None
    referer = headers.get("referer")
    if referer and normalise_origin(referer) not in allowed:
        return "the request came from another site's page"
    return None


CROSS_SITE_REFUSED = "Cross-site request refused: state-changing requests must come from this portal's own pages."
