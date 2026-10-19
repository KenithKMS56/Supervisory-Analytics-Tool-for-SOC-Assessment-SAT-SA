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

from fastapi import HTTPException

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


# Response headers for every page and file of both portals (docs/security/threat_model.md, T4).
# The templates still use inline scripts and event handlers, so script-src keeps 'unsafe-inline';
# everything else is limited to the portal itself: no external script, style, font or connection
# (which also keeps an air-gapped page from trying the network), no plugins, no framing by another
# site, and forms that post only back to the portal.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class BodyTooLarge(HTTPException):
    """A request body passed its cap while it was being read. An HTTPException, so a route or body
    parser that meets it answers 413 rather than treating it as a malformed body."""

    def __init__(self, limit: int) -> None:
        super().__init__(status_code=413, detail=f"The request body is larger than {limit // (1024 * 1024)} MiB.")


class SecurityMiddleware:
    """Pure ASGI middleware for both portals: adds SECURITY_HEADERS to every HTTP response and caps
    every request body at `limit_for(path)` bytes.

    The cap is enforced on the bytes actually received, so a chunked body that declares no length
    is stopped too, not only one whose Content-Length is too large. Over the cap, the client gets
    413 and the route sees an error instead of the rest of the body."""

    def __init__(self, app, limit_for):  # type: ignore[no-untyped-def]
        self.app = app
        self.limit_for = limit_for

    async def __call__(self, scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = int(self.limit_for(scope.get("path", "")))
        started = False
        overflowed = False
        replaced = False

        async def send_with_headers(message):  # type: ignore[no-untyped-def]
            nonlocal started, replaced
            if overflowed:
                # The body passed the cap. Whatever the route made of the cut-off body (often
                # "error parsing the body") is replaced by a 413 that says why.
                if not started:
                    replaced = True
                    await too_large()
                if replaced:
                    return
            if message["type"] == "http.response.start":
                started = True
                present = {k.lower() for k, _ in message.get("headers", [])}
                extra = [(k.lower().encode("latin-1"), v.encode("latin-1"))
                         for k, v in SECURITY_HEADERS.items() if k.lower().encode("latin-1") not in present]
                message = {**message, "headers": [*message.get("headers", []), *extra]}
            await send(message)

        async def too_large():  # type: ignore[no-untyped-def]
            body = f'{{"detail": "The request body is larger than {limit // (1024 * 1024)} MiB."}}'.encode()
            nonlocal started
            started = True
            headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                       *((k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in SECURITY_HEADERS.items())]
            await send({"type": "http.response.start", "status": 413, "headers": headers})
            await send({"type": "http.response.body", "body": body})

        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            await too_large()
            return

        received = 0

        async def counting_receive():  # type: ignore[no-untyped-def]
            nonlocal received, overflowed
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    overflowed = True
                    raise BodyTooLarge(limit)
            return message

        try:
            await self.app(scope, counting_receive, send_with_headers)
        except BodyTooLarge:
            if not started:
                await too_large()
        except Exception as exc:
            # Body parsers (FastAPI, Starlette's multipart) may wrap the error; find it in the chain.
            cause: BaseException | None = exc
            while cause is not None and not isinstance(cause, BodyTooLarge):
                cause = cause.__cause__ or cause.__context__
            if cause is None:
                raise
            if not started:
                await too_large()
