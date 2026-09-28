"""Helpers for enumerating every route an app actually serves (used by RBAC/offline sweeps)."""

from collections.abc import Iterator
from typing import Any

from fastapi.routing import APIRoute, APIWebSocketRoute

EXCLUDED_PREFIXES = ("/static", "/docs", "/openapi.json", "/redoc")


def iter_routes(routes: list[Any], prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Yield (full_path, route) for every route, descending into included routers.

    Newer FastAPI versions wrap `app.include_router(...)` in an internal
    `_IncludedRouter` whose routes live on `.original_router` (with the include
    prefix on `.include_context`), so a flat `app.routes` scan would miss them.
    """
    for r in routes:
        original = getattr(r, "original_router", None)
        if original is not None:
            ctx = getattr(r, "include_context", None)
            sub_prefix = prefix + (getattr(ctx, "prefix", "") or "")
            yield from iter_routes(original.routes, sub_prefix)
        elif hasattr(r, "path"):
            yield prefix + r.path, r


def served_http_routes(app: Any) -> set[tuple[str, str]]:
    """Every (METHOD, path) served by `app`, minus static/docs/openapi."""
    served = set()
    for path, r in iter_routes(app.routes):
        if isinstance(r, APIRoute) and not path.startswith(EXCLUDED_PREFIXES):
            for m in r.methods - {"HEAD"}:
                served.add((m, path))
    return served


def served_websocket_paths(app: Any) -> set[str]:
    return {path for path, r in iter_routes(app.routes) if isinstance(r, APIWebSocketRoute)}
