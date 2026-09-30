"""NCIIPC Administration Application.

Dedicated FastAPI control plane for national cyber resilience oversight,
centralized identity provisioning, and supervisory role-based access control.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from satsa.admin.routes import AdminAuthRequired, AdminPasswordChangeRequired
from satsa.admin.routes import router as admin_router
from satsa.store.sqlite import SQLiteStore

_ADMIN_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _ADMIN_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize SQLite database connection, run seed migrations, and close on shutdown."""
    db_path = "data/satsa.db"
    store = SQLiteStore(db_path)
    # Ensure default organisations, CSEs, and admin account are seeded
    store.seed_default_organisations_and_cses()
    store.seed_default_admin()
    # A database seeded before first-login rotation was enforced is covered here.
    store.flag_unrotated_default_accounts()
    app.state.store = store
    yield
    store.close()


app = FastAPI(
    title="NCIIPC Administration Portal",
    description="National Critical Information Infrastructure Protection Centre — Administrative & Supervisory Control Portal",
    version="2.1.0",
    docs_url=None,  # Air-gapped / hardened security perimeter
    redoc_url=None,
    lifespan=lifespan,
)

# Mount admin static assets
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="admin_static")

# Include administrative routes
app.include_router(admin_router)


@app.exception_handler(AdminAuthRequired)
async def admin_auth_required_handler(request: Request, exc: AdminAuthRequired) -> Response:
    """Unauthenticated: browser page loads go to /login; API calls and mutations get 401."""
    if request.method == "GET" and not request.url.path.startswith("/api/"):
        return RedirectResponse(url="/login", status_code=303)
    return JSONResponse({"detail": "Authentication required."}, status_code=401)


@app.exception_handler(AdminPasswordChangeRequired)
async def admin_password_change_required_handler(
    request: Request, exc: AdminPasswordChangeRequired
) -> Response:
    """A default or reset passphrase must be replaced before anything else is served."""
    if request.method == "GET" and not request.url.path.startswith("/api/"):
        return RedirectResponse(url="/change-password", status_code=303)
    return JSONResponse(
        {"detail": "A new passphrase must be set at /change-password before this account can be used."},
        status_code=403,
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception) -> HTMLResponse:
    """Render hardened 404 page."""
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found | NCIIPC Administration Portal</title>
    <link rel="stylesheet" href="/static/admin.css">
</head>
<body>
    <div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; flex-direction: column; text-align: center; padding: 2rem;">
        <div style="font-size: 3rem; font-weight: 700; color: var(--accent-primary); margin-bottom: 0.5rem;">404</div>
        <h2 style="margin-bottom: 0.5rem;">Administrative Resource Not Found</h2>
        <p style="color: var(--admin-text-muted); margin-bottom: 1.5rem;">The requested supervisory console endpoint does not exist or has been relocated.</p>
        <a href="/" class="btn-admin btn-admin-primary">Return to Administration Console</a>
    </div>
</body>
</html>""",
        status_code=404,
    )
