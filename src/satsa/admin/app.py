"""NCIIPC Administration Application.

Dedicated FastAPI control plane for national cyber resilience oversight,
centralized identity provisioning, and supervisory role-based access control.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

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
