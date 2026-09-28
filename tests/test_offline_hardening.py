"""Offline / air-gap hardening.

1. Socket-level guard: socket.socket.connect / connect_ex, socket.create_connection
   and socket.getaddrinfo are patched to RECORD and REFUSE any non-loopback target.
   Every GET route of both apps (SAT-SA and the Admin Portal, including the admin
   activity feed polling endpoints) is requested as an admin with path params
   filled from the seeded DB; the test asserts zero outbound attempts and no 5xx.
2. Static scan: no template or static asset references an external http(s) URL
   via src=, href=, url(...), @import or fetch(...). Vendored minified libraries
   are excluded (their license headers/strings mention URLs but are never fetched).
"""

import ipaddress
import re
import socket
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from route_utils import iter_routes

from satsa.admin.app import app as admin_app
from satsa.admin.routes import ADMIN_COOKIE_NAME
from satsa.api.routes import app as satsa_app
from satsa.store.sqlite import SQLiteStore

LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", ""}


def _is_loopback(host: object) -> bool:
    if host is None:
        return True
    h = host.decode() if isinstance(host, bytes) else str(host)
    h = h.strip("[]").lower()
    if h in LOOPBACK_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(h.split("%")[0])
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


@pytest.fixture
def socket_guard(monkeypatch):
    """Record and refuse every non-loopback connection or name lookup."""
    attempts: list[str] = []
    orig_connect = socket.socket.connect
    orig_connect_ex = socket.socket.connect_ex
    orig_create_connection = socket.create_connection
    orig_getaddrinfo = socket.getaddrinfo

    def _host(address):
        return address[0] if isinstance(address, tuple) else address

    def guarded_connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6) and not _is_loopback(_host(address)):
            attempts.append(f"connect {address!r}")
            raise ConnectionRefusedError(f"air-gap violation: connect to {address!r}")
        return orig_connect(self, address)

    def guarded_connect_ex(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6) and not _is_loopback(_host(address)):
            attempts.append(f"connect_ex {address!r}")
            return 111  # ECONNREFUSED
        return orig_connect_ex(self, address)

    def guarded_create_connection(address, *args, **kwargs):
        if not _is_loopback(_host(address)):
            attempts.append(f"create_connection {address!r}")
            raise ConnectionRefusedError(f"air-gap violation: create_connection {address!r}")
        return orig_create_connection(address, *args, **kwargs)

    def guarded_getaddrinfo(host, *args, **kwargs):
        if not _is_loopback(host):
            attempts.append(f"getaddrinfo {host!r}")
            raise socket.gaierror(f"air-gap violation: DNS lookup for {host!r}")
        return orig_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    return attempts


def test_socket_guard_blocks_and_records_external(socket_guard):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(ConnectionRefusedError):
        s.connect(("8.8.8.8", 53))
    assert s.connect_ex(("1.1.1.1", 443)) != 0
    s.close()
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("example.com", 443))
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("fonts.googleapis.com", 443)
    assert len(socket_guard) == 4
    # Loopback stays allowed.
    assert socket.getaddrinfo("localhost", 80)


def _real_ids() -> dict[str, str]:
    store = SQLiteStore("data/satsa.db")
    try:
        finding = store.conn.execute(
            "SELECT finding_id, entity_id FROM findings ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
    finally:
        store.close()
    assert finding, "bootstrapped data required (satsa generate-data / ingest / run)"
    return {
        "finding_id": finding["finding_id"],
        "entity_id": finding["entity_id"],
        "template_name": "alerts.csv",
        "username": "examiner",
    }


def _get_paths(app) -> list[str]:
    paths = []
    for path, r in iter_routes(app.routes):
        if isinstance(r, APIRoute) and "GET" in r.methods and not path.startswith(("/docs", "/openapi")):
            paths.append(path)
    return sorted(set(paths))


def _fill(path: str, ids: dict[str, str]) -> str:
    for name, value in ids.items():
        path = path.replace("{" + name + "}", value)
    assert "{" not in path, f"unfilled path parameter in {path}"
    return path


def test_every_get_route_is_offline_and_healthy(socket_guard, monkeypatch):
    monkeypatch.setenv("SATSA_RULEPACK_SECRET", "offline-sweep-secret-" + "x" * 32)
    ids = _real_ids()
    results: dict[str, int] = {}

    satsa = TestClient(satsa_app)
    r = satsa.post("/login", data={"username": "admin", "password": "ChangeMe-Admin#2026"},
                   follow_redirects=False)
    assert r.status_code == 303
    satsa_paths = _get_paths(satsa_app)
    for path in satsa_paths:
        url = _fill(path, ids)
        results[f"satsa GET {url}"] = satsa.get(url, follow_redirects=False).status_code

    with TestClient(admin_app) as admin:  # lifespan opens data/satsa.db
        store: SQLiteStore = admin_app.state.store
        admin.cookies.set(
            ADMIN_COOKIE_NAME, store.create_admin_session("nciipc_admin", "NCIIPC Super Administrator")
        )
        admin_paths = _get_paths(admin_app)
        for path in admin_paths:
            url = _fill(path, ids)
            results[f"admin GET {url}"] = admin.get(url, follow_redirects=False).status_code
        # The admin activity feed polling endpoint, with explicit cursor params.
        feed = admin.get("/api/activity/stream", params={"since_id": 0, "limit": 50})
        results["admin GET /api/activity/stream?since_id=0&limit=50"] = feed.status_code
        assert feed.status_code == 200 and "events" in feed.json()

    assert "/api/activity/stream" in admin_paths and "/api/activity/recent" in admin_paths
    assert "/users" in admin_paths and "/portfolio" in satsa_paths
    assert socket_guard == [], f"outbound connection attempts: {socket_guard}"
    server_errors = {k: v for k, v in results.items() if v >= 500}
    assert not server_errors, server_errors
    # Authenticated as admin, nothing should be refused either.
    assert not {k: v for k, v in results.items() if v in (401, 403)}


# ---------------------------------------------------------------- static scan

ASSET_ROOTS = [Path("src/satsa/ui"), Path("src/satsa/admin")]
VENDORED = {"echarts.min.js"}
URL_PATTERNS = [
    re.compile(r"""(?:src|href|action)\s*=\s*["']\s*(https?://[^"'\s>]+)""", re.IGNORECASE),
    re.compile(r"""url\(\s*["']?\s*(https?://[^)"'\s]+)""", re.IGNORECASE),
    re.compile(r"""@import\s+(?:url\()?\s*["']?(https?://[^)"'\s;]+)""", re.IGNORECASE),
    re.compile(r"""fetch\(\s*["'](https?://[^"']+)""", re.IGNORECASE),
]


def _external(url: str) -> bool:
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0]
    return not _is_loopback(host)


def test_no_external_urls_in_templates_or_static_assets():
    offenders = []
    scanned = 0
    for root in ASSET_ROOTS:
        for f in root.rglob("*"):
            if f.suffix.lower() not in {".html", ".css", ".js"} or f.name in VENDORED:
                continue
            scanned += 1
            text = f.read_text(encoding="utf-8", errors="replace")
            for pat in URL_PATTERNS:
                for m in pat.finditer(text):
                    if _external(m.group(1)):
                        offenders.append(f"{f}: {m.group(1)}")
    assert scanned >= 20
    assert offenders == [], offenders


def test_static_scan_catches_a_cdn_link(tmp_path):
    """Guard the guard: the patterns do flag a typical CDN/font reference."""
    sample = '<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">' \
             '<script src="https://cdn.example.com/x.js"></script>' \
             '<style>@import url("https://evil.example/a.css"); b{background:url(https://x.io/i.png)}</style>' \
             '<a href="http://localhost:8001/portfolio">ok</a>'
    found = {m.group(1) for pat in URL_PATTERNS for m in pat.finditer(sample) if _external(m.group(1))}
    assert found == {
        "https://fonts.googleapis.com/css2?family=Inter",
        "https://cdn.example.com/x.js",
        "https://evil.example/a.css",
        "https://x.io/i.png",
    }
