"""Browser tests: a real SAT-SA server and a real Chromium with the outside network unavailable.

The server runs as its own process (uvicorn, like a deployment) in a private copy of the session's
deployment directory, so whatever a browser test does -- a passphrase change, an upload -- never
reaches the database the rest of the suite reads.

Chromium is started with every host name except loopback resolving to nothing
(`--host-resolver-rules`), so an external DNS lookup or HTTP request genuinely fails, as on an
air-gapped machine; it is not a mock of Python sockets. Each request to a non-loopback URL is also
recorded by the `offline_page` fixture, and the test fails if there is any.

Playwright is a development dependency. When its Chromium is not installed (`uv run playwright
install chromium`), these tests are skipped with that reason; they are never silently passed.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pytest

from satsa.store.catalog import CATALOG_FILE, Catalog
from satsa.store.migrations import backup_database
from satsa.store.sqlite import SQLiteStore

sync_api = pytest.importorskip("playwright.sync_api", reason="Playwright is not installed (uv sync --dev)")

LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
NEW_PASSPHRASE = "Browser-Check-Passphrase#2026"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def copy_deployment(dest: Path) -> Path:
    """A consistent private copy of the current deployment directory (`config/`, `data/`)."""
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copytree("config", dest / "config")
    data = dest / "data"
    shutil.copytree("data/parquet", data / "parquet")
    for name in ("templates",):
        if Path("data", name).is_dir():
            shutil.copytree(Path("data", name), data / name)
    catalog = Catalog("data")
    try:
        backup_database(catalog.conn, data / CATALOG_FILE)
    finally:
        catalog.close()
    store = SQLiteStore("data/satsa.db")
    try:
        backup_database(store.conn, data / "satsa.db")
    finally:
        store.close()
    if Path("data/secrets").is_dir():
        shutil.copytree("data/secrets", data / "secrets")
    return dest


@dataclass
class LiveServer:
    root: Path
    base_url: str
    process: subprocess.Popen[bytes]
    log: Path

    def log_text(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")


@pytest.fixture(scope="module")
def live_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LiveServer]:
    root = copy_deployment(tmp_path_factory.mktemp("deployment"))
    port = _free_port()
    log = root / "server.log"
    with open(log, "wb") as out:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "satsa.api:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=root,
            stdout=out,
            stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "NO_PROXY": "*"},
        )
    server = LiveServer(root, f"http://127.0.0.1:{port}", process, log)
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                if httpx.get(f"{server.base_url}/splash", timeout=2, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if process.poll() is not None or time.monotonic() > deadline:
                pytest.fail(f"the server did not start:\n{server.log_text()[-3000:]}")
            time.sleep(0.3)
        yield server
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture(scope="module")
def chromium() -> Iterator[object]:
    with sync_api.sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(
                args=["--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost"],
            )
        except sync_api.Error as exc:
            pytest.skip(f"Chromium for Playwright is not installed (uv run playwright install chromium): {exc}")
        try:
            yield browser
        finally:
            browser.close()


@dataclass
class OfflinePage:
    page: object
    external_requests: list[str] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    failed_requests: list[str] = field(default_factory=list)


@pytest.fixture
def offline_page(chromium: object, live_server: LiveServer) -> Iterator[OfflinePage]:
    context = chromium.new_context(viewport={"width": 1440, "height": 900})  # type: ignore[attr-defined]
    page = context.new_page()
    seen = OfflinePage(page)

    def on_request(request: object) -> None:
        url = request.url  # type: ignore[attr-defined]
        host = urlparse(url).hostname or ""
        if url.startswith(("http:", "https:", "ws:", "wss:")) and host not in LOOPBACK:
            seen.external_requests.append(url)

    page.on("request", on_request)
    page.on("console", lambda m: seen.console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: seen.page_errors.append(str(e)))
    page.on("requestfailed", lambda r: seen.failed_requests.append(f"{r.url}: {r.failure}"))
    try:
        yield seen
    finally:
        context.close()


def sign_in(page: object, base_url: str, username: str, passphrase: str) -> None:
    """Sign in through the login form, choosing a new passphrase if the server asks for one."""
    page.goto(f"{base_url}/login")  # type: ignore[attr-defined]
    page.fill("input[name=username]", username)  # type: ignore[attr-defined]
    page.fill("input[name=password]", passphrase)  # type: ignore[attr-defined]
    page.click("button[type=submit]")  # type: ignore[attr-defined]
    page.wait_for_load_state()  # type: ignore[attr-defined]
    if "/change-password" in page.url:  # type: ignore[attr-defined]
        page.fill("input[name=current_password]", passphrase)  # type: ignore[attr-defined]
        page.fill("input[name=new_password]", NEW_PASSPHRASE)  # type: ignore[attr-defined]
        page.fill("input[name=confirm_password]", NEW_PASSPHRASE)  # type: ignore[attr-defined]
        page.click("button[type=submit]")  # type: ignore[attr-defined]
        page.wait_for_load_state()  # type: ignore[attr-defined]
    elif "/login" in page.url:  # type: ignore[attr-defined]
        # Signed in already in an earlier test of this module: the passphrase has been changed.
        page.fill("input[name=username]", username)  # type: ignore[attr-defined]
        page.fill("input[name=password]", NEW_PASSPHRASE)  # type: ignore[attr-defined]
        page.click("button[type=submit]")  # type: ignore[attr-defined]
        page.wait_for_load_state()  # type: ignore[attr-defined]
