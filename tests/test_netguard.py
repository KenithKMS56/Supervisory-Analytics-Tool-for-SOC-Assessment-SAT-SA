"""The runtime egress guard (satsa.netguard): loopback only, best-effort, and leaves no trace.

Every test that installs the guard does so through the `guard` fixture, whose teardown
uninstalls it and asserts the original socket functions are back, so no later test runs with
a guard it did not ask for.
"""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from satsa import netguard
from satsa.ingest.adapters import SourceAdapter
from satsa.netguard import (
    EgressBlockedError,
    egress_guard_installed,
    install_egress_guard,
    is_loopback_destination,
    uninstall_egress_guard,
)


def _socket_functions():
    return socket.socket.connect, socket.socket.connect_ex, socket.create_connection


@pytest.fixture
def guard(monkeypatch):
    monkeypatch.delenv(netguard.ENV_ALLOW_EGRESS, raising=False)
    before = _socket_functions()
    assert not egress_guard_installed()
    assert install_egress_guard() is True
    yield
    uninstall_egress_guard()
    assert not egress_guard_installed()
    assert _socket_functions() == before


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "127.8.9.10", "::1", "[::1]", "localhost", "LOCALHOST", "0.0.0.0", "::ffff:127.0.0.1"],
)
def test_loopback_destinations_are_allowed(host):
    assert is_loopback_destination(host)


@pytest.mark.parametrize(
    "host", ["8.8.8.8", "10.0.0.5", "192.168.1.1", "2001:4860:4860::8888", "example.com", "pypi.org", None]
)
def test_other_destinations_are_not(host):
    assert not is_loopback_destination(host)


def test_external_connect_is_blocked_before_any_packet(guard):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(EgressBlockedError, match="egress guard"):
            s.connect(("8.8.8.8", 53))
        with pytest.raises(EgressBlockedError):
            s.connect_ex(("1.1.1.1", 443))
    finally:
        s.close()
    # A host name is refused without being resolved.
    with pytest.raises(EgressBlockedError):
        socket.create_connection(("example.com", 443), timeout=1)


def test_blocked_error_is_a_connection_error(guard):
    """Libraries treat it as an ordinary refused connection (urllib wraps it in URLError)."""
    assert issubclass(EgressBlockedError, ConnectionRefusedError)
    import urllib.error
    import urllib.request

    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen("http://203.0.113.10/", timeout=1)


def test_loopback_traffic_still_works(guard):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        conn, _ = server.accept()
        client.sendall(b"ok")
        assert conn.recv(2) == b"ok"
        conn.close()
        client.close()
    finally:
        server.close()


def test_read_api_against_a_loopback_server_works_with_the_guard(guard):
    body = json.dumps({"tickets": [{"ticket_id": "TCK-GUARDED"}]}).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        rows = SourceAdapter.read_api(
            {"url": f"http://127.0.0.1:{server.server_address[1]}/t", "records_key": "tickets"}
        )
        assert rows == [{"ticket_id": "TCK-GUARDED"}]
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_install_is_reference_counted(guard):
    assert install_egress_guard() is True
    uninstall_egress_guard()
    assert egress_guard_installed()  # the fixture's install is still active
    with pytest.raises(EgressBlockedError):
        socket.create_connection(("8.8.4.4", 53), timeout=1)


def test_opt_out_disables_the_guard(monkeypatch, caplog):
    monkeypatch.setenv(netguard.ENV_ALLOW_EGRESS, "1")
    before = _socket_functions()
    with caplog.at_level("WARNING"):
        assert install_egress_guard() is False
    assert "DISABLED" in caplog.text
    assert not egress_guard_installed()
    assert _socket_functions() == before


def test_a_wrapper_left_behind_by_another_patch_is_inert(monkeypatch):
    """A guard wrapper that outlives its uninstall (e.g. restored by someone else's patch
    teardown) passes calls straight through instead of blocking them."""
    monkeypatch.delenv(netguard.ENV_ALLOW_EGRESS, raising=False)
    calls = []
    monkeypatch.setattr(socket, "create_connection", lambda address, *a, **k: calls.append(address))
    install_egress_guard()
    wrapper = socket.create_connection
    with pytest.raises(EgressBlockedError):
        wrapper(("8.8.8.8", 53))
    uninstall_egress_guard()
    wrapper(("8.8.8.8", 53))  # stale wrapper: reaches the stub, nothing is blocked
    assert calls == [("8.8.8.8", 53)]


@pytest.mark.parametrize("module", ["satsa.api.routes", "satsa.admin.app"])
def test_app_lifespan_installs_and_removes_the_guard(module, monkeypatch):
    monkeypatch.delenv(netguard.ENV_ALLOW_EGRESS, raising=False)
    import importlib

    app = importlib.import_module(module).app
    before = _socket_functions()
    assert not egress_guard_installed()
    with TestClient(app) as client:
        assert egress_guard_installed()
        assert client.get("/splash").status_code == 200
        with pytest.raises(EgressBlockedError):
            socket.create_connection(("198.51.100.7", 80), timeout=1)
    assert not egress_guard_installed()
    assert _socket_functions() == before


@pytest.mark.parametrize("command", ["serve", "admin"])
def test_cli_portals_run_with_the_guard_and_release_it(command, monkeypatch):
    """`satsa serve` / `satsa admin` hold the guard for as long as uvicorn runs."""
    import uvicorn
    from typer.testing import CliRunner

    from satsa.cli import app

    monkeypatch.delenv(netguard.ENV_ALLOW_EGRESS, raising=False)
    monkeypatch.delenv("SATSA_HOST", raising=False)
    seen = []
    monkeypatch.setattr(uvicorn, "run", lambda target, **kw: seen.append(egress_guard_installed()))
    before = _socket_functions()
    result = CliRunner().invoke(app, [command])
    assert result.exit_code == 0, result.output
    assert seen == [True]
    assert not egress_guard_installed()
    assert _socket_functions() == before
