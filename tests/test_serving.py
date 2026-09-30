"""Bind address and optional TLS: loopback and plain HTTP unless explicitly configured otherwise.

The TLS tests generate a real self-signed certificate with the local `openssl` and start a
real server on a loopback port; they are skipped when `openssl` is not installed.
"""

import importlib.util
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

from satsa.serving import (
    CERT_FILENAME,
    KEY_FILENAME,
    ServingConfigError,
    exposure_warning,
    generate_self_signed_cert,
    serving_config,
)

REPO = Path(__file__).resolve().parent.parent
needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


# ------------------------------------------------------------------ bind address


def test_default_bind_is_loopback_plain_http():
    config = serving_config(env={})
    assert (config.host, config.tls, config.scheme, config.external) == ("127.0.0.1", False, "http", False)
    assert exposure_warning(config) is None
    assert config.uvicorn_args("satsa.api:app", 8001) == [
        "satsa.api:app", "--host", "127.0.0.1", "--port", "8001", "--log-level", "info",
    ]  # fmt: skip


def test_external_bind_is_an_explicit_opt_in_and_warns_without_tls():
    config = serving_config(env={"SATSA_HOST": "0.0.0.0"})
    assert config.external and config.host == "0.0.0.0"
    assert "plain HTTP" in exposure_warning(config)
    # An explicit argument wins over the environment.
    assert serving_config(env={"SATSA_HOST": "0.0.0.0"}, host="127.0.0.1").external is False


def test_cli_serve_and_admin_default_to_loopback(monkeypatch):
    import uvicorn
    from typer.testing import CliRunner

    from satsa.cli import app

    monkeypatch.delenv("SATSA_HOST", raising=False)
    monkeypatch.delenv("SATSA_TLS_CERT", raising=False)
    monkeypatch.delenv("SATSA_TLS_KEY", raising=False)
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda target, **kw: calls.append((target, kw)))
    runner = CliRunner()
    assert runner.invoke(app, ["serve"]).exit_code == 0
    assert runner.invoke(app, ["admin"]).exit_code == 0
    assert runner.invoke(app, ["serve", "--host", "0.0.0.0"]).exit_code == 0
    assert [(t, kw["host"], kw["port"], kw["ssl_certfile"]) for t, kw in calls] == [
        ("satsa.api:app", "127.0.0.1", 8001, None),
        ("satsa.admin.app:app", "127.0.0.1", 8000, None),
        ("satsa.api:app", "0.0.0.0", 8001, None),
    ]


def test_compose_publishes_on_loopback_unless_told_otherwise():
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["satsa-platform"]
    assert service["ports"] == [
        "${SATSA_BIND_ADDRESS:-127.0.0.1}:8000:8000",
        "${SATSA_BIND_ADDRESS:-127.0.0.1}:8001:8001",
    ]
    assert service["healthcheck"]["test"] == ["CMD", "python", "/app/entrypoint.py", "--healthcheck"]
    assert {"SATSA_TLS_CERT", "SATSA_TLS_KEY"} <= set(service["environment"])


def _entrypoint():
    spec = importlib.util.spec_from_file_location("satsa_entrypoint", REPO / "entrypoint.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_entrypoint_launches_both_portals_on_the_configured_address(tmp_path, monkeypatch):
    """No hard-coded 0.0.0.0: the entrypoint binds where satsa.serving says."""
    entrypoint = _entrypoint()
    assert "0.0.0.0" not in (REPO / "entrypoint.py").read_text(encoding="utf-8")

    launched = []

    class _Proc:
        def poll(self):
            return 0  # "exited", so main() shuts down on its first health pass

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SATSA_HOST", raising=False)
    monkeypatch.delenv("SATSA_TLS_CERT", raising=False)
    monkeypatch.delenv("SATSA_TLS_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["entrypoint.py"])
    monkeypatch.setattr(entrypoint.subprocess, "Popen", lambda cmd, env=None: launched.append(cmd) or _Proc())
    monkeypatch.setattr(entrypoint.signal, "signal", lambda *a: None)
    # Skip the demo-data seed: only the launch commands are under test.
    import satsa.store.sqlite as sqlite_module

    monkeypatch.setattr(sqlite_module, "SQLiteStore", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("skip")))
    with pytest.raises(SystemExit):
        entrypoint.main()
    assert [cmd[3:7] for cmd in launched] == [
        ["satsa.admin.app:app", "--host", "127.0.0.1", "--port"],
        ["satsa.api:app", "--host", "127.0.0.1", "--port"],
    ]


# ------------------------------------------------------------------ TLS configuration


def test_half_a_tls_configuration_refuses_to_start(tmp_path):
    cert = tmp_path / "c.pem"
    cert.write_text("x")
    with pytest.raises(ServingConfigError, match="both a certificate and a key"):
        serving_config(env={"SATSA_TLS_CERT": str(cert)})
    with pytest.raises(ServingConfigError, match="both a certificate and a key"):
        serving_config(env={"SATSA_TLS_KEY": str(cert)})
    with pytest.raises(ServingConfigError, match="key file not found"):
        serving_config(env={"SATSA_TLS_CERT": str(cert), "SATSA_TLS_KEY": str(tmp_path / "missing.pem")})


def test_tls_marks_session_cookies_secure(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("x")
    key.write_text("x")
    config = serving_config(env={"SATSA_HOST": "0.0.0.0", "SATSA_TLS_CERT": str(cert), "SATSA_TLS_KEY": str(key)})
    assert config.tls and config.scheme == "https"
    assert "TLS on" in exposure_warning(config)
    assert config.uvicorn_args("satsa.api:app", 8001)[-4:] == [
        "--ssl-certfile", str(cert), "--ssl-keyfile", str(key),
    ]  # fmt: skip
    assert config.child_env({})["SATSA_COOKIE_SECURE"] == "1"
    assert "SATSA_COOKIE_SECURE" not in serving_config(env={}).child_env({})


# ------------------------------------------------------------------ certificate + live TLS


@needs_openssl
def test_generated_certificate_names_the_requested_hosts(tmp_path):
    cert, key = generate_self_signed_cert(tmp_path, ["satsa.internal", "localhost"], ["127.0.0.1", "10.0.0.5"], days=30)
    assert (cert.name, key.name) == (CERT_FILENAME, KEY_FILENAME)
    assert "BEGIN CERTIFICATE" in cert.read_text() and "PRIVATE KEY" in key.read_text()
    text = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-text"], capture_output=True, text=True, check=True
    ).stdout
    for name in ("DNS:satsa.internal", "DNS:localhost", "IP Address:127.0.0.1", "IP Address:10.0.0.5"):
        assert name in text
    assert "CA:FALSE" in text and "TLS Web Server Authentication" in text
    assert "Public-Key: (3072 bit)" in text

    # An existing pair is never silently replaced.
    with pytest.raises(ServingConfigError, match="already exists"):
        generate_self_signed_cert(tmp_path)
    before = cert.read_bytes()
    generate_self_signed_cert(tmp_path, force=True)
    assert cert.read_bytes() != before
    with pytest.raises(ServingConfigError, match="1 to 825 days"):
        generate_self_signed_cert(tmp_path / "other", days=5000)


@needs_openssl
def test_the_script_writes_a_certificate(tmp_path):
    out = tmp_path / "certs"
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "generate_selfsigned_cert.py"), "--out", str(out)],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert (out / CERT_FILENAME).is_file() and (out / KEY_FILENAME).is_file()
    assert "SATSA_TLS_CERT=" in result.stdout


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@needs_openssl
def test_portal_serves_https_with_the_generated_certificate(tmp_path):
    """A real server, a real handshake: the client trusts only the generated certificate."""
    cert, key = generate_self_signed_cert(tmp_path / "certs")
    config = serving_config(env={"SATSA_TLS_CERT": str(cert), "SATSA_TLS_KEY": str(key)})
    port = _free_port()
    env = config.child_env({**os.environ, "PYTHONPATH": str(REPO / "src")})
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", *config.uvicorn_args("satsa.api:app", port)],
        cwd=tmp_path, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    trusted = ssl.create_default_context(cafile=str(cert))
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                with urllib.request.urlopen(f"https://127.0.0.1:{port}/splash", timeout=5, context=trusted) as r:
                    assert r.status == 200
                    break
            except (urllib.error.URLError, ConnectionError):
                assert server.poll() is None, "server exited"
                assert time.monotonic() < deadline, "server did not come up"
                time.sleep(0.5)

        # Verified against the certificate's names: localhost matches, the default trust store does not know it.
        with urllib.request.urlopen(f"https://localhost:{port}/splash", timeout=5, context=trusted) as r:
            assert r.status == 200
        with pytest.raises(urllib.error.URLError) as untrusted:
            urllib.request.urlopen(f"https://127.0.0.1:{port}/splash", timeout=5, context=ssl.create_default_context())
        assert "CERTIFICATE_VERIFY_FAILED" in str(untrusted.value)

        # Plain HTTP is not served on the TLS port.
        with pytest.raises((urllib.error.URLError, ConnectionError, OSError)):
            urllib.request.urlopen(f"http://127.0.0.1:{port}/splash", timeout=5)

        # Over TLS the session cookie is Secure (a failed login sets none, so use a seeded account).
        body = b"username=analyst&password=ChangeMe-Analyst%232026"
        request = urllib.request.Request(f"https://127.0.0.1:{port}/login", data=body, method="POST")

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=trusted), _NoRedirect)
        with pytest.raises(urllib.error.HTTPError) as redirect:
            opener.open(request, timeout=30)
        assert redirect.value.code == 303
        # A fresh install: the seeded passphrase only leads to the change-password page.
        assert redirect.value.headers["location"] == "/change-password"
        cookie = redirect.value.headers["set-cookie"]
        assert "satsa_session=" in cookie and "Secure" in cookie and "HttpOnly" in cookie
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
