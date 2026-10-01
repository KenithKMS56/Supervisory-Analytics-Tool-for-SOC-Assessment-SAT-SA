"""Best-effort, in-process outbound network guard (defence in depth for the air gap).

SAT-SA makes no outbound network calls by design; this module makes an accidental one fail
loudly instead of silently leaving the host. `install_egress_guard()` wraps the Python socket
entry points (`socket.socket.connect`, `socket.socket.connect_ex`, `socket.create_connection`)
so that only loopback destinations are allowed: 127.0.0.0/8, ::1 (and IPv4-mapped loopback),
the name `localhost`, and 0.0.0.0 (used by local self-probes). Any other destination raises
`EgressBlockedError` before a connection is attempted. Unix-domain sockets are local and allowed.

What it does NOT do (stated plainly; it is best-effort, not a sandbox):

* Native code that opens sockets without going through Python's `socket` module (a C
  extension, a subprocess) is not covered. The host firewall and the air gap itself remain
  the real controls.
* DNS lookups (`socket.getaddrinfo`) are not blocked. `create_connection` refuses a
  non-loopback host name before resolving it, but other code may still resolve names.
* Listening sockets (`bind`/`accept`) are unaffected, so the portals still serve on any
  address the operator configures.

Installation is reference-counted: every `install_egress_guard()` that returned True must be
matched by one `uninstall_egress_guard()`, and the original functions come back when the count
reaches zero. The FastAPI lifespans install on start-up and uninstall on shutdown, so test
clients leave the process as they found it. `SATSA_ALLOW_EGRESS=1` disables the guard (logged).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

ENV_ALLOW_EGRESS = "SATSA_ALLOW_EGRESS"
_ALLOWED_NAMES = frozenset({"localhost", "0.0.0.0", ""})


class EgressBlockedError(ConnectionRefusedError):
    """An outbound connection to a non-loopback destination was refused by the guard."""


_lock = threading.Lock()
_depth = 0
_originals: dict[str, Callable[..., Any]] = {}
_installed: dict[str, Callable[..., Any]] = {}


def is_loopback_destination(host: object) -> bool:
    """True if `host` (an address or the name `localhost`) is on this machine's loopback."""
    if not isinstance(host, str):
        return False
    name = host.strip().strip("[]").lower()
    if name in _ALLOWED_NAMES:
        return True
    name = name.split("%", 1)[0]  # IPv6 zone id
    try:
        addr = ipaddress.ip_address(name)
    except ValueError:
        return False  # any other host name: refused without resolving it
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_loopback


def _check(address: Any) -> None:
    if isinstance(address, (tuple, list)) and address:
        host = address[0]
    elif isinstance(address, (str, bytes)):
        return  # AF_UNIX path: local by definition
    else:
        host = address
    if not is_loopback_destination(host):
        raise EgressBlockedError(
            f"SAT-SA egress guard: outbound connection to {host!r} refused (loopback only; "
            f"set {ENV_ALLOW_EGRESS}=1 to disable)."
        )


def _family_is_inet(sock: socket.socket) -> bool:
    return sock.family in (socket.AF_INET, socket.AF_INET6)


def egress_guard_installed() -> bool:
    """True while the guard is active in this process."""
    return _depth > 0


def install_egress_guard() -> bool:
    """Install the guard (idempotent, reference-counted). Returns False when disabled by env."""
    global _depth
    if os.environ.get(ENV_ALLOW_EGRESS, "").strip() in ("1", "true", "yes"):
        logger.warning("%s is set: the in-process egress guard is DISABLED.", ENV_ALLOW_EGRESS)
        return False
    with _lock:
        _depth += 1
        if _depth > 1:
            return True
        orig_connect = socket.socket.connect
        orig_connect_ex = socket.socket.connect_ex
        orig_create = socket.create_connection
        _originals.update(connect=orig_connect, connect_ex=orig_connect_ex, create=orig_create)

        # The wrappers check _depth on every call, so a wrapper that outlives its uninstall
        # (another patch layered on top restored it later) passes everything through.
        def guarded_connect(self: socket.socket, address: Any) -> None:
            if _depth and _family_is_inet(self):
                _check(address)
            return orig_connect(self, address)

        def guarded_connect_ex(self: socket.socket, address: Any) -> int:
            if _depth and _family_is_inet(self):
                _check(address)
            return orig_connect_ex(self, address)

        def guarded_create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
            if _depth:
                _check(address)
            return orig_create(address, *args, **kwargs)

        socket.socket.connect = guarded_connect  # type: ignore[method-assign,assignment]
        socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign,assignment]
        socket.create_connection = guarded_create_connection  # type: ignore[assignment]
        _installed.update(connect=guarded_connect, connect_ex=guarded_connect_ex,
                          create=guarded_create_connection)
    return True


def uninstall_egress_guard() -> None:
    """Undo one install; the original socket functions return when the count reaches zero."""
    global _depth
    with _lock:
        if _depth == 0:
            return
        _depth -= 1
        if _depth:
            return
        # Restore only what is still ours: if something patched over the guard, leave its
        # patch in place (it restores itself); our wrapper underneath is now inert.
        if socket.socket.connect is _installed["connect"]:
            socket.socket.connect = _originals["connect"]  # type: ignore[method-assign,assignment]
        if socket.socket.connect_ex is _installed["connect_ex"]:
            socket.socket.connect_ex = _originals["connect_ex"]  # type: ignore[method-assign,assignment]
        if socket.create_connection is _installed["create"]:
            socket.create_connection = _originals["create"]  # type: ignore[assignment]
        _originals.clear()
        _installed.clear()
