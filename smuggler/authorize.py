"""Target authorization guard.

By default only loopback / private-address targets are allowed. Anything else
requires an explicit acknowledgement flag (and an environment variable for
non-interactive runs) so the tool cannot be pointed at third-party systems by
accident.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

ENVVAR = "SMUGGLER_CONFIRM"
CONFIRM_TEXT = "YES_I_HAVE_AUTHORIZATION"


def _hostname_to_ips(host: str) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    out: list[ipaddress._BaseAddress] = []
    for info in infos:
        addr = info[4][0]
        try:
            out.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    return out


def is_private_target(host: str) -> bool:
    """Loopback, RFC1918, link-local or unique-local addresses are allowed."""
    if host in ("localhost",):
        return True
    for ip in _hostname_to_ips(host):
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return True
        # is_unique_local only exists on IPv4Address.
        if getattr(ip, "is_unique_local", False):
            return True
    return False


def assert_authorized(target: str, acknowledged: bool) -> None:
    """Raise PermissionError unless the target is safe to probe."""
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or ""
    if is_private_target(host):
        return
    if not acknowledged:
        raise PermissionError(
            f"{host!r} is not a loopback/private address. Refusing to probe. "
            f"Re-run with --i-have-authorization once you have written permission."
        )
    if os.environ.get(ENVVAR) != CONFIRM_TEXT:
        raise PermissionError(
            f"Non-interactive confirmation missing: set {ENVVAR}={CONFIRM_TEXT} "
            "in the environment to probe a non-private target."
        )
