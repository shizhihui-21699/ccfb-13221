"""Response reading and the probe runner.

The runner opens one client connection to the front end, writes a sequence of
raw requests (a *probe* plus a benign *bait*), and reads every response until
the connection goes quiet.  Responses are parsed just enough to recover status
lines and bodies, so the engine can look for markers leaking across a boundary.

All traffic is tagged with unpredictable per-run nonces; that is what lets the
engine tell "the origin executed bytes I hid in a body" apart from ordinary
traffic.
"""

from __future__ import annotations

import os
import re
import socket
import time
from dataclasses import dataclass, field

__all__ = ["Response", "ProbeRun", "run_probe", "new_nonce"]

NONCE_RE = re.compile(r"ECHO ([A-Za-z0-9]+)")


def new_nonce(prefix: str = "n") -> str:
    return prefix + os.urandom(6).hex()


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    raw: bytes = b""

    def body_text(self) -> str:
        return self.body.decode("latin-1", "replace")

    def nonces(self) -> list[str]:
        return NONCE_RE.findall(self.body_text())

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "headers": [list(h) for h in self.headers],
            "body": self.body_text()[:2000],
            "nonces": self.nonces(),
        }


@dataclass
class ProbeRun:
    sent: bytes
    responses: list[Response]
    elapsed: float
    timed_out: bool
    error: str | None = None


def _parse_responses(data: bytes) -> list[Response]:
    out: list[Response] = []
    pos = 0
    n = len(data)
    while pos < n:
        # Find end of head.
        head_end = data.find(b"\r\n\r\n", pos)
        if head_end == -1:
            break
        head = data[pos:head_end]
        lines = head.split(b"\r\n")
        if not lines or not lines[0].startswith(b"HTTP/"):
            # Not a response boundary; stop.
            break
        try:
            status = int(lines[0].split(b" ")[1])
            reason = lines[0].split(b" ", 2)[2].decode("latin-1") if len(lines[0].split(b" ", 2)) > 2 else ""
        except (IndexError, ValueError):
            break
        headers: list[tuple[str, str]] = []
        length: int | None = None
        chunked = False
        for line in lines[1:]:
            if b":" not in line:
                continue
            k, v = line.split(b":", 1)
            ks = k.decode("latin-1").strip()
            vs = v.decode("latin-1").strip()
            headers.append((ks, vs))
            if ks.lower() == "content-length":
                try:
                    length = int(vs)
                except ValueError:
                    pass
            if ks.lower() == "transfer-encoding" and "chunked" in vs.lower():
                chunked = True
        body_start = head_end + 4
        if chunked:
            body, pos = _read_chunked(data, body_start)
        elif length is not None:
            body = data[body_start:body_start + length]
            pos = body_start + length
        else:
            body = data[body_start:]
            pos = n
        out.append(Response(status, reason, headers, body, data[pos - len(body):pos]))
        if pos >= n:
            break
    return out


def _read_chunked(data: bytes, pos: int) -> tuple[bytes, int]:
    body = b""
    n = len(data)
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            return body, n
        size_field = data[pos:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            return body, n
        if size == 0:
            trailer_end = data.find(b"\r\n\r\n", line_end)
            if trailer_end == -1:
                return body, n
            return body, trailer_end + 4
        body += data[line_end + 2:line_end + 2 + size]
        pos = line_end + 2 + size + 2


def run_probe(
    host: str,
    port: int,
    sequence: list[bytes],
    *,
    read_timeout: float = 1.2,
    connect_timeout: float = 3.0,
    half_close: bool = False,
    idle_gap: float | None = None,
) -> ProbeRun:
    """Send ``sequence`` back to back on one connection and read responses.

    ``read_timeout`` is the overall quiet window.  When ``idle_gap`` is set and
    at least one complete response has arrived, reading stops as soon as that
    many seconds pass with no further bytes -- useful against keep-alive servers
    where blocking until ``read_timeout`` would waste time.
    """
    payload = b"".join(sequence)
    t0 = time.time()
    responses: list[Response] = []
    raw = b""
    timed_out = False
    error: str | None = None
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
        sock.settimeout(read_timeout)
        sock.sendall(payload)
        if half_close:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        deadline = time.time() + read_timeout
        last_data = time.time()
        while time.time() < deadline:
            if idle_gap is not None and raw and (time.time() - last_data) >= idle_gap:
                break
            try:
                sock.settimeout(min(0.05, read_timeout) if idle_gap is not None else read_timeout)
                chunk = sock.recv(65536)
            except socket.timeout:
                if idle_gap is not None:
                    if raw and (time.time() - last_data) >= idle_gap:
                        break
                    continue
                timed_out = True
                break
            if not chunk:
                break
            raw += chunk
            last_data = time.time()
            # Extend deadline slightly while data keeps flowing.
            deadline = time.time() + read_timeout
        responses = _parse_responses(raw)
    except OSError as e:
        error = f"{type(e).__name__}: {e}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return ProbeRun(
        sent=payload,
        responses=responses,
        elapsed=time.time() - t0,
        timed_out=timed_out,
        error=error,
    )
