"""Byte-level HTTP/1.1 request construction and response parsing.

Everything here works on raw bytes so that ambiguous framing (bare LF,
obfuscated headers, duplicate length fields) is preserved exactly — using a
high-level client library would normalize the very things we test.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional

CRLF = b"\r\n"
LF = b"\n"
CR = b"\r"
HEADER_END = b"\r\n\r\n"


class RawHTTPError(Exception):
    pass


@dataclass
class RawRequest:
    """A raw request. `body` is included verbatim; the builder does not
    re-derive Content-Length, because length-header disagreement is what we
    are probing."""

    method: str = "POST"
    target: str = "/"
    version: str = "HTTP/1.1"
    # Each header is (name-bytes-or-None, value-bytes).
    # name=None means a "bare" line already encoded in value (fold lines etc.).
    headers: list[tuple[Optional[bytes], bytes]] = field(default_factory=list)
    body: bytes = b""
    # Line ending used between header lines (CRLF default; bare LF probes).
    eol: bytes = CRLF

    def to_bytes(self) -> bytes:
        line = f"{self.method} {self.target} {self.version}".encode()
        out = [line]
        for name, value in self.headers:
            if name is None:
                out.append(value)
            else:
                out.append(name + b": " + value)
        head = self.eol.join(out)
        return head + self.eol + self.eol + self.body

    def header_names(self) -> list[bytes]:
        return [n.lower() for n, _ in self.headers if n is not None]


@dataclass
class RawResponse:
    version: bytes
    status: int
    reason: bytes
    headers: list[tuple[bytes, bytes]]
    body: bytes
    raw: bytes
    socket_alive: bool
    elapsed: float

    def header(self, name: bytes) -> Optional[bytes]:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_all(self, name: bytes) -> list[bytes]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


@dataclass
class ExchangeResult:
    """Result of one send: the response (or None on timeout) plus any bytes
    the server sent after the response body — a smuggled/queued response is
    exactly such leftover traffic."""

    response: Optional[RawResponse]
    leftover: bytes
    timed_out: bool
    elapsed: float
    error: Optional[str] = None


def _recv_until(sock: socket.socket, marker: bytes, timeout: float,
                initial: bytearray) -> Optional[bytearray]:
    sock.settimeout(timeout)
    buf = initial
    while marker not in buf:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            return None
        if not chunk:
            break
        buf.extend(chunk)
    return buf


def _parse_headers(head: bytes) -> tuple[bytes, int, bytes, list[tuple[bytes, bytes]]]:
    # Tolerate LF-only and CR-only servers when splitting.
    text = head.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = text.split(b"\n")
    status_line = lines[0]
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        raise RawHTTPError(f"malformed status line: {status_line!r}")
    version = parts[0]
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise RawHTTPError(f"non-numeric status: {status_line!r}") from exc
    reason = parts[2] if len(parts) > 2 else b""
    headers: list[tuple[bytes, bytes]] = []
    i = 1
    while i < len(lines):
        line = lines[i]
        if not line:
            break
        # obs-fold: continuation lines (leading SP/HTAB) merge into previous.
        if line[:1] in (b" ", b"\t") and headers:
            k, v = headers[-1]
            headers[-1] = (k, v + b" " + line[1:].lstrip())
            i += 1
            continue
        if b":" not in line:
            raise RawHTTPError(f"malformed header line: {line!r}")
        name, value = line.split(b":", 1)
        headers.append((name.strip(), value.strip()))
        i += 1
    return version, status, reason, headers


def _expected_body_length(resp: RawResponse, method: str) -> Optional[int]:
    """How many body bytes to read per HTTP/1.1 framing rules.
    Returns None when the body runs until connection close."""
    if method == "HEAD":
        return 0
    if 100 <= resp.status < 200 or resp.status in (204, 304):
        return 0
    te = resp.header(b"transfer-encoding")
    if te and b"chunked" in te.lower():
        return None  # handled by chunk reader below via sentinel
    cl = resp.header(b"content-length")
    if cl is not None:
        try:
            return int(cl.split(b",")[0].strip())
        except ValueError:
            return None
    return None


def _dechunk(buf: bytearray) -> tuple[bytes, int]:
    """Decode chunked body from buf; returns (body, bytes-consumed).
    Raises on truncation."""
    out = bytearray()
    pos = 0
    while True:
        end = buf.find(b"\r\n", pos)
        if end == -1:
            raise RawHTTPError("truncated chunk size line")
        size_line = bytes(buf[pos:end]).split(b";")[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError as exc:
            raise RawHTTPError(f"bad chunk size {size_line!r}") from exc
        pos = end + 2
        if size == 0:
            # trailers until blank line
            trail_end = buf.find(b"\r\n", pos)
            while trail_end != -1 and trail_end != pos:
                pos = trail_end + 2
                trail_end = buf.find(b"\r\n", pos)
            if trail_end == -1:
                raise RawHTTPError("truncated trailers")
            return bytes(out), trail_end + 2
        if pos + size + 2 > len(buf):
            raise RawHTTPError("truncated chunk data")
        out.extend(buf[pos:pos + size])
        pos += size + 2


def parse_response(data: bytes, method: str = "GET",
                   socket_alive: bool = True,
                   elapsed: float = 0.0) -> tuple[RawResponse, bytes]:
    """Parse exactly one response out of `data`; return it plus leftover bytes."""
    # Find header terminator in any EOL flavor the peer used.
    idx = data.find(HEADER_END)
    sep_len = 4
    if idx == -1:
        for alt in (b"\n\n", b"\r\r"):
            idx = data.find(alt)
            if idx != -1:
                sep_len = 2
                break
    if idx == -1:
        raise RawHTTPError("no header terminator in response")
    head = data[:idx]
    rest = bytearray(data[idx + sep_len:])
    version, status, reason, headers = _parse_headers(head)
    resp = RawResponse(version, status, reason, headers, b"", data,
                       socket_alive, elapsed)
    te = resp.header(b"transfer-encoding")
    if te and b"chunked" in te.lower():
        body, consumed = _dechunk(rest)
        resp.body = body
        leftover = bytes(rest[consumed:])
    else:
        length = _expected_body_length(resp, method)
        if length is None:
            # Framed by connection close: everything belongs to this response.
            resp.body = bytes(rest)
            leftover = b""
        else:
            length = max(length, 0)
            resp.body = bytes(rest[:length])
            leftover = bytes(rest[length:])
    return resp, leftover


class Connection:
    """One TCP connection speaking raw HTTP/1.1 (or HTTPS)."""

    def __init__(self, host: str, port: int, tls: bool = False,
                 connect_timeout: float = 5.0):
        self.host = host
        self.port = port
        self.tls = tls
        self.connect_timeout = connect_timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port),
                                        timeout=self.connect_timeout)
        if self.tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        self.sock = sock

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self) -> "Connection":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def send_request(self, req: RawRequest, timeout: float = 10.0,
                     linger: float = 0.35) -> ExchangeResult:
        assert self.sock is not None
        raw = req.to_bytes()
        start = time.monotonic()
        try:
            self.sock.sendall(raw)
        except OSError as exc:
            return ExchangeResult(None, b"", False, time.monotonic() - start,
                                  f"send failed: {exc}")
        buf = bytearray()
        # Header read with timeout: a timeout here is the classic smuggling
        # timing signal (a queued request is waiting for more body bytes).
        head_res = _recv_until(self.sock, HEADER_END, timeout, buf)
        elapsed = time.monotonic() - start
        if head_res is None:
            return ExchangeResult(None, bytes(buf), True, elapsed)
        # Drain whatever is immediately available (body, queued responses).
        self.sock.setblocking(False)
        deadline = time.monotonic() + linger
        while time.monotonic() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except (BlockingIOError, ssl.SSLWantReadError):
                time.sleep(0.02)
                continue
            except ssl.SSLError as exc:
                return ExchangeResult(None, bytes(buf), False, elapsed,
                                      f"tls error: {exc}")
            except OSError as exc:
                try:
                    return self._finish(bytes(buf), req.method, False, elapsed,
                                        f"connection closed: {exc}")
                except RawHTTPError:
                    return ExchangeResult(None, bytes(buf), False, elapsed,
                                          str(exc))
            if not chunk:
                try:
                    return self._finish(bytes(buf), req.method, False, elapsed)
                except RawHTTPError as exc:
                    return ExchangeResult(None, bytes(buf), False, elapsed,
                                          str(exc))
            buf.extend(chunk)
        try:
            return self._finish(bytes(buf), req.method, True, elapsed)
        except RawHTTPError as exc:
            return ExchangeResult(None, bytes(buf), False, elapsed, str(exc))

    def _finish(self, data: bytes, method: str, alive: bool,
                elapsed: float, error: Optional[str] = None) -> ExchangeResult:
        if not data:
            return ExchangeResult(None, b"", alive, elapsed,
                                  error or "empty response")
        resp, leftover = parse_response(data, method, alive, elapsed)
        return ExchangeResult(resp, leftover, False, elapsed, error)
