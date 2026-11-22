"""Loopback-only lab front-end proxy.

The proxy accepts a client connection, parses each request with ITS
ParserProfile, slices the exact byte range it considers one message, and
forwards those bytes over one persistent upstream connection to the backend.
Responses are relayed back verbatim.

Smuggling happens precisely when the proxy's slice differs from the
backend's slice: bytes the proxy considered part of request N arrive as the
start of request N+1 (or get merged into the body) on the backend.

A `rebuild-hardened` profile additionally re-encodes the message instead of
forwarding raw bytes, which collapses every ambiguity it can parse.
"""

from __future__ import annotations

import socket
import threading

from .parser import ParseReject, ParserProfile, parse_one


class LabProxy:
    def __init__(self, listen_port: int, backend_port: int,
                 profile: ParserProfile, read_timeout: float = 8.0):
        self.listen_port = listen_port
        self.backend_port = backend_port
        self.profile = profile
        self.read_timeout = read_timeout
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.listen_port))
        sock.listen(16)
        sock.settimeout(0.25)
        self._sock = sock
        self._thread = threading.Thread(
            target=self._accept_loop,
            name=f"proxy-{self.listen_port}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._pump, args=(client,),
                             daemon=True).start()

    def _pump(self, client: socket.socket) -> None:
        try:
            upstream = socket.create_connection(
                ("127.0.0.1", self.backend_port), timeout=self.read_timeout)
        except OSError:
            client.close()
            return
        upstream.settimeout(self.read_timeout)
        client.settimeout(self.read_timeout)
        buf = bytearray()
        try:
            while not self._stop.is_set():
                frame = self._next_frame(client, buf)
                if frame is None:
                    return
                upstream.sendall(frame)
                self._relay_response(upstream, client)
        except (ConnectionError, OSError, ParseReject):
            pass
        finally:
            client.close()
            upstream.close()

    def _next_frame(self, client: socket.socket,
                    buf: bytearray) -> bytes | None:
        """Return the raw bytes of exactly one request per the proxy profile."""
        while True:
            try:
                parsed = parse_one(bytes(buf), self.profile)
            except ParseReject as exc:
                if exc.close:
                    self._reject(client, exc.status, exc.reason)
                    raise ConnectionError(exc.reason)
            else:
                if len(buf) >= parsed.consumed:
                    frame = bytes(buf[:parsed.consumed])
                    del buf[:parsed.consumed]
                    if self.profile.name == "rebuild-hardened":
                        return self._rebuild(parsed)
                    return frame
            try:
                chunk = client.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return None
            buf.extend(chunk)

    def _rebuild(self, parsed) -> bytes:
        lines = [f"{parsed.method} {parsed.target} {parsed.version}"]
        has_cl = any(n.lower() == b"content-length" for n, _ in parsed.headers)
        for name, value in parsed.headers:
            if name.lower() == b"transfer-encoding":
                continue  # re-emitted canonically below when needed
            lines.append(f"{name.decode('latin1')}: {value.decode('latin1')}")
        if parsed.used_chunked:
            lines.append("Transfer-Encoding: chunked")
            body = (f"{len(parsed.body):x}\r\n".encode() + parsed.body
                    + b"\r\n0\r\n\r\n")
        else:
            if not has_cl:
                lines.append(f"Content-Length: {len(parsed.body)}")
            body = parsed.body
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + body

    def _relay_response(self, upstream: socket.socket,
                        client: socket.socket) -> None:
        """Relay exactly one backend response (headers + framed body)."""
        upstream.setblocking(False)
        head = bytearray()
        deadline = self._deadline()
        while b"\r\n\r\n" not in head:
            if self._stop.is_set():
                return
            try:
                chunk = upstream.recv(65536)
            except BlockingIOError:
                if self._expired(deadline):
                    raise ConnectionError("response header timeout")
                continue
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("upstream closed")
            head.extend(chunk)
        idx = head.index(b"\r\n\r\n") + 4
        header_bytes = bytes(head[:idx])
        client.sendall(header_bytes)
        length, chunked = self._body_framing(header_bytes)
        rest = bytearray(head[idx:])
        if chunked:
            self._relay_chunked(upstream, client, rest)
        elif length is not None:
            self._relay_fixed(upstream, client, rest, length)
        else:
            client.sendall(rest)

    def _relay_fixed(self, upstream, client, rest: bytearray,
                     length: int) -> None:
        sent = len(rest)
        client.sendall(rest)
        while sent < length:
            chunk = upstream.recv(65536)
            if not chunk:
                raise ConnectionError("upstream closed mid-body")
            client.sendall(chunk)
            sent += len(chunk)

    def _relay_chunked(self, upstream, client, rest: bytearray) -> None:
        client.sendall(rest)
        # Forward until the terminating 0-chunk has been observed.
        pending = bytes(rest)
        while b"\r\n0\r\n" not in pending and b"\n0\n" not in pending:
            chunk = upstream.recv(65536)
            if not chunk:
                raise ConnectionError("upstream closed mid-chunk")
            client.sendall(chunk)
            pending = (pending + chunk)[-256:]

    def _body_framing(self, header_bytes: bytes) -> tuple[int | None, bool]:
        length = None
        chunked = False
        for line in header_bytes.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"content-length:"):
                try:
                    length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    length = None
            elif low.startswith(b"transfer-encoding:"):
                chunked = b"chunked" in line.lower()
        return length, chunked

    def _deadline(self) -> float:
        import time
        return time.monotonic() + self.read_timeout

    def _expired(self, deadline: float) -> bool:
        import time
        return time.monotonic() > deadline

    def _reject(self, client: socket.socket, status: int, reason: str) -> None:
        body = reason.encode()
        payload = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + body
        try:
            client.sendall(payload)
        except OSError:
            pass
