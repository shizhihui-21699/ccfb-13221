"""Loopback-only lab backend.

Serves the canary/ping endpoints used by the detector and applies one
configurable ParserProfile per listening port. A backend keeps the
connection alive and keeps parsing queued messages, so a request smuggled
into its buffer genuinely becomes the next request on that connection —
including blocking the next real request while it waits for an unfinished
smuggled message (the timing signal the engine measures).
"""

from __future__ import annotations

import json
import socket
import threading
from dataclasses import dataclass, field

from .parser import ParseReject, ParserProfile, parse_one


@dataclass
class CanaryStore:
    hits: dict[str, dict] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, marker: str, peer: str, headers: list[tuple[bytes, bytes]]):
        with self.lock:
            self.hits[marker] = {
                "hit": True,
                "peer": peer,
                "headers": [(k.decode("latin1", "replace"),
                             v.decode("latin1", "replace"))
                            for k, v in headers],
            }

    def get(self, marker: str) -> dict | None:
        with self.lock:
            return self.hits.get(marker)


class LabBackend:
    def __init__(self, port: int, profile: ParserProfile,
                 store: CanaryStore, read_timeout: float = 8.0):
        self.port = port
        self.profile = profile
        self.store = store
        self.read_timeout = read_timeout
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", self.port))
        sock.listen(16)
        sock.settimeout(0.25)
        self._sock = sock
        self._thread = threading.Thread(
            target=self._accept_loop, name=f"backend-{self.port}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()

    # ------------------------------------------------------------------
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn, addr),
                             daemon=True).start()

    def _serve(self, conn: socket.socket, addr) -> None:
        conn.settimeout(self.read_timeout)
        buf = bytearray()
        try:
            while not self._stop.is_set():
                req = self._read_one(conn, buf)
                if req is None:
                    return
                parsed = req
                close = self._handle(conn, parsed)
                if close or parsed.wants_close:
                    return
        except (socket.timeout, ConnectionError, OSError):
            return
        finally:
            conn.close()

    def _read_one(self, conn: socket.socket,
                  buf: bytearray):
        """Block until one complete request (per this profile) is buffered."""
        while True:
            try:
                parsed = parse_one(bytes(buf), self.profile)
            except ParseReject as exc:
                if not exc.close and len(buf) < 1024 * 1024:
                    # Incomplete headers — wait for more bytes.
                    pass
                else:
                    self._send_error(conn, exc.status, exc.reason)
                    raise ConnectionError(exc.reason)
            else:
                # parse_one succeeded: verify the full body arrived.
                total = parsed.consumed
                if len(buf) >= total:
                    del buf[:total]
                    return parsed
            chunk = conn.recv(65536)
            if not chunk:
                return None
            buf.extend(chunk)

    def _handle(self, conn: socket.socket, parsed) -> bool:
        target = parsed.target
        if target.startswith("/__smuggler/canary/"):
            marker = target.rsplit("/", 1)[1]
            self.store.record(marker, "backend", parsed.headers)
            body = json.dumps({"canary": marker, "status": "recorded"}).encode()
            self._send(conn, 200, b"application/json", body, parsed)
            return False
        if target.startswith("/__smuggler/canaries"):
            marker = target.split("marker=", 1)[-1] if "marker=" in target else ""
            data = self.store.get(marker) or {"hit": False}
            self._send(conn, 200, b"application/json",
                       json.dumps(data).encode(), parsed)
            return False
        if target.startswith("/__smuggler/ping"):
            self._send(conn, 200, b"text/plain", b"pong", parsed)
            return False
        body = json.dumps({
            "backend": self.profile.name,
            "method": parsed.method,
            "target": parsed.target,
            "used_chunked": parsed.used_chunked,
            "declared_cl": parsed.declared_cl,
            "leftover_bytes": len(parsed.leftover),
        }).encode()
        self._send(conn, 200, b"application/json", body, parsed)
        return False

    def _send(self, conn: socket.socket, status: int,
              content_type: bytes, body: bytes, parsed) -> None:
        reason = {200: "OK", 400: "Bad Request", 502: "Bad Gateway"}.get(
            status, "OK")
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-Backend-Profile: {self.profile.name}\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode()
        conn.sendall(head + body)

    def _send_error(self, conn: socket.socket, status: int, reason: str) -> None:
        body = reason.encode()
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        try:
            conn.sendall(head + body)
        except OSError:
            pass
