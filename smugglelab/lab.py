"""A two-hop HTTP lab: a front-end proxy and a back-end origin.

The front hop parses client bytes with ``front``'s dialect and forwards them to
the back hop, which parses them again with ``back``'s dialect.  When the two
disagree, bytes one hop considers "body" become a request to the other -- HTTP
request smuggling.

Two features make this a faithful and *testable* range:

* **An upstream connection pool.**  Like a real load balancer, the front end
  keeps back-end connections alive and lends them to different clients.  A
  desync can therefore poison a connection and deliver an attacker's smuggled
  response to another client -- the cross-user impact that makes smuggling
  dangerous, and the signal black-box detection relies on.

* **A framing recorder.**  Each hop records every request *it* framed.  For a
  single probe run (reset -> drive -> snapshot) the back end having framed a
  request the front end never framed is exact proof of a desync, with no
  timing heuristics.  The harness uses this as ground truth to score the
  response-based detector's false positives.

This is a local test range.  It listens on loopback only.
"""

from __future__ import annotations

import select
import socket
import threading
import time
from dataclasses import dataclass

from .httpdialect import Dialect, NeedMore, Reject, Request, parse_request, render_request

__all__ = ["Lab", "LabConfig", "FrameRecord"]


@dataclass
class FrameRecord:
    hop: str                    # "front" | "back"
    client_conn: int            # client connection id the front assigned
    seq: int                    # 1-based order within that connection
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    framing: dict
    raw_head: bytes
    body: bytes
    time: float

    @property
    def nonce(self) -> str | None:
        path = self.target.split("?", 1)[0]
        if path.startswith("/__lab/echo/"):
            return path.rsplit("/", 1)[-1]
        return None

    def as_dict(self) -> dict:
        return {
            "hop": self.hop,
            "client_conn": self.client_conn,
            "seq": self.seq,
            "method": self.method,
            "target": self.target,
            "version": self.version,
            "headers": [list(h) for h in self.headers],
            "framing": self.framing,
            "raw_head": self.raw_head.decode("latin-1"),
            "body_len": len(self.body),
            "nonce": self.nonce,
        }


@dataclass
class LabConfig:
    front: Dialect
    back: Dialect
    host: str = "127.0.0.1"
    front_port: int = 0
    back_port: int = 0
    name: str = "lab"
    pool_upstream: bool = True
    pool_max_idle: int = 8


class _Recorder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.records: list[FrameRecord] = []

    def add(self, r: FrameRecord) -> None:
        with self._lock:
            self.records.append(r)

    def snapshot(self) -> list[FrameRecord]:
        with self._lock:
            return list(self.records)

    def clear(self) -> None:
        with self._lock:
            self.records.clear()


def _response(status: int, reason: str, body: bytes) -> bytes:
    lines = [
        f"HTTP/1.1 {status} {reason}",
        f"Content-Length: {len(body)}",
        "Content-Type: text/plain; charset=utf-8",
        "Connection: keep-alive",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


class _BackEnd:
    """The origin.  Parses with ``cfg.back`` and records every framed request."""

    def __init__(self, cfg: LabConfig, recorder: _Recorder):
        self.cfg = cfg
        self.recorder = recorder
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._conn_seq = 0
        self._lock = threading.Lock()

    def start(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.cfg.host, self.cfg.back_port))
        s.listen(128)
        self.sock = s
        self.cfg.back_port = s.getsockname()[1]
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        return self.cfg.back_port

    def stop(self) -> None:
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()  # type: ignore[union-attr]
            except OSError:
                return
            with self._lock:
                self._conn_seq += 1
                cid = -self._conn_seq  # negative: not a client connection
            threading.Thread(target=self._serve, args=(conn, cid), daemon=True).start()

    def _serve(self, conn: socket.socket, cid: int) -> None:
        buf = b""
        seq = 0
        try:
            conn.settimeout(30.0)
            while not self._stop.is_set():
                if not buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    buf += chunk
                    continue
                try:
                    req = parse_request(buf, self.cfg.back)
                except NeedMore:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    buf += chunk
                    continue
                except Reject as e:
                    conn.sendall(_response(e.status, "Bad Request", e.reason.encode()))
                    return
                buf = buf[req.consumed:]
                seq += 1
                self._record_and_answer(conn, req, cid, seq)
                if req.get("connection", "").lower() == "close":
                    return
        except (OSError, ConnectionError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _record_and_answer(self, conn: socket.socket, req: Request, cid: int, seq: int) -> None:
        self.recorder.add(
            FrameRecord(
                hop="back",
                client_conn=cid,
                seq=seq,
                method=req.method,
                target=req.target,
                version=req.version,
                headers=req.headers,
                framing=req.framing.as_dict(),
                raw_head=req.raw_head,
                body=req.body,
                time=time.time(),
            )
        )
        path = req.target.split("?", 1)[0]
        if path.startswith("/__lab/echo/"):
            nonce = path.rsplit("/", 1)[-1]
            conn.sendall(_response(200, "OK", f"ECHO {nonce}".encode()))
            return
        if path == "/__lab/noop":
            conn.sendall(_response(200, "OK", b"noop"))
            return
        conn.sendall(_response(404, "Not Found", f"no route for {req.target}".encode()))


class _UpstreamPool:
    """Idle back-end sockets, reused across client connections (LIFO)."""

    def __init__(self, cfg: LabConfig):
        self.cfg = cfg
        self._idle: list[socket.socket] = []
        self._lock = threading.Lock()

    def borrow(self) -> socket.socket:
        while True:
            with self._lock:
                if self._idle:
                    return self._idle.pop()
            s = socket.create_connection((self.cfg.host, self.cfg.back_port), timeout=10.0)
            s.settimeout(30.0)
            return s

    def give_back(self, sock: socket.socket) -> None:
        with self._lock:
            if len(self._idle) < self.cfg.pool_max_idle:
                self._idle.append(sock)
                return
        try:
            sock.close()
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            for s in self._idle:
                try:
                    s.close()
                except OSError:
                    pass
            self._idle.clear()


class _FrontEnd:
    """The proxy.  Parses with ``cfg.front``, then forwards to a pooled upstream."""

    def __init__(self, cfg: LabConfig, recorder: _Recorder, pool: _UpstreamPool):
        self.cfg = cfg
        self.recorder = recorder
        self.pool = pool
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._conn_seq = 0
        self._lock = threading.Lock()

    def start(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.cfg.host, self.cfg.front_port))
        s.listen(128)
        self.sock = s
        self.cfg.front_port = s.getsockname()[1]
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        return self.cfg.front_port

    def stop(self) -> None:
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()  # type: ignore[union-attr]
            except OSError:
                return
            with self._lock:
                self._conn_seq += 1
                cid = self._conn_seq
            threading.Thread(target=self._serve, args=(conn, cid), daemon=True).start()

    def _serve(self, conn: socket.socket, cid: int) -> None:
        if self.cfg.pool_upstream:
            upstream = self.pool.borrow()
            reusable = True
        else:
            try:
                upstream = socket.create_connection((self.cfg.host, self.cfg.back_port), timeout=10.0)
                upstream.settimeout(30.0)
                reusable = False
            except OSError:
                conn.close()
                return

        conn.settimeout(30.0)
        cbuf = b""
        ubuf_pending = b""   # read from upstream, not yet sent to client
        seq = 0
        client_open = True
        try:
            while not self._stop.is_set():
                if not client_open and not ubuf_pending:
                    break
                rlist = [upstream]
                if client_open:
                    rlist.append(conn)
                try:
                    readable, _, _ = select.select(rlist, [], [], 0.2)
                except (OSError, ValueError):
                    break
                if upstream in readable:
                    try:
                        data = upstream.recv(65536)
                    except OSError:
                        reusable = False
                        break
                    if not data:
                        reusable = False
                        break
                    ubuf_pending += data
                    if client_open:
                        try:
                            conn.sendall(ubuf_pending)
                            ubuf_pending = b""
                        except OSError:
                            client_open = False
                if client_open and conn in readable:
                    try:
                        data = conn.recv(65536)
                    except OSError:
                        client_open = False
                        data = b""
                    if not data:
                        client_open = False
                    else:
                        cbuf += data
                        while True:
                            try:
                                req = parse_request(cbuf, self.cfg.front)
                            except NeedMore:
                                break
                            except Reject as e:
                                try:
                                    conn.sendall(_response(e.status, "Bad Request", e.reason.encode()))
                                except OSError:
                                    client_open = False
                                cbuf = b""
                                break
                            cbuf = cbuf[req.consumed:]
                            seq += 1
                            self.recorder.add(
                                FrameRecord(
                                    hop="front",
                                    client_conn=cid,
                                    seq=seq,
                                    method=req.method,
                                    target=req.target,
                                    version=req.version,
                                    headers=req.headers,
                                    framing=req.framing.as_dict(),
                                    raw_head=req.raw_head,
                                    body=req.body,
                                    time=time.time(),
                                )
                            )
                            try:
                                upstream.sendall(render_request(req, self.cfg.front))
                            except OSError:
                                reusable = False
                                client_open = False
                                break
        except (OSError, ConnectionError):
            reusable = False
        finally:
            try:
                conn.close()
            except OSError:
                pass
            if self.cfg.pool_upstream and reusable:
                self.pool.give_back(upstream)
            else:
                try:
                    upstream.close()
                except OSError:
                    pass


class Lab:
    """A running pair of hops.  Use as a context manager."""

    def __init__(self, cfg: LabConfig):
        self.cfg = cfg
        self.recorder = _Recorder()
        self.pool = _UpstreamPool(cfg)
        self.back = _BackEnd(cfg, self.recorder)
        self.front = _FrontEnd(cfg, self.recorder, self.pool)

    def __enter__(self) -> "Lab":
        self.back.start()
        self.front.start()
        return self

    def __exit__(self, *exc) -> None:
        self.front.stop()
        self.back.stop()
        self.pool.close()

    @property
    def front_port(self) -> int:
        return self.cfg.front_port

    @property
    def back_port(self) -> int:
        return self.cfg.back_port

    def frames(self, hop: str | None = None) -> list[FrameRecord]:
        recs = self.recorder.snapshot()
        if hop is None:
            return recs
        return [r for r in recs if r.hop == hop]

    def reset(self) -> None:
        self.recorder.clear()

    def info(self) -> dict:
        return {
            "name": self.cfg.name,
            "front": self.cfg.front.name,
            "back": self.cfg.back.name,
            "front_port": self.cfg.front_port,
            "back_port": self.cfg.back_port,
        }
