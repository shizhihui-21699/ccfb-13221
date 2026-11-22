"""Parser unit tests: each dialect's framing decision on the same bytes.

Run with ``python3 -m unittest discover -s tests`` (no third-party deps).
"""

from __future__ import annotations

import unittest

from smugglelab import dialects as D
from smugglelab.httpdialect import NeedMore, Reject, parse_request


def frame(raw: bytes, d) -> tuple[str, int | None, int]:
    r = parse_request(raw, d)
    return r.framing.kind, r.framing.length, r.consumed


class TeClFraming(unittest.TestCase):
    both = (
        b"POST /a HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    )

    def test_rejecting_hops_refuse_te_plus_cl(self):
        for d in (D.HAPROXY, D.PYTHON_ORIGIN, D.GO_ORIGIN, D.ENVOY):
            with self.subTest(dialect=d.name):
                with self.assertRaises(Reject):
                    parse_request(self.both, d)

    def test_chunked_wins_hops_use_te(self):
        for d in (D.NGINX, D.APACHE_PROXY, D.JAVA_ORIGIN, D.LEGACY_LB):
            if d.te_with_cl != "chunked_wins":
                continue
            with self.subTest(dialect=d.name):
                kind, length, _ = frame(self.both, d)
                self.assertEqual(kind, "chunked")

    def test_cl_wins_hops_use_content_length(self):
        kind, length, _ = frame(self.both, D.NODE_ORIGIN)
        self.assertEqual((kind, length), ("length", 5))


class DuplicateContentLength(unittest.TestCase):
    raw = (
        b"POST /a HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 3\r\nContent-Length: 6\r\n\r\nAAAAAA"
    )

    def test_first_wins(self):
        for d in (D.APACHE_PROXY, D.LEGACY_LB, D.LOOSE_PROXY, D.NODE_ORIGIN):
            with self.subTest(dialect=d.name):
                self.assertEqual(frame(self.raw, d)[:2], ("length", 3))

    def test_last_wins(self):
        for d in (D.NGINX, D.PYTHON_ORIGIN, D.JAVA_ORIGIN, D.TE_FIRST_ONLY):
            with self.subTest(dialect=d.name):
                self.assertEqual(frame(self.raw, d)[:2], ("length", 6))

    def test_reject(self):
        for d in (D.HAPROXY, D.GO_ORIGIN, D.ENVOY):
            with self.subTest(dialect=d.name):
                with self.assertRaises(Reject):
                    parse_request(self.raw, d)


class WhitespaceBeforeColon(unittest.TestCase):
    raw = b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\nAAAAA"

    def test_strict_rejects(self):
        for d in (D.NGINX, D.HAPROXY, D.ENVOY, D.PYTHON_ORIGIN, D.GO_ORIGIN):
            with self.subTest(dialect=d.name):
                with self.assertRaises(Reject):
                    parse_request(self.raw, d)

    def test_lenient_accepts(self):
        for d in (D.APACHE_PROXY, D.LOOSE_PROXY, D.LEGACY_ORIGIN, D.NODE_ORIGIN):
            with self.subTest(dialect=d.name):
                self.assertEqual(frame(self.raw, d)[:2], ("length", 5))


class BareLf(unittest.TestCase):
    raw = b"POST /a HTTP/1.1\nHost: x\nContent-Length: 3\n\nAAAA"

    def test_strict_rejects(self):
        for d in (D.NGINX, D.HAPROXY, D.ENVOY, D.PYTHON_ORIGIN):
            with self.subTest(dialect=d.name):
                with self.assertRaises(Reject):
                    parse_request(self.raw, d)

    def test_lenient_accepts(self):
        for d in (D.LOOSE_PROXY, D.LEGACY_ORIGIN):
            with self.subTest(dialect=d.name):
                self.assertEqual(frame(self.raw, d)[:2], ("length", 3))


class TeListHandling(unittest.TestCase):
    def test_chunked_not_last_rejected_by_strict(self):
        raw = (
            b"POST /a HTTP/1.1\r\nHost: x\r\n"
            b"Transfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n"
        )
        with self.assertRaises(Reject):
            parse_request(raw, D.HAPROXY)

    def test_unknown_coding_after_chunked(self):
        raw = (
            b"POST /a HTTP/1.1\r\nHost: x\r\n"
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n0\r\n\r\n"
        )
        # A hop that only reads the first TE header frames chunked...
        self.assertEqual(parse_request(raw, D.TE_FIRST_ONLY).framing.kind, "chunked")
        # ...while a strict hop refuses the unknown coding.
        with self.assertRaises(Reject):
            parse_request(raw, D.NGINX)


class TeFallback(unittest.TestCase):
    raw = (
        b"POST /a HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 40\r\n"
        b"Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n"
    )

    def test_fallback_uses_content_length(self):
        r = parse_request(self.raw + b"A" * 40, D.TE_FALLBACK)
        self.assertEqual(r.framing.kind, "length")
        self.assertEqual(r.framing.length, 40)


class IncompleteInput(unittest.TestCase):
    def test_incomplete_head(self):
        with self.assertRaises(NeedMore):
            parse_request(b"POST /a HTTP/1.1\r\nHost: x\r\n", D.NGINX)

    def test_incomplete_body(self):
        with self.assertRaises(NeedMore):
            parse_request(b"POST /a HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc", D.NGINX)


class RequestLine(unittest.TestCase):
    def test_extra_spaces_rejected_by_strict(self):
        with self.assertRaises(Reject):
            parse_request(b"POST  /a  HTTP/1.1\r\n\r\n", D.NGINX)

    def test_javastyle_accepts_extra_ws(self):
        r = parse_request(b"POST  /a  HTTP/1.1\r\n\r\n", D.JAVA_ORIGIN)
        self.assertEqual(r.target, "/a")


if __name__ == "__main__":
    unittest.main()
