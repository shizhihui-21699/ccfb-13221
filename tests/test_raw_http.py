"""Unit tests for byte-level HTTP construction/parsing (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smuggler.raw_http import (CRLF, RawRequest, RawResponse,
                               parse_response)
from smuggler.variants import (CL_STYLES, EOL_STYLES, ProbeContext,
                               REGISTRY, TE_STYLES, build_clte, build_tecl)


class TestRawRequest(unittest.TestCase):
    def test_canonical_bytes(self):
        req = RawRequest(
            headers=[(b"Host", b"x"), (b"Content-Length", b"5")],
            body=b"hello")
        self.assertEqual(
            req.to_bytes(),
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")

    def test_bare_lf_preserved(self):
        req = RawRequest(headers=[(b"Host", b"x")], body=b"", eol=b"\n")
        self.assertEqual(req.to_bytes(), b"POST / HTTP/1.1\nHost: x\n\n")

    def test_obfuscated_header_whitespace_preserved(self):
        req = RawRequest(headers=[(b"Transfer-Encoding ", b"chunked")],
                         body=b"")
        self.assertIn(b"Transfer-Encoding : chunked", req.to_bytes())

    def test_duplicate_headers_kept_in_order(self):
        req = RawRequest(headers=[(b"Content-Length", b"4"),
                                  (b"Content-Length", b"11")])
        raw = req.to_bytes()
        self.assertLess(raw.index(b"Content-Length: 4"),
                        raw.index(b"Content-Length: 11"))


class TestResponseParsing(unittest.TestCase):
    def test_fixed_length_with_leftover(self):
        data = (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        resp, leftover = parse_response(data)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, b"hello")
        self.assertTrue(leftover.startswith(b"HTTP/1.1"))

    def test_chunked_decoding_and_leftover(self):
        body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
        resp, leftover = parse_response(data)
        self.assertEqual(resp.body, b"hello world")
        self.assertEqual(leftover, b"")

    def test_bare_lf_response_headers(self):
        data = b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok"
        resp, leftover = parse_response(data)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, b"ok")

    def test_obs_fold_merged(self):
        data = (b"HTTP/1.1 200 OK\r\nX-Multi: one\r\n two\r\n"
                b"Content-Length: 0\r\n\r\n")
        resp, _ = parse_response(data)
        self.assertEqual(resp.header(b"X-Multi"), b"one two")


class TestVariantCatalog(unittest.TestCase):
    def test_registry_nonempty_and_unique(self):
        ids = [v.vid for v in REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreater(len(REGISTRY), 80)

    def test_every_variant_builds_all_probe_kinds(self):
        ctx = ProbeContext(marker="smg-test", host="127.0.0.1",
                           canary_path="/__smuggler/canary/smg-test")
        for variant in REGISTRY:
            for kind in ("control", "timing", "canary"):
                req = variant.build(ctx, kind)
                raw = req.to_bytes()
                self.assertIsInstance(raw, bytes)
                first_line = (raw.split(b"\r", 1)[0]
                              if b"\r" in raw else raw.split(b"\n", 1)[0])
                self.assertIn(b"HTTP/1.", first_line)

    def test_clte_timing_contains_incomplete_trailing_post(self):
        ctx = ProbeContext(marker="m", host="h",
                           canary_path="/__smuggler/canary/m")
        req = build_clte(TE_STYLES[0], CRLF, ctx, "timing")
        self.assertIn(b"Content-Length: 50000", req.body)
        self.assertTrue(req.body.rstrip(b"\r\n").endswith(b"x="))
        self.assertIn(b"Transfer-Encoding: chunked", req.to_bytes())

    def test_clte_canary_embeds_smuggled_get(self):
        ctx = ProbeContext(marker="m", host="h",
                           canary_path="/__smuggler/canary/m")
        req = build_clte(TE_STYLES[0], CRLF, ctx, "canary")
        self.assertIn(b"GET /__smuggler/canary/m HTTP/1.1", req.body)

    def test_tecl_control_has_no_smuggled_line(self):
        ctx = ProbeContext(marker="m", host="h",
                           canary_path="/__smuggler/canary/m")
        req = build_tecl(TE_STYLES[0], None, CRLF, ctx, "control")
        self.assertNotIn(b"GET /__smuggler", req.body)

    def test_tecl_timing_gpost_declares_underfull_cl(self):
        ctx = ProbeContext(marker="m", host="h",
                           canary_path="/__smuggler/canary/m")
        req = build_tecl(TE_STYLES[0], None, CRLF, ctx, "timing",
                         gpost=True)
        self.assertIn(b"GPOST", req.body)
        self.assertIn(b"Content-Length: 50000", req.body)

    def test_style_counts(self):
        self.assertGreaterEqual(len(TE_STYLES), 20)
        self.assertGreaterEqual(len(CL_STYLES), 12)
        self.assertEqual(len(EOL_STYLES), 3)


if __name__ == "__main__":
    unittest.main()
