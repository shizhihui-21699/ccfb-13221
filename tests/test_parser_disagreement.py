"""Tests that the lab parser profiles disagree exactly where intended."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lab.parser import (ParseReject, ParserProfile, PROFILES,
                        parse_one)
from smuggler.variants import (ProbeContext, TE_STYLES, build_clcl,
                               build_clte, build_tecl, build_tete,
                               _h)

CTX = ProbeContext(marker="m", host="127.0.0.1",
                   canary_path="/__smuggler/canary/m")


def feed(profile: ParserProfile, req_bytes: bytes):
    return parse_one(req_bytes, profile)


class TestCLTE(unittest.TestCase):
    def test_cl_front_te_back_slices_differ(self):
        front = PROFILES["lenient-cl"]     # ignores TE -> Content-Length
        back = PROFILES["lenient-te"]      # honors chunked
        req = build_clte(TE_STYLES[0], b"\r\n", CTX, "canary")
        raw = req.to_bytes()
        p_front = feed(front, raw)
        p_back = feed(back, raw)
        # Proxy forwards the whole CL-sized message in one go.
        self.assertEqual(p_front.consumed, len(raw))
        # Backend ends the first message at the 0-chunk, leaving the smuggled
        # GET queued as the next request.
        self.assertLess(p_back.consumed, len(raw))
        self.assertIn(b"GET /__smuggler/canary/m", p_back.leftover)

    def test_strict_pair_slices_identically(self):
        req = build_clte(TE_STYLES[0], b"\r\n", CTX, "canary")
        p1 = feed(PROFILES["strict"], req.to_bytes())
        p2 = feed(PROFILES["strict"], req.to_bytes())
        self.assertEqual(p1.consumed, p2.consumed)

    def test_obfuscated_te_only_recognized_by_lenient(self):
        # Space before colon in TE name.
        te = next(t for t in TE_STYLES if t.sid == "TE07")
        req = build_clte(te, b"\r\n", CTX, "canary")
        with self.assertRaises(ParseReject):
            feed(PROFILES["strict"], req.to_bytes())
        p = feed(PROFILES["lenient-te"], req.to_bytes())
        self.assertTrue(p.used_chunked)


class TestTECL(unittest.TestCase):
    def test_te_front_cl_back_slices_differ(self):
        front = PROFILES["lenient-te"]
        back = PROFILES["lenient-cl"]
        req = build_tecl(TE_STYLES[0], None, b"\r\n", CTX, "canary")
        raw = req.to_bytes()
        p_front = feed(front, raw)
        p_back = feed(back, raw)
        # Frontend consumes the whole chunked stream; backend stops after
        # only the first chunk (its Content-Length equals the size line).
        self.assertEqual(p_front.consumed, len(raw))
        self.assertLess(p_back.consumed, len(raw))
        self.assertTrue(len(p_back.leftover) > 0)


class TestTETE(unittest.TestCase):
    def test_first_vs_last_te_disagree(self):
        first = PROFILES["te-first-lenient"]
        last = PROFILES["lenient-te"]
        te_chunked = (_h("Transfer-Encoding", "chunked"),)
        te_x = (_h("Transfer-Encoding", "x"),)
        req = build_tete(te_chunked, te_x, b"\r\n", CTX, "canary")
        p_first = feed(first, req.to_bytes())
        p_last = feed(last, req.to_bytes())
        self.assertTrue(p_first.used_chunked)
        # "last" profile honors the second TE line (x) -> not chunked.
        self.assertFalse(p_last.used_chunked)


class TestCLCL(unittest.TestCase):
    def test_duplicate_length_first_vs_last(self):
        first = PROFILES["cl-first-lenient"]
        last = PROFILES["lenient-te"]
        req = build_clcl(None, None, b"\r\n", CTX, "canary")
        p_first = feed(first, req.to_bytes())
        p_last = feed(last, req.to_bytes())
        self.assertNotEqual(p_first.consumed, p_last.consumed)

    def test_strict_rejects_conflicting_duplicates(self):
        req = build_clcl(None, None, b"\r\n", CTX, "canary")
        with self.assertRaises(ParseReject):
            feed(PROFILES["strict"], req.to_bytes())


class TestLineEndings(unittest.TestCase):
    def test_bare_lf_rejected_by_strict_accepted_by_lenient(self):
        req = build_clte(TE_STYLES[0], b"\n", CTX, "control")
        with self.assertRaises(ParseReject):
            feed(PROFILES["strict"], req.to_bytes())
        p = feed(PROFILES["lenient-te"], req.to_bytes())
        self.assertIsNotNone(p)


class TestChunkQuirks(unittest.TestCase):
    def test_noncanonical_chunk_size_rejected_strict(self):
        # Plus-prefixed size (CQ07) inside a chunked body.
        raw = (b"POST / HTTP/1.1\r\nHost: h\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n+4\r\nabcd\r\n0\r\n\r\n")
        with self.assertRaises(ParseReject):
            feed(PROFILES["strict"], raw)
        p = feed(PROFILES["lenient-te"], raw)
        self.assertEqual(p.body, b"abcd")


if __name__ == "__main__":
    unittest.main()
