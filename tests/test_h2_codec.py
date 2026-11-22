"""Tests for the minimal HTTP/2 codec used by downgrade probes."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smuggler.h2 import (H2_PREFACE, build_downgrade_probe,
                         crlf_injection_header, encode_int,
                         encode_literal_header, frame, headers_frame,
                         settings_frame)


class TestHPACKIntegers(unittest.TestCase):
    def test_small_value_fits_prefix(self):
        self.assertEqual(encode_int(10, 5, 0x00), b"\x0a")

    def test_value_at_prefix_boundary(self):
        self.assertEqual(encode_int(31, 5, 0x00), b"\x1f\x00")

    def test_multibyte_integer(self):
        # 1337 is the worked example in RFC 7541 §5.1.
        self.assertEqual(encode_int(1337, 5, 0x00),
                         b"\x1f\x9a\x0a")

    def test_prefix_byte_flags_preserved(self):
        out = encode_int(10, 5, 0xE0)
        self.assertEqual(out[0] & 0xE0, 0xE0)


class TestFrames(unittest.TestCase):
    def test_frame_layout(self):
        raw = frame(0x1, 0x4, 1, b"abc")
        self.assertEqual(raw[:3], b"\x00\x00\x03")   # 24-bit length
        self.assertEqual(raw[3], 0x1)                # type
        self.assertEqual(raw[4], 0x4)                # flags
        self.assertEqual(raw[5:9], b"\x00\x00\x00\x01")  # stream id
        self.assertEqual(raw[9:], b"abc")

    def test_settings_and_headers_flags(self):
        self.assertEqual(settings_frame()[3], 0x4)
        hf = headers_frame(1, b"x", end_stream=True)
        self.assertEqual(hf[4], 0x4 | 0x1)

    def test_oversized_payload_rejected(self):
        with self.assertRaises(ValueError):
            frame(0x0, 0, 1, b"x" * (1 << 24))


class TestLiteralHeaders(unittest.TestCase):
    def test_literal_name_and_value_roundtrip_bytes(self):
        raw = encode_literal_header(b"foo", b"bar")
        # 0x40 (incremental, index 0), len 3 "foo", len 3 "bar"
        self.assertEqual(raw, b"\x40\x03foo\x03bar")

    def test_never_indexed_marker(self):
        raw = encode_literal_header(b"foo", b"bar", never_indexed=True)
        self.assertEqual(raw[0] & 0xF0, 0x10)


class TestDowngradeProbe(unittest.TestCase):
    def test_probe_starts_with_preface_and_settings(self):
        probe = build_downgrade_probe()
        raw = probe.to_bytes()
        self.assertTrue(raw.startswith(H2_PREFACE))
        self.assertIn(settings_frame(), raw)

    def test_pseudo_headers_present(self):
        raw = build_downgrade_probe(path="/x").to_bytes()
        for token in (b":method", b":path", b":scheme", b":authority"):
            self.assertIn(token, raw)
        self.assertIn(b"/x", raw)

    def test_crlf_injection_carrier(self):
        name, value = crlf_injection_header("smg-1")
        self.assertEqual(name, b"X-Forwarded-For")
        self.assertIn(b"\r\nTransfer-Encoding: chunked\r\n", value)
        self.assertIn(b"smg-1", value)
        probe = build_downgrade_probe(injected_header=(name, value))
        self.assertIn(b"Transfer-Encoding: chunked", probe.to_bytes())


if __name__ == "__main__":
    unittest.main()
