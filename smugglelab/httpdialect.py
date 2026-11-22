"""Incremental HTTP/1.1 request parser parameterised by a "dialect".

A *dialect* is the set of small decisions every HTTP implementation makes when
turning bytes into a request boundary: where a header line ends, whether
whitespace before the colon is legal, how a list of transfer-codings is read,
which of several ``Content-Length`` headers wins, and so on.

Two hops that disagree on any of these decisions can assign the same bytes to
different requests -- that is HTTP request smuggling.  The lab in this project
puts two dialects back to back and this module is the single source of truth
for how each hop frames bytes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Iterable

__all__ = [
    "Dialect",
    "NeedMore",
    "Reject",
    "Request",
    "Framing",
    "parse_request",
]


class NeedMore(Exception):
    """The buffer does not yet contain a complete request head/body."""

    def __init__(self, need: int = 1):
        super().__init__(f"need at least {need} more byte(s)")
        self.need = need


class Reject(Exception):
    """The dialect refuses to frame this message as a request."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
OCTETS_RE = re.compile(rb"^[\x20-\x7e\x80-\xff]*$")
HEX_RE = re.compile(rb"^[0-9a-fA-F]+$")

KNOWN_TRANSFER_CODINGS = {"chunked", "identity", "gzip", "deflate", "compress", "br"}


@dataclass(frozen=True)
class Framing:
    """How a dialect decided the body of one request is delimited."""

    kind: str                 # "chunked" | "length" | "none"
    length: int | None = None
    header_source: str = ""   # human readable: which headers drove the decision

    def as_dict(self) -> dict:
        return {"kind": self.kind, "length": self.length, "source": self.header_source}


@dataclass(frozen=True)
class Dialect:
    """One hop's rules for reading HTTP/1.1 bytes.

    Every flag names a real-world divergence point.  Defaults are deliberately
    strict (RFC 7230) so that a dialect is defined by what it *loosens*.
    """

    name: str = "custom"
    description: str = ""

    # -- line / header syntax -------------------------------------------------
    accept_bare_lf: bool = False          # bare LF terminates a header line
    reject_bare_cr: bool = True           # bare CR anywhere in the head is fatal
    allow_ws_before_colon: bool = False   # "Content-Length : 5"
    allow_obs_fold: bool = False          # header continuation lines
    trim_ows: bool = True                 # strip SP/HTAB around field values
    header_name_casefold: bool = True     # X / x treated the same
    invalid_header_policy: str = "reject"  # reject | ignore
    request_line_allow_extra_ws: bool = False
    request_line_allow_tab: bool = False
    header_limit: int = 128

    # -- Transfer-Encoding ----------------------------------------------------
    te_tokens_casefold: bool = True
    te_allow_ws_in_list: bool = True      # "chunked , identity"
    te_requires_chunked_last: bool = True # "chunked, gzip" -> reject
    te_unknown_policy: str = "reject"     # reject | ignore
    te_with_cl: str = "chunked_wins"      # chunked_wins | reject | cl_wins
    # Some hops only consult the *first* Transfer-Encoding header and ignore
    # any that follow.  Others, unable to make sense of the list, quietly fall
    # back to Content-Length.  Both are real-TE.TE divergence sources.
    te_first_header_only: bool = False
    te_unusable_falls_back_to_cl: bool = False

    # -- Content-Length -------------------------------------------------------
    cl_duplicate_policy: str = "reject"   # first | last | reject | all_match
    cl_allow_sign: bool = False           # "+5"
    cl_allow_ows: bool = True             # " 5 "
    cl_allow_comma: bool = False          # "5, 5"

    # -- Chunked body ---------------------------------------------------------
    chunk_allow_ws: bool = False          # "5 ;ext" / " 5"
    chunk_allow_0x: bool = False          # "0x5"
    chunk_ext_policy: str = "strip"       # strip | reject

    # -- forwarding -----------------------------------------------------------
    # "raw" keeps the header block byte-for-byte when proxying; "normalize"
    # rewrites framing headers to the ones this hop actually used.
    forward_mode: str = "raw"

    max_body: int = 2 * 1024 * 1024

    def with_(self, **kw) -> "Dialect":
        return replace(self, **kw)

    def as_dict(self) -> dict:
        d = {
            "name": self.name,
            "description": self.description,
        }
        return d

    def framing_flags(self) -> dict:
        return {
            k: v
            for k, v in self.__dict__.items()
            if k.startswith(("te_", "cl_", "chunk_", "accept_", "reject_", "allow_"))
        }


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    raw_head: bytes          # request line + headers, ending with the blank line
    body: bytes
    consumed: int            # bytes of the buffer belonging to this request
    framing: Framing
    raw_request_line: bytes = b""

    def get_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def get(self, name: str, default: str | None = None) -> str | None:
        vals = self.get_all(name)
        return vals[0] if vals else default

    def header_names(self) -> list[str]:
        return [k for k, _ in self.headers]

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "target": self.target,
            "version": self.version,
            "headers": [[k, v] for k, v in self.headers],
            "framing": self.framing.as_dict(),
        }


# ---------------------------------------------------------------------------
# line scanning
# ---------------------------------------------------------------------------


def _read_line(buf: bytes, pos: int, d: Dialect) -> tuple[bytes, int]:
    """Return (line_without_terminator, index_after_terminator).

    Accepts CRLF, and bare LF when the dialect allows it.  A bare CR is either
    fatal or treated as ordinary data, depending on the dialect.
    """
    while True:
        lf = buf.find(b"\n", pos)
        if lf == -1:
            raise NeedMore(1)
        cr = buf.rfind(b"\r", pos, lf)
        if cr != -1:
            # CRLF only if the CR is immediately before the LF.
            if cr == lf - 1:
                return buf[pos:cr], lf + 1
            # A CR earlier in the line: bare CR.
            if d.reject_bare_cr:
                raise Reject(400, "bare CR in header line")
            # treat CR as data: fall through and use the LF terminator
        if not d.accept_bare_lf:
            raise Reject(400, "bare LF line terminator")
        return buf[pos:lf], lf + 1


def _split_request_line(line: bytes, d: Dialect) -> tuple[bytes, bytes, bytes]:
    sep = b"\t" if d.request_line_allow_tab else b" "
    parts = [p for p in re.split(rb"[ \t]+" if d.request_line_allow_tab else rb" +", line.strip()) if p]
    if len(parts) != 3:
        raise Reject(400, "malformed request line")
    method, target, version = parts
    if not d.request_line_allow_extra_ws and (b"  " in line or line != line.strip()):
        # multiple/edge spaces only tolerated when the dialect is lenient
        raise Reject(400, "malformed request line whitespace")
    if not TOKEN_RE.match(method):
        raise Reject(400, "invalid method token")
    if not version.startswith(b"HTTP/"):
        raise Reject(400, "invalid HTTP version")
    return method, target, version


# ---------------------------------------------------------------------------
# framing decisions
# ---------------------------------------------------------------------------


def _collect_te(headers: list[tuple[str, str]], d: Dialect) -> list[str] | None:
    raw_values = [v for k, v in headers if _hname(k, d) == "transfer-encoding"]
    if not raw_values:
        return None
    if d.te_first_header_only:
        raw_values = raw_values[:1]
    tokens: list[str] = []
    unusable = False
    for value in raw_values:
        parts = value.split(",")
        for part in parts:
            tok = part.strip(" \t") if d.te_allow_ws_in_list else part
            if not tok:
                if d.te_unknown_policy == "ignore":
                    continue
                unusable = True
                continue
            tok = tok.lower() if d.te_tokens_casefold else tok
            if tok not in KNOWN_TRANSFER_CODINGS:
                if d.te_unknown_policy == "reject":
                    unusable = True
                    continue
            tokens.append(tok)
    if unusable:
        # Signal "found Transfer-Encoding I cannot use" without raising, so the
        # caller can decide between falling back to CL and rejecting.
        return ["__unusable__"]
    return tokens


def _collect_cl(headers: list[tuple[str, str]], d: Dialect) -> list[tuple[int, str]]:
    values: list[str] = []
    for k, v in headers:
        if _hname(k, d) != "content-length":
            continue
        if d.cl_allow_comma:
            values.extend(v.split(","))
        else:
            values.append(v)

    parsed: list[tuple[int, str]] = []
    for value in values:
        raw = value
        v = value.strip(" \t") if d.cl_allow_ows else value
        if not d.cl_allow_ows and v != v.strip(" \t"):
            raise Reject(400, "whitespace in Content-Length")
        if d.cl_allow_sign and v[:1] in ("+", "-"):
            if v[0] == "-":
                raise Reject(400, "negative Content-Length")
            v = v[1:]
        if not v.isdigit():
            raise Reject(400, f"invalid Content-Length {raw!r}")
        # Reject absurdly long numbers rather than converting forever.
        if len(v.lstrip("0")) > 18:
            raise Reject(400, "Content-Length too large")
        parsed.append((int(v), raw))
    return parsed


def _hname(name: str, d: Dialect) -> str:
    return name.lower() if d.header_name_casefold else name


def _decide_framing(headers: list[tuple[str, str]], d: Dialect) -> Framing:
    te = _collect_te(headers, d)
    cl = _collect_cl(headers, d)

    if te == ["__unusable__"]:
        # Transfer-Encoding was present but this hop could not use it.
        if d.te_unusable_falls_back_to_cl and cl:
            return _decide_cl(cl, d, source="Content-Length (unusable Transfer-Encoding)")
        raise Reject(400, "unusable Transfer-Encoding")

    if te is not None:
        if cl:
            if d.te_with_cl == "reject":
                raise Reject(400, "both Transfer-Encoding and Content-Length")
            if d.te_with_cl == "cl_wins":
                return _decide_cl(cl, d, source="Content-Length (TE present, CL preferred)")

        if d.te_requires_chunked_last and te[-1] != "chunked":
            # A hop that ignores unknown tokens may still find "chunked"
            # earlier in the list; a strict hop rejects.
            if not (d.te_unknown_policy == "ignore" and "chunked" in te):
                raise Reject(400, "chunked is not the final transfer-coding")
        if "chunked" in te:
            return Framing("chunked", None, "Transfer-Encoding: " + ", ".join(te))
        if te and d.te_unknown_policy == "ignore":
            # TE present but nothing usable: no body, unless CL also present
            # (handled above).
            return Framing("none", 0, "Transfer-Encoding without chunked")
        raise Reject(400, "Transfer-Encoding without chunked")

    if cl:
        return _decide_cl(cl, d, source="Content-Length")

    return Framing("none", 0, "no framing headers")


def _decide_cl(cl: list[tuple[int, str]], d: Dialect, source: str) -> Framing:
    if len(cl) == 1:
        return Framing("length", cl[0][0], source)
    policy = d.cl_duplicate_policy
    if policy == "first":
        return Framing("length", cl[0][0], source + " (first)")
    if policy == "last":
        return Framing("length", cl[-1][0], source + " (last)")
    if policy == "all_match":
        if len({v for v, _ in cl}) != 1:
            raise Reject(400, "conflicting Content-Length values")
        return Framing("length", cl[0][0], source + " (all match)")
    raise Reject(400, "duplicate Content-Length")


# ---------------------------------------------------------------------------
# chunked body
# ---------------------------------------------------------------------------


def _read_chunked(buf: bytes, pos: int, d: Dialect) -> tuple[int, int]:
    """Parse a chunked body starting at ``pos``.

    Returns (consumed_end, total_body_bytes).  The body itself stays in the
    buffer; the caller slices it out.
    """
    start = pos
    total = 0
    while True:
        line, nxt = _read_line(buf, pos, d)
        size_part = line
        if b";" in size_part:
            if d.chunk_ext_policy == "reject":
                raise Reject(400, "chunk extension")
            size_part = size_part.split(b";", 1)[0]
        if d.chunk_allow_ws:
            size_part = size_part.strip(b" \t")
        if d.chunk_allow_0x and size_part[:2].lower() == b"0x":
            size_part = size_part[2:]
        if not size_part:
            raise Reject(400, "empty chunk size")
        if not HEX_RE.match(size_part):
            raise Reject(400, f"invalid chunk size {size_part!r}")
        size = int(size_part, 16)
        if size == 0:
            # trailer section, terminated by an empty line
            while True:
                tline, tnxt = _read_line(buf, nxt, d)
                if tline == b"":
                    return tnxt, total
        data_end = nxt + size
        term_end = data_end + 2
        if len(buf) < term_end:
            raise NeedMore(term_end - len(buf))
        term = buf[data_end:term_end]
        if term == b"\r\n":
            pass
        elif term[:1] == b"\n" and d.accept_bare_lf:
            term_end = data_end + 1
        elif d.reject_bare_cr and term[:1] == b"\r":
            raise Reject(400, "chunk data not CRLF terminated")
        else:
            raise Reject(400, "chunk data not CRLF terminated")
        total += size
        if total > d.max_body:
            raise Reject(413, "chunked body too large")
        pos = term_end


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------


def parse_request(buf: bytes, d: Dialect) -> Request:
    """Parse exactly one request from the front of ``buf``.

    Raises :class:`NeedMore` if ``buf`` is a prefix of a request and
    :class:`Reject` if the dialect refuses to frame it.
    """
    pos = 0
    raw_lines: list[bytes] = []
    while True:
        line, nxt = _read_line(buf, pos, d)
        if line == b"":
            head_end = nxt
            break
        raw_lines.append(line)
        pos = nxt
        if len(raw_lines) > d.header_limit:
            raise Reject(431, "too many header lines")

    if not raw_lines:
        raise Reject(400, "empty request head")

    method_b, target_b, version_b = _split_request_line(raw_lines[0], d)
    method = method_b.decode("latin-1")
    target = target_b.decode("latin-1")
    version = version_b.decode("latin-1")

    headers: list[tuple[str, str]] = []
    for raw in raw_lines[1:]:
        if raw[:1] in (b" ", b"\t"):
            if not d.allow_obs_fold or not headers:
                raise Reject(400, "unexpected obs-fold")
            k, v = headers[-1]
            add = raw.strip(b" \t").decode("latin-1")
            headers[-1] = (k, f"{v} {add}".strip())
            continue

        if b"\x00" in raw:
            raise Reject(400, "NUL in header")
        name_b, sep, value_b = raw.partition(b":")
        if not sep:
            if d.invalid_header_policy == "ignore":
                continue
            raise Reject(400, "header without colon")
        stripped_name = name_b.strip(b" \t")
        if stripped_name != name_b:
            if not d.allow_ws_before_colon:
                raise Reject(400, "whitespace before colon")
            name_b = stripped_name
        if not TOKEN_RE.match(name_b):
            if d.invalid_header_policy == "ignore":
                continue
            raise Reject(400, "invalid header name")
        value = value_b
        if d.trim_ows:
            value = value.strip(b" \t")
        if not OCTETS_RE.match(value):
            raise Reject(400, "invalid header value bytes")
        headers.append((name_b.decode("latin-1"), value.decode("latin-1")))

    framing = _decide_framing(headers, d)

    if framing.kind == "chunked":
        end, total = _read_chunked(buf, head_end, d)
        return Request(
            method=method,
            target=target,
            version=version,
            headers=headers,
            raw_head=buf[:head_end],
            body=buf[head_end:end],
            consumed=end,
            framing=framing,
            raw_request_line=raw_lines[0],
        )

    if framing.kind == "length":
        assert framing.length is not None
        if framing.length > d.max_body:
            raise Reject(413, "body too large")
        end = head_end + framing.length
        if len(buf) < end:
            raise NeedMore(end - len(buf))
        return Request(
            method=method,
            target=target,
            version=version,
            headers=headers,
            raw_head=buf[:head_end],
            body=buf[head_end:end],
            consumed=end,
            framing=framing,
            raw_request_line=raw_lines[0],
        )

    return Request(
        method=method,
        target=target,
        version=version,
        headers=headers,
        raw_head=buf[:head_end],
        body=b"",
        consumed=head_end,
        framing=framing,
        raw_request_line=raw_lines[0],
    )


def render_request(req: Request, d: Dialect) -> bytes:
    """Serialize a parsed request back to wire bytes for forwarding."""
    if d.forward_mode == "raw":
        return req.raw_head + req.body
    # normalized: re-emit a canonical head with the framing this hop chose
    lines = [f"{req.method} {req.target} {req.version}".encode("latin-1")]
    drop = {"content-length", "transfer-encoding"} if d.header_name_casefold else {
        "Content-Length", "Transfer-Encoding"
    }
    for k, v in req.headers:
        if (k.lower() if d.header_name_casefold else k) in drop:
            continue
        lines.append(f"{k}: {v}".encode("latin-1"))
    if req.framing.kind == "chunked":
        lines.append(b"Transfer-Encoding: chunked")
    elif req.framing.kind == "length":
        lines.append(f"Content-Length: {req.framing.length}".encode("latin-1"))
    return b"\r\n".join(lines) + b"\r\n\r\n" + req.body
