"""A deliberately configurable HTTP/1.1 request parser for the local lab.

Real servers differ in exactly the edge cases this parser can be told to
tolerate or reject: duplicate length headers, obfuscated Transfer-Encoding,
non-standard line endings, header folding, chunk-size syntax. Each lab
backend runs one `ParserProfile`; each front-end proxy runs another, which is
how the range creates pairs that agree (SAFE) and pairs that disagree
(smuggable).

This is NOT a general-purpose HTTP stack and is only ever bound to loopback.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParserProfile:
    name: str
    # Length header handling
    reject_conflicting_duplicates: bool = True
    duplicate_pick: str = "first"          # "first" | "last"
    reject_multivalue_cl: bool = True
    lenient_cl_numbers: bool = False       # leading zero, plus, whitespace
    # Transfer-Encoding handling
    recognize_te: bool = True
    lenient_te_values: bool = False        # case handled anyway; tolerate junk
    lenient_te_name: bool = False          # whitespace before colon
    duplicate_te_pick: str = "first"       # "first" | "last"
    # Framing / syntax
    accept_bare_lf: bool = False
    accept_lone_cr: bool = False
    accept_obs_fold: bool = False
    lenient_chunk_sizes: bool = False
    # Precedence when both CL and TE are recognized
    te_over_cl: bool = True
    # Reject header values containing CR/LF (anti-smuggling hardening)
    reject_eol_in_value: bool = True
    # Connection behavior on parse failure
    close_on_error: bool = True
    # Only RFC token methods (GET/POST/PUT/...); reject unknown ones like GPOST.
    reject_non_standard_methods: bool = False


# Canonical profiles used by the lab scenarios.
PROFILES: dict[str, ParserProfile] = {
    "strict": ParserProfile(
        name="strict",
    ),
    "lenient-te": ParserProfile(
        name="lenient-te",
        lenient_te_values=True,
        lenient_te_name=True,
        accept_bare_lf=True,
        accept_obs_fold=True,
        lenient_chunk_sizes=True,
        lenient_cl_numbers=True,
        reject_conflicting_duplicates=False,
        reject_multivalue_cl=False,
        duplicate_te_pick="last",
        duplicate_pick="last",
    ),
    "lenient-cl": ParserProfile(
        # Tolerates odd length values and duplicates but does not recognize
        # obfuscated TE, so it falls back to Content-Length.
        name="lenient-cl",
        recognize_te=False,
        accept_bare_lf=True,
        lenient_cl_numbers=True,
        reject_conflicting_duplicates=False,
        reject_multivalue_cl=False,
        duplicate_pick="last",
        lenient_chunk_sizes=False,
    ),
    "te-first-lenient": ParserProfile(
        name="te-first-lenient",
        lenient_te_values=True,
        lenient_te_name=True,
        accept_bare_lf=True,
        duplicate_te_pick="first",
        reject_conflicting_duplicates=False,
        duplicate_pick="first",
        lenient_cl_numbers=True,
        lenient_chunk_sizes=True,
    ),
    "cl-first-lenient": ParserProfile(
        # Lenient about duplicates but keeps the FIRST Content-Length value.
        name="cl-first-lenient",
        recognize_te=False,
        accept_bare_lf=True,
        lenient_cl_numbers=True,
        reject_conflicting_duplicates=False,
        reject_multivalue_cl=False,
        duplicate_pick="first",
        lenient_chunk_sizes=False,
    ),
    "te-last-cl-fallback": ParserProfile(
        # Sees TE headers but duplicate_pick=last makes it honor the second
        # non-chunked TE line, so it falls back to Content-Length.
        name="te-last-cl-fallback",
        recognize_te=True,
        duplicate_te_pick="last",
        accept_bare_lf=True,
        lenient_te_values=True,
        lenient_te_name=True,
        reject_conflicting_duplicates=False,
        lenient_cl_numbers=True,
    ),
    "rebuild-hardened": ParserProfile(
        # Reject everything ambiguous: a hardened front-end that rebuilds
        # messages and refuses anything it cannot fully parse.
        name="rebuild-hardened",
        reject_conflicting_duplicates=True,
        reject_multivalue_cl=True,
        lenient_te_values=False,
        lenient_te_name=False,
        accept_bare_lf=False,
        accept_lone_cr=False,
        accept_obs_fold=False,
        lenient_chunk_sizes=False,
        reject_eol_in_value=True,
        close_on_error=True,
    ),
}


class ParseReject(Exception):
    def __init__(self, status: int, reason: str, close: bool = True):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.close = close


def _split_header_lines(head: bytes, profile: ParserProfile) -> list[bytes]:
    if b"\r\n" in head:
        raw_lines = head.split(b"\r\n")
    elif b"\n" in head:
        if not profile.accept_bare_lf:
            raise ParseReject(400, "bare LF not accepted")
        raw_lines = head.split(b"\n")
    elif b"\r" in head:
        if not profile.accept_lone_cr:
            raise ParseReject(400, "lone CR not accepted")
        raw_lines = head.split(b"\r")
    else:
        raw_lines = [head]
    lines: list[bytes] = []
    for line in raw_lines:
        if line[:1] in (b" ", b"\t"):
            if not profile.accept_obs_fold or not lines:
                raise ParseReject(400, "obs-fold not accepted")
            lines[-1] += b" " + line[1:].lstrip()
        else:
            lines.append(line)
    return lines


def _te_is_chunked(value: bytes, profile: ParserProfile) -> bool:
    v = value.strip()
    # Token-by-token for comma lists.
    tokens = [t.strip().lower() for t in v.split(b",")]
    if any(t == b"chunked" for t in tokens):
        # Strict parsers reject unknown sibling codings / junk.
        if profile.lenient_te_values:
            return True
        return all(t in (b"chunked", b"identity", b"gzip", b"deflate")
                   for t in tokens) and b";" not in v
    # Tolerant substring match (e.g. "xchunked", "chunked;x=1").
    if profile.lenient_te_values and b"chunked" in v.lower():
        return True
    return False


def _header_name_ok(raw_name: bytes, profile: ParserProfile) -> bytes:
    stripped = raw_name.strip()
    if stripped != raw_name and not profile.lenient_te_name:
        raise ParseReject(400, "whitespace before header colon")
    return stripped


def _parse_cl(value: bytes, profile: ParserProfile) -> int:
    v = value.strip()
    if v.isdigit():
        return int(v)
    if profile.lenient_cl_numbers:
        cleaned = v.lstrip(b"+").lstrip(b"0") or b"0"
        if cleaned.isdigit():
            return int(cleaned)
        # tolerate embedded trailing whitespace/tab
        compact = v.replace(b" ", b"").replace(b"\t", b"")
        if compact.lstrip(b"+").isdigit():
            return int(compact.lstrip(b"+"))
    raise ParseReject(400, f"invalid Content-Length: {value!r}")


def _decode_chunked(body: bytes, profile: ParserProfile) -> tuple[bytes, bytes]:
    """Return (decoded body, leftover bytes after the chunked stream)."""
    out = bytearray()
    pos = 0
    while True:
        # Find size-line terminator in accepted EOL flavors.
        eol_idx = -1
        eol_len = 2
        for marker, mlen in ((b"\r\n", 2), (b"\n", 1), (b"\r", 1)):
            idx = body.find(marker, pos)
            if idx != -1 and (eol_idx == -1 or idx < eol_idx):
                eol_idx, eol_len = idx, mlen
        if eol_idx == -1:
            raise ParseReject(400, "truncated chunk")
        size_raw = bytes(body[pos:eol_idx])
        size_field = size_raw.split(b";")[0]
        if not profile.lenient_chunk_sizes:
            # Strict RFC: plain hex token only — no whitespace, sign,
            # 0x prefix, or leading-zero padding ("0" itself is allowed).
            if not _is_plain_hex(size_field):
                raise ParseReject(400, "non-canonical chunk size")
        try:
            cleaned = size_field.strip().lstrip(b"+")
            if cleaned.startswith(b"0x"):
                cleaned = cleaned[2:]
            size = int(cleaned, 16)
        except ValueError as exc:
            raise ParseReject(400, "bad chunk size") from exc
        pos = eol_idx + eol_len
        if size == 0:
            # Skip trailers up to blank line.
            term = body.find(b"\r\n", pos)
            if term == -1:
                term = body.find(b"\n", pos)
                eol_len = 1
            if term == -1:
                raise ParseReject(400, "truncated chunk trailers")
            while term != pos:
                pos = term + eol_len
                term = body.find(b"\r\n" if eol_len == 2 else b"\n", pos)
                if term == -1:
                    raise ParseReject(400, "truncated chunk trailers")
            return bytes(out), body[term + eol_len:]
        if pos + size + eol_len > len(body):
            raise ParseReject(400, "incomplete chunk data")
        out.extend(body[pos:pos + size])
        pos += size + eol_len


def _is_plain_hex(token: bytes) -> bool:
    if token in (b"", b"0"):
        return token == b"0"
    return all(c in b"0123456789abcdefABCDEF" for c in token)


@dataclass
class ParsedRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[bytes, bytes]]
    body: bytes
    leftover: bytes
    wants_close: bool
    declared_cl: int | None = None
    used_chunked: bool = False
    consumed: int = 0


def parse_one(data: bytes, profile: ParserProfile) -> ParsedRequest:
    """Parse exactly one request from `data`; leftover bytes are the start of
    the next pipelined/queued message — the artifact of any smuggling."""
    head_end, sep_len = _find_header_end(data, profile)
    if head_end == -1:
        raise ParseReject(400, "incomplete request headers", close=False)
    head = data[:head_end]
    rest = data[head_end + sep_len:]
    lines = _split_header_lines(head, profile)
    if not lines:
        raise ParseReject(400, "empty request")
    status_parts = lines[0].split(b" ")
    if len(status_parts) < 3:
        raise ParseReject(400, "malformed request line")
    method, target, version = (p.decode("latin1") for p in status_parts[:3])

    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if b":" not in line:
            raise ParseReject(400, "malformed header")
        raw_name, value = line.split(b":", 1)
        name = _header_name_ok(raw_name, profile)
        value = value.strip() if not profile.lenient_te_name else value.strip()
        if profile.reject_eol_in_value and (
                b"\n" in value or b"\r" in value):
            raise ParseReject(400, "EOL inside header value")
        headers.append((name, value))

    cl_values = [v for n, v in headers if n.lower() == b"content-length"]
    te_headers = [(n, v) for n, v in headers if n.lower() == b"transfer-encoding"]

    cl: int | None = None
    if cl_values:
        if len(cl_values) > 1:
            if profile.reject_conflicting_duplicates and \
                    len(set(cl_values)) > 1:
                raise ParseReject(400, "conflicting Content-Length headers")
            cl = _parse_cl(
                cl_values[-1 if profile.duplicate_pick == "last" else 0],
                profile)
        else:
            cl = _parse_cl(cl_values[0], profile)
        # Multi-value single header ("11, 12").
        if b"," in cl_values[0]:
            if profile.reject_multivalue_cl:
                raise ParseReject(400, "comma list in Content-Length")
            parts = [p.strip() for p in cl_values[0].split(b",")]
            chosen = parts[-1 if profile.duplicate_pick == "last" else 0]
            cl = _parse_cl(chosen, profile)

    te_chunked = False
    if te_headers and profile.recognize_te:
        if len(te_headers) > 1:
            idx = -1 if profile.duplicate_te_pick == "last" else 0
            te_chunked = _te_is_chunked(te_headers[idx][1], profile)
        else:
            te_chunked = _te_is_chunked(te_headers[0][1], profile)

    wants_close = any(
        n.lower() == b"connection" and b"close" in v.lower()
        for n, v in headers)

    head_consumed = head_end + sep_len
    if te_chunked and (cl is None or profile.te_over_cl):
        body, leftover = _decode_chunked(rest, profile)
        consumed = head_consumed + (len(rest) - len(leftover))
        return ParsedRequest(method, target, version, headers, body,
                             leftover, wants_close, declared_cl=cl,
                             used_chunked=True, consumed=consumed)
    if cl is None:
        body, leftover = b"", rest
        consumed = head_consumed
    else:
        body, leftover = rest[:cl], rest[cl:]
        consumed = head_consumed + cl
    return ParsedRequest(method, target, version, headers, body,
                         leftover, wants_close, declared_cl=cl,
                         used_chunked=False, consumed=consumed)


def _find_header_end(data: bytes, profile: ParserProfile) -> tuple[int, int]:
    for marker, mlen in ((b"\r\n\r\n", 4), (b"\n\n", 2), (b"\r\r", 2)):
        idx = data.find(marker)
        if idx != -1:
            if mlen == 2 and marker != b"\r\n\r\n":
                if marker == b"\n\n" and not profile.accept_bare_lf:
                    raise ParseReject(400, "bare LF not accepted")
                if marker == b"\r\r" and not profile.accept_lone_cr:
                    raise ParseReject(400, "lone CR not accepted")
            return idx, mlen
    return -1, 0
