"""Detection engine.

For every variant the engine runs four stages, all on freshly opened
connections so one test cannot poison another:

  1. baseline   — benign requests over a reused connection, measuring the
                  victim-request latency distribution for this very target
  2. control    — the variant's own control probe; it must produce no signal
                  at all, otherwise the test is inconclusive (noise guard)
  3. timing     — repeated probes whose second message is intentionally
                  incomplete; parser disagreement stalls the follow-up request
  4. canary     — probes smuggling a complete GET carrying a unique marker;
                  detection uses both misrouted responses and an independent
                  backend state channel

Verdicts: VULNERABLE / SUSPICIOUS / REJECTED / SAFE.
"""

from __future__ import annotations

import json
import statistics
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional

from .raw_http import CRLF, Connection, RawRequest
from .variants import ProbeContext, REGISTRY, Variant


@dataclass
class Target:
    host: str
    port: int
    tls: bool = False
    host_header: Optional[str] = None

    @property
    def http_host(self) -> str:
        return self.host_header or self.host

    @property
    def base_url(self) -> str:
        scheme = "https" if self.tls else "http"
        return f"{scheme}://{self.host}:{self.port}"


@dataclass
class EngineConfig:
    timeout: float = 8.0
    victim_timeout: float = 2.0      # follow-up request: a stall only needs
                                     # to clear the timing floor, not the
                                     # full request timeout
    linger: float = 0.35
    timing_repeats: int = 3
    timing_threshold_sigma: float = 3.0
    timing_floor: float = 1.5          # minimum stall to even count as signal
    first_response_floor: float = 0.6  # the outer response must come back
                                       # fast for a timing hit to count
    baseline_samples: int = 5
    canary_retries: int = 3            # independent connections per canary
                                       # probe; any poisoning wins (safe
                                       # targets never produce one)
    canary_state_path: str = "/__smuggler/canaries"


@dataclass
class Evidence:
    request_bytes: str
    response_bytes: str = ""
    note: str = ""


@dataclass
class VariantResult:
    vid: str
    family: str
    name: str
    ambiguity: str
    tags: list[str]
    verdict: str
    timing_observed: list[float]
    timing_threshold: float
    timing_hits: int
    canary_misroute: bool
    canary_state_hit: bool
    control_clean: bool
    control_status: Optional[int]
    control_error: Optional[str]
    error: Optional[str]
    evidence: list[Evidence] = field(default_factory=list)
    replay: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = [asdict(e) for e in self.evidence]
        return d


def _victim_request(ctx: ProbeContext) -> RawRequest:
    return RawRequest(
        method="GET", target=ctx.ping_path,
        headers=[(b"Host", ctx.host.encode()),
                 (b"User-Agent", b"smuggler-victim"),
                 (b"X-Victim-Marker", ctx.marker.encode()),
                 (b"Connection", b"keep-alive")],
        eol=CRLF,
    )


def _benign_post(ctx: ProbeContext) -> RawRequest:
    body = b"a=1&b=2"
    return RawRequest(
        method="POST", target="/",
        headers=[(b"Host", ctx.host.encode()),
                 (b"Content-Type", b"application/x-www-form-urlencoded"),
                 (b"Content-Length", str(len(body)).encode()),
                 (b"Connection", b"keep-alive")],
        body=body, eol=CRLF,
    )


def _evidence(req: RawRequest, result, note: str) -> Evidence:
    resp_bytes = result.response.raw if result and result.response else ""
    return Evidence(
        request_bytes=req.to_bytes().decode("latin1"),
        response_bytes=(resp_bytes.decode("latin1")
                        if isinstance(resp_bytes, bytes) else resp_bytes),
        note=note,
    )


def _replay_cmd(target: Target, req: RawRequest) -> str:
    path = f"/tmp/smuggler-{uuid.uuid4().hex[:8]}.http"
    return (
        f"# 1) save the request bytes to {path}\n"
        f"#    printf %s {req.to_bytes()!r} > {path}\n"
        f"# 2) replay (must be against the authorized lab target):\n"
        f"curl -sS --max-time {int(EngineConfig.timeout)} -i "
        f"--http1.1 -X {req.method} "
        f"http://{target.host}:{target.port}{req.target} "
        f"--data-binary @{path}"
    )


def measure_baseline(target: Target, ctx: ProbeContext,
                     cfg: EngineConfig) -> tuple[list[float], list[Evidence]]:
    """Victim-request latency over a reused connection carrying benign traffic."""
    samples: list[float] = []
    ev: list[Evidence] = []
    try:
        with Connection(target.host, target.port, target.tls) as conn:
            for _ in range(cfg.baseline_samples):
                r1 = conn.send_request(_benign_post(ctx), cfg.timeout, cfg.linger)
                if r1.response is None:
                    ev.append(Evidence("", note="baseline POST failed: "
                                       + str(r1.error)))
                    continue
                start = time.monotonic()
                r2 = conn.send_request(_victim_request(ctx),
                                       cfg.victim_timeout, cfg.linger)
                elapsed = time.monotonic() - start
                if r2.response is not None:
                    samples.append(elapsed)
    except OSError as exc:
        ev.append(Evidence("", note=f"baseline connection error: {exc}"))
    return samples, ev


def query_canary_state(target: Target, marker: str,
                       cfg: EngineConfig) -> Optional[bool]:
    """Independent state channel: did the backend log the smuggled canary as
    a real request? Returns None when the channel is unavailable."""
    path = f"{cfg.canary_state_path}?marker={marker}"
    req = RawRequest(method="GET", target=path,
                     headers=[(b"Host", target.http_host.encode()),
                              (b"Connection", b"close")], eol=CRLF)
    try:
        with Connection(target.host, target.port, target.tls) as conn:
            res = conn.send_request(req, cfg.timeout, cfg.linger)
    except OSError:
        return None
    if res.response is None or res.response.status != 200:
        return None
    try:
        data = json.loads(res.response.body)
    except (json.JSONDecodeError, ValueError):
        return None
    return bool(data.get("hit"))


def _explicit_canary_request(ctx: ProbeContext) -> RawRequest:
    """A properly framed, standalone GET to the canary — used to measure
    what legitimate pipelining looks like on this target."""
    return RawRequest(
        method="GET", target=ctx.canary_path,
        headers=[(b"Host", ctx.host.encode()),
                 (b"X-Smuggler-Marker", ctx.marker.encode()),
                 (b"Connection", b"keep-alive")],
        eol=CRLF,
    )


def _pipeline_baseline(target: Target, ctx: ProbeContext,
                       cfg: EngineConfig) -> bool:
    """Send a benign POST followed immediately by a correctly-framed canary
    GET, then a normal GET. Return True only if the *normal* GET receives the
    canary's response — genuine response-queue poisoning under unambiguous
    framing, which would make all canary verdicts unreliable.

    A proxy that serializes requests (one upstream exchange per client
    message) returns each response in order to the right request, so the
    marker legitimately appears in its OWN response, never in a third
    request's response.
    """
    try:
        with Connection(target.host, target.port, target.tls) as conn:
            conn.send_request(_benign_post(ctx), cfg.timeout, cfg.linger)
            conn.send_request(_explicit_canary_request(ctx),
                              cfg.victim_timeout, cfg.linger)
            innocent = conn.send_request(_victim_request(ctx),
                                         cfg.victim_timeout, cfg.linger)
    except OSError:
        return False
    # Poisoning means an unrelated request got the canary response.
    return _marker_in_response(innocent, ctx.marker)


def _marker_in_response(result, marker: str) -> bool:
    """Marker inside a fully parsed response — the response-queue-poisoning
    signal (the victim got the canary's response, not its own)."""
    return bool(result is not None and result.response is not None
                and marker.encode() in result.response.raw)


def _marker_in_leftover(result, marker: str) -> bool:
    """Marker only in unparsed leftover bytes. Benign pipelining produces
    this too, so it is never sufficient on its own."""
    return bool(result is not None and marker.encode() in result.leftover)


def run_timing_probe(target: Target, variant: Variant, ctx: ProbeContext,
                     cfg: EngineConfig
                     ) -> tuple[float, bool, float, bool, object, RawRequest]:
    """Send the timing probe then a victim on the SAME connection.

    Returns (victim_elapsed, victim_stalled, first_elapsed, first_completed,
             victim_result, request).

    The discriminator: when the two parsers genuinely disagree, the front
    end considers the outer message complete and answers it fast, while only
    the back end stalls the victim. When both parsers agree, the front end
    itself blocks on the embedded unfinished message, so the FIRST response
    never comes back either.
    """
    req = variant.build(ctx, "timing")
    conn = Connection(target.host, target.port, target.tls)
    try:
        conn.connect()
        first = conn.send_request(req, cfg.timeout, cfg.linger)
        first_elapsed = first.elapsed
        first_completed = first.response is not None
        start = time.monotonic()
        victim = conn.send_request(_victim_request(ctx),
                                   cfg.victim_timeout, cfg.linger)
        elapsed = time.monotonic() - start
        stalled = victim.timed_out or victim.response is None
        return (elapsed, stalled, first_elapsed, first_completed,
                victim, req)
    except OSError as exc:
        return (0.0, False, 0.0, False,
                type("R", (), {"error": str(exc), "response": None,
                               "leftover": b""})(), req)
    finally:
        conn.close()


def run_canary_probe(target: Target, variant: Variant, ctx: ProbeContext,
                     cfg: EngineConfig
                     ) -> tuple[bool, bool, list[Evidence], RawRequest]:
    """Retry the canary exchange on fresh connections. Poisoning is never
    emitted by a correctly-paired target, so OR-ing across attempts only
    recovers true positives lost to a short read window — it cannot create
    a false one.
    """
    any_leftover = False
    all_ev: list[Evidence] = []
    req: RawRequest | None = None
    poisoned = False
    for _ in range(max(1, cfg.canary_retries)):
        poisoned, leftover, ev, req = _canary_attempt(
            target, variant, ctx, cfg)
        any_leftover = any_leftover or leftover
        all_ev.extend(ev)
        if poisoned:
            break
    return poisoned, any_leftover, all_ev, req


def _canary_attempt(target: Target, variant: Variant, ctx: ProbeContext,
                    cfg: EngineConfig
                    ) -> tuple[bool, bool, list[Evidence], RawRequest]:
    """Returns (queue_poisoned, leftover_marker, evidence, request).

    Sequence on one connection:
      1. the smuggling probe (carries an embedded canary GET)
      2. a victim GET
      3. an innocent GET — if THIS one receives the canary response, the
         back-end's response queue was poisoned by the embedded request.

    queue_poisoned: an unrelated follow-up got the canary's response — a
                    reliable smuggling signal.
    leftover_marker: the canary only appeared as queued bytes; benign request
                    pipelining looks identical, so callers must corroborate.
    """
    req = variant.build(ctx, "canary")
    try:
        with Connection(target.host, target.port, target.tls) as conn:
            first = conn.send_request(req, cfg.timeout, cfg.linger)
            victim = conn.send_request(_victim_request(ctx),
                                       cfg.victim_timeout, cfg.linger)
            innocent = conn.send_request(_victim_request(ctx),
                                         cfg.victim_timeout, cfg.linger)
    except OSError:
        return False, False, [], req
    # Both follow-ups are pings to the canary-free /ping endpoint. Under
    # correct pairing their responses can never contain the canary marker.
    # Either one carrying it means an embedded request's response was
    # misrouted into the queue (response-queue poisoning).
    poisoned = (_marker_in_response(victim, ctx.marker)
                or _marker_in_response(innocent, ctx.marker))
    leftover = (_marker_in_leftover(victim, ctx.marker)
                or _marker_in_leftover(first, ctx.marker)
                or _marker_in_leftover(innocent, ctx.marker))
    ev: list[Evidence] = []
    if poisoned:
        ev.append(Evidence(
            request_bytes=req.to_bytes().decode("latin1"),
            response_bytes=((victim.response.raw if victim.response else b"")
                            + b"\n--- next ---\n"
                            + (innocent.response.raw
                               if innocent.response else b"")).decode("latin1"),
            note="response queue poisoning: a follow-up /ping request "
                 "received the smuggled canary's response"))
    elif leftover:
        ev.append(Evidence(
            request_bytes=req.to_bytes().decode("latin1"),
            note="canary marker seen in queued bytes (ambiguous: also "
                 "consistent with benign pipelining; needs corroboration)"))
    return poisoned, leftover, ev, req


def run_variant(target: Target, variant: Variant,
                cfg: EngineConfig,
                baseline: list[float]) -> VariantResult:
    marker = "smg-" + uuid.uuid4().hex
    ctx = ProbeContext(marker=marker, host=target.http_host,
                       canary_path=f"/__smuggler/canary/{marker}",
                       ping_path="/__smuggler/ping")

    # ---- stage 2: control probes (noise guard) ---------------------------
    # 2a. The variant's own benign control framing must be accepted cleanly.
    control_req = variant.build(ctx, "control")
    control_status: Optional[int] = None
    control_error: Optional[str] = None
    control_clean = True
    try:
        with Connection(target.host, target.port, target.tls) as conn:
            c1 = conn.send_request(control_req, cfg.timeout, cfg.linger)
            c2 = conn.send_request(_victim_request(ctx),
                                   cfg.victim_timeout, cfg.linger)
    except OSError as exc:
        return _rejected(variant, baseline, f"connection error: {exc}",
                         control_req, target)
    if c1.response is None:
        return _rejected(variant, baseline,
                         f"control probe got no response ({c1.error})",
                         control_req, target)
    control_status = c1.response.status
    if control_status >= 400 or c1.timed_out:
        return _rejected(variant, baseline,
                         f"control probe rejected with status {control_status}",
                         control_req, target)
    if c2.timed_out or _marker_in_response(c2, marker):
        # The benign control must never stall a victim nor poison a queue.
        control_clean = False

    # 2b. Pipelining baseline: send an EXPLICIT, properly-framed canary GET
    # right after a benign request. A proxy that pipelines will legitimately
    # deliver this to the backend (state channel hit), so a state hit alone
    # can never be evidence of smuggling. We only learn the target's baseline
    # behavior here; it does not by itself fail the control.
    pipe_poisoned = _pipeline_baseline(target, ctx, cfg)
    if pipe_poisoned:
        # Even a correctly framed pipelined request poisons the response queue
        # — the target multiplexes responses unsafely regardless of smuggling,
        # which makes all canary verdicts unreliable.
        control_clean = False

    evidence = [Evidence(
        request_bytes=control_req.to_bytes().decode("latin1"),
        response_bytes=(c1.response.raw.decode("latin1")
                        if c1.response else ""),
        note="control probe response (benign framing)")]

    # ---- timing threshold from this target's own baseline ---------------
    if len(baseline) >= 2:
        mu = statistics.mean(baseline)
        sigma = statistics.pstdev(baseline)
    else:
        mu, sigma = 0.0, 0.0
    threshold = max(cfg.timing_floor, mu + cfg.timing_threshold_sigma * sigma)

    # ---- stage 3: timing probes, repeated --------------------------------
    # A qualifying timing hit needs BOTH:
    #   (a) the victim stalls (parser disagreement on the back-end), and
    #   (b) the outer/front-end response completed quickly — proving the
    #       front end did NOT itself block on the embedded message, i.e. the
    #       two parsers framed it differently rather than both waiting.
    timings: list[float] = []
    hits = 0
    last_req: Optional[RawRequest] = None
    for _ in range(cfg.timing_repeats):
        (elapsed, stalled, first_elapsed, first_completed,
         victim, last_req) = run_timing_probe(target, variant, ctx, cfg)
        timings.append(round(elapsed, 4))
        victim_slow = stalled or elapsed >= threshold
        front_fast = first_completed and first_elapsed <= \
            cfg.first_response_floor
        if victim_slow and front_fast:
            hits += 1
            evidence.append(Evidence(
                request_bytes=last_req.to_bytes().decode("latin1"),
                note=f"front-end responded in {first_elapsed:.3f}s while the "
                     f"follow-up stalled {elapsed:.2f}s (threshold "
                     f"{threshold:.2f}s) — framing disagreement"))
        elif victim_slow and not front_fast:
            evidence.append(Evidence(
                request_bytes=last_req.to_bytes().decode("latin1"),
                note=f"follow-up stalled but the front-end also blocked "
                     f"(first response in {first_elapsed:.2f}s, completed="
                     f"{first_completed}): consistent parsing, not smuggling"))

    # ---- stage 4: canary probes ------------------------------------------
    poisoned, leftover_marker, canary_ev, canary_req = run_canary_probe(
        target, variant, ctx, cfg)
    evidence.extend(canary_ev)
    state_hit = query_canary_state(target, marker, cfg)
    if state_hit:
        evidence.append(Evidence(
            request_bytes=canary_req.to_bytes().decode("latin1"),
            note="backend state channel recorded the canary request "
                 "(corroborating only; pipelining can produce the same)"))

    # ---- verdict ----------------------------------------------------------
    # What the lab established empirically about each candidate signal:
    #   * timing stall     — ALSO occurs when both parsers agree, because a
    #                        front-end that parses the embedded pipelined
    #                        request blocks on its unfinished body itself.
    #   * leftover marker  — ALSO occurs under agreement, since the front-end
    #                        legitimately forwards the embedded request and
    #                        its response lands in queued bytes.
    #   * state-channel hit— benign explicit pipelining produces it too.
    # Only response-queue POISONING (an unrelated follow-up receives the
    # canary's response) requires the two parsers to frame the stream
    # differently, so it is the sole basis for a VULNERABLE verdict. The
    # other signals are recorded as evidence/metadata, never as a verdict.
    reproducible = hits >= 2 and hits >= cfg.timing_repeats - 1
    verdict = "SAFE"
    error: Optional[str] = None
    if not control_clean:
        verdict = "REJECTED"
        error = "control/pipeline baseline produced a smuggle-like signal"
    elif poisoned:
        verdict = "VULNERABLE"
    elif reproducible:
        # Reproducible stalls without poisoning: keep as low-confidence note
        # rather than a finding, to protect the false-positive rate.
        evidence.append(Evidence(
            request_bytes=canary_req.to_bytes().decode("latin1"),
            note=f"{hits}/{cfg.timing_repeats} timing stalls but no "
                 "response-queue poisoning; timing alone is not specific "
                 "enough (consistent parsers can stall identically)"))

    replay = _replay_cmd(target, canary_req)
    return VariantResult(
        vid=variant.vid, family=variant.family, name=variant.name,
        ambiguity=variant.ambiguity, tags=variant.tags, verdict=verdict,
        timing_observed=timings, timing_threshold=round(threshold, 4),
        timing_hits=hits, canary_misroute=poisoned,
        canary_state_hit=bool(state_hit), control_clean=control_clean,
        control_status=control_status, control_error=control_error,
        error=error, evidence=evidence, replay=replay,
    )


def _rejected(variant: Variant, baseline: list[float], error: str,
              req: RawRequest, target: Target) -> VariantResult:
    return VariantResult(
        vid=variant.vid, family=variant.family, name=variant.name,
        ambiguity=variant.ambiguity, tags=variant.tags, verdict="REJECTED",
        timing_observed=[], timing_threshold=0.0, timing_hits=0,
        canary_misroute=False, canary_state_hit=False,
        control_clean=False, control_status=None, control_error=error,
        error=error,
        evidence=[Evidence(request_bytes=req.to_bytes().decode("latin1"),
                           note=error)],
        replay=_replay_cmd(target, req),
    )


def scan(target: Target, cfg: Optional[EngineConfig] = None,
         variant_filter: Optional[list[str]] = None) -> dict:
    cfg = cfg or EngineConfig()
    variants = REGISTRY
    if variant_filter:
        wanted = {v.lower() for v in variant_filter}
        variants = [v for v in variants
                    if v.family.lower() in wanted
                    or v.vid.lower() in wanted
                    or any(t in wanted for t in v.tags)]
    ctx = ProbeContext(marker="smg-baseline", host=target.http_host,
                       canary_path="/__smuggler/canary/smg-baseline")
    baseline, baseline_ev = measure_baseline(target, ctx, cfg)
    results: list[VariantResult] = []
    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    for variant in variants:
        results.append(run_variant(target, variant, cfg, baseline))
    summary = {
        "target": target.base_url,
        "started": started,
        "baseline_latency": baseline,
        "baseline_notes": [asdict(e) for e in baseline_ev],
        "config": asdict(cfg),
        "counts": {
            "total": len(results),
            "VULNERABLE": sum(r.verdict == "VULNERABLE" for r in results),
            "SUSPICIOUS": sum(r.verdict == "SUSPICIOUS" for r in results),
            "REJECTED": sum(r.verdict == "REJECTED" for r in results),
            "SAFE": sum(r.verdict == "SAFE" for r in results),
        },
        "results": [r.to_dict() for r in results],
    }
    return summary
