# Detection design notes

Internal notes on *why* the detector is shaped the way it is. The user-facing
overview lives in `README.md`.

## The two-parser model

Every lab endpoint runs one `lab.parser.ParserProfile`. A front-end proxy and
a back-end each own a profile. The proxy slices each inbound message using
**its own** profile and forwards the raw bytes over one persistent upstream
connection; the back-end re-slices the same bytes using **its** profile.
Smuggling is exactly the difference between those two slices.

The proxy deliberately forwards raw bytes rather than re-encoding, except for
the `rebuild-hardened` profile, which normalizes everything it can parse —
demonstrating why message rebuilding defeats this whole class.

## Why response-queue poisoning is the only hard signal

We tried three candidate signals against the lab and measured each on both a
consistent pair and a divergent pair.

| Signal | Observed on a *consistent* pair? | Verdict |
|---|---|---|
| follow-up timing stall | **yes** — the front-end itself parses the embedded pipelined request and blocks on its unfinished body | not specific |
| canary marker in queued/leftover bytes | **yes** — the front-end legitimately forwards the embedded request; its response lands in queued bytes | not specific |
| backend canary state-channel hit | **yes** — correctly framed explicit pipelining also reaches the canary endpoint | corroboration only |
| **response-queue poisoning** — an unrelated follow-up `/ping` receives the canary's response | **no** — only a real boundary mismatch can misroute a response | **hard signal** |

Consequently a `VULNERABLE` verdict requires observed queue poisoning plus a
clean control/pipelining baseline. Everything else is retained in the evidence
panel but never escalated on its own. This is the main reason the false-positive
rate is zero across the three consistent lab pairs.

## EOL style vs. TE obfuscation — two different things

Bare-LF / lone-CR handling changes how header *lines* are split, but the body
boundary still comes from Content-Length or Transfer-Encoding. A hardened
front-end that rejects non-canonical line endings means the request never
reaches the back-end at all, so an EOL-only tolerance difference cannot smuggle
on its own. EOL style only matters in combination with a CL/TE ambiguity, which
is why every structural family carries `EOL-LF` (and an `EOL-CR`) variant rather
than a standalone EOL scenario.

TE *value* obfuscation is a real, distinct attack. The `te-obfuscation-fallback`
lab pair (strict front-end, lenient back-end) demonstrates it: values such as
`chunked; x=1`, `xchunked`, `chunked\x00`, or duplicate TE lines are not valid
chunked coding to a strict parser, so the front-end ignores TE and frames by
Content-Length; a lenient back-end still recognizes chunked and frames by
chunks. That CL-vs-TE mismatch is genuine CL.TE smuggling and the engine flags
the corresponding variants VULNERABLE while the bare-LF variants stay REJECTED.

## Timing probe shape

The embedded unfinished message declares `Content-Length: 50000` but only sends
a couple of body bytes. A small value (e.g. 100) can be silently completed by
the bytes of the follow-up request, so the large value guarantees the back-end
blocks until its own read timeout. The measured first-response latency is
recorded alongside the follow-up stall even though, per the table above, the
stall alone cannot drive a verdict.
