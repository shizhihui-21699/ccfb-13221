# Method: why this detector rarely lies

Request smuggling is a disagreement between two parsers about one boundary.
The hard part is not *sending* an ambiguous request — that is a dozen lines of
bytes — it is *deciding whether the target actually desynced* without guessing
wrong. This note records the reasoning, including where each detector is blind.

## 1. The signal we trust

A desync that matters is one where a request the attacker hid inside a body is
executed **for a different client**. That is the standard impact story: poison
a shared connection, the next user's request completes the hidden body, and the
response the back end queues for *their* request is delivered to *the attacker*
(or the hidden request runs in *their* session). Either way the smuggled
request has crossed a connection boundary.

So the oracle is built around exactly that, and nothing weaker:

```
attacker:  connect ─▶ send(ambiguous) ─▶ close
                                            │  (back end left mid-body on the
                                            │   pooled upstream connection)
victim:    connect ─▶ send(benign, nonce) ─▶ read responses
                                            └─▶ if attacker's nonce appears,
                                                the hidden request ran here
```

The leak we look for is the attacker's nonce showing up in the *victim's*
responses. That is only possible if the back end framed the hidden request out
of bytes that belonged to the victim — a genuine boundary disagreement.

## 2. Why this is not a timing heuristic

Classic CL.TE detection stalls the connection and watches for a timeout: "if
the back end were reading a body it would be waiting, so my next request hangs."
That conflates several things — server slowness, connection reuse policy,
keep-alive races — and the threshold is guesswork.

Here the *content* proves it: a nonce that was sent only inside the attacker's
"body" is echoed back on the victim's socket. No threshold, nothing to tune,
and the same property holds whether the two hops are the lab's or a remote
target's.

## 3. The four false-positive controls

| # | control | failure it excludes |
| --- | --- | --- |
| 1 | Attacker connection is **closed** before any victim connects | The hidden request being a normal pipelined request *on the attacker's own socket*. If the attacker has no live socket when the victim connects, a leak cannot be self-pipelining. |
| 2 | **Fresh random nonce per trial**, never reused, never in a URL a cache could serve | Marker guessing, response caching, a coincidental echo. |
| 3 | **Negative control** per shape: a non-ambiguous request carrying the *same kind* of nonce, framed as plain body | The *range* itself being noisy — e.g. an endpoint that echoes bodies. If the control leaks, the result is discarded (`confidence *= 0.25`, `vulnerable = False`) rather than reported. |
| 4 | **Reproduction across N trials**, `confidence = leaked / trials` | One-off flukes and partially-flaky desyncs. A single leak is reported with its real rate, not rounded up to "vulnerable and certain". |

On the seven scenarios the black-box oracle is exact: 5 expected findings found,
0 false positives, 0 false negatives. The instrumented differential is 7/7/0/0.

## 4. Where the black box is blind (and why that is stated, not hidden)

A cross-connection leak needs the desynced bytes to survive on a *pooled*
connection until the next client picks it up. Several ambiguity families do not
produce that:

* **Bare-LF line endings** — a hop that accepts bare LF and one that does not
  usually just reject the request rather than split it; there is no leftover
  body to carry a request.
* **Chunk-size whitespace / chunk extensions** — a *single* hop mishandling
  these shifts its own read pointer; whether that becomes a second request
  depends on body shape and often stays on one connection.
* **Whitespace before a header colon** — is often simply a 400 at one hop.

These are still real boundary disagreements — they are in the template
catalogue — but a black box cannot confirm them without exactly the timing
guesswork we refuse to use. So we detect them a different way and label the
difference:

* against the **local range**, where both hops are in-process, we read each
  hop's own framing record and ask whether the back end framed a request the
  front end did not. That is a differential, not a heuristic — exact for all 12
  templates.
* that result is shown under "instrumented" and **never** reported as a remote
  finding, because a remote target gives you no framing record. Claiming
  otherwise would be the kind of confident-but-ungrounded result that makes
  scanners untrustworthy.

## 5. The negative scenarios matter as much as the positive ones

Three scenarios are expected to be *clean*:

* `matched-strict` (nginx → python): both reject TE+CL.
* `matched-modern` (envoy → go): both refuse ambiguous framing.
* `matched-lenient` (loose-proxy → legacy-origin): **both are sloppy, in the
  same way.** Same bare-LF rule, same first-CL rule, same chunk handling.

The last one is the point. A detector that keys on "this proxy accepts bare LF"
or "this origin keeps the first Content-Length" would fire here and be wrong.
Being lenient is not the vulnerability; *disagreeing* is. A detector that only
measures one side is a false-positive machine; this one measures the boundary
between them, so it stays quiet.

## 6. What a human still has to do

* Confirm the target environment: a lab pair is not the production pair, and
  dialect presets are approximations.
* Prefer the non-destructive shapes; `CL.TE` with a short declared body is the
  gentlest. Avoid shapes that leave the back end waiting on real infrastructure
  longer than necessary.
* Read the reproduction. Every finding ships the exact bytes (with CR/LF shown
  literally) and a `socket` replay, so the claim is checkable by hand.

## 7. Reproducing a finding

`python3 -m smugglelab.cli sample <shape> --python` prints the canonical poison
and trigger for a shape with a fixed marker. The replay opens the attacker
connection, sends the poison, **closes it**, then opens a fresh connection and
sends the trigger — mirroring the oracle. If the target desyncs you will see the
hidden marker echoed on the second connection.
