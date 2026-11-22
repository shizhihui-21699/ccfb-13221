# smugglelab — HTTP request-smuggling lab and detector

A local test range for **HTTP/1.1 request smuggling** plus a detector that
decides, per pair of hops, whether they disagree about where one request ends
and the next begins.

The idea is simple and old: a load balancer in front, a business service behind,
and if the two *parse the request boundary differently*, an attacker can tuck a
second request inside the body of the first. The front end forwards the whole
thing; the back end cuts it at a different place and runs the smuggled request —
often on a connection the attacker no longer owns, i.e. in someone else's
session.

This repo gives you:

* a **parser with named dialect flags** (`smugglelab/httpdialect.py`) that makes
  every divergence point explicit;
* a **live two-hop lab** (`smugglelab/lab.py`) — a real front-end proxy and
  back-end origin on loopback, with an upstream connection pool like a real LB;
* **10 dialect presets** modelled on the behaviours of nginx / haproxy / apache
  / envoy and Python / Node / Go / Java / legacy origins, plus a couple of
  deliberately divergent ones;
* **7 scenarios** — three where the hops agree, four where they disagree — each
  with documented ground truth;
* **two detectors**: a black-box oracle you could point at a remote target, and
  an instrumented per-hop framing differential for the whole range;
* an **HTML report** and **reproducible request samples**.

Everything binds `127.0.0.1`. It is a lab, not a scanner for other people's
systems.

## Quick start

```bash
# list what's here
python3 -m smugglelab.cli list

# run every scenario, write reports/report.html and .json
python3 -m smugglelab.cli report --trials 3

# the self-check: assert zero false positives/negatives against ground truth
python3 -m smugglelab.cli selftest --trials 2

# keep one scenario's hops up to poke at by hand
python3 -m smugglelab.cli serve cl-te-desync

# probe any host:port with the black-box oracle (e.g. a lab you ran above)
python3 -m smugglelab.cli scan 127.0.0.1:12345 --trials 3

# print a reproducible request for one wire shape
python3 -m smugglelab.cli sample cl_te --python
```

No third-party dependencies. Python 3.10+.

## How detection works

### Nothing is a timing guess

A black-box smuggling detector usually infers a desync from response timing:
if the back end is "waiting" for a body that never comes, the next request on
the connection stalls. Timing is noisy and easy to get wrong.

This lab instead uses a **cross-connection oracle**:

1. **Poison.** Open a connection to the front end. Send one ambiguous request
   whose hidden request declares a body it never sends. Close the connection.
2. **Trigger.** Open a *fresh* connection and send a benign request tagged with
   a random nonce. If the two hops disagreed, the back end is sitting mid-body
   on the upstream connection the front end will lend to this new client; the
   new client's bytes complete the hidden request, and the hidden request's
   response — carrying the attacker's nonce — comes back on the victim's
   connection.

Because the attacker connection is **closed** before the victim connects, and
every marker is a fresh random nonce, a leak cannot be explained by pipelining
on the attacker's own socket or by a cached response. And because it is exactly
the response-queue-poisoning mechanism, the same probe travels to a remote
target.

### Keeping false positives near zero

Four independent controls:

| control | what it rules out |
| --- | --- |
| attacker connection closed before the victim connects | "it was just pipelining on my own socket" |
| random per-trial nonces | marker guessing, caching, coincidence |
| negative control per shape | the *range* being noisy (a non-ambiguous request carrying the same marker must never fire) |
| reproduction across N trials + confidence = observed rate | one-off flukes |

The report shows the control result and the per-trial reproduction count for
every shape, so a reader can see *why* something was called vulnerable.

### Two detectors, honestly separated

* **Black-box (`--trials N`)** — confirms the wire shapes that produce a
  cross-connection leak: `CL.TE`, `TE.CL`, `CL.CL`, `TE.TE`. This is the part
  that generalises to a remote target.

* **Instrumented differential** — the lab runs both hops in-process, so it can
  ask directly: *did the back end frame a request the front end did not?* That
  is exact proof of disagreement for **every** ambiguity family, including the
  ones a black box cannot confirm without timing noise (bare-LF line endings,
  chunk-size whitespace, chunk extensions, whitespace before a header colon,
  ...). It is labelled "instrumented" everywhere and never reported as a remote
  finding, because a remote target gives you no such record.

The self-check scores both against each scenario's declared ground truth.

## What is covered

Seven scenarios (`python3 -m smugglelab.cli list`):

| scenario | front → back | expected |
| --- | --- | --- |
| `matched-strict` | nginx → python-origin | consistent |
| `matched-modern` | envoy → go-origin | consistent |
| `matched-lenient` | loose-proxy → legacy-origin | consistent (both loose, identically) |
| `cl-te-desync` | legacy-lb → java-origin | CL.TE, CL.CL |
| `te-cl-desync` | apache → node-origin | TE.CL |
| `cl-cl-desync` | legacy-lb → python-origin | CL.CL |
| `te-te-desync` | te-fallback → te-first-only | TE.TE |

Twelve ambiguity templates feed the instrumented differential:

| family | templates |
| --- | --- |
| CL.TE | `cl_te` (both headers, front obeys CL) |
| TE.CL | `te_cl` (both headers, front obeys TE, short CL) |
| CL.CL | `cl_cl`, `cl_cl_reverse` (duplicate CL, both orderings) |
| TE.TE | `te_te_unknown`, `te_te_space`, `te_te_identity`, `te_te_name_ws`, `te_te_dup_chunked` |
| LF | `bare_lf` (bare-LF line terminators) |
| CHUNK | `chunk_size_ws`, `chunk_ext` |

`matched-lenient` is the important negative: two hops that are *both* sloppy in
the *same* way do not desync. Being lenient is not the bug; disagreeing is.

## Layout

```
smugglelab/
  httpdialect.py   parser + the framing flags that define a hop's behaviour
  dialects.py      named presets (nginx, haproxy, apache, envoy, *-origin, ...)
  lab.py           live front-end proxy + back-end origin, upstream pool
  templates.py     12 ambiguous request constructions
  engine.py        black-box cross-connection oracle (4 wire shapes)
  instrumented.py  per-hop framing differential (all 12 templates)
  scenarios.py     front/back pairs with documented ground truth
  range.py         run the matrix, score against truth
  report.py        self-contained HTML report
  samples.py       reproducible transcript + python replay
  cli.py           list / report / selftest / scan / serve / sample
tests/             parser unit tests + end-to-end lab tests (stdlib unittest)
docs/METHOD.md     the reasoning behind the oracle and the false-positive controls
```

## Testing

```bash
python3 tests/run_tests.py          # ~80s; spins up real loopback sockets
```

28 tests: framing decisions per dialect, the lab round-trip, the black-box
oracle on known-bad and matched pairs, the instrumented differential, the full
matrix against ground truth (zero FP/FN asserted), and that every generated
replay sample is valid Python.

## Scope and safety

* Local range only; every listener is on `127.0.0.1`, chosen ports, no external
  traffic.
* Dialect presets are **behavioural approximations** assembled from the public
  divergence points of real software — they are not copies of any vendor's code
  and will not match any specific version exactly.
* `scan` sends ambiguous requests. Only point it at systems you own or are
  explicitly authorised to test. Against real infrastructure prefer the
  non-destructive shapes and read `docs/METHOD.md` first.
