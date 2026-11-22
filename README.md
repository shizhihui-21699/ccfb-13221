# HTTP Request Smuggling Detector

A byte-level HTTP/1.1 request-smuggling probe engine with a standalone HTML
report and a self-contained loopback lab. **For authorized security testing
only** — the tool refuses non-private targets unless you explicitly confirm
written authorization.

## Why it works

Smuggling exists when the front-end (load balancer / reverse proxy) and the
back-end disagree about where one request ends and the next begins. The
engine expresses every known framing ambiguity as exact raw bytes and looks
for two hard-to-fake consequences:

1. **Response-queue poisoning** — a follow-up request receives the response
   meant for a request that was smuggled into the back-end's buffer.
2. **Reproducible timing stalls** — a deliberately unfinished smuggled
   message makes the back-end hold the next real request while it waits for
   more body bytes.

A backend *state channel* (a canary endpoint that records inbound requests)
is used only as **corroboration**, because benign HTTP pipelining delivers a
canary to the backend too. This distinction is what keeps false positives
low.

## Layout

```
smuggler/            detection engine (the reusable library + CLI)
  raw_http.py        byte-level request builder / response parser
  variants.py        ambiguity matrix (CL.TE / TE.CL / TE.TE / CL.CL + quirks)
  detector.py        baseline, control, timing & canary stages, verdicts
  h2.py              minimal HTTP/2 + HPACK codec for downgrade probes
  report.py          single-file HTML report writer
  authorize.py       loopback/private-target guard
  cli.py             command-line entry point
lab/                 local, loopback-only vulnerable/consistent ranges
  parser.py          configurable-strictness HTTP parser (the "two opinions")
  proxy.py           front-end that slices messages per its own profile
  backend.py         back-end with canary state channel
  scenarios.py       profile pairs (clean controls + divergent targets)
  runner.py          start/stop the whole lab
tests/               unit tests + end-to-end + fast smoke
```

## Quick start

```bash
# 1. start the lab (8 proxy/backend pairs on 127.0.0.1)
python3 -m lab.runner start

# 2. in another shell, list the ambiguity variants
python3 -m smuggler.cli list

# 3. scan a deliberately vulnerable pair (CL.TE)
python3 -m smuggler.cli scan http://127.0.0.1:18084 \
    --json out/scan.json --html out/report.html

# 4. scan a consistent pair and confirm zero findings
python3 -m smuggler.cli scan http://127.0.0.1:18081 --html out/clean.html
```

### Lab pairs (all loopback)

| Proxy port | Scenario | Expectation |
|---|---|---|
| 18081 | strict → strict | clean |
| 18082 | rebuild-hardened → strict | clean |
| 18083 | lenient-te → lenient-te | clean |
| 18084 | lenient-cl → lenient-te | CL.TE |
| 18085 | lenient-te → lenient-cl | TE.CL |
| 18086 | te-last-cl-fallback → te-first-lenient | TE.TE |
| 18087 | cl-first-lenient → lenient-te | CL.CL |
| 18088 | strict → lenient-te | CL.TE via TE obfuscation |

## Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | **response-queue poisoning** observed: an unrelated follow-up request received the response of the request smuggled into the back-end's buffer. This is the only signal that *requires* the two parsers to disagree. |
| `SUSPICIOUS` | reserved for corroborated boundary shifts; the engine records non-specific stalls as evidence rather than findings to protect precision |
| `REJECTED` | the control/pipeline baseline itself produced a smuggle-like signal — result not trustworthy |
| `SAFE` | no queue poisoning survived the control gates |

### Why timing and state-channel hits alone never qualify

The lab demonstrated that the two tempting shortcuts are not specific to
smuggling:

- a **timing stall** also happens when both parsers *agree*, because a
  front-end that parses the embedded request itself blocks on its unfinished
  body and delays the follow-up anyway;
- a **canary state-channel hit** (and a marker in queued bytes) also happens
  under plain, correctly framed HTTP pipelining.

Both are still measured and stored in the evidence panel, but a finding
requires the definitive queue-poisoning signal plus a clean control.

Every finding stores the exact request bytes, the raw response, and a
copy-pasteable replay recipe in the report's evidence panel.

## False-positive controls

- per-target latency baseline (threshold = mean + 3σ, with an absolute floor)
- benign control probe per variant; any control signal → `REJECTED`
- explicit pipelining baseline so a state-channel hit alone never qualifies
- unique random marker per variant; no shared state between tests
- every probe on a fresh connection; 2-of-3 repeat agreement required
- connection resets / 400s classify as `REJECTED`, never as vulnerabilities

## Tests

The project uses only the Python standard library (3.10+). From the repo
root (no third-party packages, no virtualenv needed):

```bash
# fast, no network: byte codec, parser disagreement, h2 codec, authz guard
python3 -m unittest discover -s tests -p "test_raw_http.py"
python3 -m unittest discover -s tests -p "test_parser_disagreement.py"
python3 -m unittest discover -s tests -p "test_h2_codec.py"
python3 -m unittest discover -s tests -p "test_authorize.py"

# fast lab check: all 8 scenario pairs, only the discriminating variants each
python3 -u tests/verify_scenarios.py

# broad lab sweep: every variant against every pair (slow, thorough)
python3 -u tests/smoke.py

# complete end-to-end suite (spins every pair up/down once)
python3 -m unittest discover -s tests -p "test_end_to_end.py"
```

`python3 -I` (isolated mode) omits the working directory from `sys.path`;
run the project's own tests without `-I`. Use `-I` only when executing code
from an untrusted source, per the environment guidance.
