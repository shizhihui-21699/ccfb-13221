"""Lab scenarios: fixed front/back dialect pairs with documented expectations.

Two kinds of expectation are recorded, matching the two detectors:

* ``expected_blackbox`` -- wire shapes (``cl_te``/``te_cl``/``cl_cl``/``te_te``)
  the response-queue oracle should confirm.  These are the shapes that produce
  a cross-connection leak, so a remote target could be found the same way.
* ``expected_instrumented`` -- template keys (any of the 12) whose boundaries the
  two hops are expected to frame differently, measured from the lab's own
  framing record.

Both are ground truth for the self-check command and are shown in the report.
The detectors never see them; a mismatch is a bug in the detector or the range.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import dialects as D
from .lab import LabConfig

__all__ = ["Scenario", "SCENARIOS", "get_scenario"]


@dataclass(frozen=True)
class Scenario:
    key: str
    title: str
    story: str
    front: str
    back: str
    expected_blackbox: tuple[str, ...]
    expected_instrumented: tuple[str, ...]
    consistent: bool

    def lab_config(self, name: str | None = None) -> LabConfig:
        return LabConfig(
            front=D.get_dialect(self.front),
            back=D.get_dialect(self.back),
            name=name or self.key,
        )


SCENARIOS: list[Scenario] = [
    Scenario(
        key="matched-strict",
        title="Strict proxy in front of a strict origin",
        story="An nginx-style proxy and a Python-style origin both reject TE+CL "
        "and normalise framing. They agree on every boundary, so nothing "
        "desyncs -- the detector must stay silent.",
        front="nginx",
        back="python-origin",
        expected_blackbox=(),
        expected_instrumented=(),
        consistent=True,
    ),
    Scenario(
        key="matched-modern",
        title="Modern proxy in front of a Go-style origin",
        story="An envoy-style proxy and a Go-style origin both refuse ambiguous "
        "framing. A hardened baseline pair.",
        front="envoy",
        back="go-origin",
        expected_blackbox=(),
        expected_instrumented=(),
        consistent=True,
    ),
    Scenario(
        key="matched-lenient",
        title="Two lenient hops that happen to agree",
        story="A legacy appliance and an ancient origin are both loose, but loose "
        "in the *same* way: same bare-LF rule, same first-CL rule, same chunk "
        "handling. Being sloppy is not the bug; disagreeing is.",
        front="loose-proxy",
        back="legacy-origin",
        expected_blackbox=(),
        expected_instrumented=(),
        consistent=True,
    ),
    Scenario(
        key="cl-te-desync",
        title="Load balancer trusts Content-Length, origin trusts chunked",
        story="A load balancer that prefers Content-Length fronts a Java-style "
        "origin that prefers Transfer-Encoding. A chunked-looking tail is body "
        "to the balancer and a new request to the origin: classic CL.TE.",
        front="legacy-lb",
        back="java-origin",
        expected_blackbox=("cl_te", "cl_cl"),
        expected_instrumented=("cl_te", "cl_cl", "te_te_dup_chunked"),
        consistent=False,
    ),
    Scenario(
        key="te-cl-desync",
        title="Proxy decodes chunked, origin obeys Content-Length",
        story="An apache-style proxy decodes the chunked body and forwards it, "
        "but the Node-style origin obeys the smaller Content-Length, stops "
        "mid-chunk and parses the remainder as a request: classic TE.CL.",
        front="apache",
        back="node-origin",
        expected_blackbox=("te_cl",),
        expected_instrumented=("te_cl",),
        consistent=False,
    ),
    Scenario(
        key="cl-cl-desync",
        title="First-wins front end, last-wins origin, on duplicate CL",
        story="Both hops honour duplicate Content-Length but pick opposite "
        "values, so the body boundary shifts by the difference: CL.CL. Paired "
        "with a Python-style origin to keep the CL.CL signal isolated.",
        front="legacy-lb",
        back="python-origin",
        expected_blackbox=("cl_cl",),
        expected_instrumented=("cl_cl",),
        consistent=False,
    ),
    Scenario(
        key="te-te-desync",
        title="Origin falls back to Content-Length on an unusable TE list",
        story="The front end cannot use the Transfer-Encoding list and quietly "
        "falls back to Content-Length; the origin reads only the first TE header "
        "and decodes chunked. The two disagree on where the body ends: TE.TE.",
        front="te-fallback",
        back="te-first-only",
        expected_blackbox=("te_te",),
        expected_instrumented=("te_te_unknown", "te_te_space"),
        consistent=False,
    ),
]


SCENARIOS_BY_KEY = {s.key: s for s in SCENARIOS}


def get_scenario(key: str) -> Scenario:
    try:
        return SCENARIOS_BY_KEY[key]
    except KeyError:
        raise KeyError(f"unknown scenario {key!r}; known: {sorted(SCENARIOS_BY_KEY)}") from None
