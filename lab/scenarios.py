"""Local lab scenarios: front-end/back-end profile pairs.

Each scenario binds one proxy port (what the detector scans) to one backend
port. The first scenarios are *consistent* pairs and must stay clean; the
divergent pairs each make a specific smuggling family possible.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    expected: str                 # "clean" | family name
    proxy_port: int
    proxy_profile: str
    backend_port: int
    backend_profile: str


SCENARIOS: list[Scenario] = [
    Scenario("strict-strict",
             "Both sides RFC-strict: every ambiguity is rejected identically.",
             "clean", 18081, "strict", 19081, "strict"),
    Scenario("hardened-hardened",
             "Hardened rebuilding front-end + strict backend: disagreements "
             "are normalized away.",
             "clean", 18082, "rebuild-hardened", 19082, "strict"),
    Scenario("lenientte-lenientte",
             "Both sides use the same tolerant parser: slices still agree.",
             "clean", 18083, "lenient-te", 19083, "lenient-te"),
    Scenario("clte-lenient-te",
             "CL.TE: front-end counts Content-Length (TE not recognized), "
             "backend honors obfuscated chunked framing.",
             "CL.TE", 18084, "lenient-cl", 19084, "lenient-te"),
    Scenario("tecl-lenient-cl",
             "TE.CL: front-end honors chunked framing, backend ignores "
             "obfuscated TE and counts Content-Length.",
             "TE.CL", 18085, "lenient-te", 19085, "lenient-cl"),
    Scenario("tete-order-diff",
             "TE.TE: duplicate TE headers, front-end honors the last line "
             "(non-chunked -> falls back to CL), backend honors the first "
             "chunked line.",
             "TE.TE", 18086, "te-last-cl-fallback", 19086, "te-first-lenient"),
    Scenario("clcl-dup-diff",
             "CL.CL: duplicate conflicting lengths, each side picks a "
             "different value.",
             "CL.CL", 18087, "cl-first-lenient", 19087, "lenient-te"),
    Scenario("te-obfuscation-fallback",
             "CL.TE via TE obfuscation: the strict front-end does not "
             "recognize obfuscated Transfer-Encoding values (chunked;x, "
             "xchunked, NUL, duplicate lines) as valid chunked coding and "
             "falls back to Content-Length; the lenient back-end honors "
             "them and switches to chunked. Bare-LF/CR requests are still "
             "rejected by the front-end (REJECTED), but the TE-obfuscation "
             "variants smuggle.",
             "CL.TE", 18088, "strict", 19088, "lenient-te"),
]
