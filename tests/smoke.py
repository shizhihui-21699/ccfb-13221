#!/usr/bin/env python3
"""Fast smoke check: one clean pair + the four divergent pairs, limited
variant sets. Not part of the unit suite (it binds real ports)."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lab.backend import CanaryStore, LabBackend
from lab.parser import PROFILES
from lab.proxy import LabProxy
from lab.scenarios import SCENARIOS
from smuggler.detector import EngineConfig, Target, scan

# One canonical variant per family keeps the smoke run fast while still
# exercising every framing disagreement end-to-end.
LIMIT = {
    # Canonical framing for plain CL.TE pairs; the TE-obfuscation variant
    # (chunked;param) for the strict-front-end fallback pair.
    "CL.TE": ["clte-te01-eol-crlf", "clte-te15-eol-crlf"],
    "TE.CL": ["tecl-te01-eol-crlf"],
    "TE.TE": ["tete-01"],
    "CL.CL": ["clcl-01"],
}


def main() -> int:
    store = CanaryStore()
    backends, proxies = [], []
    for sc in SCENARIOS:
        be = LabBackend(sc.backend_port, PROFILES[sc.backend_profile],
                        store, read_timeout=1.2)
        be.start()
        backends.append(be)
    time.sleep(0.2)
    for sc in SCENARIOS:
        px = LabProxy(sc.proxy_port, sc.backend_port,
                      PROFILES[sc.proxy_profile], read_timeout=1.2)
        px.start()
        proxies.append(px)
    time.sleep(0.4)

    cfg = EngineConfig(timeout=1.5, victim_timeout=1.0, linger=0.15,
                       timing_repeats=3, timing_floor=0.5,
                       baseline_samples=3)
    failures = []
    try:
        for sc in SCENARIOS:
            if sc.expected != "clean":
                result = scan(Target("127.0.0.1", sc.proxy_port), cfg,
                              variant_filter=[sc.expected])
                allowed = {v.lower() for v in LIMIT[sc.expected]}
                result["results"] = [r for r in result["results"]
                                     if r["vid"].lower() in allowed]
            else:
                result = scan(Target("127.0.0.1", sc.proxy_port), cfg,
                              variant_filter=list(LIMIT.keys()))
            counts = result["counts"].copy()
            if sc.expected != "clean":
                counts = {"VULNERABLE": sum(
                    r["verdict"] == "VULNERABLE" for r in result["results"]),
                    "SUSPICIOUS": sum(
                        r["verdict"] == "SUSPICIOUS" for r in result["results"])}
            print(f"\n=== {sc.name} (expected {sc.expected}) ===")
            print(f"    {counts}")
            for r in result["results"]:
                if r["verdict"] != "SAFE":
                    print(f"    {r['verdict']:<10} {r['vid']:<26} "
                          f"hits={r['timing_hits']} "
                          f"misroute={r['canary_misroute']} "
                          f"state={r['canary_state_hit']} "
                          f"err={r['error']}")
            if sc.expected == "clean" and result["counts"]["VULNERABLE"]:
                failures.append(f"{sc.name}: false positive")
            if sc.expected != "clean" and not (
                    counts["VULNERABLE"] or counts["SUSPICIOUS"]):
                failures.append(f"{sc.name}: missed expected {sc.expected}")
    finally:
        for px in proxies:
            px.stop()
        for be in backends:
            be.stop()

    print("\n" + ("ALL SCENARIOS MATCHED EXPECTATIONS" if not failures
                  else "FAILURES:\n" + "\n".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
