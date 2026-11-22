#!/usr/bin/env python3
"""Fast per-scenario verification: each scenario runs only the variants
relevant to its expected family, so the full 8-pair check finishes quickly.

This complements the broad smoke.py (which sweeps every variant); it asserts
the same expected/found contract with a much smaller probe set.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lab.backend import CanaryStore, LabBackend
from lab.parser import PROFILES
from lab.proxy import LabProxy
from lab.scenarios import SCENARIOS
from smuggler.detector import EngineConfig, Target, scan

# Small but discriminating variant set per family. Filtering by exact
# variant id keeps each scan to a handful of probes instead of a whole family.
PROBE = {
    "CL.TE": ["CLTE-TE01-EOL-CRLF", "CLTE-TE15-EOL-CRLF"],
    "TE.CL": ["TECL-TE01-EOL-CRLF"],
    "TE.TE": ["TETE-01"],
    "CL.CL": ["CLCL-01"],
}
CLEAN_IDS = sorted({vid for ids in PROBE.values() for vid in ids})


def main() -> int:
    store = CanaryStore()
    backends, proxies = [], []
    for sc in SCENARIOS:
        b = LabBackend(sc.backend_port, PROFILES[sc.backend_profile],
                       store, read_timeout=1.2)
        b.start()
        backends.append(b)
    time.sleep(0.2)
    for sc in SCENARIOS:
        p = LabProxy(sc.proxy_port, sc.backend_port,
                     PROFILES[sc.proxy_profile], read_timeout=1.2)
        p.start()
        proxies.append(p)
    time.sleep(0.4)

    cfg = EngineConfig(timeout=1.5, victim_timeout=1.0, linger=0.2,
                       timing_repeats=2, timing_floor=0.5,
                       baseline_samples=2, canary_retries=2)
    failures = []
    try:
        for sc in SCENARIOS:
            ids = CLEAN_IDS if sc.expected == "clean" else PROBE[sc.expected]
            res = scan(Target("127.0.0.1", sc.proxy_port), cfg,
                       variant_filter=ids)
            rows = res["results"]
            vuln = sum(r["verdict"] == "VULNERABLE" for r in rows)
            print(f"{sc.name:<26} expected={sc.expected:<6} "
                  f"VULNERABLE={vuln} (of {len(rows)} targeted)", flush=True)
            if sc.expected == "clean" and vuln:
                failures.append(f"{sc.name}: false positive")
            if sc.expected != "clean" and not vuln:
                failures.append(f"{sc.name}: missed {sc.expected}")
    finally:
        for p in proxies:
            p.stop()
        for b in backends:
            b.stop()

    print("\n" + ("ALL 8 SCENARIOS MATCH EXPECTATIONS" if not failures
                  else "FAILURES:\n" + "\n".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
