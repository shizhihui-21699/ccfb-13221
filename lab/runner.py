#!/usr/bin/env python3
"""Start/stop the local smuggling lab (loopback only).

Usage:
    python -m lab.runner start
    python -m lab.runner status
    python -m lab.runner stop
"""

from __future__ import annotations

import json
import signal
import sys
import time

from .backend import CanaryStore, LabBackend
from .parser import PROFILES
from .proxy import LabProxy
from .scenarios import SCENARIOS

PID_FILE = "/tmp/smuggler-lab.pids"


def start() -> int:
    backends = []
    proxies = []
    store = CanaryStore()
    for sc in SCENARIOS:
        backend = LabBackend(sc.backend_port,
                             PROFILES[sc.backend_profile], store)
        backend.start()
        backends.append(backend)
    time.sleep(0.2)
    for sc in SCENARIOS:
        proxy = LabProxy(sc.proxy_port, sc.backend_port,
                         PROFILES[sc.proxy_profile])
        proxy.start()
        proxies.append(proxy)
    time.sleep(0.3)
    mapping = {
        "pids": [b._thread.ident for b in backends + proxies],
        "ports": [
            {"name": sc.name, "proxy": sc.proxy_port,
             "backend": sc.backend_port,
             "proxy_profile": sc.proxy_profile,
             "backend_profile": sc.backend_profile,
             "expected": sc.expected,
             "description": sc.description}
            for sc in SCENARIOS
        ],
    }
    with open(PID_FILE, "w") as fh:
        json.dump(mapping, fh, indent=2)
    print("Lab started (loopback only). Scan targets:")
    for row in mapping["ports"]:
        print(f"  http://127.0.0.1:{row['proxy']:<5} {row['name']:<22} "
              f"expected={row['expected']}")
    print("\nKeep this process in the foreground; Ctrl-C stops everything.")

    stop_event = False

    def _shutdown(*_):
        nonlocal stop_event
        stop_event = True

    signal.signal(signal.SIGTERM, _shutdown)
    try:
        while not stop_event:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for proxy in proxies:
            proxy.stop()
        for backend in backends:
            backend.stop()
        print("\nLab stopped.")
    return 0


def status() -> int:
    try:
        with open(PID_FILE) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print("Lab is not running (no pid file).")
        return 1
    print(json.dumps(data, indent=2))
    return 0


def stop() -> int:
    # The foreground process owns the threads; operator normally Ctrl-C's it.
    print("Stop the foreground `lab.runner start` process with Ctrl-C.")
    return 0


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "start"
    return {"start": start, "status": status, "stop": stop}.get(
        cmd, lambda: print(__doc__) or 2)()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
