"""Command-line interface.

Commands
--------
``serve <scenario>``      run one scenario's front end (and back end) and wait
``report``                run the whole matrix, write HTML + JSON
``scan <host:port>``      probe an arbitrary target (black-box only)
``sample <shape>``        print a reproducible request for a wire shape
``list``                  list scenarios, dialects, templates and shapes
``selftest``              run the matrix and assert zero FP/FN against truth
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import dialects as D
from . import scenarios as S
from . import templates as T
from .engine import WIRE_SHAPES_BY_KEY, Target, run_campaign
from .lab import Lab


def _parse_hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    if not host:
        host, port = s, "80"
    return host, int(port)


def cmd_list(args) -> int:
    print("Scenarios:")
    for sc in S.SCENARIOS:
        flag = "consistent" if sc.consistent else "DESYNC    "
        print(f"  {sc.key:18} {flag}  {sc.front:14} -> {sc.back:14}  {sc.title}")
    print("\nDialects:")
    for name in sorted(D.ALL_DIALECTS):
        d = D.ALL_DIALECTS[name]
        print(f"  {name:16} {d.description}")
    print("\nWire shapes (black-box oracle):")
    for k, s in WIRE_SHAPES_BY_KEY.items():
        print(f"  {k:8} {s.family:6} {s.title}")
    print("\nAmbiguity templates (instrumented differential):")
    for t in T.TEMPLATES:
        print(f"  {t.key:18} {t.family:6} {t.title}")
    return 0


def cmd_report(args) -> int:
    from .range import run_matrix
    from .report import write_report

    keys = args.scenario or None
    report = run_matrix(keys=keys, trials=args.trials, victim_len=args.victim_len)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report.as_dict(), f, indent=2)
        print(f"wrote {args.json}")
    html_path = args.html or "reports/report.html"
    import os
    os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)
    write_report(report, html_path)
    print(f"wrote {html_path}")
    s = report.as_dict()["summary"]
    print(f"black-box: detected {s['blackbox']['detected']}/{s['blackbox']['expected']}, "
          f"FP={s['blackbox']['false_positives']} FN={s['blackbox']['false_negatives']}")
    print(f"instrumented: detected {s['instrumented']['detected']}/"
          f"{s['instrumented']['expected']}, FP={s['instrumented']['false_positives']} "
          f"FN={s['instrumented']['false_negatives']}")
    return 0


def cmd_scan(args) -> int:
    host, port = _parse_hostport(args.target)
    target = Target(host, port, label=args.target, read_timeout=args.timeout)
    keys = args.shape or None
    finding = run_campaign(target, keys=keys, trials=args.trials, victim_len=args.victim_len)
    out = finding.as_dict()
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"wrote {args.json}")
    print(f"target {host}:{port}: {out['vulnerable_count']} of {out['tested_count']} "
          f"shapes confirmed")
    for r in finding.results:
        state = "VULN" if r.vulnerable else "ok  "
        print(f"  [{state}] {r.key:8} {r.family:6} repro={r.reproductions}/{len(r.trials)} "
              f"conf={r.confidence:.0%}  {r.note}")
    return 0 if finding.vulnerable_results else 1


def cmd_sample(args) -> int:
    from .samples import build_sample

    key = args.shape
    if key not in WIRE_SHAPES_BY_KEY:
        print(f"unknown shape {key!r}; known: {sorted(WIRE_SHAPES_BY_KEY)}", file=sys.stderr)
        return 2
    sample = build_sample(key)
    print(f"# {WIRE_SHAPES_BY_KEY[key].title}")
    print(sample.transcript())
    if args.python:
        print("\n# ---- python replay ----")
        print(sample.python_replay())
    return 0


def cmd_serve(args) -> int:
    sc = S.get_scenario(args.scenario)
    cfg = sc.lab_config()
    with Lab(cfg) as lab:
        print(f"scenario {sc.key}: {sc.front} (front) -> {sc.back} (back)")
        print(f"front end listening on 127.0.0.1:{lab.front_port}")
        print(f"back end  listening on 127.0.0.1:{lab.back_port}")
        print("Ctrl-C to stop.")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nstopping")
    return 0


def cmd_selftest(args) -> int:
    from .range import run_matrix

    report = run_matrix(trials=args.trials, victim_len=args.victim_len)
    d = report.as_dict()
    s = d["summary"]
    ok = True
    for run in report.runs:
        fp = run.fp_blackbox | run.fp_instrumented
        fn = run.fn_blackbox | run.fn_instrumented
        status = "PASS" if not (fp or fn or run.error) else "FAIL"
        if status == "FAIL":
            ok = False
        print(f"[{status}] {run.scenario.key:16} "
              f"bb_detected={sorted(run.detected_blackbox)} "
              f"fn={sorted(run.fn_blackbox)} fp={sorted(run.fp_blackbox)}"
              + (f" error={run.error}" if run.error else ""))
    print(f"\nblack-box   FP={s['blackbox']['false_positives']} "
          f"FN={s['blackbox']['false_negatives']}")
    print(f"instrumented FP={s['instrumented']['false_positives']} "
          f"FN={s['instrumented']['false_negatives']}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="smugglelab", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list", help="list scenarios, dialects, templates, shapes")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("report", help="run the matrix and write HTML + JSON")
    sp.add_argument("--scenario", action="append", help="limit to scenario key(s)")
    sp.add_argument("--trials", type=int, default=3)
    sp.add_argument("--victim-len", type=int, default=96)
    sp.add_argument("--html", default="reports/report.html")
    sp.add_argument("--json", default="reports/report.json")
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("scan", help="probe an arbitrary host:port (black-box)")
    sp.add_argument("target")
    sp.add_argument("--shape", action="append", help="limit to wire shape key(s)")
    sp.add_argument("--trials", type=int, default=3)
    sp.add_argument("--victim-len", type=int, default=96)
    sp.add_argument("--timeout", type=float, default=1.0)
    sp.add_argument("--json", default=None)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("sample", help="print a reproducible request for a shape")
    sp.add_argument("shape")
    sp.add_argument("--python", action="store_true", help="also print the python replay")
    sp.set_defaults(func=cmd_sample)

    sp = sub.add_parser("serve", help="run one scenario's hops and wait")
    sp.add_argument("scenario")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("selftest", help="assert zero FP/FN against ground truth")
    sp.add_argument("--trials", type=int, default=2)
    sp.add_argument("--victim-len", type=int, default=96)
    sp.set_defaults(func=cmd_selftest)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
