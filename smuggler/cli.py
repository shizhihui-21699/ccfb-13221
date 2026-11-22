#!/usr/bin/env python3
"""Command-line entry point for the smuggling detector.

Examples (local lab):
    python -m smuggler.cli list
    python -m smuggler.cli scan http://127.0.0.1:18084 \
        --json out/scan.json --html out/report.html
    python -m smuggler.cli scan http://127.0.0.1:18081 --family CL.TE
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlparse

from .authorize import assert_authorized
from .detector import EngineConfig, Target, scan
from .report import render
from .variants import REGISTRY


def _parse_target(raw: str) -> Target:
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    if parsed.scheme not in ("http", "https"):
        raise SystemExit(f"unsupported scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise SystemExit("target must include a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return Target(host=parsed.hostname, port=port,
                  tls=parsed.scheme == "https",
                  host_header=parsed.hostname)


def cmd_list(_args) -> int:
    families = {}
    for v in REGISTRY:
        families.setdefault(v.family, []).append(v)
    print(f"{len(REGISTRY)} variants across {len(families)} families\n")
    for family, variants in sorted(families.items()):
        print(f"== {family} ({len(variants)}) ==")
        for v in variants[:6]:
            print(f"  {v.vid:<28} {v.name}")
        if len(variants) > 6:
            print(f"  … {len(variants) - 6} more")
        print()
    return 0


def cmd_scan(args) -> int:
    target = _parse_target(args.target)
    try:
        assert_authorized(args.target, args.i_have_authorization)
    except PermissionError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 3
    cfg = EngineConfig(
        timeout=args.timeout, linger=args.linger,
        timing_repeats=args.repeats,
        timing_floor=args.timing_floor)
    families = args.family or None
    result = scan(target, cfg, variant_filter=families)
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)),
                    exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        print(f"JSON written: {args.json}")
    if args.html:
        os.makedirs(os.path.dirname(os.path.abspath(args.html)),
                    exist_ok=True)
        render(result, args.html)
        print(f"HTML report: {args.html}")
    if not args.json and not args.html:
        print(json.dumps(result["counts"], indent=2))
        for row in result["results"]:
            if row["verdict"] != "SAFE":
                print(f"  {row['verdict']:<10} {row['vid']:<28} {row['name']}")
    counts = result["counts"]
    print("\nSummary:", json.dumps(counts))
    return 0 if counts["VULNERABLE"] == 0 or args.allow_findings else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="smuggler",
        description="HTTP request smuggling detector (authorized testing).")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list all ambiguity variants").set_defaults(
        func=cmd_list)

    s = sub.add_parser("scan", help="scan one target")
    s.add_argument("target", help="http(s)://host:port of the authorized target")
    s.add_argument("--json", help="write full machine-readable results")
    s.add_argument("--html", help="write standalone HTML report")
    s.add_argument("--family", action="append",
                   help="limit to family/tag/variant-id (repeatable), "
                        "e.g. CL.TE, tete, CLTE-TE01-EOL-CRLF")
    s.add_argument("--timeout", type=float, default=8.0)
    s.add_argument("--linger", type=float, default=0.35)
    s.add_argument("--repeats", type=int, default=3)
    s.add_argument("--timing-floor", type=float, default=1.5)
    s.add_argument("--i-have-authorization", action="store_true",
                   help="required for non-loopback/private targets")
    s.add_argument("--allow-findings", action="store_true",
                   help="exit 0 even when VULNERABLE results exist")
    s.set_defaults(func=cmd_scan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
