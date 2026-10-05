"""Command-line entry point for read-only DEX invocation evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from .parser import DexError, scan_dex_file


def main(argv: list[str] | None = None) -> int:
    arguments = argparse.ArgumentParser(
        prog="dex-invoke-evidence",
        description="Locate bounded, static method-reference invocations in one DEX file",
    )
    arguments.add_argument("dex_file", help="self-owned or otherwise authorized .dex input")
    args = arguments.parse_args(argv)
    try:
        parser, sites = scan_dex_file(args.dex_file)
    except (DexError, OSError) as exc:
        print(f"DEX_REJECT: {exc}", file=sys.stderr)
        return 2
    report = {
        "schema": 1,
        "scope": "static DEX method-reference locations; no runtime execution claim",
        "dex_version": parser.version,
        "dex_sha256": hashlib.sha256(parser.data).hexdigest(),
        "site_count": len(sites),
        "sites": [site.to_dict() for site in sites],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
