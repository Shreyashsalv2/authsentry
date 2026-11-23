"""Command line: python -m authsentry <logfile> [options]"""
import argparse
import json
import sys

from . import analyze_text, load_rules, to_dict, to_markdown
from .models import SEVERITIES, SEVERITY_RANK


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="authsentry", description="Detect brute force, password spraying, "
                                 "logins after failures and lockout bursts in auth logs.")
    ap.add_argument("logfile", help="auth.log / secure file, or Windows Security events as JSON ('-' for stdin)")
    ap.add_argument("--format", default="auto", choices=["auto", "linux", "windows"])
    ap.add_argument("--year", type=int, help="year for syslog timestamps (they have none)")
    ap.add_argument("--rules", help="path to a YAML rules file (default: built-in rules)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a Markdown report")
    ap.add_argument("-o", "--output", help="write the report to this file")
    ap.add_argument("--fail-on", choices=SEVERITIES, help="exit 2 if any alert is at least this severe")
    args = ap.parse_args(argv)

    text = sys.stdin.read() if args.logfile == "-" else open(args.logfile, encoding="utf-8", errors="replace").read()
    result = analyze_text(text, fmt=args.format, year=args.year, ruleset=load_rules(args.rules))
    out = json.dumps(to_dict(result), indent=2) if args.json else to_markdown(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    else:
        print(out)
    if args.fail_on and any(SEVERITY_RANK[a.severity] >= SEVERITY_RANK[args.fail_on] for a in result.alerts):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
