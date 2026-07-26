import argparse
import sys

from .collector import collect
from .config import apply_cli_credentials, load_targets
from .diff import compare_all
from .query import analyze_findings, select_findings
from .report import build_report, render_text, write_csv, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="driftwatch", description="Compare SQL Server schemas.")
    parser.add_argument("--config", required=True, help="JSON configuration with at least two targets")
    parser.add_argument("--output", help="write the selected output to this path")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text",
                        help="output format (default: text)")
    parser.add_argument("--kind", action="append", help="filter by finding kind (repeat or comma-separate)")
    parser.add_argument("--severity", action="append", help="filter by severity (repeat or comma-separate)")
    parser.add_argument("--target", action="append", help="filter by target name (repeat or comma-separate)")
    parser.add_argument("--object", dest="objects", action="append",
                        help="filter by object name (repeat or comma-separate)")
    parser.add_argument("--query", help="case-insensitive search across finding fields")
    parser.add_argument("--username", help="SQL Server login used for every configured target")
    password = parser.add_mutually_exclusive_group()
    password.add_argument("--password", help="SQL Server password (visible to the process list)")
    password.add_argument("--password-stdin", action="store_true", help="read the SQL Server password from stdin")
    args = parser.parse_args(argv)
    try:
        if args.password_stdin:
            if sys.stdin.isatty():
                raise ValueError("--password-stdin requires a piped password")
            password_value = sys.stdin.readline().rstrip("\r\n")
        else:
            password_value = args.password
        targets = apply_cli_credentials(load_targets(args.config), args.username, password_value)
        inventories = [collect(target) for target in targets]
        findings = select_findings(
            compare_all(inventories),
            kinds=args.kind,
            severities=args.severity,
            targets=args.target,
            objects=args.objects,
            query=args.query,
        )
        analysis = analyze_findings(findings)
        if args.format == "json":
            write_json(build_report(inventories, findings, analysis), args.output)
        elif args.format == "csv":
            write_csv(findings, args.output)
        else:
            render_text(findings, analysis, args.output)
        return 2 if findings else 0
    except (OSError, ValueError) as exc:
        print(f"driftwatch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
