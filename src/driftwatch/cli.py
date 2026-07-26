import argparse
import sys

from .collector import collect
from .config import apply_cli_credentials, load_config
from .diff import compare_all
from .models import CollectionStatus, ComparisonStrategy
from .query import analyze_findings, select_findings
from .report import build_report, render_text, write_csv, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="driftwatch", description="Compare SQL Server schemas.")
    parser.add_argument("--config", required=True, help="JSON configuration with at least two targets")
    parser.add_argument("--output", help="write the selected output to this path")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text",
                        help="output format (default: text)")
    parser.add_argument("--strategy", choices=("baseline", "pairwise"),
                        help="comparison strategy (default: config or pairwise)")
    parser.add_argument("--baseline", help="reference target for baseline comparisons")
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
        settings = load_config(args.config)
        targets = apply_cli_credentials(settings.targets, args.username, password_value)
        inventories = [collect(target) for target in targets]
        strategy = ComparisonStrategy(args.strategy) if args.strategy else settings.strategy
        baseline = args.baseline or settings.baseline
        if args.baseline and args.strategy is None:
            strategy = ComparisonStrategy.BASELINE
        comparable_inventories = [
            inventory for inventory in inventories if inventory.status != CollectionStatus.FAILED
        ]
        if strategy == ComparisonStrategy.BASELINE and baseline not in {
            inventory.target for inventory in comparable_inventories
        }:
            all_findings = []
        elif strategy == ComparisonStrategy.PAIRWISE and baseline is None:
            all_findings = compare_all(comparable_inventories) if len(comparable_inventories) >= 2 else []
        else:
            all_findings = (
                compare_all(comparable_inventories, strategy=strategy, baseline=baseline)
                if len(comparable_inventories) >= 2 else []
            )
        findings = select_findings(
            all_findings,
            kinds=args.kind,
            severities=args.severity,
            targets=args.target,
            objects=args.objects,
            query=args.query,
        )
        analysis = analyze_findings(findings)
        report = build_report(inventories, findings, analysis, strategy=strategy, baseline=baseline)
        if args.format == "json":
            write_json(report, args.output)
        elif args.format == "csv":
            write_csv(findings, args.output)
        else:
            render_text(findings, analysis, args.output, inventories, strategy, baseline)
        if any(inventory.status != CollectionStatus.SUCCESS for inventory in inventories):
            return 1
        return 2 if findings else 0
    except (OSError, ValueError) as exc:
        print(f"driftwatch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
