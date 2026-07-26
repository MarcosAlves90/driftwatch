import argparse
import os
import sys
import time
from dataclasses import replace

from .collector import collect, collect_many
from .config import apply_cli_credentials, load_config
from .diff import compare, compare_all
from .github import annotations, job_summary
from .models import CollectionStatus, ComparisonStrategy, DatabaseTarget, Inventory, Severity
from .normalize import NormalizationOptions
from .policy import Policy, PolicyResult, load_policy
from .query import analyze_findings, select_findings
from .report import build_report, render_html, render_sarif, render_text, write_csv, write_json
from .snapshot import inventory_from_snapshot, write_snapshot


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="driftwatch", description="Compare SQL Server schemas.")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("check", "compare", "snapshot", "explain", "inspect", "config", "migration"),
        default="check",
    )
    parser.add_argument(
        "subcommand", nargs="?", choices=("validate", "verify"), help="secondary command, e.g. config validate"
    )
    parser.add_argument("--config", help="JSON configuration with at least two targets")
    parser.add_argument("--output", help="write the selected output to this path")
    parser.add_argument("--snapshot-output", help="write a collected schema snapshot to this path")
    parser.add_argument("--snapshot", "--expected", dest="snapshot_path", help="expected schema snapshot")
    parser.add_argument(
        "--format",
        choices=("text", "json", "csv", "sarif", "html"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--strategy", choices=("baseline", "pairwise"), help="comparison strategy (default: config or pairwise)"
    )
    parser.add_argument("--baseline", help="reference target for baseline comparisons")
    parser.add_argument("--policy", help="versioned JSON policy file")
    parser.add_argument(
        "--fail-on", choices=tuple(item.value for item in Severity), help="minimum severity that fails the command"
    )
    parser.add_argument("--workers", type=int, help="maximum concurrent target collections")
    parser.add_argument("--connect-timeout", type=int, help="connection timeout in seconds")
    parser.add_argument("--query-timeout", type=int, help="metadata query timeout in seconds")
    parser.add_argument("--kind", action="append", help="filter by finding kind (repeat or comma-separate)")
    parser.add_argument("--severity", action="append", help="filter by severity (repeat or comma-separate)")
    parser.add_argument("--target", action="append", help="filter by target name (repeat or comma-separate)")
    parser.add_argument(
        "--object", dest="objects", action="append", help="filter by object name (repeat or comma-separate)"
    )
    parser.add_argument("--query", help="case-insensitive search across finding fields")
    parser.add_argument(
        "--summary-only", action="store_true", help="render aggregate totals without individual findings"
    )
    parser.add_argument("--quiet", action="store_true", help="suppress stdout while preserving exit codes")
    parser.add_argument("--previous", help="previous JSON report for finding lifecycle")
    parser.add_argument("--report", help="existing JSON report for explain/inspect")
    parser.add_argument("--fingerprint", help="finding fingerprint for explain")
    parser.add_argument("--before", dest="before_snapshot", help="before snapshot for migration verify")
    parser.add_argument("--after", dest="after_snapshot", help="after snapshot for migration verify")
    parser.add_argument("--expected-effect", action="append", help="expected migration kind/object/fingerprint")
    parser.add_argument("--impact-depth", type=int, default=3, help="dependency traversal depth for impact metadata")
    parser.add_argument("--verbose", action="store_true", help="include policy counters in text output")
    parser.add_argument("--github-summary", action="store_true", help="write a Markdown summary to GITHUB_STEP_SUMMARY")
    parser.add_argument("--github-annotations", action="store_true", help="emit GitHub workflow annotations")
    parser.add_argument("--username", help="SQL Server login used for every configured target")
    password = parser.add_mutually_exclusive_group()
    password.add_argument("--password", help="SQL Server password (visible to the process list)")
    password.add_argument("--password-stdin", action="store_true", help="read the SQL Server password from stdin")
    return parser


def _collect_with_options(
    targets: list[DatabaseTarget],
    workers: int,
    connect_timeout: int,
    query_timeout: int | None,
    normalization: dict | None = None,
) -> list[Inventory]:
    settings_normalization = normalization or {}

    def target_collector(target: DatabaseTarget, *_args) -> Inventory:
        if connect_timeout == 30 and query_timeout is None and not settings_normalization:
            # Keep the small public collector seam compatible with callers/tests.
            return collect(target)
        return collect(target, connect_timeout, query_timeout, NormalizationOptions(**settings_normalization))

    return collect_many(
        targets,
        workers=workers,
        connect_timeout=connect_timeout,
        query_timeout=query_timeout,
        collector=target_collector,
    )


def _policy_from_args(path: str | None, fail_on: str | None) -> Policy:
    policy = load_policy(path)
    return replace(policy, fail_on=Severity.parse(fail_on)) if fail_on else policy


def _emit_report(report, findings, args, inventories, strategy, baseline) -> None:
    if args.quiet and not args.output:
        return
    if args.format == "json":
        write_json(report, args.output)
    elif args.format == "csv":
        write_csv(findings, args.output, enhanced=True)
    elif args.format == "html":
        render_html(findings, report["analysis"], args.output)
    elif args.format == "sarif":
        render_sarif(findings, args.output)
    else:
        render_text(
            findings,
            report["analysis"],
            args.output,
            inventories,
            strategy,
            baseline,
            len(report.get("policy", {}).get("ignored", [])),
            len(report.get("policy", {}).get("allowed", [])),
            args.verbose,
        )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        execution_started = time.perf_counter()
        if args.command in {"explain", "inspect"}:
            if not args.report:
                raise ValueError(f"{args.command} requires --report")
            import json

            with open(args.report, encoding="utf-8") as stream:
                report = json.load(stream)
            findings = report.get("findings", [])
            selected = [
                item
                for item in findings
                if (not args.fingerprint or item.get("fingerprint") == args.fingerprint)
                and (
                    not args.objects
                    or any(name.casefold() in item.get("object_name", "").casefold() for name in args.objects)
                )
            ]
            if not args.quiet:
                print(
                    json.dumps(
                        selected
                        if args.command == "explain"
                        else {"summary": report.get("summary"), "findings": selected},
                        indent=2,
                        sort_keys=True,
                    )
                )
            return 2 if selected and args.command == "explain" else 0
        if args.command == "config" and args.subcommand == "validate":
            if not args.config:
                raise ValueError("config validate requires --config")
            load_config(args.config)
            if not args.quiet:
                print("configuration is valid")
            return 0
        if args.command == "migration" and args.subcommand == "verify":
            if not args.before_snapshot or not args.after_snapshot:
                raise ValueError("migration verify requires --before and --after")
            from .migration import verify_migration

            before = inventory_from_snapshot(args.before_snapshot)
            after = inventory_from_snapshot(args.after_snapshot)
            migration_report = verify_migration(before, after, expected=args.expected_effect or ())
            if not args.quiet:
                write_json(migration_report.as_dict(), args.output)
            return 2 if migration_report.unexpected or migration_report.missing else 0
        if not args.config:
            raise ValueError("--config is required")
        if args.password_stdin:
            if sys.stdin.isatty():
                raise ValueError("--password-stdin requires a piped password")
            password_value = sys.stdin.readline().rstrip("\r\n")
        else:
            password_value = args.password

        # Policy/config/snapshot validation happens before opening a connection.
        settings = load_config(
            args.config,
            min_targets=1 if args.command in {"snapshot", "config"} or args.snapshot_path else 2,
        )
        policy = _policy_from_args(args.policy, args.fail_on)
        targets = apply_cli_credentials(settings.targets, args.username, password_value)
        workers = args.workers if args.workers is not None else settings.workers
        connect_timeout = args.connect_timeout if args.connect_timeout is not None else settings.connect_timeout
        query_timeout = args.query_timeout if args.query_timeout is not None else settings.query_timeout
        if workers < 1 or workers > 32:
            raise ValueError("workers must be an integer from 1 to 32")
        if connect_timeout < 1 or (query_timeout is not None and query_timeout < 1):
            raise ValueError("timeouts must be positive integers")

        strategy = ComparisonStrategy(args.strategy) if args.strategy else policy.strategy or settings.strategy
        baseline = args.baseline or policy.baseline or settings.baseline
        if args.baseline and args.strategy is None:
            strategy = ComparisonStrategy.BASELINE
        if baseline is not None and not args.snapshot_path and baseline not in {target.name for target in targets}:
            raise ValueError(f"baseline target {baseline!r} is not configured")

        if args.command == "snapshot":
            inventories = _collect_with_options(
                targets, workers, connect_timeout, query_timeout, settings.normalization
            )
            if args.target:
                selected = [item for item in inventories if item.target in set(args.target)]
            elif len(inventories) == 1:
                selected = inventories
            else:
                raise ValueError("snapshot requires --target when config contains multiple targets")
            if len(selected) != 1:
                raise ValueError("snapshot requires exactly one target")
            output = args.snapshot_output or args.output
            if not output:
                raise ValueError("snapshot requires --snapshot-output or --output")
            write_snapshot(selected[0], output)
            return 1 if selected[0].status != CollectionStatus.SUCCESS else 0

        collection_started = time.perf_counter()
        inventories = _collect_with_options(targets, workers, connect_timeout, query_timeout, settings.normalization)
        collection_seconds = time.perf_counter() - collection_started
        comparison_started = time.perf_counter()
        if args.snapshot_path:
            expected = inventory_from_snapshot(args.snapshot_path)
            comparable = [item for item in inventories if item.status != CollectionStatus.FAILED]
            all_findings = [finding for actual in comparable for finding in compare(expected, actual)]
            inventories_for_report = [expected, *inventories]
        else:
            comparable = [item for item in inventories if item.status != CollectionStatus.FAILED]
            if strategy == ComparisonStrategy.BASELINE and baseline not in {item.target for item in comparable}:
                all_findings = []
            elif len(comparable) < 2:
                all_findings = []
            elif (
                strategy == ComparisonStrategy.PAIRWISE
                and args.strategy is None
                and policy.strategy is None
                and settings.strategy == ComparisonStrategy.PAIRWISE
            ):
                all_findings = compare_all(comparable)
            else:
                all_findings = compare_all(comparable, strategy=strategy, baseline=baseline)
            inventories_for_report = inventories
        comparison_seconds = time.perf_counter() - comparison_started

        if args.impact_depth < 0:
            raise ValueError("impact depth must not be negative")
        if args.impact_depth:
            from .dependency import add_impact, graph_from_inventory

            graph = graph_from_inventory(inventories_for_report[0]) if inventories_for_report else None
            if graph is not None:
                all_findings = add_impact(all_findings, graph, args.impact_depth)
        if args.previous:
            from .lifecycle import classify_findings, load_previous_report

            all_findings = classify_findings(all_findings, load_previous_report(args.previous))
        evaluated: PolicyResult = policy.evaluate(all_findings)
        findings = select_findings(
            evaluated.findings,
            kinds=args.kind,
            severities=args.severity,
            targets=args.target,
            objects=args.objects,
            query=args.query,
        )
        analysis = analyze_findings(findings)
        report = build_report(
            inventories_for_report,
            findings,
            analysis,
            strategy=strategy,
            baseline=baseline,
            policy=policy,
            ignored_findings=evaluated.ignored,
            allowed_findings=evaluated.allowed,
            allowed_reasons=evaluated.allowed_reasons,
            timings={
                "collection_seconds": round(collection_seconds, 6),
                "comparison_seconds": round(comparison_seconds, 6),
                "total_seconds": round(time.perf_counter() - execution_started, 6),
            },
        )
        report["policy"]["blocking_count"] = len(policy.blocking(evaluated))
        if not args.summary_only:
            _emit_report(report, findings, args, inventories_for_report, strategy, baseline)
        elif not args.quiet:
            if args.format == "text":
                render_text(
                    [],
                    analysis,
                    args.output,
                    inventories_for_report,
                    strategy,
                    baseline,
                    len(evaluated.ignored),
                    len(evaluated.allowed),
                    args.verbose,
                    summary_only=True,
                )
            else:
                _emit_report(report, [], args, inventories_for_report, strategy, baseline)
        if args.github_summary or os.getenv("GITHUB_STEP_SUMMARY"):
            summary_path = os.getenv("GITHUB_STEP_SUMMARY")
            if summary_path:
                with open(summary_path, "a", encoding="utf-8") as stream:
                    stream.write(job_summary(findings, tuple(item.target for item in inventories_for_report)))
        if args.github_annotations or os.getenv("GITHUB_ACTIONS") == "true":
            print(annotations(findings), end="")
        if any(inventory.status != CollectionStatus.SUCCESS for inventory in inventories):
            return 1
        blocking = policy.blocking(evaluated)
        return 2 if blocking else 0
    except (OSError, ValueError) as exc:
        print(f"driftwatch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
