import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path

from .collector import collect, collect_many
from .config import DriftConfig, apply_cli_credentials, load_config
from .diff import compare, compare_all
from .evidence import attach_evidence
from .github import annotations, job_summary
from .issues import aggregate_issues, analyze_issues
from .models import CollectionStatus, ComparisonStrategy, DatabaseTarget, Inventory, Severity
from .normalize import NormalizationOptions
from .policy import Policy, PolicyResult, load_policy
from .query import analyze_findings, select_findings
from .report import build_report, render_html, render_sarif, render_text, write_csv, write_json
from .snapshot import inventory_from_snapshot, write_snapshot

EXIT_CLEAN = 0
EXIT_RUNTIME = 1
EXIT_POLICY = 2
EXIT_INCONCLUSIVE = 3


def _collection_exit(inventories: list[Inventory]) -> int:
    if any(item.status == CollectionStatus.FAILED for item in inventories):
        return EXIT_RUNTIME
    if any(item.status == CollectionStatus.PARTIAL for item in inventories):
        return EXIT_INCONCLUSIVE
    return EXIT_CLEAN


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="driftwatch", description="Compare and investigate SQL Server schemas.")
    parser.add_argument(
        "command",
        nargs="?",
        choices=(
            "check",
            "compare",
            "snapshot",
            "explain",
            "inspect",
            "deps",
            "plan",
            "history",
            "config",
            "migration",
        ),
        default="check",
    )
    parser.add_argument(
        "subcommand",
        nargs="?",
        help="command-specific subject, e.g. config validate or inspect dbo.Users",
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
    parser.add_argument("--strategy", choices=("baseline", "pairwise"), help="comparison strategy")
    parser.add_argument("--baseline", help="reference target for baseline comparisons")
    parser.add_argument("--policy", help="versioned JSON policy file")
    parser.add_argument("--fail-on", choices=tuple(item.value for item in Severity), help="minimum severity that fails")
    parser.add_argument("--workers", type=int, help="maximum concurrent target collections")
    parser.add_argument("--connect-timeout", type=int, help="connection timeout in seconds")
    parser.add_argument("--query-timeout", type=int, help="metadata query timeout in seconds")
    parser.add_argument("--kind", action="append", help="filter by finding kind")
    parser.add_argument("--severity", action="append", help="filter by severity")
    parser.add_argument("--target", action="append", help="filter/select target")
    parser.add_argument("--object", dest="objects", action="append", help="filter by object name")
    parser.add_argument("--property", dest="properties", action="append", help="filter by changed property")
    parser.add_argument("--lifecycle", action="append", help="filter by lifecycle state")
    parser.add_argument("--issue", dest="issues", action="append", help="filter/select issue or occurrence ID")
    parser.add_argument("--query", help="case-insensitive search across finding evidence")
    parser.add_argument("--created-before")
    parser.add_argument("--created-after")
    parser.add_argument("--modified-before")
    parser.add_argument("--modified-after")
    parser.add_argument("--depends-on", help="select findings whose impact mentions an object")
    parser.add_argument("--summary-only", action="store_true", help="render aggregate totals only")
    parser.add_argument("--quiet", action="store_true", help="suppress stdout while preserving exit codes")
    parser.add_argument(
        "--raw-findings",
        action="store_true",
        help="show comparison observations instead of grouped issues",
    )
    parser.add_argument("--previous", help="previous JSON report or snapshot for lifecycle/history")
    parser.add_argument("--report", help="existing JSON report for inspect/explain/deps/plan/history")
    parser.add_argument("--fingerprint", help="legacy finding fingerprint for explain")
    parser.add_argument("--before", dest="before_snapshot", help="before snapshot for migration verify")
    parser.add_argument("--after", dest="after_snapshot", help="after snapshot for migration verify")
    parser.add_argument("--expected-effect", action="append", help="expected migration kind/object/fingerprint")
    parser.add_argument("--impact-depth", type=int, default=3, help="dependency traversal depth for impact metadata")
    parser.add_argument("--direction", choices=("dependents", "dependencies"), default="dependents")
    parser.add_argument("--dependency-depth", type=int, default=3)
    parser.add_argument("--desired-target", help="reference target used for remediation planning")
    parser.add_argument("--verbose", action="store_true", help="include policy counters in text output")
    parser.add_argument("--github-summary", action="store_true", help="write Markdown summary to GITHUB_STEP_SUMMARY")
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
    auth: str | None = None,
) -> list[Inventory]:
    settings_normalization = normalization or {}

    def target_collector(target: DatabaseTarget, *_args) -> Inventory:
        if connect_timeout == 30 and query_timeout is None and not settings_normalization and auth is None:
            return collect(target)
        return collect(target, connect_timeout, query_timeout, NormalizationOptions(**settings_normalization), auth)

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


def _write_text(rendered: str, output: str | None, quiet: bool = False) -> None:
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
    elif not quiet:
        print(rendered, end="")


def _load_report(path: str | None) -> dict:
    if not path:
        raise ValueError("this command requires --report")
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid report {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("report root must be an object")
    return value


def _subject(args) -> str | None:
    if args.issues:
        return args.issues[0]
    if args.fingerprint:
        return args.fingerprint
    if args.subcommand:
        return args.subcommand
    if args.objects:
        return args.objects[0]
    return None


def _json_text(key: str, value: str) -> str:
    return json.dumps({key: value}, ensure_ascii=False, indent=2) + "\n"


def _require_subject(args) -> str:
    subject = _subject(args)
    if not subject:
        raise ValueError(f"{args.command} requires an object, --issue, or --fingerprint")
    return subject


def _offline_inspect(args, report: dict) -> int:
    from .investigation import inspect_report

    rendered = inspect_report(report, _subject(args))
    payload = rendered if args.format == "text" else _json_text("text", rendered)
    _write_text(payload, args.output, args.quiet)
    return EXIT_CLEAN


def _offline_explain(args, report: dict) -> int:
    from .investigation import explain_report

    rendered = explain_report(report, _require_subject(args))
    payload = rendered if args.format == "text" else _json_text("explanation", rendered)
    _write_text(payload, args.output, args.quiet)
    return EXIT_CLEAN


def _dependency_text(payload: dict) -> str:
    lines: list[str] = []
    for result in payload["results"]:
        lines.append(
            f"{result['target']} {result['object']} {result['direction']} "
            f"(coverage={result['coverage']}, depth={result['depth']})"
        )
        lines.extend(f"- {item}" for item in result["objects"])
    return "\n".join(lines) + "\n"


def _offline_deps(args, report: dict) -> int:
    from .investigation import dependency_report

    target = args.target[0] if args.target and len(args.target) == 1 else None
    payload = dependency_report(
        report,
        _require_subject(args),
        target=target,
        direction=args.direction,
        depth=args.dependency_depth,
    )
    rendered = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.format == "json"
        else _dependency_text(payload)
    )
    _write_text(rendered, args.output, args.quiet)
    return EXIT_CLEAN


def _offline_plan(args, report: dict) -> int:
    from .investigation import plan_report

    rendered = plan_report(report, _require_subject(args), desired_target=args.desired_target)
    payload = rendered if args.format == "text" else _json_text("plan", rendered)
    _write_text(payload, args.output, args.quiet)
    return EXIT_CLEAN


def _offline_history(args, report: dict) -> int:
    from .investigation import history_report

    previous = _load_report(args.previous) if args.previous else None
    rendered = history_report(report, previous, _require_subject(args))
    _write_text(rendered, args.output, args.quiet)
    return EXIT_CLEAN


_OFFLINE_HANDLERS = {
    "inspect": _offline_inspect,
    "explain": _offline_explain,
    "deps": _offline_deps,
    "plan": _offline_plan,
    "history": _offline_history,
}


def _offline_command(args) -> int | None:
    handler = _OFFLINE_HANDLERS.get(args.command)
    if handler is None:
        return None
    return handler(args, _load_report(args.report))


def _emit_report(report, findings, issues, args, inventories, strategy, baseline) -> None:
    if args.quiet and not args.output:
        return
    grouped = [] if args.raw_findings else issues
    if args.format == "json":
        write_json(report, args.output)
    elif args.format == "csv":
        write_csv(findings, args.output, enhanced=True)
    elif args.format == "html":
        render_html(findings, report["analysis"], args.output, issues=grouped)
    elif args.format == "sarif":
        render_sarif(findings, args.output, issues=grouped)
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
            issues=grouped,
        )


def _representative_findings(findings, issues):
    by_key = {finding.issue_key: finding for finding in findings}
    return [by_key[issue.issue_key] for issue in issues if issue.issue_key in by_key]


def _run_config(args) -> int:
    if args.subcommand != "validate":
        raise ValueError("config requires the validate subcommand")
    if not args.config:
        raise ValueError("config validate requires --config")
    load_config(args.config, min_targets=1)
    if not args.quiet:
        print("configuration is valid")
    return EXIT_CLEAN


def _render_migration(args, migration_report, evaluated: PolicyResult, policy: Policy) -> None:
    if args.quiet and not args.output:
        return
    from .migration import render_migration_text

    payload = migration_report.as_dict()
    payload["policy"] = {"blocking_count": len(policy.blocking(evaluated))}
    payload["findings"] = [item.as_dict(enhanced=True) for item in evaluated.findings]
    if args.format == "json":
        write_json(payload, args.output)
    elif args.format == "text":
        _write_text(render_migration_text(migration_report), args.output, args.quiet)
    elif args.format == "html":
        render_html(migration_report.findings, analyze_findings(migration_report.findings), args.output)
    elif args.format == "csv":
        write_csv(migration_report.findings, args.output, enhanced=True)
    else:
        render_sarif(migration_report.findings, args.output)


def _run_migration(args) -> int:
    if args.subcommand != "verify":
        raise ValueError("migration requires the verify subcommand")
    if not args.before_snapshot or not args.after_snapshot:
        raise ValueError("migration verify requires --before and --after")
    from .migration import verify_migration

    before = inventory_from_snapshot(args.before_snapshot)
    after = inventory_from_snapshot(args.after_snapshot)
    migration_report = verify_migration(before, after, expected=args.expected_effect or ())
    policy = _policy_from_args(args.policy, args.fail_on)
    evaluated = policy.evaluate(migration_report.findings)
    _render_migration(args, migration_report, evaluated, policy)
    return EXIT_POLICY if policy.blocking(evaluated) else EXIT_CLEAN


@dataclass(frozen=True)
class _Runtime:
    settings: DriftConfig
    policy: Policy
    targets: list[DatabaseTarget]
    workers: int
    connect_timeout: int
    query_timeout: int | None
    strategy: ComparisonStrategy
    baseline: str | None


def _read_password(args) -> str | None:
    if not args.password_stdin:
        return args.password
    if sys.stdin.isatty():
        raise ValueError("--password-stdin requires a piped password")
    return sys.stdin.readline().rstrip("\r\n")


def _effective_strategy(args, settings: DriftConfig, policy: Policy) -> tuple[ComparisonStrategy, str | None]:
    strategy = ComparisonStrategy(args.strategy) if args.strategy else policy.strategy or settings.strategy
    baseline = args.baseline or policy.baseline or settings.baseline
    if args.baseline and args.strategy is None:
        strategy = ComparisonStrategy.BASELINE
    return strategy, baseline


def _validate_runtime_limits(workers: int, connect_timeout: int, query_timeout: int | None) -> None:
    if workers < 1 or workers > 32:
        raise ValueError("workers must be an integer from 1 to 32")
    if connect_timeout < 1 or (query_timeout is not None and query_timeout < 1):
        raise ValueError("timeouts must be positive integers")


def _runtime(args) -> _Runtime:
    if not args.config:
        raise ValueError("--config is required")
    min_targets = 1 if args.command == "snapshot" or args.snapshot_path else 2
    settings = load_config(args.config, min_targets=min_targets)
    policy = _policy_from_args(args.policy, args.fail_on)
    targets = apply_cli_credentials(settings.targets, args.username, _read_password(args))
    workers = args.workers if args.workers is not None else settings.workers
    connect_timeout = args.connect_timeout if args.connect_timeout is not None else settings.connect_timeout
    query_timeout = args.query_timeout if args.query_timeout is not None else settings.query_timeout
    _validate_runtime_limits(workers, connect_timeout, query_timeout)
    strategy, baseline = _effective_strategy(args, settings, policy)
    if baseline is not None and not args.snapshot_path and baseline not in {target.name for target in targets}:
        raise ValueError(f"baseline target {baseline!r} is not configured")
    return _Runtime(settings, policy, targets, workers, connect_timeout, query_timeout, strategy, baseline)


def _collect_runtime(runtime: _Runtime) -> list[Inventory]:
    return _collect_with_options(
        runtime.targets,
        runtime.workers,
        runtime.connect_timeout,
        runtime.query_timeout,
        runtime.settings.normalization,
        runtime.settings.auth,
    )


def _run_snapshot(args, runtime: _Runtime) -> int:
    inventories = _collect_runtime(runtime)
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
    return _collection_exit(selected)


def _compare_with_snapshot(args, inventories: list[Inventory]) -> tuple[list, list[Inventory]]:
    expected = inventory_from_snapshot(args.snapshot_path)
    comparable = [item for item in inventories if item.status != CollectionStatus.FAILED]
    findings = [finding for actual in comparable for finding in compare(expected, actual)]
    return findings, [expected, *inventories]


def _compare_targets(args, runtime: _Runtime, inventories: list[Inventory]) -> tuple[list, list[Inventory]]:
    comparable = [item for item in inventories if item.status != CollectionStatus.FAILED]
    if runtime.strategy == ComparisonStrategy.BASELINE and runtime.baseline not in {item.target for item in comparable}:
        return [], inventories
    if len(comparable) < 2:
        return [], inventories
    use_default_pairwise = (
        runtime.strategy == ComparisonStrategy.PAIRWISE
        and args.strategy is None
        and runtime.policy.strategy is None
        and runtime.settings.strategy == ComparisonStrategy.PAIRWISE
    )
    findings = (
        compare_all(comparable)
        if use_default_pairwise
        else compare_all(comparable, strategy=runtime.strategy, baseline=runtime.baseline)
    )
    return findings, inventories


def _compare_runtime(args, runtime: _Runtime, inventories: list[Inventory]) -> tuple[list, list[Inventory]]:
    return _compare_with_snapshot(args, inventories) if args.snapshot_path else _compare_targets(args, runtime, inventories)


def _apply_lifecycle(args, findings: list, inventories: list[Inventory]) -> list:
    if not args.previous:
        return findings
    from .lifecycle import classify_findings, load_previous_report

    previous = load_previous_report(args.previous)
    if "snapshot_version" in previous:
        previous_inventory = inventory_from_snapshot(args.previous)
        previous_findings = [
            finding
            for actual in inventories
            if actual.status != CollectionStatus.FAILED
            for finding in compare(previous_inventory, actual)
        ]
        previous = {"findings": [finding.as_dict(enhanced=True) for finding in previous_findings]}
    observed_at = max((item.observed_at for item in inventories if item.observed_at), default=None)
    return classify_findings(findings, previous, observed_at=observed_at)


def _enrich_findings(args, findings: list, inventories: list[Inventory]) -> list:
    if args.impact_depth < 0:
        raise ValueError("impact depth must not be negative")
    if args.impact_depth:
        from .dependency import add_target_impact

        findings = add_target_impact(findings, inventories, args.impact_depth)
    findings = attach_evidence(findings, inventories)
    return _apply_lifecycle(args, findings, inventories)


def _select(args, evaluated: PolicyResult) -> list:
    return select_findings(
        evaluated.findings,
        kinds=args.kind,
        severities=args.severity,
        targets=args.target,
        objects=args.objects,
        query=args.query,
        lifecycles=args.lifecycle,
        properties=args.properties,
        created_before=args.created_before,
        created_after=args.created_after,
        modified_before=args.modified_before,
        modified_after=args.modified_after,
        depends_on=args.depends_on,
        issue_keys=args.issues,
    )


def _build_runtime_report(
    runtime: _Runtime,
    inventories: list[Inventory],
    findings: list,
    evaluated: PolicyResult,
    collection_seconds: float,
    comparison_seconds: float,
    execution_started: float,
):
    analysis = analyze_findings(findings)
    issues = aggregate_issues(findings)
    report = build_report(
        inventories,
        findings,
        analysis,
        strategy=runtime.strategy,
        baseline=runtime.baseline,
        policy=runtime.policy,
        ignored_findings=evaluated.ignored,
        allowed_findings=evaluated.allowed,
        allowed_reasons=evaluated.allowed_reasons,
        timings={
            "collection_seconds": round(collection_seconds, 6),
            "comparison_seconds": round(comparison_seconds, 6),
            "total_seconds": round(time.perf_counter() - execution_started, 6),
        },
        issues=issues,
        issue_analysis=analyze_issues(issues),
        enhanced=True,
    )
    report["policy"]["blocking_count"] = len(runtime.policy.blocking(evaluated))
    return report, analysis, issues


def _emit_runtime_report(args, runtime: _Runtime, inventories, report, analysis, findings, issues, evaluated) -> None:
    if not args.summary_only:
        _emit_report(report, findings, issues, args, inventories, runtime.strategy, runtime.baseline)
        return
    if args.quiet and not args.output:
        return
    if args.format != "text":
        _emit_report(report, [], issues, args, inventories, runtime.strategy, runtime.baseline)
        return
    render_text(
        [],
        analysis,
        args.output,
        inventories,
        runtime.strategy,
        runtime.baseline,
        len(evaluated.ignored),
        len(evaluated.allowed),
        args.verbose,
        summary_only=True,
        issues=issues,
    )


def _emit_github(args, findings, issues, inventories) -> None:
    representatives = _representative_findings(findings, issues)
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if (args.github_summary or summary_path) and summary_path:
        with open(summary_path, "a", encoding="utf-8") as stream:
            stream.write(job_summary(representatives, tuple(item.target for item in inventories)))
    if args.github_annotations or os.getenv("GITHUB_ACTIONS") == "true":
        print(annotations(representatives), end="")


def _run_live(args, execution_started: float) -> int:
    runtime = _runtime(args)
    if args.command == "snapshot":
        return _run_snapshot(args, runtime)
    collection_started = time.perf_counter()
    collected = _collect_runtime(runtime)
    collection_seconds = time.perf_counter() - collection_started
    comparison_started = time.perf_counter()
    all_findings, inventories = _compare_runtime(args, runtime, collected)
    comparison_seconds = time.perf_counter() - comparison_started
    all_findings = _enrich_findings(args, all_findings, inventories)
    evaluated = runtime.policy.evaluate(all_findings)
    findings = _select(args, evaluated)
    report, analysis, issues = _build_runtime_report(
        runtime,
        inventories,
        findings,
        evaluated,
        collection_seconds,
        comparison_seconds,
        execution_started,
    )
    _emit_runtime_report(args, runtime, inventories, report, analysis, findings, issues, evaluated)
    _emit_github(args, findings, issues, inventories)
    collection_exit = _collection_exit(collected)
    if collection_exit:
        return collection_exit
    return EXIT_POLICY if runtime.policy.blocking(evaluated) else EXIT_CLEAN


def _dispatch(args, execution_started: float) -> int:
    offline_exit = _offline_command(args)
    if offline_exit is not None:
        return offline_exit
    if args.command == "config":
        return _run_config(args)
    if args.command == "migration":
        return _run_migration(args)
    return _run_live(args, execution_started)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _dispatch(args, time.perf_counter())
    except (OSError, ValueError) as exc:
        print(f"driftwatch: {exc}", file=sys.stderr)
        return EXIT_RUNTIME


if __name__ == "__main__":
    raise SystemExit(main())
