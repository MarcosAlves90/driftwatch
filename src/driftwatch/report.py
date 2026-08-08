import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from .issues import Issue
from .models import CollectionStatus, ComparisonStrategy, Finding, Inventory
from .policy import Policy


def build_report(
    inventories: list[Inventory],
    findings: list[Finding],
    analysis: dict[str, Any] | None = None,
    strategy: ComparisonStrategy | None = None,
    baseline: str | None = None,
    policy: Policy | None = None,
    ignored_findings: list[Finding] | None = None,
    allowed_findings: list[Finding] | None = None,
    allowed_reasons: dict[str, str] | None = None,
    timings: dict[str, float] | None = None,
    *,
    issues: Iterable[Issue] | None = None,
    issue_analysis: dict[str, Any] | None = None,
    enhanced: bool = False,
) -> dict[str, Any]:
    issue_items = list(issues or [])
    report: dict[str, Any] = {
        "format_version": 2 if enhanced else 1,
        "schema_version": 2 if enhanced else 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "execution": {"timings": timings or {}},
        "targets": [x.as_report(include_inventory=enhanced) for x in inventories],
        "summary": {"finding_count": len(findings), "error_count": sum(len(x.errors) for x in inventories)},
        "findings": [x.as_dict(enhanced=enhanced) for x in findings],
    }
    if enhanced:
        report["summary"]["issue_count"] = len(issue_items)
        report["issues"] = [item.as_dict() for item in issue_items]
        if issue_analysis is not None:
            report["issue_analysis"] = issue_analysis
    if analysis is not None:
        report["analysis"] = analysis
    if strategy is not None:
        strategy = ComparisonStrategy(strategy)
        report["comparison"] = {"strategy": strategy.value, "baseline": baseline}
    if policy is not None:
        report["policy"] = {
            "version": policy.version,
            "fail_on": policy.fail_on.value,
            "ignored_count": len(ignored_findings or []),
            "allowed_count": len(allowed_findings or []),
            "ignored": [finding.as_dict(enhanced=enhanced) for finding in (ignored_findings or [])],
            "allowed": [finding.as_dict(enhanced=enhanced) for finding in (allowed_findings or [])],
            "allowed_reasons": allowed_reasons or {},
        }
    report["collection_failures"] = [
        {"target": inventory.target, "status": inventory.status.value, "errors": inventory.as_report()["errors"]}
        for inventory in inventories
        if inventory.status != CollectionStatus.SUCCESS
    ]
    return report


def write_json(report: dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")


def _issue_lines(issues: Iterable[Issue]) -> list[str]:
    values = list(issues)
    if not values:
        return []
    lines = ["", f"Distinct issues: {len(values)}", ""]
    for issue in values:
        lifecycle = f" {issue.lifecycle.value}" if issue.lifecycle else ""
        evidence = f" ({len(issue.evidence)} observation{'s' if len(issue.evidence) != 1 else ''})"
        lines.append(f"[{issue.severity}]{lifecycle} {issue.kind} {issue.object_type}|{issue.object_name}{evidence}")
        if len(issue.variants) > 1:
            for variant in issue.variants:
                rendered = json.dumps(variant.value, ensure_ascii=False, sort_keys=True, default=str)
                lines.append(f"  {', '.join(variant.targets) or '?'}: {rendered}")
        if issue.impact and issue.impact.get("blast_radius"):
            lines.append(f"  impact: {issue.impact['blast_radius']} dependent object(s)")
    return lines


def _comparison_text(strategy: ComparisonStrategy | None, baseline: str | None) -> str | None:
    if strategy is None:
        return None
    description = ComparisonStrategy(strategy).value
    return f"{description} (baseline={baseline})" if baseline else description


def _analysis_lines(analysis: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for label, key in (("severity", "by_severity"), ("kind", "by_kind"), ("object type", "by_object_type")):
        counts = analysis[key]
        rendered = ", ".join(f"{name}={count}" for name, count in counts.items()) or "none"
        lines.append(f"By {label}: {rendered}")
    return lines


def _collection_problem_lines(inventories: list[Inventory] | None) -> list[str]:
    failures = [inventory for inventory in (inventories or []) if inventory.status != CollectionStatus.SUCCESS]
    if not failures:
        return []
    lines = ["", "Collection problems:"]
    for inventory in failures:
        lines.append(f"- {inventory.target}: {inventory.status.value}")
        lines.extend(f"  {error['stage']}: {error['message']}" for error in inventory.as_report()["errors"])
    return lines


def _finding_lines(findings: list[Finding]) -> list[str]:
    return [
        "",
        *(
            f"[{finding.severity}] {finding.kind} {finding.object_type}|{finding.object_name}: {finding.message}"
            for finding in findings
        ),
    ]


def _write_rendered(rendered: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")


def render_text(
    findings: list[Finding],
    analysis: dict[str, Any],
    output: str | None,
    inventories: list[Inventory] | None = None,
    strategy: ComparisonStrategy | None = None,
    baseline: str | None = None,
    ignored_count: int = 0,
    allowed_count: int = 0,
    verbose: bool = False,
    summary_only: bool = False,
    issues: Iterable[Issue] | None = None,
) -> None:
    issue_items = list(issues or [])
    lines = [f"Findings: {analysis['selected_count']}" + (" observations" if issue_items else "")]
    if issue_items:
        lines.append(f"Issues: {len(issue_items)}")
    comparison = _comparison_text(strategy, baseline)
    if comparison is not None:
        lines.append(f"Comparison: {comparison}")
    if verbose:
        lines.append(f"Policy: ignored={ignored_count}, allowed={allowed_count}")
    lines.extend(_analysis_lines(analysis))
    lines.extend(_collection_problem_lines(inventories))
    if not summary_only:
        if issue_items:
            lines.extend(_issue_lines(issue_items))
        elif findings:
            lines.extend(_finding_lines(findings))
        else:
            lines.append("No findings match the selected filters.")
    _write_rendered("\n".join(lines) + "\n", output)


def write_csv(findings: list[Finding], output: str | None, *, enhanced: bool = False) -> None:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    columns = [
        "kind",
        "object_type",
        "object_name",
        "severity",
        "property",
        "message",
        "targets",
        "expected",
        "actual",
        "left",
        "right",
    ]
    if enhanced:
        columns += ["baseline", "fingerprint"]
    writer.writerow(columns)
    for finding in findings:
        row = [
            finding.kind,
            finding.object_type,
            finding.object_name,
            finding.severity,
            finding.property or "",
            finding.message,
            ",".join(finding.targets),
            json.dumps(finding.expected, ensure_ascii=False, sort_keys=True),
            json.dumps(finding.actual, ensure_ascii=False, sort_keys=True),
            json.dumps(finding.left, ensure_ascii=False, sort_keys=True),
            json.dumps(finding.right, ensure_ascii=False, sort_keys=True),
        ]
        if enhanced:
            baseline = finding.comparison[0] if finding.comparison else ""
            if not baseline and finding.targets:
                baseline = finding.targets[0]
            row += [baseline, finding.fingerprint]
        writer.writerow(row)
    rendered = stream.getvalue()
    if output:
        with open(output, "w", encoding="utf-8", newline="") as file:
            file.write(rendered)
    else:
        print(rendered, end="")


def render_html(
    findings: list[Finding], analysis: dict[str, Any], output: str | None, *, issues: Iterable[Issue] | None = None
) -> None:
    """Write a self-contained, escaped static report."""
    issue_items = list(issues or [])
    rows = []
    if issue_items:
        for issue in issue_items:
            variants = "; ".join(f"{','.join(variant.targets)}={variant.value!r}" for variant in issue.variants)
            impact = str((issue.impact or {}).get("blast_radius", 0))
            cells = [
                issue.severity,
                issue.kind,
                issue.object_type,
                issue.object_name,
                issue.property or "",
                variants,
                impact,
            ]
            rows.append("<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in cells) + "</tr>")
        header = (
            "<th>Severity</th><th>Kind</th><th>Type</th><th>Object</th>"
            "<th>Property</th><th>Variants</th><th>Blast radius</th>"
        )
        count = len(issue_items)
        label = "Issues"
    else:
        for finding in findings:
            cells = [
                finding.severity,
                finding.kind,
                finding.object_type,
                finding.object_name,
                finding.property or "",
                finding.message,
                str(finding.expected),
                str(finding.actual),
            ]
            rows.append("<tr>" + "".join(f"<td>{html.escape(cell)}</td>" for cell in cells) + "</tr>")
        header = (
            "<th>Severity</th><th>Kind</th><th>Type</th><th>Object</th>"
            "<th>Property</th><th>Message</th><th>Expected</th><th>Actual</th>"
        )
        count = analysis.get("selected_count", len(findings))
        label = "Findings"
    document = (
        """<!doctype html><meta charset="utf-8"><title>Driftwatch report</title>
<style>
body{font:14px system-ui;margin:2rem}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ddd;padding:.4rem;text-align:left}
th{background:#f4f4f4}
.critical,.breaking{font-weight:700}
</style>
<h1>Driftwatch report</h1><p>"""
        + label
        + ": "
        + str(count)
        + "</p><table><thead><tr>"
        + header
        + "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>\n"
    )
    if output:
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(document)
    else:
        print(document, end="")


def render_sarif(findings: list[Finding], output: str | None, *, issues: Iterable[Issue] | None = None) -> None:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level_map = {"info": "note", "warning": "warning", "breaking": "error", "critical": "error"}
    issue_items = list(issues or [])
    if issue_items:
        for issue in issue_items:
            rules.setdefault(
                issue.kind,
                {
                    "id": issue.kind,
                    "name": issue.kind,
                    "shortDescription": {"text": issue.message},
                    "help": {"text": "Review the grouped schema issue, dependencies, and remediation plan."},
                },
            )
            results.append(
                {
                    "ruleId": issue.kind,
                    "level": level_map.get(issue.severity, "warning"),
                    "message": {"text": f"{issue.object_type}|{issue.object_name}: {issue.message}"},
                    "fingerprints": {"driftwatch/v2": issue.issue_key},
                    "properties": {
                        "severity": issue.severity,
                        "object_type": issue.object_type,
                        "object_name": issue.object_name,
                        "property": issue.property,
                        "evidence_count": len(issue.evidence),
                        "affected_targets": list(issue.affected_targets),
                        "variants": [variant.as_dict() for variant in issue.variants],
                    },
                }
            )
    else:
        for finding in findings:
            rule_id = finding.kind
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": finding.message},
                    "help": {"text": "Review the schema difference against the expected state."},
                },
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level_map.get(finding.severity, "warning"),
                    "message": {"text": finding.message},
                    "fingerprints": {"driftwatch/v1": finding.fingerprint},
                    "properties": {
                        "severity": finding.severity,
                        "object_type": finding.object_type,
                        "object_name": finding.object_name,
                        "property": finding.property,
                        "expected": finding.expected,
                        "actual": finding.actual,
                    },
                }
            )
    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "driftwatch",
                        "informationUri": "https://github.com/MarcosAlves90/driftwatch",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")
