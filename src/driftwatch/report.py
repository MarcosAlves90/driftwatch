import json
import csv
import io
from datetime import datetime, timezone
from typing import Any

from .models import CollectionStatus, ComparisonStrategy, Finding, Inventory


def build_report(
    inventories: list[Inventory],
    findings: list[Finding],
    analysis: dict[str, Any] | None = None,
    strategy: ComparisonStrategy | None = None,
    baseline: str | None = None,
) -> dict[str, Any]:
    report = {
        "format_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": [x.as_report() for x in inventories],
        "summary": {"finding_count": len(findings), "error_count": sum(len(x.errors) for x in inventories)},
        "findings": [x.as_dict() for x in findings],
    }
    if analysis is not None:
        report["analysis"] = analysis
    if strategy is not None:
        strategy = ComparisonStrategy(strategy)
        report["comparison"] = {"strategy": strategy.value, "baseline": baseline}
    report["collection_failures"] = [
        {"target": inventory.target, "status": inventory.status.value, "errors": inventory.errors}
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


def render_text(
    findings: list[Finding], analysis: dict[str, Any], output: str | None,
    inventories: list[Inventory] | None = None,
    strategy: ComparisonStrategy | None = None,
    baseline: str | None = None,
) -> None:
    lines = [f"Findings: {analysis['selected_count']}"]
    if strategy is not None:
        strategy = ComparisonStrategy(strategy)
        description = strategy.value
        if baseline:
            description += f" (baseline={baseline})"
        lines.append(f"Comparison: {description}")
    for label, key in (("severity", "by_severity"), ("kind", "by_kind"), ("object type", "by_object_type")):
        counts = analysis[key]
        rendered = ", ".join(f"{name}={count}" for name, count in counts.items()) or "none"
        lines.append(f"By {label}: {rendered}")
    failures = [inventory for inventory in (inventories or []) if inventory.status != CollectionStatus.SUCCESS]
    if failures:
        lines.append("")
        lines.append("Collection problems:")
        for inventory in failures:
            lines.append(f"- {inventory.target}: {inventory.status.value}")
            for error in inventory.errors:
                lines.append(f"  {error['stage']}: {error['message']}")
    if findings:
        lines.append("")
        for finding in findings:
            lines.append(
                f"[{finding.severity}] {finding.kind} {finding.object_type}|{finding.object_name}: {finding.message}"
            )
    else:
        lines.append("No findings match the selected filters.")
    rendered = "\n".join(lines) + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")


def write_csv(findings: list[Finding], output: str | None) -> None:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow([
        "kind", "object_type", "object_name", "severity", "property", "message",
        "targets", "expected", "actual", "left", "right",
    ])
    for finding in findings:
        writer.writerow([
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
        ])
    rendered = stream.getvalue()
    if output:
        with open(output, "w", encoding="utf-8", newline="") as file:
            file.write(rendered)
    else:
        print(rendered, end="")
