import json
import csv
import io
from datetime import datetime, timezone
from typing import Any

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
) -> dict[str, Any]:
    report = {
        "format_version": 1,
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "execution": {"timings": timings or {}},
        "targets": [x.as_report() for x in inventories],
        "summary": {"finding_count": len(findings), "error_count": sum(len(x.errors) for x in inventories)},
        "findings": [x.as_dict() for x in findings],
    }
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
            "ignored": [finding.as_dict() for finding in (ignored_findings or [])],
            "allowed": [finding.as_dict() for finding in (allowed_findings or [])],
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


def render_text(
    findings: list[Finding], analysis: dict[str, Any], output: str | None,
    inventories: list[Inventory] | None = None,
    strategy: ComparisonStrategy | None = None,
    baseline: str | None = None,
    ignored_count: int = 0,
    allowed_count: int = 0,
    verbose: bool = False,
) -> None:
    lines = [f"Findings: {analysis['selected_count']}"]
    if strategy is not None:
        strategy = ComparisonStrategy(strategy)
        description = strategy.value
        if baseline:
            description += f" (baseline={baseline})"
        lines.append(f"Comparison: {description}")
    if verbose:
        lines.append(f"Policy: ignored={ignored_count}, allowed={allowed_count}")
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
            for error in inventory.as_report()["errors"]:
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


def render_sarif(findings: list[Finding], output: str | None) -> None:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level_map = {"info": "note", "warning": "warning", "breaking": "error", "critical": "error"}
    for finding in findings:
        rule_id = finding.kind
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding.message},
            "help": {"text": "Review the schema difference against the expected state."},
        })
        results.append({
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
        })
    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "driftwatch", "informationUri": "https://github.com/MarcosAlves90/driftwatch", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")
