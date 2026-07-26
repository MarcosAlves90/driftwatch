import json
import csv
import io
from datetime import datetime, timezone
from typing import Any

from .models import Finding, Inventory


def build_report(
    inventories: list[Inventory],
    findings: list[Finding],
    analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    report = {
        "format_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": [{"name": x.target, "object_count": len(x.objects), "errors": x.errors} for x in inventories],
        "summary": {"finding_count": len(findings), "error_count": sum(len(x.errors) for x in inventories)},
        "findings": [x.as_dict() for x in findings],
    }
    if analysis is not None:
        report["analysis"] = analysis
    return report


def write_json(report: dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")


def render_text(
    findings: list[Finding], analysis: dict[str, Any], output: str | None
) -> None:
    lines = [f"Findings: {analysis['selected_count']}"]
    for label, key in (("severity", "by_severity"), ("kind", "by_kind"), ("object type", "by_object_type")):
        counts = analysis[key]
        rendered = ", ".join(f"{name}={count}" for name, count in counts.items()) or "none"
        lines.append(f"By {label}: {rendered}")
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
    writer.writerow(["kind", "object_type", "object_name", "severity", "message", "targets", "left", "right"])
    for finding in findings:
        writer.writerow([
            finding.kind,
            finding.object_type,
            finding.object_name,
            finding.severity,
            finding.message,
            ",".join(finding.targets),
            json.dumps(finding.left, ensure_ascii=False, sort_keys=True),
            json.dumps(finding.right, ensure_ascii=False, sort_keys=True),
        ])
    rendered = stream.getvalue()
    if output:
        with open(output, "w", encoding="utf-8", newline="") as file:
            file.write(rendered)
    else:
        print(rendered, end="")
