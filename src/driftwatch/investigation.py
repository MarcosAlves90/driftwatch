"""Human-oriented inspection, explanation, dependency and history views for reports."""

from typing import Any

from .dependency import dependency_view
from .issues import Issue, IssueVariant
from .models import (
    CollectionSectionStatus,
    CollectionStatus,
    Finding,
    FindingLifecycle,
    Inventory,
    ObjectId,
)
from .remediation import RemediationPlan, plan_for_finding, render_remediation_text


def inventory_from_report_target(target: dict[str, Any]) -> Inventory:
    inventory = target.get("inventory") or {}
    sections = {
        name: CollectionSectionStatus(CollectionStatus(value.get("status", "SUCCESS")), value.get("error"))
        for name, value in (target.get("sections") or {}).items()
        if isinstance(value, dict) and value.get("status") in {item.value for item in CollectionStatus}
    }
    return Inventory(
        target=str(target.get("name", "")),
        objects=dict(inventory.get("objects") or {}),
        errors=list(target.get("errors") or []),
        status=CollectionStatus(target.get("status", "SUCCESS")),
        sections=sections,
        metadata=dict(target.get("metadata") or {}),
        object_metadata=dict(inventory.get("object_metadata") or {}),
        dependencies=list(inventory.get("dependencies") or []),
        observed_at=target.get("observed_at"),
    )


def inventories_from_report(report: dict[str, Any]) -> list[Inventory]:
    return [inventory_from_report_target(target) for target in report.get("targets", [])]


def _comparison_pair(value: Any) -> tuple[str, str] | None:
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return (str(value[0]), str(value[1]))
    return None


def finding_from_dict(value: dict[str, Any]) -> Finding:
    lifecycle = value.get("lifecycle")
    return Finding(
        kind=str(value.get("kind", "")),
        object_type=str(value.get("object_type", "")),
        object_name=str(value.get("object_name", "")),
        severity=str(value.get("severity", "warning")),
        message=str(value.get("message", "")),
        left=value.get("left"),
        right=value.get("right"),
        targets=tuple(value.get("targets") or ()),
        property=value.get("property"),
        expected=value.get("expected"),
        actual=value.get("actual"),
        lifecycle=FindingLifecycle(lifecycle) if lifecycle in {item.value for item in FindingLifecycle} else None,
        planned=value.get("planned"),
        impact=value.get("impact"),
        rule=value.get("rule"),
        comparison=_comparison_pair(value.get("comparison")),
        first_seen_at=value.get("first_seen_at"),
        last_seen_at=value.get("last_seen_at"),
        metadata=value.get("metadata"),
        stable_issue_key=value.get("issue_key"),
    )


def issue_from_dict(value: dict[str, Any]) -> Issue:
    lifecycle = value.get("lifecycle")
    return Issue(
        issue_key=str(value.get("issue_key", "")),
        kind=str(value.get("kind", "")),
        object_type=str(value.get("object_type", "")),
        object_name=str(value.get("object_name", "")),
        severity=str(value.get("severity", "warning")),
        message=str(value.get("message", "")),
        property=value.get("property"),
        variants=tuple(
            IssueVariant(item.get("value"), tuple(item.get("targets") or ())) for item in value.get("variants", [])
        ),
        affected_targets=tuple(value.get("affected_targets") or ()),
        evidence=tuple(value.get("evidence") or ()),
        comparisons=tuple(tuple(item) for item in value.get("comparisons", [])),
        lifecycle=FindingLifecycle(lifecycle) if lifecycle in {item.value for item in FindingLifecycle} else None,
        first_seen_at=value.get("first_seen_at"),
        last_seen_at=value.get("last_seen_at"),
        impact=value.get("impact"),
    )


def _matching_findings(report: dict[str, Any], key: str | None = None) -> list[Finding]:
    findings = [finding_from_dict(item) for item in report.get("findings", [])]
    if not key:
        return findings
    normalized = key.casefold()
    return [
        item
        for item in findings
        if normalized
        in {
            item.fingerprint.casefold(),
            item.issue_key.casefold(),
            item.occurrence_id.casefold(),
            item.object_name.casefold(),
        }
        or normalized in item.object_name.casefold()
    ]


def _matching_issues(report: dict[str, Any], key: str | None = None) -> list[Issue]:
    issues = [issue_from_dict(item) for item in report.get("issues", [])]
    if not key:
        return issues
    normalized = key.casefold()
    return [
        item
        for item in issues
        if normalized in {item.issue_key.casefold(), item.object_name.casefold()}
        or normalized in item.object_name.casefold()
    ]


def _matching_object_keys(inventories: list[Inventory], object_query: str) -> list[str]:
    normalized = object_query.casefold()
    return sorted(
        {
            key
            for inventory in inventories
            for key in inventory.objects
            if normalized in key.casefold() or normalized in ObjectId.parse(key).qualified_name.casefold()
        }
    )


def _append_object_details(lines: list[str], key: str, inventories: list[Inventory]) -> None:
    lines.extend(["", key, "Targets"])
    lines.extend(
        f"- {inventory.target}: {'present' if key in inventory.objects else 'missing'}" for inventory in inventories
    )
    lines.append("Metadata")
    metadata_lines = [
        f"- {inventory.target}: created={metadata.get('created_at') or 'unknown'}, "
        f"modified={metadata.get('modified_at') or 'unknown'}, observed={inventory.observed_at or 'unknown'}"
        for inventory in inventories
        if (metadata := inventory.object_metadata.get(key))
    ]
    lines.extend(metadata_lines or ["- unavailable in this report"])
    node = ObjectId.parse(key)
    lines.append("Dependencies")
    for inventory in inventories:
        if key not in inventory.objects:
            continue
        view = dependency_view(inventory, node, direction="dependents", depth=3)
        lines.append(f"- {inventory.target}: {len(view['objects'])} dependent(s), coverage={view['coverage']}")
        lines.extend(f"  - {dependent}" for dependent in view["objects"][:10])


def _append_issue_or_finding_summary(lines: list[str], issues: list[Issue], findings: list[Finding]) -> None:
    if issues:
        lines.extend(["", "Open issues"])
        for issue in issues:
            lifecycle = f" {issue.lifecycle.value}" if issue.lifecycle else ""
            lines.append(f"- [{issue.severity}]{lifecycle} {issue.kind} {issue.issue_key[:12]}")
            lines.extend(f"  - {', '.join(variant.targets)}: {variant.value!r}" for variant in issue.variants)
        return
    if findings:
        lines.extend(["", "Findings"])
        lines.extend(f"- [{item.severity}] {item.kind}: {item.message}" for item in findings)


def inspect_report(report: dict[str, Any], object_query: str | None = None) -> str:
    if not object_query:
        summary = report.get("summary", {})
        return (
            f"Issues: {summary.get('issue_count', len(report.get('issues', [])))}\n"
            f"Findings: {summary.get('finding_count', len(report.get('findings', [])))}\n"
            f"Targets: {', '.join(str(item.get('name')) for item in report.get('targets', []))}\n"
        )
    inventories = inventories_from_report(report)
    matching_keys = _matching_object_keys(inventories, object_query)
    issues = _matching_issues(report, object_query)
    findings = _matching_findings(report, object_query)
    if not matching_keys and not issues and not findings:
        return f"No report data matches {object_query!r}.\n"
    lines = [f"Object query: {object_query}"]
    for key in matching_keys:
        _append_object_details(lines, key, inventories)
    _append_issue_or_finding_summary(lines, issues, findings)
    return "\n".join(lines) + "\n"


def _plan_for_report(
    report: dict[str, Any],
    finding: Finding,
    *,
    desired_target: str | None = None,
) -> RemediationPlan:
    comparison = report.get("comparison") or {}
    strategy = comparison.get("strategy")
    if desired_target is None and strategy == "baseline":
        desired_target = comparison.get("baseline")
    if desired_target is None and strategy == "pairwise":
        return RemediationPlan(
            status="MANUAL_REVIEW_REQUIRED",
            confidence="high",
            risk="unknown",
            reason=(
                "Pairwise comparison has no authoritative target. Select --desired-target "
                "before generating directional DDL."
            ),
            verification=("Rerun Driftwatch after applying an explicitly reviewed migration.",),
        )
    return plan_for_finding(
        finding,
        inventories_from_report(report),
        desired_target=desired_target,
    )


def _explanation_context(report: dict[str, Any], key: str) -> tuple[Issue | None, Finding]:
    issues = _matching_issues(report, key)
    findings = _matching_findings(report, key)
    if not issues and not findings:
        raise ValueError(f"no finding or issue matches {key!r}")
    issue = issues[0] if issues else None
    evidence = findings
    if issue is not None:
        evidence = [item for item in findings_from_report(report) if item.issue_key == issue.issue_key]
    return issue, evidence[0] if evidence else findings[0]


def _append_variants(lines: list[str], issue: Issue | None, finding: Finding) -> None:
    if issue is not None and issue.variants:
        lines.extend(["", "Variants"])
        lines.extend(f"- {', '.join(variant.targets)}: {variant.value!r}" for variant in issue.variants)
        return
    if finding.comparison:
        lines.extend(
            [
                "",
                "Comparison",
                f"- {finding.comparison[0]}: {finding.expected!r}",
                f"- {finding.comparison[1]}: {finding.actual!r}",
            ]
        )


def _append_lifecycle(lines: list[str], issue: Issue | None) -> None:
    if issue is None or issue.lifecycle is None:
        return
    lines.extend(
        [
            "",
            "Lifecycle",
            f"- State: {issue.lifecycle.value}",
            f"- First seen: {issue.first_seen_at or 'unknown'}",
            f"- Last seen: {issue.last_seen_at or 'unknown'}",
        ]
    )


def _append_impact(lines: list[str], impact: dict[str, Any] | None) -> None:
    if not impact:
        return
    lines.extend(
        [
            "",
            "Impact",
            f"- Direct dependents: {impact.get('direct_dependents', 0)}",
            f"- Indirect dependents: {impact.get('indirect_dependents', 0)}",
            f"- Blast radius: {impact.get('blast_radius', 0)}",
        ]
    )
    for target, target_impact in sorted((impact.get("by_target") or {}).items()):
        lines.append(f"- {target} dependency coverage: {target_impact.get('coverage', 'unknown')}")


def explain_report(report: dict[str, Any], key: str) -> str:
    issue, representative = _explanation_context(report, key)
    severity = issue.severity if issue else representative.severity
    object_type = issue.object_type if issue else representative.object_type
    object_name = issue.object_name if issue else representative.object_name
    lines = [
        f"{severity.upper()} — {object_type}|{object_name}",
        "",
        "Problem",
        issue.message if issue else representative.message,
    ]
    _append_variants(lines, issue, representative)
    _append_lifecycle(lines, issue)
    _append_impact(lines, issue.impact if issue else representative.impact)
    lines.extend(["", "Severity rationale", _severity_rationale(representative)])
    plan = _plan_for_report(report, representative)
    lines.extend(["", "Recommended resolution", render_remediation_text(plan).rstrip()])
    return "\n".join(lines) + "\n"


def findings_from_report(report: dict[str, Any]) -> list[Finding]:
    return [finding_from_dict(item) for item in report.get("findings", [])]


def dependency_report(
    report: dict[str, Any],
    object_query: str,
    *,
    target: str | None = None,
    direction: str = "dependents",
    depth: int = 3,
) -> dict[str, Any]:
    inventories = inventories_from_report(report)
    if target:
        inventories = [item for item in inventories if item.target == target]
        if not inventories:
            raise ValueError(f"target {target!r} is not present in report")
    normalized = object_query.casefold()
    exact: list[tuple[Inventory, ObjectId]] = []
    partial: list[tuple[Inventory, ObjectId]] = []
    for inventory in inventories:
        for key in inventory.objects:
            node = ObjectId.parse(key)
            if normalized in {key.casefold(), node.qualified_name.casefold()}:
                exact.append((inventory, node))
            elif normalized in key.casefold():
                partial.append((inventory, node))
    matched = exact or partial
    if not matched:
        raise ValueError(f"object {object_query!r} is not present in report inventory")
    return {"results": [dependency_view(inv, node, direction=direction, depth=depth) for inv, node in matched]}


def plan_report(report: dict[str, Any], key: str, *, desired_target: str | None = None) -> str:
    findings = _matching_findings(report, key)
    if not findings:
        issues = _matching_issues(report, key)
        if issues:
            findings = [item for item in findings_from_report(report) if item.issue_key == issues[0].issue_key]
    if not findings:
        raise ValueError(f"no finding or issue matches {key!r}")
    selected = findings[0]
    if desired_target:
        selected = next(
            (item for item in findings if item.comparison and desired_target in item.comparison),
            selected,
        )
    return render_remediation_text(_plan_for_report(report, selected, desired_target=desired_target))


def history_report(current: dict[str, Any], previous: dict[str, Any] | None = None, key: str | None = None) -> str:
    records: list[tuple[str, str, str, str]] = []
    for report in [previous, current]:
        if not report:
            continue
        timestamp = str(report.get("generated_at", "unknown"))
        issues = _matching_issues(report, key)
        if issues:
            records.extend(
                (timestamp, issue.lifecycle.value if issue.lifecycle else "OBSERVED", issue.object_name, issue.kind)
                for issue in issues
            )
        else:
            records.extend(
                (
                    timestamp,
                    finding.lifecycle.value if finding.lifecycle else "OBSERVED",
                    finding.object_name,
                    finding.kind,
                )
                for finding in _matching_findings(report, key)
            )
    if not records:
        return "No matching history is available.\n"
    return "\n".join(f"{timestamp} {state:<8} {name} {kind}" for timestamp, state, name, kind in records) + "\n"


def _severity_rationale(finding: Finding) -> str:
    if finding.kind == "column_length_changed":
        if isinstance(finding.expected, int) and isinstance(finding.actual, int) and finding.actual < finding.expected:
            return (
                "The actual column is narrower than the reference and can reject values "
                "accepted by the reference schema."
            )
        return "Column length differs and can change accepted data ranges."
    if finding.kind == "column_nullability_changed" and finding.expected is True and finding.actual is False:
        return "The actual column rejects NULL values accepted by the reference schema."
    if finding.kind == "missing_right":
        return "An object present in the reference is absent from the compared target."
    if finding.kind == "missing_left":
        return (
            "The compared target contains an object absent from the reference; intent must be "
            "established before removal."
        )
    return "Severity is derived from Driftwatch's schema-risk classification and may be overridden by policy."
