"""Aggregate pairwise comparison observations into distinct schema issues."""

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from .models import Finding, FindingLifecycle, Severity, _canonical


@dataclass(frozen=True)
class IssueVariant:
    value: Any
    targets: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"value": self.value, "targets": list(self.targets)}


@dataclass(frozen=True)
class Issue:
    issue_key: str
    kind: str
    object_type: str
    object_name: str
    severity: str
    message: str
    property: str | None
    variants: tuple[IssueVariant, ...]
    affected_targets: tuple[str, ...]
    evidence: tuple[str, ...]
    comparisons: tuple[tuple[str, str], ...]
    lifecycle: FindingLifecycle | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    impact: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "issue_key": self.issue_key,
            "kind": self.kind,
            "object_type": self.object_type,
            "object_name": self.object_name,
            "severity": self.severity,
            "message": self.message,
            "property": self.property,
            "variants": [variant.as_dict() for variant in self.variants],
            "affected_targets": list(self.affected_targets),
            "evidence": list(self.evidence),
            "comparisons": [list(pair) for pair in self.comparisons],
        }
        if self.lifecycle is not None:
            result["lifecycle"] = self.lifecycle.value
        if self.first_seen_at is not None:
            result["first_seen_at"] = self.first_seen_at
        if self.last_seen_at is not None:
            result["last_seen_at"] = self.last_seen_at
        if self.impact is not None:
            result["impact"] = self.impact
        return result


def _target_values(finding: Finding) -> dict[str, Any]:
    expected = finding.expected if finding.expected is not None else finding.left
    actual = finding.actual if finding.actual is not None else finding.right
    comparison = finding.comparison
    if comparison is not None:
        return {comparison[0]: expected, comparison[1]: actual}
    if len(finding.targets) >= 2:
        return {finding.targets[0]: expected, finding.targets[1]: actual}
    if len(finding.targets) == 1:
        target = finding.targets[0]
        if finding.kind == "missing_right":
            return {target: None}
        return {target: actual}
    return {}


def _aggregate_impact(findings: list[Finding]) -> dict[str, Any] | None:
    impacts = [item.impact for item in findings if item.impact]
    if not impacts:
        return None
    affected: set[str] = set()
    by_target: dict[str, Any] = {}
    direct = indirect = blast = 0
    for impact in impacts:
        direct = max(direct, int(impact.get("direct_dependents", 0)))
        indirect = max(indirect, int(impact.get("indirect_dependents", 0)))
        blast = max(blast, int(impact.get("blast_radius", 0)))
        affected.update(impact.get("affected_objects", ()))
        by_target.update(impact.get("by_target", {}))
    return {
        "direct_dependents": direct,
        "indirect_dependents": indirect,
        "blast_radius": blast,
        "affected_objects": sorted(affected),
        "by_target": dict(sorted(by_target.items())),
    }


def _aggregate_lifecycle(findings: list[Finding]) -> FindingLifecycle | None:
    states = {finding.lifecycle for finding in findings if finding.lifecycle is not None}
    for state in (FindingLifecycle.CHANGED, FindingLifecycle.NEW, FindingLifecycle.EXISTING, FindingLifecycle.RESOLVED):
        if state in states:
            return state
    return None


def aggregate_issues(findings: Iterable[Finding]) -> list[Issue]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.issue_key].append(finding)
    issues: list[Issue] = []
    for issue_key in sorted(grouped):
        evidence = grouped[issue_key]
        representative = evidence[0]
        values: dict[str, tuple[Any, set[str]]] = {}
        affected_targets: set[str] = set()
        comparisons: set[tuple[str, str]] = set()
        for finding in evidence:
            affected_targets.update(finding.targets)
            if finding.comparison:
                comparisons.add(finding.comparison)
            for target, value in _target_values(finding).items():
                canonical = _canonical(value)
                values.setdefault(canonical, (value, set()))[1].add(target)
        variants = tuple(
            IssueVariant(value=value, targets=tuple(sorted(targets)))
            for _canonical_value, (value, targets) in sorted(values.items(), key=lambda item: item[0])
        )
        severity = max((Severity.parse(item.severity) for item in evidence), key=lambda item: item.rank).value
        first_seen = min((item.first_seen_at for item in evidence if item.first_seen_at), default=None)
        last_seen = max((item.last_seen_at for item in evidence if item.last_seen_at), default=None)
        issues.append(
            Issue(
                issue_key=issue_key,
                kind=representative.kind,
                object_type=representative.object_type,
                object_name=representative.object_name,
                severity=severity,
                message=representative.message,
                property=representative.property,
                variants=variants,
                affected_targets=tuple(sorted(affected_targets)),
                evidence=tuple(sorted({item.occurrence_id for item in evidence})),
                comparisons=tuple(sorted(comparisons)),
                lifecycle=_aggregate_lifecycle(evidence),
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                impact=_aggregate_impact(evidence),
            )
        )
    return issues


def analyze_issues(issues: Iterable[Issue]) -> dict[str, Any]:
    items = list(issues)
    return {
        "issue_count": len(items),
        "by_severity": dict(sorted(Counter(item.severity for item in items).items())),
        "by_kind": dict(sorted(Counter(item.kind for item in items).items())),
        "by_object_type": dict(sorted(Counter(item.object_type for item in items).items())),
        "by_lifecycle": dict(
            sorted(Counter(item.lifecycle.value for item in items if item.lifecycle is not None).items())
        ),
    }
