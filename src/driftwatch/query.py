from collections import Counter
from collections.abc import Iterable
from typing import Any

from .models import Finding


def _values(values: Iterable[str] | None) -> frozenset[str]:
    """Normalize repeated/comma-separated CLI values for case-insensitive matching."""
    if values is None:
        return frozenset()
    return frozenset(item.strip().casefold() for value in values for item in value.split(",") if item.strip())


def select_findings(
    findings: Iterable[Finding],
    *,
    kinds: Iterable[str] | None = None,
    severities: Iterable[str] | None = None,
    targets: Iterable[str] | None = None,
    objects: Iterable[str] | None = None,
    query: str | None = None,
) -> list[Finding]:
    """Return findings matching all supplied dimensions in stable input order."""
    kind_values = _values(kinds)
    severity_values = _values(severities)
    target_values = _values(targets)
    object_values = _values(objects)
    term = query.casefold() if query else None
    selected = []
    for finding in findings:
        if kind_values and finding.kind.casefold() not in kind_values:
            continue
        if severity_values and finding.severity.casefold() not in severity_values:
            continue
        if target_values and not target_values.intersection(target.casefold() for target in finding.targets):
            continue
        if object_values and finding.object_name.casefold() not in object_values:
            continue
        if term:
            searchable = " ".join(
                [
                    finding.kind,
                    finding.object_type,
                    finding.object_name,
                    finding.severity,
                    finding.message,
                    *finding.targets,
                ]
            ).casefold()
            if term not in searchable:
                continue
        selected.append(finding)
    return selected


def analyze_findings(findings: Iterable[Finding]) -> dict[str, Any]:
    """Build deterministic counts for the selected findings."""
    items = list(findings)
    return {
        "selected_count": len(items),
        "by_severity": dict(sorted(Counter(item.severity for item in items).items())),
        "by_kind": dict(sorted(Counter(item.kind for item in items).items())),
        "by_object_type": dict(sorted(Counter(item.object_type for item in items).items())),
    }
