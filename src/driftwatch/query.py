from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import Finding


def _values(values: Iterable[str] | None) -> frozenset[str]:
    """Normalize repeated/comma-separated CLI values for case-insensitive matching."""
    if values is None:
        return frozenset()
    return frozenset(item.strip().casefold() for value in values for item in value.split(",") if item.strip())


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _metadata_dates(finding: Finding, key: str) -> list[datetime]:
    values: list[datetime] = []
    for entry in (finding.metadata or {}).get("by_target", {}).values():
        parsed = _timestamp((entry.get("object") or {}).get(key))
        if parsed is not None:
            values.append(parsed)
    return values


@dataclass(frozen=True)
class FindingFilters:
    kinds: Iterable[str] | None = None
    severities: Iterable[str] | None = None
    targets: Iterable[str] | None = None
    objects: Iterable[str] | None = None
    query: str | None = None
    lifecycles: Iterable[str] | None = None
    properties: Iterable[str] | None = None
    created_before: str | None = None
    created_after: str | None = None
    modified_before: str | None = None
    modified_after: str | None = None
    depends_on: Iterable[str] | None = None
    issue_keys: Iterable[str] | None = None


@dataclass(frozen=True)
class _PreparedFilters:
    kinds: frozenset[str]
    severities: frozenset[str]
    targets: frozenset[str]
    objects: frozenset[str]
    lifecycles: frozenset[str]
    properties: frozenset[str]
    dependencies: frozenset[str]
    issues: frozenset[str]
    term: str | None
    created_before: datetime | None
    created_after: datetime | None
    modified_before: datetime | None
    modified_after: datetime | None


def _prepare(filters: FindingFilters) -> _PreparedFilters:
    return _PreparedFilters(
        kinds=_values(filters.kinds),
        severities=_values(filters.severities),
        targets=_values(filters.targets),
        objects=_values(filters.objects),
        lifecycles=_values(filters.lifecycles),
        properties=_values(filters.properties),
        dependencies=_values(filters.depends_on),
        issues=_values(filters.issue_keys),
        term=filters.query.casefold() if filters.query else None,
        created_before=_timestamp(filters.created_before),
        created_after=_timestamp(filters.created_after),
        modified_before=_timestamp(filters.modified_before),
        modified_after=_timestamp(filters.modified_after),
    )


def _matches_filter(value: str, accepted: frozenset[str]) -> bool:
    return not accepted or value.casefold() in accepted


def _matches_lifecycle(finding: Finding, accepted: frozenset[str]) -> bool:
    if not accepted:
        return True
    return finding.lifecycle is not None and finding.lifecycle.value.casefold() in accepted


def _identity_matches(finding: Finding, filters: _PreparedFilters) -> bool:
    identities = {finding.issue_key.casefold(), finding.occurrence_id.casefold()}
    comparison_targets = {target.casefold() for target in (finding.comparison or finding.targets)}
    return all(
        (
            not filters.issues or bool(identities & filters.issues),
            _matches_filter(finding.kind, filters.kinds),
            _matches_filter(finding.severity, filters.severities),
            not filters.targets or bool(filters.targets & comparison_targets),
            _matches_filter(finding.object_name, filters.objects),
            _matches_lifecycle(finding, filters.lifecycles),
            _matches_filter(finding.property or "", filters.properties),
        )
    )


def _date_matches(finding: Finding, filters: _PreparedFilters) -> bool:
    created = _metadata_dates(finding, "created_at")
    modified = _metadata_dates(finding, "modified_at")
    checks = (
        (filters.created_before, created, lambda value, bound: value < bound),
        (filters.created_after, created, lambda value, bound: value > bound),
        (filters.modified_before, modified, lambda value, bound: value < bound),
        (filters.modified_after, modified, lambda value, bound: value > bound),
    )
    return all(bound is None or any(compare(value, bound) for value in values) for bound, values, compare in checks)


def _dependency_matches(finding: Finding, dependencies: frozenset[str]) -> bool:
    if not dependencies:
        return True
    affected = {str(value).casefold() for value in (finding.impact or {}).get("affected_objects", ())}
    return bool(dependencies.intersection(affected))


def _search_matches(finding: Finding, term: str | None) -> bool:
    if term is None:
        return True
    searchable = " ".join(
        [
            finding.kind,
            finding.object_type,
            finding.object_name,
            finding.severity,
            finding.message,
            finding.property or "",
            str(finding.expected),
            str(finding.actual),
            finding.lifecycle.value if finding.lifecycle else "",
            str(finding.metadata or ""),
            str(finding.impact or ""),
            *finding.targets,
            *(finding.comparison or ()),
        ]
    ).casefold()
    return term in searchable


def _matches(finding: Finding, filters: _PreparedFilters) -> bool:
    return (
        _identity_matches(finding, filters)
        and _date_matches(finding, filters)
        and _dependency_matches(finding, filters.dependencies)
        and _search_matches(finding, filters.term)
    )


def select_findings(
    findings: Iterable[Finding],
    *,
    filters: FindingFilters | None = None,
    **criteria: Any,
) -> list[Finding]:
    """Return findings matching all supplied dimensions in stable input order.

    ``filters`` is the typed API. Keyword criteria remain accepted for backwards
    compatibility with the v1/v2 CLI and existing callers.
    """
    if filters is not None and criteria:
        raise ValueError("pass either filters or keyword filter criteria, not both")
    if filters is None:
        try:
            filters = FindingFilters(**criteria)
        except TypeError as exc:
            raise ValueError(f"unknown finding filter: {exc}") from exc
    prepared = _prepare(filters)
    return [finding for finding in findings if _matches(finding, prepared)]


def analyze_findings(findings: Iterable[Finding]) -> dict[str, Any]:
    """Build deterministic counts for the selected findings."""
    items = list(findings)
    return {
        "selected_count": len(items),
        "by_severity": dict(sorted(Counter(item.severity for item in items).items())),
        "by_kind": dict(sorted(Counter(item.kind for item in items).items())),
        "by_object_type": dict(sorted(Counter(item.object_type for item in items).items())),
    }
