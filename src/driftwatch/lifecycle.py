"""File-based finding lifecycle analysis with stable issue and occurrence identities."""

from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from .models import Finding, FindingLifecycle


def _previous_items(previous: Any) -> list[Any]:
    if previous is None:
        return []
    if isinstance(previous, dict):
        return list(previous.get("findings", previous.get("fingerprints", [])) or [])
    return list(previous or [])


def _previous_by_issue(previous: Any) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in _previous_items(previous):
        if isinstance(item, str):
            grouped.setdefault(item, []).append({"fingerprint": item})
            continue
        issue_key = str(item.get("issue_key") or item.get("fingerprint", ""))
        if issue_key:
            grouped.setdefault(issue_key, []).append(item)
    return grouped


def _classify_current(
    item: Finding, previous_by_issue: dict[str, list[dict[str, Any]]], previous: Any, now: str
) -> Finding:
    prior = previous_by_issue.get(item.issue_key, [])
    first_seen: str | None
    if not prior:
        lifecycle = FindingLifecycle.NEW
        first_seen = now
    else:
        known_occurrences = {str(entry.get("occurrence_id")) for entry in prior if entry.get("occurrence_id")}
        lifecycle = (
            FindingLifecycle.EXISTING
            if not known_occurrences or item.occurrence_id in known_occurrences
            else FindingLifecycle.CHANGED
        )
        first_seen = next((entry.get("first_seen_at") for entry in prior if entry.get("first_seen_at")), None)
        if first_seen is None and isinstance(previous, dict):
            first_seen = previous.get("generated_at")
        first_seen = first_seen or now
    return Finding(**{**item.__dict__, "lifecycle": lifecycle, "first_seen_at": first_seen, "last_seen_at": now})


def _resolved_finding(issue_key: str, prior: dict[str, Any], now: str) -> Finding:
    return Finding(
        kind=str(prior.get("kind", "resolved")),
        object_type=str(prior.get("object_type", "finding")),
        object_name=str(prior.get("object_name", issue_key)),
        severity="info",
        message="finding was resolved",
        targets=(),
        property=prior.get("property"),
        lifecycle=FindingLifecycle.RESOLVED,
        first_seen_at=prior.get("first_seen_at"),
        last_seen_at=now,
        stable_issue_key=issue_key,
    )


def classify_findings(
    current: Iterable[Finding], previous: Any = None, *, observed_at: str | None = None
) -> list[Finding]:
    """Attach NEW/EXISTING/CHANGED lifecycle and emit RESOLVED issues."""
    current_items = list(current)
    previous_by_issue = _previous_by_issue(previous)
    now = observed_at or datetime.now(timezone.utc).isoformat()
    result = [_classify_current(item, previous_by_issue, previous, now) for item in current_items]
    current_issue_keys = {item.issue_key for item in current_items}
    for issue_key in sorted(set(previous_by_issue) - current_issue_keys):
        result.append(_resolved_finding(issue_key, previous_by_issue[issue_key][0], now))
    return result


def load_previous_report(path: str) -> dict[str, Any]:
    import json
    from pathlib import Path

    return json.loads(Path(path).read_text(encoding="utf-8"))
