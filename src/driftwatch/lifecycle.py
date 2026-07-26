"""File-based finding lifecycle analysis."""

from collections.abc import Iterable
from typing import Any

from .models import Finding, FindingLifecycle


def _fingerprints(previous: Any) -> set[str]:
    if previous is None:
        return set()
    if isinstance(previous, dict):
        values = previous.get("findings", previous.get("fingerprints", []))
    else:
        values = previous
    result = set()
    for item in values or []:
        result.add(item if isinstance(item, str) else str(item.get("fingerprint", "")))
    return {item for item in result if item}


def classify_findings(current: Iterable[Finding], previous: Any = None) -> list[Finding]:
    """Attach NEW/EXISTING lifecycle to current findings and emit RESOLVED ones."""
    current_items = list(current)
    previous_fingerprints = _fingerprints(previous)
    current_fingerprints = {item.fingerprint for item in current_items}
    result = [
        Finding(
            **{
                **item.__dict__,
                "lifecycle": FindingLifecycle.EXISTING
                if item.fingerprint in previous_fingerprints
                else FindingLifecycle.NEW,
            }
        )
        for item in current_items
    ]
    for fingerprint in sorted(previous_fingerprints - current_fingerprints):
        result.append(
            Finding(
                kind="resolved",
                object_type="finding",
                object_name=fingerprint,
                severity="info",
                message="finding was resolved",
                targets=(),
                lifecycle=FindingLifecycle.RESOLVED,
            )
        )
    return result


def load_previous_report(path: str) -> dict[str, Any]:
    import json
    from pathlib import Path

    return json.loads(Path(path).read_text(encoding="utf-8"))
