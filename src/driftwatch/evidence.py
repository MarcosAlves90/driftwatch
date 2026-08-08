"""Attach target-specific provenance to comparison findings."""

from collections.abc import Iterable
from typing import Any

from .models import Finding, Inventory, ObjectId


def _metadata_key(finding: Finding) -> str | None:
    try:
        node = ObjectId.parse(f"{finding.object_type}|{finding.object_name}")
    except ValueError:
        return None
    if node.type in {"COLUMN", "INDEX", "CONSTRAINT"}:
        return str(ObjectId("TABLE", node.schema, node.name))
    return str(node)


def attach_evidence(findings: Iterable[Finding], inventories: Iterable[Inventory]) -> list[Finding]:
    inventory_by_target = {inventory.target: inventory for inventory in inventories}
    result: list[Finding] = []
    for finding in findings:
        key = _metadata_key(finding)
        by_target: dict[str, Any] = {}
        for target in dict.fromkeys(finding.comparison or finding.targets):
            inventory = inventory_by_target.get(target)
            if inventory is None:
                continue
            entry: dict[str, Any] = {"observed_at": inventory.observed_at}
            if key is not None and key in inventory.object_metadata:
                entry["object"] = inventory.object_metadata[key]
            by_target[target] = entry
        metadata = {"by_target": by_target} if by_target else None
        result.append(Finding(**{**finding.__dict__, "metadata": metadata}))
    return result
