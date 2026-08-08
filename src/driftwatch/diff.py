from collections.abc import Iterable
from typing import Any

from .differs import DIFFER_REGISTRY, severity_for
from .models import CollectionSection, CollectionStatus, ComparisonStrategy, Finding, Inventory, ObjectId

_ANALYSIS_ONLY_FIELDS = {
    "dependencies",
    "object_id",
    "raw_type",
    "create_date",
    "modify_date",
    "created_at",
    "modified_at",
}


def _section_for_object_type(object_type: str) -> CollectionSection:
    return {
        "COLUMN": CollectionSection.COLUMNS,
        "INDEX": CollectionSection.INDEXES,
        "CONSTRAINT": CollectionSection.CONSTRAINTS,
    }.get(object_type, CollectionSection.OBJECTS)


def _validate_comparable(inventory: Inventory) -> None:
    if inventory.status == CollectionStatus.FAILED:
        raise ValueError(f"inventory {inventory.target!r} has failed collection")


def _structural_value(value: dict[str, Any]) -> dict[str, Any]:
    """Exclude diagnostic/provenance fields from structural comparison."""
    return {key: item for key, item in value.items() if key not in _ANALYSIS_ONLY_FIELDS}


def _canonical_objects(inventory: Inventory) -> dict[str, dict[str, Any]]:
    """Normalize legacy aliases and merge duplicate logical objects deterministically."""
    result: dict[str, dict[str, Any]] = {}
    for raw_key in sorted(inventory.objects):
        try:
            key = str(ObjectId.parse(raw_key))
        except ValueError:
            key = raw_key
        value = _structural_value(inventory.objects[raw_key])
        existing = result.setdefault(key, {})
        existing.update(value)
        object_type = key.partition("|")[0]
        if object_type not in {"COLUMN", "INDEX", "CONSTRAINT"} and "type" in existing:
            existing["type"] = object_type
    return result


def _missing_finding(
    *,
    key: str,
    left: Inventory,
    right: Inventory,
    left_value: dict | None,
    right_value: dict | None,
) -> Finding:
    object_type, object_name = key.split("|", 1)
    actual_missing = right_value is None
    kind = "missing_right" if actual_missing else "missing_left"
    expected = left_value
    actual = right_value
    missing_target = right.target if actual_missing else left.target
    return Finding(
        kind=kind,
        object_type=object_type,
        object_name=object_name,
        severity=severity_for(
            kind,
            object_type,
            missing_side="actual" if actual_missing else "expected",
        ),
        message=(f"object exists only in {left.target}" if actual_missing else f"object exists only in {right.target}"),
        left=left_value,
        right=right_value,
        targets=(missing_target,),
        expected=expected,
        actual=actual,
        comparison=(left.target, right.target),
    )


def _database_collation_finding(left: Inventory, right: Inventory) -> Finding | None:
    if not left.section_is_valid(CollectionSection.DATABASE) or not right.section_is_valid(CollectionSection.DATABASE):
        return None
    left_collation = left.metadata.get("database_collation")
    right_collation = right.metadata.get("database_collation")
    if left_collation == right_collation or (left_collation is None and right_collation is None):
        return None
    return Finding(
        kind="database_collation_changed",
        object_type="DATABASE",
        object_name="__database__",
        severity="breaking",
        message=f"database collation changed from {left_collation!r} to {right_collation!r}",
        left=left_collation,
        right=right_collation,
        targets=(left.target, right.target),
        property="collation",
        expected=left_collation,
        actual=right_collation,
        comparison=(left.target, right.target),
    )


def _differ_for(object_type: str, left_value: dict[str, Any], right_value: dict[str, Any]):
    differ = DIFFER_REGISTRY.get(object_type)
    if differ is not None:
        return differ
    if object_type == "TABLE" and ("temporal_type" in left_value or "temporal_type" in right_value):
        from .differs import CatalogDiffer

        return CatalogDiffer()
    from .differs import ObjectDefinitionDiffer

    return ObjectDefinitionDiffer()


def _compare_object(
    key: str,
    left: Inventory,
    right: Inventory,
    left_objects: dict[str, dict[str, Any]],
    right_objects: dict[str, dict[str, Any]],
) -> list[Finding]:
    object_type, object_name = key.split("|", 1)
    section = _section_for_object_type(object_type)
    if not left.section_is_valid(section) or not right.section_is_valid(section):
        return []
    left_value, right_value = left_objects.get(key), right_objects.get(key)
    if left_value is None or right_value is None:
        return [_missing_finding(key=key, left=left, right=right, left_value=left_value, right_value=right_value)]
    if left_value == right_value:
        return []
    differ = _differ_for(object_type, left_value, right_value)
    generated = differ.diff(object_type, object_name, left_value, right_value, (left.target, right.target))
    return [Finding(**{**finding.__dict__, "comparison": (left.target, right.target)}) for finding in generated]


def compare(left: Inventory, right: Inventory) -> list[Finding]:
    """Compare canonical structural state; diagnostic metadata never creates drift."""
    _validate_comparable(left)
    _validate_comparable(right)
    findings: list[Finding] = []
    collation = _database_collation_finding(left, right)
    if collation is not None:
        findings.append(collation)
    left_objects = _canonical_objects(left)
    right_objects = _canonical_objects(right)
    for key in sorted(set(left_objects) | set(right_objects)):
        findings.extend(_compare_object(key, left, right, left_objects, right_objects))
    return findings


def compare_all(
    inventories: Iterable[Inventory],
    strategy: ComparisonStrategy = ComparisonStrategy.PAIRWISE,
    baseline: str | None = None,
) -> list[Finding]:
    strategy = ComparisonStrategy(strategy)
    items = list(inventories)
    if len(items) < 2:
        raise ValueError("at least two inventories are required")
    if any(item.status == CollectionStatus.FAILED for item in items):
        raise ValueError("cannot compare inventories with failed collection")
    if strategy == ComparisonStrategy.BASELINE:
        if baseline is None:
            raise ValueError("baseline strategy requires a baseline target")
        try:
            reference = next(item for item in items if item.target == baseline)
        except StopIteration as exc:
            raise ValueError(f"baseline target {baseline!r} is not present") from exc
        return [
            finding
            for actual in items
            if actual.target != reference.target and actual.status != CollectionStatus.FAILED
            for finding in compare(reference, actual)
        ]
    findings: list[Finding] = []
    for index, left in enumerate(items[:-1]):
        for right in items[index + 1 :]:
            findings.extend(compare(left, right))
    return findings
