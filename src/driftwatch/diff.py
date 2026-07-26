from collections.abc import Iterable

from .differs import DIFFER_REGISTRY, severity_for
from .models import CollectionSection, CollectionStatus, ComparisonStrategy, Finding, Inventory


def _section_for_object_type(object_type: str) -> CollectionSection:
    return {
        "COLUMN": CollectionSection.COLUMNS,
        "INDEX": CollectionSection.INDEXES,
        "CONSTRAINT": CollectionSection.CONSTRAINTS,
    }.get(object_type, CollectionSection.OBJECTS)


def _validate_comparable(inventory: Inventory) -> None:
    if inventory.status == CollectionStatus.FAILED:
        raise ValueError(f"inventory {inventory.target!r} has failed collection")


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
    target = right.target if left_value is None else left.target
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
        targets=(target,),
        expected=expected,
        actual=actual,
    )


def compare(left: Inventory, right: Inventory) -> list[Finding]:
    """Compare valid sections only; failed inventories are never interpreted as empty."""
    _validate_comparable(left)
    _validate_comparable(right)
    findings: list[Finding] = []
    left_collation = left.metadata.get("database_collation")
    right_collation = right.metadata.get("database_collation")
    if (
        left.section_is_valid(CollectionSection.DATABASE)
        and right.section_is_valid(CollectionSection.DATABASE)
        and left_collation != right_collation
        and (left_collation is not None or right_collation is not None)
    ):
        findings.append(
            Finding(
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
            )
        )
    keys = sorted(set(left.objects) | set(right.objects))
    for key in keys:
        object_type, object_name = key.split("|", 1)
        section = _section_for_object_type(object_type)
        if not left.section_is_valid(section) or not right.section_is_valid(section):
            continue
        left_value, right_value = left.objects.get(key), right.objects.get(key)
        if left_value is None or right_value is None:
            findings.append(
                _missing_finding(
                    key=key,
                    left=left,
                    right=right,
                    left_value=left_value,
                    right_value=right_value,
                )
            )
        elif left_value != right_value:
            differ = DIFFER_REGISTRY.get(object_type)
            if (
                differ is None
                and object_type == "TABLE"
                and ("temporal_type" in left_value or "temporal_type" in right_value)
            ):
                from .differs import CatalogDiffer

                differ = CatalogDiffer()
            if differ is None:
                from .differs import ObjectDefinitionDiffer

                differ = ObjectDefinitionDiffer()
            findings.extend(
                differ.diff(
                    object_type,
                    object_name,
                    left_value,
                    right_value,
                    (left.target, right.target),
                )
            )
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
        if reference.status == CollectionStatus.FAILED:
            return []
        return [
            finding
            for actual in items
            if actual.target != reference.target and actual.status != CollectionStatus.FAILED
            for finding in compare(reference, actual)
        ]
    findings = []
    for index, left in enumerate(items[:-1]):
        for right in items[index + 1 :]:
            findings.extend(compare(left, right))
    return findings
