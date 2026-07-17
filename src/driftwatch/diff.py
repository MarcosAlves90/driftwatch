from collections.abc import Iterable

from .models import Finding, Inventory


def compare(left: Inventory, right: Inventory) -> list[Finding]:
    findings: list[Finding] = []
    keys = sorted(set(left.objects) | set(right.objects))
    for key in keys:
        lval, rval = left.objects.get(key), right.objects.get(key)
        object_type, object_name = key.split("|", 1)
        if lval is None:
            findings.append(Finding("missing_left", object_type, object_name, "warning",
                                    f"object exists only in {right.target}", None, rval))
        elif rval is None:
            findings.append(Finding("missing_right", object_type, object_name, "warning",
                                    f"object exists only in {left.target}", lval, None))
        elif lval != rval:
            findings.append(Finding("definition_mismatch", object_type, object_name, "warning",
                                    "object definitions differ", lval, rval))
    return findings


def compare_all(inventories: Iterable[Inventory]) -> list[Finding]:
    items = list(inventories)
    if len(items) < 2:
        raise ValueError("at least two inventories are required")
    findings = []
    for index, left in enumerate(items[:-1]):
        for right in items[index + 1:]:
            findings.extend(compare(left, right))
    return findings
