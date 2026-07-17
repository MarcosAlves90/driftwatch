from driftwatch.diff import compare
from driftwatch.models import Inventory


def test_compare_detects_missing_and_mismatch():
    left = Inventory("dev", {"TABLE|dbo.users": {"columns": 2}, "TABLE|dbo.old": {}})
    right = Inventory("prod", {"TABLE|dbo.users": {"columns": 3}, "TABLE|dbo.new": {}})
    findings = compare(left, right)
    assert [item.kind for item in findings] == ["missing_left", "missing_right", "definition_mismatch"]


def test_compare_is_deterministic():
    left = Inventory("a", {"X|b": {}, "X|a": {}})
    right = Inventory("b", {})
    assert [item.object_name for item in compare(left, right)] == ["a", "b"]
