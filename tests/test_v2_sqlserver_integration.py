import os

import pytest

from driftwatch.collector import collect
from driftwatch.dependency import dependency_view
from driftwatch.diff import compare
from driftwatch.models import DatabaseTarget, Inventory, ObjectId

CONNECTION = os.getenv("DRIFTWATCH_TEST_CONN_A")


@pytest.mark.skipif(
    not CONNECTION,
    reason="set DRIFTWATCH_TEST_CONN_A for SQL Server integration tests",
)
def test_real_sqlserver_uses_canonical_identity_dates_dependencies_and_severity():
    assert CONNECTION is not None
    inventory = collect(DatabaseTarget("sqlserver", CONNECTION))
    assert inventory.status.value == "SUCCESS", inventory.errors
    assert "TABLE|dbo.driftwatch_ci" in inventory.objects
    assert "USER_TABLE|dbo.driftwatch_ci" not in inventory.objects

    metadata = inventory.object_metadata["TABLE|dbo.driftwatch_ci"]
    assert metadata["raw_type"] == "USER_TABLE"
    assert metadata["created_at"] and metadata["modified_at"]
    assert inventory.metadata["dependency_coverage"] == "partial"

    dependents = dependency_view(
        inventory,
        ObjectId("TABLE", "dbo", "driftwatch_ci"),
    )["objects"]
    assert "VIEW|dbo.driftwatch_ci_view" in dependents

    missing = compare(inventory, Inventory("missing", {}))
    table_finding = next(item for item in missing if item.object_name == "dbo.driftwatch_ci")
    assert table_finding.severity == "critical"
