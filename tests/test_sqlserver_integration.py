import os

import pytest

from driftwatch.collector import collect
from driftwatch.models import DatabaseTarget


CONNECTIONS = (os.getenv("DRIFTWATCH_TEST_CONN_A"), os.getenv("DRIFTWATCH_TEST_CONN_B"))


@pytest.mark.skipif(not all(CONNECTIONS), reason="set DRIFTWATCH_TEST_CONN_A and DRIFTWATCH_TEST_CONN_B for SQL Server integration tests")
def test_collects_two_real_sql_server_inventories():
    inventories = [collect(DatabaseTarget(name, connection)) for name, connection in zip(("a", "b"), CONNECTIONS)]
    assert all(not inventory.errors for inventory in inventories), inventories
    assert all(inventory.objects for inventory in inventories)
