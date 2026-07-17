from driftwatch import collector
from driftwatch.models import DatabaseTarget


class CursorFixture:
    def __init__(self):
        self.rows = {
            collector.OBJECT_QUERY: [("VIEW", "dbo", "active_users", " SELECT * FROM dbo.Users ")],
            collector.COLUMN_QUERY: [("dbo", "Users", "id", "int", 4, 10, 0, 0, None)],
            collector.INDEX_QUERY: [("dbo", "Users", "IX_Users_Id", "CLUSTERED", 1, 0, "id")],
            collector.CONSTRAINT_QUERY: [("dbo", "Users", "PK_Users", "PRIMARY_KEY_CONSTRAINT", None)],
        }
        self.current = None

    def execute(self, query):
        self.current = query

    def fetchall(self):
        return self.rows[self.current]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class ConnectionFixture:
    def __init__(self):
        self.cursor_fixture = CursorFixture()

    def cursor(self):
        return self.cursor_fixture

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_collect_builds_inventory_for_objects_columns_indexes_and_constraints(monkeypatch):
    monkeypatch.setattr(collector, "_connect", lambda _: ConnectionFixture())
    inventory = collector.collect(DatabaseTarget("fixture", "Driver=fixture"))
    assert inventory.errors == []
    assert inventory.objects["VIEW|dbo.active_users"]["definition"] == "select * from dbo.users"
    assert inventory.objects["COLUMN|dbo.Users.id"]["data_type"] == "int"
    assert inventory.objects["INDEX|dbo.Users.IX_Users_Id"]["is_unique"] is True
    assert inventory.objects["CONSTRAINT|dbo.Users.PK_Users"]["type"] == "PRIMARY_KEY_CONSTRAINT"


def test_collect_redacts_password_from_connection_errors(monkeypatch):
    def fail(_):
        raise RuntimeError("PWD={super;secret}; server unavailable")

    monkeypatch.setattr(collector, "_connect", fail)
    inventory = collector.collect(DatabaseTarget("fixture", "Driver=fixture"))
    assert inventory.errors == [{"stage": "connect", "message": "PWD=[REDACTED]; server unavailable"}]
