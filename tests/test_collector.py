from driftwatch import collector
from driftwatch.models import DatabaseTarget, Inventory


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
    assert inventory.errors[0]["stage"] == "connect"
    assert inventory.errors[0]["message"] == "PWD=[REDACTED]; server unavailable"
    assert inventory.errors[0]["category"] == "connection"


def test_collect_marks_failed_connection_and_sections(monkeypatch):
    monkeypatch.setattr(collector, "_connect", lambda _: (_ for _ in ()).throw(RuntimeError("server down")))
    inventory = collector.collect(DatabaseTarget("fixture", "Driver=fixture"))
    assert inventory.status.value == "FAILED"
    assert {section.status.value for section in inventory.sections.values()} == {"FAILED"}


def test_collect_preserves_complete_index_and_foreign_key_properties(monkeypatch):
    class RichCursor(CursorFixture):
        def __init__(self):
            super().__init__()
            self.rows[collector.INDEX_QUERY] = [
                ("dbo", "Users", "IX_Users", "NONCLUSTERED", 1, 0, "[active] = 1", 1, 1, 0, "tenant_id"),
                ("dbo", "Users", "IX_Users", "NONCLUSTERED", 1, 0, "[active] = 1", 2, 2, 0, "email"),
                ("dbo", "Users", "IX_Users", "NONCLUSTERED", 1, 0, "[active] = 1", 3, 0, 1, "name"),
            ]
            self.rows[collector.FOREIGN_KEY_QUERY] = [
                ("dbo", "Orders", "FK_Orders_Users", "dbo", "Users", "user_id", "id", 1, "NO_ACTION", "CASCADE"),
            ]

    class RichConnection(ConnectionFixture):
        def __init__(self):
            self.cursor_fixture = RichCursor()

    monkeypatch.setattr(collector, "_connect", lambda _: RichConnection())
    inventory = collector.collect(DatabaseTarget("fixture", "Driver=fixture"))
    assert inventory.status.value == "SUCCESS"
    index = inventory.objects["INDEX|dbo.Users.IX_Users"]
    assert index["key_columns"] == ["tenant_id", "email"]
    assert index["include_columns"] == ["name"]
    assert index["filter"] == "[active] = 1"
    foreign_key = inventory.objects["CONSTRAINT|dbo.Orders.FK_Orders_Users"]
    assert foreign_key["local_columns"] == ["user_id"]
    assert foreign_key["referenced_columns"] == ["id"]
    assert foreign_key["on_update"] == "CASCADE"


def test_collect_merges_unique_constraint_columns_into_existing_constraint(monkeypatch):
    class UniqueCursor(CursorFixture):
        def __init__(self):
            super().__init__()
            self.rows[collector.UNIQUE_CONSTRAINT_QUERY] = [
                ("dbo", "Users", "UQ_Users_Email", 1, "email"),
                ("dbo", "Users", "UQ_Users_Email", 2, "tenant_id"),
            ]

    class UniqueConnection(ConnectionFixture):
        def __init__(self):
            self.cursor_fixture = UniqueCursor()

    monkeypatch.setattr(collector, "_connect", lambda _: UniqueConnection())
    inventory = collector.collect(DatabaseTarget("fixture", "Driver=fixture"))
    assert inventory.errors == []
    assert inventory.objects["CONSTRAINT|dbo.Users.UQ_Users_Email"]["columns"] == ["email", "tenant_id"]


def test_collect_records_typed_module_dependencies_when_catalog_exposes_them():
    cursor = CursorFixture()
    cursor.rows[collector.DEPENDENCY_QUERY] = [
        ("dbo", "Users", "USER_TABLE", "dbo", "active_users", "VIEW"),
    ]
    inventory = Inventory("fixture")
    collector._collect_objects(cursor, inventory)
    assert inventory.objects["VIEW|dbo.active_users"]["dependencies"] == ["USER_TABLE|dbo.Users"]
