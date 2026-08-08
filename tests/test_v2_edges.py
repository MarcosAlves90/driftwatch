import json
import sys
import types
from datetime import datetime

import pytest

from driftwatch import azure_auth, cli, collector
from driftwatch.config import apply_cli_credentials, load_config
from driftwatch.models import (
    CollectionSection,
    CollectionSectionStatus,
    CollectionStatus,
    DatabaseTarget,
    Finding,
    Inventory,
    ObjectId,
    Severity,
)
from driftwatch.policy import Policy, PolicyRule, _tuple, load_policy
from driftwatch.remediation import (
    _column_alter,
    _constraint_create,
    _index_create,
    _sql_type,
    plan_for_finding,
)
from driftwatch.snapshot import write_snapshot


def test_azure_provider_success_and_missing(monkeypatch):
    class Token:
        token = "abc"

    class Credential:
        def get_token(self, scope):
            assert "database.windows.net" in scope
            return Token()

    assert azure_auth.access_token(credential=Credential()) == "abc"

    fake_identity = types.ModuleType("azure.identity")

    class DefaultCredential:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def get_token(self, scope):
            return Token()

    setattr(fake_identity, "DefaultAzureCredential", DefaultCredential)
    fake_azure = types.ModuleType("azure")
    setattr(fake_azure, "identity", fake_identity)
    monkeypatch.setitem(sys.modules, "azure", fake_azure)
    monkeypatch.setitem(sys.modules, "azure.identity", fake_identity)
    assert azure_auth.default_credential().kwargs["exclude_interactive_browser_credential"] is True

    monkeypatch.delitem(sys.modules, "azure.identity")
    monkeypatch.delitem(sys.modules, "azure")
    real_import = __import__

    def blocked(name, *args, **kwargs):
        if name.startswith("azure"):
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", blocked)
    with pytest.raises(RuntimeError, match=r"driftwatch\[azure\]"):
        azure_auth.default_credential()


def test_config_validation_matrix(tmp_path):
    def write(value):
        path = tmp_path / f"{len(list(tmp_path.iterdir()))}.json"
        path.write_text(json.dumps(value))
        return path

    missing_env = write({"targets": [{"name": "a", "connection_string": "env:NOPE"}]})
    with pytest.raises(ValueError, match="environment variable"):
        load_config(missing_env, min_targets=1)
    empty_targets = write({"targets": []})
    with pytest.raises(ValueError, match="at least"):
        load_config(empty_targets, min_targets=1)
    incomplete_target = write({"targets": [{"name": "a"}]})
    with pytest.raises(ValueError, match="each target"):
        load_config(incomplete_target, min_targets=1)

    base = {
        "targets": [
            {"name": "a", "connection_string": "x"},
            {"name": "b", "connection_string": "y"},
        ]
    }
    invalid = [
        ({"baseline": "missing"}, "baseline"),
        ({"strategy": "weird"}, "strategy"),
        ({"strategy": "baseline"}, "requires a baseline"),
        ({"normalization": []}, "normalization must"),
        ({"normalization": {"bad": True}}, "unknown normalization"),
        ({"auth": "bad"}, "auth must"),
        ({"workers": 0}, "workers"),
        ({"connect_timeout": 0}, "connect_timeout"),
        ({"query_timeout": 0}, "query_timeout"),
    ]
    for update, message in invalid:
        invalid_path = write({**base, **update})
        with pytest.raises(ValueError, match=message):
            load_config(invalid_path)

    configured = load_config(
        write(
            {
                **base,
                "workers": 2,
                "connect_timeout": 4,
                "query_timeout": 5,
                "auth": "odbc",
                "normalization": {"ignore_comments": False},
            }
        )
    )
    assert configured.workers == 2
    assert configured.query_timeout == 5
    assert apply_cli_credentials(configured.targets, None, None) is configured.targets
    with pytest.raises(ValueError, match="provided together"):
        apply_cli_credentials(configured.targets, "u", None)


def test_policy_validation_and_rule_paths(tmp_path):
    assert _tuple("x", "f") == ("x",)
    assert _tuple(["x", "y"], "f") == ("x", "y")
    with pytest.raises(ValueError, match="string or list"):
        _tuple([1], "f")

    finding = Finding(
        "k",
        "TABLE",
        "dbo.T",
        "warning",
        "m",
        targets=("dev",),
        comparison=("prod", "dev"),
    )
    policy = Policy(
        rules={"k": Severity.CRITICAL},
        object_rules=(PolicyRule("dbo.*", severity=Severity.BREAKING),),
    )
    assert policy.rule_for(finding).startswith("object:")
    assert policy.severity_for(finding).value == "breaking"
    assert policy.evaluate([finding]).blocking_count == 1

    def write(value):
        path = tmp_path / f"{len(list(tmp_path.iterdir()))}.json"
        path.write_text(json.dumps(value))
        return path

    invalid = [
        ({"version": 1, "rules": []}, "rules must"),
        ({"version": 1, "rules": {"": "warning"}}, "kinds"),
        ({"version": 1, "object_rules": {}}, "must be a list"),
        ({"version": 1, "object_rules": [7]}, "object or pattern"),
        (
            {"version": 1, "object_rules": [{"pattern": "", "severity": "warning"}]},
            "non-empty",
        ),
        ({"version": 1, "object_rules": [{"pattern": "x"}]}, "needs a severity"),
        ({"version": 1, "ignore": ["x"], "allow": ["x"]}, "conflict"),
        ({"version": 1, "strategy": "bad"}, "strategy"),
        ({"version": 1, "max_report_findings": 0}, "positive"),
        ({"version": 1, "strategy": "baseline"}, "requires a baseline"),
    ]
    for payload, message in invalid:
        invalid_path = write(payload)
        with pytest.raises(ValueError, match=message):
            load_policy(invalid_path)

    broken = tmp_path / "broken.json"
    broken.write_text("{")
    with pytest.raises(ValueError, match="invalid policy"):
        load_policy(broken)

    legacy = load_policy(
        write(
            {
                "version": 1,
                "objects": {"dbo.*": "critical"},
                "baseline": "prod",
                "strategy": "baseline",
                "rules": {"missing_right": "breaking"},
            }
        )
    )
    assert legacy.strategy is not None
    assert legacy.strategy.value == "baseline"
    legacy_finding = Finding("missing_right", "VIEW", "x", "warning", "m")
    assert legacy.severity_for(legacy_finding).value == "breaking"


def test_collector_helpers_and_status_matrix():
    assert collector._error_category(RuntimeError("timed out"), "x") == "timeout"
    assert collector._error_category(RuntimeError("permission denied"), "x") == "permission"
    assert collector._error_category(RuntimeError("boom"), "x") == "query"
    assert collector._iso_value(None) is None
    rendered_date = collector._iso_value(datetime(2026, 1, 1))
    assert rendered_date is not None
    assert rendered_date.startswith("2026-01-01")
    assert collector._iso_value(12) == "12"

    inventory = collector._new_inventory("x")
    collector._record_object_metadata(
        inventory,
        "TABLE|dbo.T",
        raw_type="USER_TABLE",
        object_id=3,
        created_at="c",
        modified_at="m",
    )
    assert inventory.object_metadata["TABLE|dbo.T"]["object_id"] == 3
    collector._record_section_error(
        inventory,
        CollectionSection.OBJECTS,
        RuntimeError("timeout"),
        0,
    )
    assert inventory.errors[-1]["category"] == "timeout"
    assert "duration_seconds" in inventory.errors[-1]

    required = (
        CollectionSection.OBJECTS,
        CollectionSection.COLUMNS,
        CollectionSection.INDEXES,
        CollectionSection.CONSTRAINTS,
        CollectionSection.DATABASE,
    )
    for section in required:
        inventory.sections[section.value] = CollectionSectionStatus(CollectionStatus.SUCCESS)
    collector._finalize_status(inventory)
    assert inventory.status == CollectionStatus.SUCCESS

    inventory.sections[CollectionSection.COLUMNS.value] = CollectionSectionStatus(CollectionStatus.FAILED)
    collector._finalize_status(inventory)
    assert inventory.status == CollectionStatus.PARTIAL

    for section in required:
        inventory.sections[section.value] = CollectionSectionStatus(CollectionStatus.FAILED)
    collector._finalize_status(inventory)
    assert inventory.status == CollectionStatus.FAILED

    inventory.errors.append({"stage": "collect"})
    collector._finalize_status(inventory)
    assert inventory.status == CollectionStatus.PARTIAL


def test_collector_validation_collect_many_and_connect_shapes(monkeypatch):
    target = DatabaseTarget("x", "Server=x")
    with pytest.raises(ValueError, match="connect_timeout"):
        collector.collect(target, 0)
    with pytest.raises(ValueError, match="query_timeout"):
        collector.collect(target, query_timeout=0)
    with pytest.raises(ValueError, match="positive"):
        collector.collect_many([target], workers=0)
    with pytest.raises(ValueError, match="32"):
        collector.collect_many([target], workers=33)
    assert collector.collect_many([], workers=1) == []

    failed = collector.collect_many(
        [target],
        collector=lambda *_: (_ for _ in ()).throw(RuntimeError("oops")),
    )[0]
    assert failed.errors[0]["stage"] == "worker"
    calls = []

    class Cursor:
        def __init__(self):
            self.timeout = None

        def execute(self, query):
            raise KeyError(query)

        def fetchall(self):
            return []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class Connection:
        def cursor(self):
            return Cursor()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def connect(connection_string, **kwargs):
        calls.append(kwargs)
        return Connection()

    monkeypatch.setattr(collector, "_connect", connect)
    result = collector.collect(target, connect_timeout=7, query_timeout=2, auth="odbc")
    assert calls[0] == {"timeout": 7, "auth": "odbc"}
    assert result.metadata["timings"]


def test_collect_objects_rich_catalog_temporal_dependencies_and_failure():
    class Cursor:
        def __init__(self, dependency_error=False):
            self.current: str | None = None
            self.dependency_error = dependency_error

        def execute(self, query: str):
            self.current = query
            if query == collector.DEPENDENCY_QUERY and self.dependency_error:
                raise RuntimeError("denied")

        def fetchall(self):
            data = {
                collector.OBJECT_QUERY: [
                    (
                        10,
                        "USER_TABLE",
                        "dbo",
                        "Users",
                        None,
                        datetime(2025, 1, 1),
                        datetime(2026, 1, 1),
                    ),
                    (
                        11,
                        "SQL_STORED_PROCEDURE",
                        "dbo",
                        "p",
                        "CREATE PROCEDURE dbo.p AS SELECT 1",
                        None,
                        None,
                    ),
                ],
                collector.SEQUENCE_QUERY: [("dbo", "seq", "int", 1, 1, 1, 100, 0)],
                collector.TRIGGER_QUERY: [("dbo", "Users", "tr", 0, "CREATE TRIGGER tr")],
                collector.UDT_QUERY: [("dbo", "code", "varchar", 20, 0, 0, 1)],
                collector.SCHEMA_QUERY: [("app", 1)],
                collector.TEMPORAL_TABLE_QUERY: [("dbo", "Users", 2, "history", "UsersHistory", 30)],
                collector.DEPENDENCY_QUERY: [
                    (
                        "dbo",
                        "Users",
                        "USER_TABLE",
                        "dbo",
                        "p",
                        "SQL_STORED_PROCEDURE",
                    )
                ],
            }
            current = self.current
            return data.get(current, []) if current is not None else []

    inventory = Inventory("x")
    collector._collect_objects(Cursor(), inventory)
    assert "TABLE|dbo.Users" in inventory.objects
    assert "USER_TABLE|dbo.Users" not in inventory.objects
    assert inventory.object_metadata["TABLE|dbo.Users"]["created_at"].startswith("2025")
    assert inventory.objects["TABLE|dbo.Users"]["temporal_type"] == 2
    assert inventory.dependencies[0]["dependency"] == "TABLE|dbo.Users"
    assert "SEQUENCE|dbo.seq" in inventory.objects
    assert "TRIGGER|dbo.Users.tr" in inventory.objects
    assert "USER_DEFINED_TYPE|dbo.code" in inventory.objects
    assert "SCHEMA|app" in inventory.objects

    failed = Inventory("x")
    collector._collect_objects(Cursor(True), failed)
    assert failed.metadata["dependency_coverage"] == "unavailable"
    assert failed.errors[-1]["stage"] == "dependencies"

    class OptionalFail:
        def execute(self, query):
            raise RuntimeError(query)

    collector._collect_optional_catalog(
        OptionalFail(),
        Inventory("x"),
        "q",
        "X",
        lambda row: row,
    )


def test_collector_row_mappers_columns_and_constraint_fallbacks():
    assert collector._sequence_row(("dbo", "s", "int", 1, 2, 0, 10, 1))[2]["is_cycling"] is True
    assert collector._trigger_row(("dbo", "T", "tr", 1, " SELECT 1 "))[2]["is_disabled"] is True
    assert collector._udt_row(("dbo", "u", "int", 4, 10, 0, 0))[2]["is_nullable"] is False
    assert collector._schema_row(("app", 5)) == ("", "app", {"principal_id": 5})

    class Cursor:
        def __init__(self):
            self.current: str | None = None

        def execute(self, query: str):
            self.current = query
            if query == collector.COLUMN_QUERY:
                raise RuntimeError("legacy")
            if query in {
                collector.CHECK_CONSTRAINT_QUERY,
                collector.UNIQUE_CONSTRAINT_QUERY,
            }:
                raise RuntimeError("legacy")

        def fetchall(self):
            rows = {
                collector.COLUMN_QUERY_LEGACY: [("dbo", "T", "c", "varchar", 10, 0, 0, 1, "('x')")],
                collector.CONSTRAINT_QUERY: [],
                collector.FOREIGN_KEY_QUERY: [],
                collector.CHECK_CONSTRAINT_QUERY_LEGACY: [("dbo", "T", "CK", None, "x > 0", 0)],
                collector.UNIQUE_CONSTRAINT_QUERY_LEGACY: [("dbo", "T", "UQ", 1, None)],
            }
            current = self.current
            return rows.get(current, []) if current is not None else []

    inventory = Inventory("x")
    cursor = Cursor()
    collector._collect_columns(cursor, inventory)
    assert "'x'" in inventory.objects["COLUMN|dbo.T.c"]["default"]
    collector._collect_constraints(cursor, inventory)
    assert inventory.objects["CONSTRAINT|dbo.T.CK"]["type"] == "CHECK_CONSTRAINT"
    assert inventory.objects["CONSTRAINT|dbo.T.UQ"]["columns"] == [None]

    class DatabaseCursor:
        def execute(self, query):
            self.query = query

        def fetchone(self):
            return ("Latin",)

    collector._collect_database_metadata(DatabaseCursor(), inventory)
    assert inventory.metadata["database_collation"] == "Latin"


def test_remediation_helper_matrix():
    assert _sql_type({}) is None
    assert _sql_type({"data_type": "nvarchar", "max_length": 20}) == "nvarchar(10)"
    assert _sql_type({"data_type": "nvarchar", "max_length": -1}) == "nvarchar(max)"
    assert _sql_type({"data_type": "decimal", "precision": 10, "scale": 2}) == "decimal(10,2)"
    assert _sql_type({"data_type": "int"}) == "int"

    column = ObjectId("COLUMN", "dbo", "T", "c")
    column_sql = _column_alter(column, {"data_type": "int", "is_nullable": False})
    assert column_sql is not None
    assert "NOT NULL" in column_sql
    assert _column_alter(ObjectId("TABLE", "dbo", "T"), {"data_type": "int"}) is None

    index = ObjectId("INDEX", "dbo", "T", "IX")
    index_sql = _index_create(
        index,
        {"type": "CLUSTERED", "key_columns": ["id"], "is_unique": False},
    )
    assert index_sql is not None
    assert index_sql.startswith("CREATE CLUSTERED")
    assert _index_create(index, {"key_columns": []}) is None

    foreign_key = ObjectId("CONSTRAINT", "dbo", "T", "FK")
    fk_sql = _constraint_create(
        foreign_key,
        {
            "type": "FOREIGN_KEY",
            "local_columns": ["x"],
            "referenced_schema": "dbo",
            "referenced_table": "R",
            "referenced_columns": ["id"],
            "on_delete": "CASCADE",
            "on_update": "SET_NULL",
        },
    )
    assert fk_sql is not None
    assert "ON DELETE CASCADE" in fk_sql
    assert "ON UPDATE SET NULL" in fk_sql
    check_sql = _constraint_create(foreign_key, {"type": "CHECK_CONSTRAINT", "expression": "x>0"})
    assert check_sql is not None
    assert "CHECK" in check_sql
    unique_sql = _constraint_create(foreign_key, {"type": "UNIQUE_CONSTRAINT", "columns": ["x"]})
    assert unique_sql is not None
    assert "UNIQUE" in unique_sql
    assert _constraint_create(foreign_key, {"type": "X"}) is None

    module = Finding(
        "view_definition_changed",
        "VIEW",
        "dbo.v",
        "warning",
        "changed",
        comparison=("prod", "dev"),
        expected={"definition": "CREATE VIEW dbo.v AS SELECT 1"},
        actual={"definition": "CREATE VIEW dbo.v AS SELECT 2"},
    )
    plan = plan_for_finding(module)
    assert plan.status == "AVAILABLE"
    assert plan.confidence == "medium"
    assert plan.as_dict()["sql"]

    invalid = Finding("x", "BAD", "not-qualified", "warning", "m")
    assert plan_for_finding(invalid).status == "MANUAL_REVIEW_REQUIRED"


def test_cli_helpers_offline_json_and_invalid_report(tmp_path, capsys):
    output = tmp_path / "x.txt"
    cli._write_text("x", str(output))
    assert output.read_text() == "x"
    cli._write_text("y", None)
    assert capsys.readouterr().out == "y"

    broken = tmp_path / "broken.json"
    broken.write_text("[")
    broken_path = str(broken)
    with pytest.raises(ValueError, match="invalid report"):
        cli._load_report(broken_path)

    root = tmp_path / "root.json"
    root.write_text("[]")
    root_path = str(root)
    with pytest.raises(ValueError, match="root"):
        cli._load_report(root_path)
    with pytest.raises(ValueError, match="requires --report"):
        cli._load_report(None)


def test_cli_compare_output_formats_summary_and_github(tmp_path, monkeypatch, capsys):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "targets": [
                    {"name": "prod", "connection_string": "x"},
                    {"name": "dev", "connection_string": "y"},
                ]
            }
        )
    )

    def fake(target):
        length = 255 if target.name == "prod" else 100
        return Inventory(
            target.name,
            {
                "COLUMN|dbo.Users.email": {
                    "schema": "dbo",
                    "table": "Users",
                    "name": "email",
                    "data_type": "varchar",
                    "max_length": length,
                    "is_nullable": True,
                }
            },
            observed_at="2026-08-07T00:00:00+00:00",
        )

    monkeypatch.setattr(cli, "collect", fake)
    for output_format, suffix in (
        ("json", "json"),
        ("csv", "csv"),
        ("html", "html"),
        ("sarif", "sarif"),
    ):
        output = tmp_path / f"r.{suffix}"
        code = cli.main(
            [
                "check",
                "--config",
                str(config),
                "--format",
                output_format,
                "--output",
                str(output),
                "--fail-on",
                "critical",
            ]
        )
        assert code == 0
        assert output.stat().st_size > 0

    assert cli.main(["check", "--config", str(config), "--summary-only", "--fail-on", "critical"]) == 0
    assert "Issues:" in capsys.readouterr().out

    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert (
        cli.main(
            [
                "check",
                "--config",
                str(config),
                "--github-annotations",
                "--fail-on",
                "critical",
            ]
        )
        == 0
    )
    assert "Driftwatch schema report" in summary.read_text()
    annotations = capsys.readouterr().out
    assert "::error" in annotations or "::warning" in annotations


def test_cli_migration_verify_formats_and_snapshot_compare(tmp_path, monkeypatch, capsys):
    before = Inventory("before", {"TABLE|dbo.T": {"definition": "a"}})
    after = Inventory("after", {"TABLE|dbo.T": {"definition": "b"}})
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    write_snapshot(before, before_path)
    write_snapshot(after, after_path)

    assert (
        cli.main(
            [
                "migration",
                "verify",
                "--before",
                str(before_path),
                "--after",
                str(after_path),
                "--expected-effect",
                "change dbo.T",
            ]
        )
        == 0
    )
    assert "Migration effects" in capsys.readouterr().out

    output = tmp_path / "migration.json"
    assert (
        cli.main(
            [
                "migration",
                "verify",
                "--before",
                str(before_path),
                "--after",
                str(after_path),
                "--expected-effect",
                "change dbo.T",
                "--format",
                "json",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text())["effect_count"] == 1

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"targets": [{"name": "dev", "connection_string": "x"}]}))
    monkeypatch.setattr(
        cli,
        "collect",
        lambda target: Inventory(target.name, {"TABLE|dbo.T": {"definition": "c"}}),
    )
    assert (
        cli.main(
            [
                "check",
                "--config",
                str(config),
                "--snapshot",
                str(before_path),
                "--fail-on",
                "critical",
            ]
        )
        == 0
    )
