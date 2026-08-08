import json

import pytest

from driftwatch.differs import CatalogDiffer, ConstraintDiffer, ObjectDefinitionDiffer, severity_for
from driftwatch.investigation import finding_from_dict
from driftwatch.lifecycle import load_previous_report
from driftwatch.migration import (
    MigrationEffect,
    MigrationReport,
    run_migration_verification,
    verify_migration,
)
from driftwatch.models import (
    ColumnDefinition,
    ConstraintDefinition,
    Finding,
    FindingLifecycle,
    IndexDefinition,
    Inventory,
    ModuleDefinition,
)
from driftwatch.query import select_findings
from driftwatch.schema import object_id, typed_definition
from driftwatch.snapshot import read_snapshot, snapshot_dict


def test_schema_typed_views_cover_all_definition_families():
    assert object_id("USER_TABLE|dbo.Users").type == "TABLE"
    column = typed_definition(
        "COLUMN|dbo.Users.email",
        {
            "schema": "dbo",
            "table": "Users",
            "name": "email",
            "data_type": "varchar",
            "max_length": 100,
        },
    )
    assert isinstance(column, ColumnDefinition)
    assert column.data_type == "varchar"
    index = typed_definition(
        "INDEX|dbo.Users.IX",
        {
            "schema": "dbo",
            "table": "Users",
            "name": "IX",
            "key_columns": ["id"],
            "include_columns": ["name"],
        },
    )
    assert isinstance(index, IndexDefinition)
    assert index.key_columns == ("id",)
    assert index.include_columns == ("name",)
    constraint = typed_definition(
        "CONSTRAINT|dbo.Users.UQ",
        {"schema": "dbo", "table": "Users", "name": "UQ", "columns": ["email"]},
    )
    assert isinstance(constraint, ConstraintDefinition)
    assert constraint.columns == ("email",)
    module = typed_definition("VIEW|dbo.v", {"definition": "select 1"})
    assert isinstance(module, ModuleDefinition)
    assert module.type == "VIEW"
    assert module.definition == "select 1"


def test_missing_comparison_is_none_in_memory_and_empty_on_wire():
    finding = finding_from_dict(
        {
            "kind": "missing_right",
            "object_type": "TABLE",
            "object_name": "dbo.Users",
            "severity": "critical",
            "message": "missing",
        }
    )
    assert finding.comparison is None
    assert finding.as_dict(enhanced=True)["comparison"] == []


def test_differ_edge_classification_paths():
    assert severity_for("x", "USER_TABLE", missing_side="actual") == "critical"
    assert severity_for("x", "COLUMN", missing_side="expected") == "info"
    assert severity_for("x", "INDEX", missing_side="expected") == "warning"
    assert severity_for("x", "COLUMN", "max_length", 100, 200) == "info"
    assert severity_for("x", "CONSTRAINT") == "breaking"

    foreign_key = ConstraintDiffer().diff(
        "CONSTRAINT",
        "dbo.T.FK",
        {"type": "FOREIGN_KEY", "referenced_schema": "dbo"},
        {"type": "FOREIGN_KEY", "referenced_schema": "app"},
        ("a", "b"),
    )
    assert foreign_key[0].object_type == "CONSTRAINT"
    procedure = ObjectDefinitionDiffer().diff("PROCEDURE", "dbo.p", {}, {}, ("a", "b"))
    assert procedure[0].kind == "stored_procedure_definition_changed"
    catalog = CatalogDiffer().diff(
        "SEQUENCE",
        "dbo.s",
        {"schema": "dbo", "name": "s", "increment": 1},
        {"schema": "dbo", "name": "s", "increment": 2},
        ("a", "b"),
    )
    assert catalog[0].kind == "sequence_property_changed"


def test_query_filters_lifecycle_dates_dependencies_and_invalid_dates():
    finding = Finding(
        "x",
        "TABLE",
        "dbo.T",
        "warning",
        "m",
        targets=("dev",),
        property="p",
        impact={"affected_objects": ["VIEW|dbo.v"]},
        metadata={
            "by_target": {
                "dev": {
                    "object": {
                        "created_at": "2026-01-01T00:00:00",
                        "modified_at": "2026-02-01T00:00:00Z",
                    }
                }
            }
        },
        lifecycle=FindingLifecycle.NEW,
    )
    assert select_findings(
        [finding],
        lifecycles=["new"],
        created_after="2025-01-01",
        depends_on=["VIEW|dbo.v"],
    ) == [finding]
    assert select_findings([finding], created_before="bad") == [finding]
    assert select_findings([finding], query="view|dbo.v") == [finding]
    assert select_findings([finding], depends_on=["TABLE|none"]) == []


def test_migration_report_helpers_and_orchestrated_capture(tmp_path):
    before = Inventory("before", {"TABLE|dbo.T": {"definition": "a"}})
    after = Inventory("after", {"TABLE|dbo.T": {"definition": "b"}})
    report = verify_migration(before, after, expected=["definition_mismatch"])
    assert report.effects[0].classification == "expected"
    assert report.as_dict()["changed"]

    effect = MigrationEffect(report.effects[0].finding, "unexpected")
    manual = MigrationReport((effect,), expected=("missing_right:dbo.X",))
    assert len(manual.unexpected) == 1
    assert manual.missing
    assert any(item.kind == "migration_expected_missing" for item in manual.findings)

    states = iter([before, after])
    applied = []
    orchestrated = run_migration_verification(
        lambda: next(states),
        lambda: applied.append(True),
        before_path=str(tmp_path / "before.json"),
        after_path=str(tmp_path / "after.json"),
    )
    assert applied == [True]
    assert orchestrated.effects
    assert (tmp_path / "before.json").exists()


def test_snapshot_validation_payload_shapes_and_lifecycle_loader(tmp_path):
    payload = snapshot_dict(Inventory("prod", {}))
    assert payload["digest"]

    cases = [
        (lambda item: item.update({"origin": {}}), r"origin\.name"),
        (lambda item: item.update({"inventory": []}), r"inventory\.objects"),
    ]
    for mutate, message in cases:
        modified = json.loads(json.dumps(payload))
        mutate(modified)
        path = tmp_path / (message.replace("\\", "").replace(".", "_") + ".json")
        path.write_text(json.dumps(modified))
        with pytest.raises(ValueError, match=message):
            read_snapshot(path)

    previous = tmp_path / "previous.json"
    previous.write_text('{"findings": []}')
    assert load_previous_report(str(previous)) == {"findings": []}
