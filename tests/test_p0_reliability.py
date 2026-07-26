import json

import pytest

from driftwatch.config import load_config
from driftwatch.diff import compare, compare_all
from driftwatch.models import (
    CollectionSection,
    CollectionSectionStatus,
    CollectionStatus,
    ComparisonStrategy,
    Finding,
    Inventory,
)
from driftwatch.report import build_report
from driftwatch.secrets import redact_secrets, split_connection_string
from driftwatch.models import DatabaseTarget


def _sections(**overrides):
    return {
        section.value: CollectionSectionStatus(overrides.get(section, CollectionStatus.SUCCESS))
        for section in CollectionSection
    }


def test_failed_inventory_is_rejected_and_never_treated_as_empty():
    failed = Inventory("staging", {"TABLE|dbo.Users": {}}, status=CollectionStatus.FAILED)
    healthy = Inventory("prod", {"TABLE|dbo.Users": {}})
    with pytest.raises(ValueError, match="failed collection"):
        compare(failed, healthy)
    with pytest.raises(ValueError, match="failed collection"):
        compare_all([failed, healthy])


def test_invalid_section_is_excluded_but_valid_sections_still_compare():
    left = Inventory(
        "prod",
        {"TABLE|dbo.Users": {"definition": "a"}, "INDEX|dbo.Users.IX": {"key_columns": ["id"]}},
        status=CollectionStatus.PARTIAL,
        sections=_sections(indexes=CollectionStatus.FAILED),
    )
    right = Inventory(
        "staging",
        {"TABLE|dbo.Users": {"definition": "b"}, "INDEX|dbo.Users.IX": {"key_columns": ["name"]}},
        status=CollectionStatus.PARTIAL,
        sections=_sections(indexes=CollectionStatus.FAILED),
    )
    findings = compare(left, right)
    assert [finding.object_type for finding in findings] == ["TABLE"]


def test_baseline_strategy_compares_only_reference_to_each_actual():
    inventories = [
        Inventory("prod", {"TABLE|dbo.Users": {"definition": "expected"}}),
        Inventory("qa", {"TABLE|dbo.Users": {"definition": "qa"}}),
        Inventory("dev", {"TABLE|dbo.Users": {"definition": "dev"}}),
    ]
    findings = compare_all(inventories, ComparisonStrategy.BASELINE, "prod")
    assert {finding.targets for finding in findings} == {("prod", "qa"), ("prod", "dev")}


def test_semantic_column_diff_reports_property_expected_actual_and_severity():
    left = Inventory("prod", {"COLUMN|dbo.Users.email": {"data_type": "varchar", "max_length": 255, "is_nullable": True}})
    right = Inventory("staging", {"COLUMN|dbo.Users.email": {"data_type": "varchar", "max_length": 100, "is_nullable": False}})
    findings = compare(left, right)
    assert {finding.property for finding in findings} == {"max_length", "is_nullable"}
    assert {finding.kind for finding in findings} == {"column_length_changed", "column_nullability_changed"}
    assert all(finding.expected is not None and finding.actual is not None for finding in findings)
    assert {finding.severity for finding in findings} == {"breaking"}


def test_specialized_index_and_foreign_key_differs_report_semantic_properties():
    left = Inventory(
        "prod",
        {
            "INDEX|dbo.Users.IX": {
                "key_columns": ["tenant_id", "email"],
                "include_columns": ["name"],
                "filter": "active = 1",
                "is_unique": True,
                "type": "NONCLUSTERED",
                "is_primary_key": False,
            },
            "CONSTRAINT|dbo.Orders.FK": {
                "type": "FOREIGN_KEY",
                "local_columns": ["user_id"],
                "referenced_schema": "dbo",
                "referenced_table": "Users",
                "referenced_columns": ["id"],
                "on_delete": "NO_ACTION",
                "on_update": "NO_ACTION",
            },
        },
    )
    right = Inventory(
        "staging",
        {
            "INDEX|dbo.Users.IX": {
                "key_columns": ["email", "tenant_id"],
                "include_columns": [],
                "filter": None,
                "is_unique": False,
                "type": "NONCLUSTERED",
                "is_primary_key": False,
            },
            "CONSTRAINT|dbo.Orders.FK": {
                "type": "FOREIGN_KEY",
                "local_columns": ["created_by"],
                "referenced_schema": "dbo",
                "referenced_table": "Users",
                "referenced_columns": ["id"],
                "on_delete": "CASCADE",
                "on_update": "NO_ACTION",
            },
        },
    )
    findings = compare(left, right)
    assert any(finding.kind == "index_key_columns_changed" for finding in findings)
    assert any(finding.kind == "index_filter_changed" for finding in findings)
    assert any(finding.kind == "foreign_key_local_columns_changed" for finding in findings)
    assert any(finding.kind == "foreign_key_on_delete_changed" for finding in findings)
    assert all(finding.property for finding in findings)


def test_missing_table_is_critical_but_new_column_is_info():
    missing_table = compare(
        Inventory("prod", {"TABLE|dbo.Users": {}}),
        Inventory("staging", {}),
    )[0]
    new_column = compare(
        Inventory("prod", {}),
        Inventory("staging", {"COLUMN|dbo.Users.id": {}}),
    )[0]
    assert missing_table.severity == "critical"
    assert new_column.severity == "info"


def test_report_exposes_collection_status_without_connection_data():
    inventory = Inventory(
        "prod",
        errors=[{"stage": "connect", "message": "PWD=[REDACTED]"}],
        status=CollectionStatus.FAILED,
        sections=_sections(**{"objects": CollectionStatus.FAILED}),
    )
    report = build_report([inventory], [])
    assert report["targets"][0]["status"] == "FAILED"
    assert report["collection_failures"][0]["target"] == "prod"
    assert "connection_string" not in json.dumps(report)


def test_secret_redaction_covers_multiple_driver_secret_names():
    message = "Client Secret=my-secret; Access Token=abc123; Token=tkn; PWD={pa}}ss;word}"
    redacted = redact_secrets(message)
    assert "my-secret" not in redacted
    assert "abc123" not in redacted
    assert "tkn" not in redacted
    assert "pa}}ss;word" not in redacted
    assert redacted.count("[REDACTED]") == 4


def test_connection_parser_separates_spaced_secret_aliases():
    base, credentials = split_connection_string(
        "Server=db;Client Secret=client-value;Access Token=access-value"
    )
    assert base == "Server=db"
    assert credentials.client_secret == "client-value"
    assert credentials.access_token == "access-value"


def test_database_target_repr_and_report_do_not_expose_connection_secrets():
    target = DatabaseTarget("prod", "Server=db;UID=alice;PWD=super-secret")
    assert "super-secret" not in repr(target)
    assert target.connection.base_connection_string == "Server=db"
    assert target.connection.credentials.password == "super-secret"


def test_config_accepts_explicit_baseline_and_strategy(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "baseline": "prod",
        "strategy": "baseline",
        "targets": [
            {"name": "prod", "connection_string": "Server=prod"},
            {"name": "dev", "connection_string": "Server=dev"},
        ],
    }))
    config = load_config(path)
    assert config.baseline == "prod"
    assert config.strategy == ComparisonStrategy.BASELINE
