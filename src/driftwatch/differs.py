from collections.abc import Mapping
from typing import Any, Protocol

from .models import Finding


class Differ(Protocol):
    def diff(
        self,
        object_type: str,
        object_name: str,
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
        targets: tuple[str, ...],
    ) -> list[Finding]: ...


def severity_for(
    kind: str,
    object_type: str,
    property_name: str | None = None,
    expected: Any = None,
    actual: Any = None,
    *,
    missing_side: str | None = None,
) -> str:
    object_type = object_type.casefold()
    if missing_side == "actual":
        if object_type in {"table", "view"}:
            return "critical"
        if object_type in {"column", "constraint"}:
            return "breaking"
        return "warning"
    if missing_side == "expected":
        if object_type == "column":
            return "info"
        return "warning"
    if property_name in {"is_nullable"} and expected is True and actual is False:
        return "breaking"
    if property_name == "max_length" and isinstance(expected, int) and isinstance(actual, int):
        return "breaking" if actual < expected else "info"
    if object_type in {"constraint", "foreign_key"}:
        return "breaking"
    if object_type == "table" and kind.endswith("removed"):
        return "critical"
    return "warning"


def _finding(
    kind: str,
    object_type: str,
    object_name: str,
    message: str,
    expected: Any,
    actual: Any,
    property_name: str,
    targets: tuple[str, ...],
) -> Finding:
    return Finding(
        kind=kind,
        object_type=object_type,
        object_name=object_name,
        severity=severity_for(kind, object_type, property_name, expected, actual),
        message=message,
        left=expected,
        right=actual,
        targets=targets,
        property=property_name,
        expected=expected,
        actual=actual,
    )


class ColumnDiffer:
    _properties = {
        "data_type": "column_data_type_changed",
        "max_length": "column_length_changed",
        "precision": "column_precision_changed",
        "scale": "column_scale_changed",
        "is_nullable": "column_nullability_changed",
        "default": "column_default_changed",
        "default_constraint_name": "default_constraint_name_changed",
        "collation": "column_collation_changed",
        "computed_expression": "computed_expression_changed",
        "is_persisted": "computed_persistence_changed",
        "is_identity": "identity_property_changed",
        "identity_seed": "identity_seed_changed",
        "identity_increment": "identity_increment_changed",
    }

    def diff(self, object_type, object_name, expected, actual, targets):
        findings = []
        for property_name, kind in self._properties.items():
            before, after = expected.get(property_name), actual.get(property_name)
            if before != after:
                findings.append(
                    _finding(
                        kind,
                        object_type,
                        object_name,
                        f"column property {property_name} changed from {before!r} to {after!r}",
                        before,
                        after,
                        property_name,
                        targets,
                    )
                )
        return findings


class IndexDiffer:
    _properties = {
        "key_columns": "index_key_columns_changed",
        "include_columns": "index_include_columns_changed",
        "filter": "index_filter_changed",
        "is_unique": "index_uniqueness_changed",
        "type": "index_type_changed",
        "is_primary_key": "index_primary_key_changed",
    }

    def diff(self, object_type, object_name, expected, actual, targets):
        findings = []
        for property_name, kind in self._properties.items():
            before, after = expected.get(property_name), actual.get(property_name)
            if before != after:
                findings.append(
                    _finding(
                        kind,
                        object_type,
                        object_name,
                        f"index property {property_name} changed from {before!r} to {after!r}",
                        before,
                        after,
                        property_name,
                        targets,
                    )
                )
        return findings


class ConstraintDiffer:
    _foreign_key_properties = {
        "local_columns": "foreign_key_local_columns_changed",
        "referenced_schema": "foreign_key_reference_changed",
        "referenced_table": "foreign_key_reference_changed",
        "referenced_columns": "foreign_key_referenced_columns_changed",
        "on_delete": "foreign_key_on_delete_changed",
        "on_update": "foreign_key_on_update_changed",
    }

    def diff(self, object_type, object_name, expected, actual, targets):
        if expected.get("type") == "FOREIGN_KEY" or actual.get("type") == "FOREIGN_KEY":
            properties = self._foreign_key_properties
        elif expected.get("type") == "CHECK_CONSTRAINT" or actual.get("type") == "CHECK_CONSTRAINT":
            properties = {
                "expression": "check_expression_changed",
                "column": "check_column_changed",
                "is_not_for_replication": "check_replication_flag_changed",
            }
        elif expected.get("type") == "UNIQUE_CONSTRAINT" or actual.get("type") == "UNIQUE_CONSTRAINT":
            properties = {"columns": "unique_constraint_columns_changed"}
        else:
            properties = {"type": "constraint_type_changed", "reference": "constraint_reference_changed"}
        findings = []
        for property_name, kind in properties.items():
            before, after = expected.get(property_name), actual.get(property_name)
            if before != after:
                findings.append(
                    _finding(
                        kind,
                        "FOREIGN_KEY" if properties is self._foreign_key_properties else object_type,
                        object_name,
                        f"constraint property {property_name} changed from {before!r} to {after!r}",
                        before,
                        after,
                        property_name,
                        targets,
                    )
                )
        return findings


class ObjectDefinitionDiffer:
    def diff(self, object_type, object_name, expected, actual, targets):
        finding_kind = {
            "VIEW": "view_definition_changed",
            "SQL_STORED_PROCEDURE": "stored_procedure_definition_changed",
            "SQL_SCALAR_FUNCTION": "function_definition_changed",
            "SQL_TABLE_VALUED_FUNCTION": "function_definition_changed",
            "SQL_INLINE_TABLE_VALUED_FUNCTION": "function_definition_changed",
        }.get(object_type, "definition_mismatch")
        return [
            Finding(
                kind=finding_kind,
                object_type=object_type,
                object_name=object_name,
                severity=severity_for("definition_mismatch", object_type),
                message="object definitions differ",
                left=expected,
                right=actual,
                targets=targets,
                expected=expected,
                actual=actual,
            )
        ]


DIFFER_REGISTRY: dict[str, Differ] = {
    "COLUMN": ColumnDiffer(),
    "INDEX": IndexDiffer(),
    "CONSTRAINT": ConstraintDiffer(),
}
