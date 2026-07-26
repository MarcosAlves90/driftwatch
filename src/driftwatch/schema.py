"""Typed views over the collector's compatibility mapping."""

from dataclasses import fields
from typing import Any

from .models import (
    ColumnDefinition,
    ConstraintDefinition,
    IndexDefinition,
    ModuleDefinition,
    ObjectId,
)


def object_id(key: str) -> ObjectId:
    return ObjectId.parse(key)


def typed_definition(key: str, value: dict[str, Any]):
    identifier = object_id(key)
    kind = identifier.type.upper()
    if kind == "COLUMN":
        allowed = {field.name for field in fields(ColumnDefinition)}
        return ColumnDefinition(**{name: value.get(name) for name in allowed if name in value})
    if kind == "INDEX":
        allowed = {field.name for field in fields(IndexDefinition)}
        normalized = dict(value)
        for name in ("key_columns", "include_columns"):
            if name in normalized:
                normalized[name] = tuple(normalized[name] or ())
        return IndexDefinition(**{name: normalized.get(name) for name in allowed if name in normalized})
    if kind == "CONSTRAINT":
        allowed = {field.name for field in fields(ConstraintDefinition)}
        normalized = dict(value)
        if "columns" in normalized:
            normalized["columns"] = tuple(normalized["columns"] or ())
        return ConstraintDefinition(**{name: normalized.get(name) for name in allowed if name in normalized})
    return ModuleDefinition(
        schema=identifier.schema,
        name=identifier.name,
        type=identifier.type,
        definition=value.get("definition"),
    )
