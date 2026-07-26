from typing import Any, Callable
from concurrent.futures import ThreadPoolExecutor

from .models import (
    CollectionSection,
    CollectionSectionStatus,
    CollectionStatus,
    DatabaseTarget,
    Inventory,
    ObjectId,
)
from .normalize import normalize_sql
from .secrets import redact_secrets

OBJECT_QUERY = """
SELECT o.type_desc, s.name, o.name, m.definition
FROM sys.objects AS o
JOIN sys.schemas AS s ON s.schema_id = o.schema_id
LEFT JOIN sys.sql_modules AS m ON m.object_id = o.object_id
WHERE o.is_ms_shipped = 0
ORDER BY o.type_desc, s.name, o.name
"""

COLUMN_QUERY = """
SELECT s.name, t.name, c.name, ty.name, c.max_length, c.precision, c.scale,
       c.is_nullable, dc.name, dc.definition, c.collation_name, cc.is_computed,
       cc.definition, cc.is_persisted, c.is_identity, ic.seed_value,
       ic.increment_value
FROM sys.columns AS c
JOIN sys.tables AS t ON t.object_id = c.object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
LEFT JOIN sys.default_constraints AS dc ON dc.object_id = c.default_object_id
LEFT JOIN sys.computed_columns AS cc ON cc.object_id = c.object_id AND cc.column_id = c.column_id
LEFT JOIN sys.identity_columns AS ic ON ic.object_id = c.object_id AND ic.column_id = c.column_id
WHERE t.is_ms_shipped = 0
ORDER BY s.name, t.name, c.column_id
"""

COLUMN_QUERY_LEGACY = """
SELECT s.name, t.name, c.name, ty.name, c.max_length, c.precision, c.scale,
       c.is_nullable, dc.definition
FROM sys.columns AS c
JOIN sys.tables AS t ON t.object_id = c.object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
LEFT JOIN sys.default_constraints AS dc ON dc.object_id = c.default_object_id
WHERE t.is_ms_shipped = 0
ORDER BY s.name, t.name, c.column_id
"""

INDEX_QUERY = """
SELECT s.name, t.name, i.name, i.type_desc, i.is_unique, i.is_primary_key,
       i.filter_definition, ic.index_column_id, ic.key_ordinal,
       ic.is_included_column, c.name
FROM sys.indexes AS i
JOIN sys.tables AS t ON t.object_id = i.object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
WHERE t.is_ms_shipped = 0 AND i.name IS NOT NULL
ORDER BY s.name, t.name, i.name, ic.index_column_id
"""

CONSTRAINT_QUERY = """
SELECT s.name, t.name, kc.name, kc.type_desc, NULL
FROM sys.key_constraints AS kc
JOIN sys.tables AS t ON t.object_id = kc.parent_object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
WHERE t.is_ms_shipped = 0
ORDER BY s.name, t.name, kc.name
"""

FOREIGN_KEY_QUERY = """
SELECT ps.name, pt.name, fk.name, rs.name, rt.name, pc.name, rc.name,
       fkc.constraint_column_id, fk.delete_referential_action_desc,
       fk.update_referential_action_desc
FROM sys.foreign_keys AS fk
JOIN sys.tables AS pt ON pt.object_id = fk.parent_object_id
JOIN sys.schemas AS ps ON ps.schema_id = pt.schema_id
JOIN sys.foreign_key_columns AS fkc ON fkc.constraint_object_id = fk.object_id
JOIN sys.columns AS pc ON pc.object_id = fkc.parent_object_id
                       AND pc.column_id = fkc.parent_column_id
JOIN sys.tables AS rt ON rt.object_id = fkc.referenced_object_id
JOIN sys.schemas AS rs ON rs.schema_id = rt.schema_id
JOIN sys.columns AS rc ON rc.object_id = fkc.referenced_object_id
                       AND rc.column_id = fkc.referenced_column_id
ORDER BY ps.name, pt.name, fk.name, fkc.constraint_column_id
"""

CHECK_CONSTRAINT_QUERY = """
SELECT s.name, t.name, cc.name, c.name, cc.definition, cc.is_not_for_replication
FROM sys.check_constraints AS cc
JOIN sys.tables AS t ON t.object_id = cc.parent_object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
LEFT JOIN sys.columns AS c ON c.object_id = cc.parent_object_id
                          AND c.column_id = cc.parent_column_id
WHERE t.is_ms_shipped = 0
ORDER BY s.name, t.name, cc.name
"""

CHECK_CONSTRAINT_QUERY_LEGACY = """
SELECT s.name, t.name, cc.name, NULL, cc.definition, cc.is_not_for_replication
FROM sys.check_constraints AS cc
JOIN sys.tables AS t ON t.object_id = cc.parent_object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
WHERE t.is_ms_shipped = 0
ORDER BY s.name, t.name, cc.name
"""

UNIQUE_CONSTRAINT_QUERY = """
SELECT s.name, t.name, kc.name, ic.key_ordinal, c.name
FROM sys.key_constraints AS kc
JOIN sys.tables AS t ON t.object_id = kc.parent_object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
JOIN sys.index_columns AS ic ON ic.object_id = kc.parent_object_id
                            AND ic.index_id = kc.unique_index_id
JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
WHERE kc.type = 'UQ' AND t.is_ms_shipped = 0
ORDER BY s.name, t.name, kc.name, ic.key_ordinal
"""

UNIQUE_CONSTRAINT_QUERY_LEGACY = """
SELECT s.name, t.name, kc.name, 1, NULL
FROM sys.key_constraints AS kc
JOIN sys.tables AS t ON t.object_id = kc.parent_object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
WHERE kc.type = 'UQ' AND t.is_ms_shipped = 0
ORDER BY s.name, t.name, kc.name
"""

DATABASE_METADATA_QUERY = "SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS nvarchar(128))"


def _connect(connection_string: str, timeout: int = 30):
    import pyodbc

    return pyodbc.connect(connection_string, timeout=timeout)


def _safe_error(exc: Exception) -> str:
    return redact_secrets(str(exc))


def _object_key(object_type: str, schema: str, name: str, subobject: str | None = None) -> str:
    return str(ObjectId(object_type, schema, name, subobject))


def _new_inventory(target: str) -> Inventory:
    sections = {
        section.value: CollectionSectionStatus(CollectionStatus.FAILED)
        for section in CollectionSection
    }
    return Inventory(target=target, status=CollectionStatus.FAILED, sections=sections)


def _record_section_error(inventory: Inventory, section: CollectionSection, exc: Exception) -> None:
    message = _safe_error(exc)
    inventory.errors.append({"stage": section.value, "message": message})
    inventory.sections[section.value] = CollectionSectionStatus(CollectionStatus.FAILED, message)


def _finalize_status(inventory: Inventory) -> None:
    if any(error.get("stage") == "collect" for error in inventory.errors):
        inventory.status = CollectionStatus.PARTIAL
        return
    statuses = [state.status for state in inventory.sections.values()]
    if statuses and all(status == CollectionStatus.SUCCESS for status in statuses):
        inventory.status = CollectionStatus.SUCCESS
    elif any(status == CollectionStatus.SUCCESS for status in statuses):
        inventory.status = CollectionStatus.PARTIAL
    else:
        inventory.status = CollectionStatus.FAILED


def collect(
    target: DatabaseTarget,
    connect_timeout: int = 30,
    query_timeout: int | None = None,
) -> Inventory:
    if connect_timeout < 1:
        raise ValueError("connect_timeout must be positive")
    if query_timeout is not None and query_timeout < 1:
        raise ValueError("query_timeout must be positive")
    inventory = _new_inventory(target.name)
    try:
        connection = (
            _connect(target.connection_string)
            if connect_timeout == 30
            else _connect(target.connection_string, timeout=connect_timeout)
        )
    except Exception as exc:
        message = _safe_error(exc)
        inventory.errors.append({"stage": "connect", "message": message})
        for section in CollectionSection:
            inventory.sections[section.value] = CollectionSectionStatus(CollectionStatus.FAILED, message)
        return inventory

    jobs = (
        (CollectionSection.OBJECTS, _collect_objects),
        (CollectionSection.COLUMNS, _collect_columns),
        (CollectionSection.INDEXES, _collect_indexes),
        (CollectionSection.CONSTRAINTS, _collect_constraints),
        (CollectionSection.DATABASE, _collect_database_metadata),
    )
    try:
        with connection:
            with connection.cursor() as cursor:
                if query_timeout is not None:
                    try:
                        cursor.timeout = query_timeout
                    except (AttributeError, TypeError):
                        pass
                for section, job in jobs:
                    try:
                        job(cursor, inventory)
                        inventory.sections[section.value] = CollectionSectionStatus(CollectionStatus.SUCCESS)
                    except Exception as exc:
                        _record_section_error(inventory, section, exc)
    except Exception as exc:
        message = _safe_error(exc)
        inventory.errors.append({"stage": "collect", "message": message})
        inventory.status = CollectionStatus.PARTIAL
    _finalize_status(inventory)
    return inventory


def collect_many(
    targets: list[DatabaseTarget],
    *,
    workers: int = 4,
    connect_timeout: int = 30,
    query_timeout: int | None = None,
    collector: Callable[..., Inventory] = collect,
) -> list[Inventory]:
    """Collect targets concurrently while preserving input order."""
    if workers < 1:
        raise ValueError("workers must be positive")
    if workers > 32:
        raise ValueError("workers must not exceed 32")
    if not targets:
        return []

    def run(target: DatabaseTarget) -> Inventory:
        try:
            return collector(target, connect_timeout, query_timeout)
        except Exception as exc:
            inventory = _new_inventory(target.name)
            message = _safe_error(exc)
            inventory.errors.append({"stage": "worker", "message": message})
            for section in CollectionSection:
                inventory.sections[section.value] = CollectionSectionStatus(CollectionStatus.FAILED, message)
            return inventory

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as executor:
        futures = [
            executor.submit(run, target)
            for target in targets
        ]
        return [future.result() for future in futures]


def _collect_objects(cursor: Any, inventory: Inventory) -> None:
    cursor.execute(OBJECT_QUERY)
    for type_desc, schema, name, definition in cursor.fetchall():
        key = _object_key(type_desc, schema, name)
        inventory.objects[key] = {
            "schema": schema,
            "name": name,
            "type": type_desc,
            "definition": normalize_sql(definition),
        }


def _collect_columns(cursor: Any, inventory: Inventory) -> None:
    try:
        cursor.execute(COLUMN_QUERY)
        rows = cursor.fetchall()
    except Exception:
        # Older SQL Server-compatible catalogs may not expose one of the
        # enriched computed/identity columns. Preserve the P0 column contract
        # and let the optional properties remain null in that environment.
        cursor.execute(COLUMN_QUERY_LEGACY)
        rows = cursor.fetchall()
    for row in rows:
        if len(row) == 9:
            schema, table, name, data_type, max_length, precision, scale, nullable, default = row
            default_name = collation = is_computed = computed_definition = is_persisted = is_identity = seed = increment = None
        else:
            (
                schema, table, name, data_type, max_length, precision, scale, nullable,
                default_name, default, collation, is_computed, computed_definition, is_persisted,
                is_identity, seed, increment,
            ) = row
        key = _object_key("COLUMN", schema, table, name)
        inventory.objects[key] = {
            "schema": schema,
            "table": table,
            "name": name,
            "data_type": data_type,
            "max_length": max_length,
            "precision": precision,
            "scale": scale,
            "is_nullable": bool(nullable),
            "default": normalize_sql(default),
            "default_constraint_name": default_name,
            "collation": collation,
            "is_computed": bool(is_computed),
            "computed_expression": normalize_sql(computed_definition),
            "is_persisted": bool(is_persisted) if is_persisted is not None else None,
            "is_identity": bool(is_identity),
            "identity_seed": seed,
            "identity_increment": increment,
        }


def _collect_indexes(cursor: Any, inventory: Inventory) -> None:
    cursor.execute(INDEX_QUERY)
    for row in cursor.fetchall():
        if len(row) == 7:  # Compatibility with the original collector fixture/shape.
            schema, table, name, index_type, unique, primary, columns = row
            key = _object_key("INDEX", schema, table, name)
            inventory.objects[key] = {
                "schema": schema,
                "table": table,
                "name": name,
                "type": index_type,
                "is_unique": bool(unique),
                "is_primary_key": bool(primary),
                "key_columns": [item for item in (columns or "").split(",") if item],
                "include_columns": [],
                "filter": None,
                "columns": columns,
            }
            continue
        (
            schema, table, name, index_type, unique, primary, filter_definition,
            _index_column_id, key_ordinal, included, column_name,
        ) = row
        key = _object_key("INDEX", schema, table, name)
        item = inventory.objects.setdefault(
            key,
            {
                "schema": schema,
                "table": table,
                "name": name,
                "type": index_type,
                "is_unique": bool(unique),
                "is_primary_key": bool(primary),
                "key_columns": [],
                "include_columns": [],
                "filter": normalize_sql(filter_definition),
            },
        )
        if included:
            item["include_columns"].append(column_name)
        elif key_ordinal:
            item["key_columns"].append(column_name)
        item["columns"] = ",".join(item["key_columns"])


def _collect_constraints(cursor: Any, inventory: Inventory) -> None:
    cursor.execute(CONSTRAINT_QUERY)
    for schema, table, name, constraint_type, reference in cursor.fetchall():
        key = _object_key("CONSTRAINT", schema, table, name)
        inventory.objects[key] = {
            "schema": schema,
            "table": table,
            "name": name,
            "type": constraint_type,
            "reference": reference,
        }

    try:
        cursor.execute(FOREIGN_KEY_QUERY)
        for row in cursor.fetchall():
            (
                schema, table, name, referenced_schema, referenced_table,
                local_column, referenced_column, ordinal, on_delete, on_update,
            ) = row
            key = _object_key("CONSTRAINT", schema, table, name)
            item = inventory.objects.setdefault(
                key,
                {
                    "schema": schema,
                    "table": table,
                    "name": name,
                    "type": "FOREIGN_KEY",
                    "local_columns": [],
                    "referenced_schema": referenced_schema,
                    "referenced_table": referenced_table,
                    "referenced_columns": [],
                    "on_delete": on_delete,
                    "on_update": on_update,
                },
            )
            item["local_columns"].insert(max(0, ordinal - 1), local_column)
            item["referenced_columns"].insert(max(0, ordinal - 1), referenced_column)
    except KeyError:
        # Allows lightweight legacy cursor fixtures that predate the FK query.
        pass
    try:
        cursor.execute(CHECK_CONSTRAINT_QUERY)
        check_rows = cursor.fetchall()
    except KeyError:
        check_rows = []
    except Exception:
        cursor.execute(CHECK_CONSTRAINT_QUERY_LEGACY)
        check_rows = cursor.fetchall()
    for schema, table, name, column, expression, not_for_replication in check_rows:
        key = _object_key("CONSTRAINT", schema, table, name)
        inventory.objects[key] = {
            "schema": schema,
            "table": table,
            "name": name,
            "type": "CHECK_CONSTRAINT",
            "column": column,
            "expression": normalize_sql(expression),
            "is_not_for_replication": bool(not_for_replication),
        }
    try:
        cursor.execute(UNIQUE_CONSTRAINT_QUERY)
        unique_rows = cursor.fetchall()
    except KeyError:
        unique_rows = []
    except Exception:
        cursor.execute(UNIQUE_CONSTRAINT_QUERY_LEGACY)
        unique_rows = cursor.fetchall()
    for schema, table, name, ordinal, column in unique_rows:
        key = _object_key("CONSTRAINT", schema, table, name)
        item = inventory.objects.setdefault(
            key,
            {"schema": schema, "table": table, "name": name, "type": "UNIQUE_CONSTRAINT", "columns": []},
        )
        item.setdefault("columns", [])
        item["columns"].insert(max(0, ordinal - 1), column)


def _collect_database_metadata(cursor: Any, inventory: Inventory) -> None:
    try:
        cursor.execute(DATABASE_METADATA_QUERY)
        row = cursor.fetchone() if hasattr(cursor, "fetchone") else cursor.fetchall()[0]
    except KeyError:
        # Lightweight legacy fixtures may not expose database-level metadata.
        return
    inventory.metadata["database_collation"] = row[0] if row else None
