from typing import Any

from .models import DatabaseTarget, Inventory
from .normalize import normalize_sql

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
       STRING_AGG(c.name, ',') WITHIN GROUP (ORDER BY ic.key_ordinal)
FROM sys.indexes AS i
JOIN sys.tables AS t ON t.object_id = i.object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
JOIN sys.index_columns AS ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
JOIN sys.columns AS c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
WHERE t.is_ms_shipped = 0 AND i.name IS NOT NULL
GROUP BY s.name, t.name, i.name, i.type_desc, i.is_unique, i.is_primary_key
ORDER BY s.name, t.name, i.name
"""

CONSTRAINT_QUERY = """
SELECT s.name, t.name, kc.name, kc.type_desc, NULL
FROM sys.key_constraints AS kc
JOIN sys.tables AS t ON t.object_id = kc.parent_object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
WHERE t.is_ms_shipped = 0
UNION ALL
SELECT s.name, t.name, fk.name, 'FOREIGN_KEY', OBJECT_SCHEMA_NAME(fk.referenced_object_id) + '.' + OBJECT_NAME(fk.referenced_object_id)
FROM sys.foreign_keys AS fk
JOIN sys.tables AS t ON t.object_id = fk.parent_object_id
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
WHERE t.is_ms_shipped = 0
ORDER BY 1, 2, 3
"""


def _connect(connection_string: str):
    import pyodbc
    return pyodbc.connect(connection_string, timeout=30)


def collect(target: DatabaseTarget) -> Inventory:
    inventory = Inventory(target=target.name)
    try:
        connection = _connect(target.connection_string)
    except Exception as exc:
        inventory.errors.append({"stage": "connect", "message": str(exc)})
        return inventory
    try:
        with connection:
            with connection.cursor() as cursor:
                _collect_objects(cursor, inventory)
                _collect_columns(cursor, inventory)
                _collect_indexes(cursor, inventory)
                _collect_constraints(cursor, inventory)
    except Exception as exc:
        inventory.errors.append({"stage": "collect", "message": str(exc)})
    return inventory


def _collect_objects(cursor: Any, inventory: Inventory) -> None:
    try:
        cursor.execute(OBJECT_QUERY)
        for type_desc, schema, name, definition in cursor.fetchall():
            key = f"{type_desc}|{schema}.{name}"
            inventory.objects[key] = {"schema": schema, "name": name,
                                      "type": type_desc, "definition": normalize_sql(definition)}
    except Exception as exc:
        inventory.errors.append({"stage": "objects", "message": str(exc)})


def _collect_columns(cursor: Any, inventory: Inventory) -> None:
    try:
        cursor.execute(COLUMN_QUERY)
        for schema, table, name, data_type, max_length, precision, scale, nullable, default in cursor.fetchall():
            key = f"COLUMN|{schema}.{table}.{name}"
            inventory.objects[key] = {"schema": schema, "table": table, "name": name,
                                      "data_type": data_type, "max_length": max_length,
                                      "precision": precision, "scale": scale,
                                      "is_nullable": bool(nullable), "default": normalize_sql(default)}
    except Exception as exc:
        inventory.errors.append({"stage": "columns", "message": str(exc)})


def _collect_indexes(cursor: Any, inventory: Inventory) -> None:
    try:
        cursor.execute(INDEX_QUERY)
        for schema, table, name, index_type, unique, primary, columns in cursor.fetchall():
            key = f"INDEX|{schema}.{table}.{name}"
            inventory.objects[key] = {"schema": schema, "table": table, "name": name,
                                      "type": index_type, "is_unique": bool(unique),
                                      "is_primary_key": bool(primary), "columns": columns}
    except Exception as exc:
        inventory.errors.append({"stage": "indexes", "message": str(exc)})


def _collect_constraints(cursor: Any, inventory: Inventory) -> None:
    try:
        cursor.execute(CONSTRAINT_QUERY)
        for schema, table, name, constraint_type, reference in cursor.fetchall():
            key = f"CONSTRAINT|{schema}.{table}.{name}"
            inventory.objects[key] = {"schema": schema, "table": table, "name": name,
                                      "type": constraint_type, "reference": reference}
    except Exception as exc:
        inventory.errors.append({"stage": "constraints", "message": str(exc)})
