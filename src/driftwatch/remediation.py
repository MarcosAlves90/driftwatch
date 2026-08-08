"""Conservative, read-only remediation planning for schema drift findings."""

from dataclasses import dataclass
from typing import Any, Iterable

from .models import Finding, Inventory, ObjectId, canonical_object_type


@dataclass(frozen=True)
class RemediationPlan:
    status: str
    confidence: str
    risk: str
    reason: str
    preconditions: tuple[str, ...] = ()
    steps: tuple[str, ...] = ()
    sql: tuple[str, ...] = ()
    rollback: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    manual_notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "confidence": self.confidence,
            "risk": self.risk,
            "reason": self.reason,
            "preconditions": list(self.preconditions),
            "steps": list(self.steps),
            "sql": list(self.sql),
            "rollback": list(self.rollback),
            "verification": list(self.verification),
            "manual_notes": list(self.manual_notes),
        }


def _quote(name: str) -> str:
    return "[" + name.replace("]", "]]") + "]"


def _table_name(identifier: ObjectId) -> str:
    return f"{_quote(identifier.schema)}.{_quote(identifier.name)}"


def _object_state(inventories: Iterable[Inventory], target: str, key: str) -> dict[str, Any] | None:
    for inventory in inventories:
        if inventory.target == target:
            return inventory.objects.get(key)
    return None


def _sql_type(column: dict[str, Any]) -> str | None:
    data_type = column.get("data_type")
    if not data_type:
        return None
    data_type = str(data_type)
    lowered = data_type.casefold()
    if lowered in {"varchar", "char", "varbinary", "binary"}:
        length = column.get("max_length")
        suffix = "max" if length == -1 else str(length)
        return f"{data_type}({suffix})" if length is not None else data_type
    if lowered in {"nvarchar", "nchar"}:
        length = column.get("max_length")
        if length == -1:
            suffix = "max"
        elif isinstance(length, int):
            suffix = str(max(1, length // 2))
        else:
            return data_type
        return f"{data_type}({suffix})"
    if lowered in {"decimal", "numeric"}:
        precision, scale = column.get("precision"), column.get("scale")
        if precision is not None and scale is not None:
            return f"{data_type}({precision},{scale})"
    return data_type


def _column_alter(identifier: ObjectId, column: dict[str, Any]) -> str | None:
    sql_type = _sql_type(column)
    if sql_type is None or identifier.subobject is None:
        return None
    nullable = "NULL" if column.get("is_nullable", True) else "NOT NULL"
    return f"ALTER TABLE {_table_name(identifier)} ALTER COLUMN {_quote(identifier.subobject)} {sql_type} {nullable};"


def _index_clustered_prefix(index_type: str) -> str:
    if index_type == "CLUSTERED":
        return "CLUSTERED "
    if index_type == "NONCLUSTERED":
        return "NONCLUSTERED "
    return ""


def _index_create(identifier: ObjectId, state: dict[str, Any]) -> str | None:
    keys = state.get("key_columns") or []
    if not keys or identifier.subobject is None:
        return None
    unique = "UNIQUE " if state.get("is_unique") else ""
    clustered = _index_clustered_prefix(str(state.get("type") or "").upper())
    sql = (
        f"CREATE {unique}{clustered}INDEX {_quote(identifier.subobject)} ON {_table_name(identifier)} "
        f"({', '.join(_quote(str(item)) for item in keys)})"
    )
    includes = state.get("include_columns") or []
    if includes:
        sql += f" INCLUDE ({', '.join(_quote(str(item)) for item in includes)})"
    if state.get("filter"):
        sql += f" WHERE {state['filter']}"
    return sql + ";"


def _foreign_key_create(prefix: str, state: dict[str, Any]) -> str | None:
    local = state.get("local_columns") or []
    referenced = state.get("referenced_columns") or []
    referenced_table = state.get("referenced_table")
    if not local or not referenced or not referenced_table:
        return None
    reference = f"{_quote(str(state.get('referenced_schema') or 'dbo'))}.{_quote(str(referenced_table))}"
    sql = (
        prefix
        + f"FOREIGN KEY ({', '.join(_quote(str(item)) for item in local)}) REFERENCES {reference} "
        + f"({', '.join(_quote(str(item)) for item in referenced)})"
    )
    on_delete = state.get("on_delete")
    on_update = state.get("on_update")
    if on_delete and on_delete != "NO_ACTION":
        sql += " ON DELETE " + str(on_delete).replace("_", " ")
    if on_update and on_update != "NO_ACTION":
        sql += " ON UPDATE " + str(on_update).replace("_", " ")
    return sql + ";"


def _check_constraint_create(prefix: str, state: dict[str, Any]) -> str | None:
    expression = state.get("expression")
    return prefix + f"CHECK ({expression});" if expression else None


def _unique_constraint_create(prefix: str, state: dict[str, Any]) -> str | None:
    columns = state.get("columns") or []
    if not columns:
        return None
    return prefix + f"UNIQUE ({', '.join(_quote(str(item)) for item in columns)});"


def _constraint_create(identifier: ObjectId, state: dict[str, Any]) -> str | None:
    if identifier.subobject is None:
        return None
    prefix = f"ALTER TABLE {_table_name(identifier)} ADD CONSTRAINT {_quote(identifier.subobject)} "
    handlers = {
        "FOREIGN_KEY": _foreign_key_create,
        "CHECK_CONSTRAINT": _check_constraint_create,
        "UNIQUE_CONSTRAINT": _unique_constraint_create,
    }
    handler = handlers.get(str(state.get("type")))
    return handler(prefix, state) if handler else None


def _manual(reason: str, *, risk: str = "high", notes: tuple[str, ...] = ()) -> RemediationPlan:
    return RemediationPlan(
        status="MANUAL_REVIEW_REQUIRED",
        confidence="medium",
        risk=risk,
        reason=reason,
        verification=("Rerun Driftwatch and confirm the issue is RESOLVED.",),
        manual_notes=notes,
    )


_COLUMN_PROPERTIES = {"max_length", "is_nullable", "data_type", "precision", "scale", "collation"}
_MODULE_TYPES = {"VIEW", "PROCEDURE", "FUNCTION", "TRIGGER"}


def _column_plan(
    finding: Finding,
    identifier: ObjectId,
    desired_state: dict[str, Any] | None,
    desired: str | None,
    precondition: tuple[str, ...],
    verification: tuple[str, ...],
) -> RemediationPlan | None:
    if identifier.type != "COLUMN" or finding.property not in _COLUMN_PROPERTIES:
        return None
    column = desired_state or (finding.expected if isinstance(finding.expected, dict) else None)
    sql = _column_alter(identifier, column) if column else None
    if sql is None:
        return _manual(
            "The desired column definition is incomplete; generate a migration after inspecting the full column state."
        )
    widening = (
        finding.property == "max_length"
        and isinstance(finding.expected, int)
        and isinstance(finding.actual, int)
        and finding.expected >= finding.actual
    )
    relaxation = finding.property == "is_nullable" and finding.expected is True
    risk = "low" if widening or relaxation else "high"
    notes = (
        ()
        if risk == "low"
        else ("Narrowing, type conversion, collation, or NOT NULL changes can reject existing data.",)
    )
    return RemediationPlan(
        status="AVAILABLE",
        confidence="high",
        risk=risk,
        reason=f"Align the column definition with target {desired!r}.",
        preconditions=precondition,
        steps=("Review data compatibility and generated DDL.", "Apply the DDL through the normal migration process."),
        sql=(sql,),
        verification=verification,
        manual_notes=notes,
    )


def _missing_index_plan(
    finding: Finding, identifier: ObjectId, precondition: tuple[str, ...], verification: tuple[str, ...]
) -> RemediationPlan | None:
    state = finding.expected if finding.kind == "missing_right" else None
    if finding.kind != "missing_right" or identifier.type != "INDEX" or not isinstance(state, dict):
        return None
    sql = _index_create(identifier, state)
    if sql is None:
        return None
    return RemediationPlan(
        status="AVAILABLE",
        confidence="high",
        risk="low",
        reason="Recreate the missing index from the observed authoritative definition.",
        preconditions=precondition,
        steps=("Review index workload impact.", "Apply through the normal migration process."),
        sql=(sql,),
        verification=verification,
    )


def _missing_constraint_plan(
    finding: Finding, identifier: ObjectId, precondition: tuple[str, ...], verification: tuple[str, ...]
) -> RemediationPlan | None:
    state = finding.expected if finding.kind == "missing_right" else None
    if finding.kind != "missing_right" or identifier.type != "CONSTRAINT" or not isinstance(state, dict):
        return None
    sql = _constraint_create(identifier, state)
    if sql is None:
        return None
    risk = "high" if state.get("type") == "FOREIGN_KEY" else "medium"
    return RemediationPlan(
        status="AVAILABLE",
        confidence="high",
        risk=risk,
        reason="Recreate the missing constraint from catalog evidence.",
        preconditions=precondition,
        steps=("Validate existing rows against the constraint.", "Apply through the normal migration process."),
        sql=(sql,),
        verification=verification,
    )


def _module_plan(
    finding: Finding,
    identifier: ObjectId,
    desired_state: dict[str, Any] | None,
    desired: str | None,
    precondition: tuple[str, ...],
    verification: tuple[str, ...],
) -> RemediationPlan | None:
    if canonical_object_type(identifier.type) not in _MODULE_TYPES:
        return None
    definition = desired_state.get("definition") if desired_state else None
    if definition is None and isinstance(finding.expected, dict):
        definition = finding.expected.get("definition")
    if not definition:
        return None
    sql = str(definition).strip()
    if not sql.rstrip().endswith(";"):
        sql += ";"
    return RemediationPlan(
        status="AVAILABLE",
        confidence="medium",
        risk="medium",
        reason=f"Restore the module definition observed on {desired or 'the reference target'}.",
        preconditions=precondition,
        steps=("Review the module definition and dependencies.", "Apply it through the normal migration process."),
        sql=(sql,),
        verification=verification,
        manual_notes=("sys.sql_modules text should be reviewed before execution; Driftwatch does not execute it.",),
    )


def plan_for_finding(
    finding: Finding, inventories: Iterable[Inventory] = (), *, desired_target: str | None = None
) -> RemediationPlan:
    """Return a conservative plan. This function never connects to or mutates a database."""
    try:
        identifier = ObjectId.parse(f"{finding.object_type}|{finding.object_name}")
    except ValueError:
        return _manual("The finding does not identify a remediable SQL Server object.")
    comparison = finding.comparison
    desired = desired_target
    if comparison:
        desired = desired or comparison[0]
        actual_target = next((target for target in comparison if target != desired), comparison[-1])
    else:
        actual_target = None
    desired_state = _object_state(inventories, desired, str(identifier)) if desired else None
    precondition = (
        f"Confirm {actual_target or 'the target'} still matches the analyzed schema state before applying DDL.",
    )
    verification = ("Rerun Driftwatch against the same comparison and confirm this issue is RESOLVED.",)
    planners = (
        lambda: _column_plan(finding, identifier, desired_state, desired, precondition, verification),
        lambda: _missing_index_plan(finding, identifier, precondition, verification),
        lambda: _missing_constraint_plan(finding, identifier, precondition, verification),
        lambda: _module_plan(finding, identifier, desired_state, desired, precondition, verification),
    )
    for planner in planners:
        plan = planner()
        if plan is not None:
            return plan
    destructive = finding.kind == "missing_left" and identifier.type in {"TABLE", "COLUMN"}
    return _manual(
        "No deterministic, safely bounded DDL plan is available for this finding.",
        risk="destructive" if destructive else "high",
        notes=("Inspect affected data, dependencies, and rollback strategy before changing the schema.",),
    )


def render_remediation_text(plan: RemediationPlan) -> str:
    lines = [
        f"Resolution: {plan.status}",
        f"Confidence: {plan.confidence}",
        f"Risk: {plan.risk}",
        "",
        "Reason",
        plan.reason,
    ]
    for label, values in (
        ("Preconditions", plan.preconditions),
        ("Steps", plan.steps),
        ("Proposed SQL", plan.sql),
        ("Rollback", plan.rollback),
        ("Verification", plan.verification),
        ("Notes", plan.manual_notes),
    ):
        if values:
            lines.extend(["", label])
            lines.extend(f"- {value}" for value in values)
    return "\n".join(lines) + "\n"
