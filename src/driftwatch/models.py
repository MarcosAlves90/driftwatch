import builtins
import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, ClassVar


class CollectionStatus(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class CollectionSection(StrEnum):
    OBJECTS = "objects"
    COLUMNS = "columns"
    INDEXES = "indexes"
    CONSTRAINTS = "constraints"
    DATABASE = "database"


class ComparisonStrategy(StrEnum):
    BASELINE = "baseline"
    PAIRWISE = "pairwise"


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    BREAKING = "breaking"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.casefold())
        except (AttributeError, ValueError) as exc:
            raise ValueError("severity must be info, warning, breaking, or critical") from exc


class FindingKind(StrEnum):
    MISSING_LEFT = "missing_left"
    MISSING_RIGHT = "missing_right"
    DEFINITION_MISMATCH = "definition_mismatch"
    COLUMN_DATA_TYPE_CHANGED = "column_data_type_changed"
    COLUMN_LENGTH_CHANGED = "column_length_changed"
    COLUMN_PRECISION_CHANGED = "column_precision_changed"
    COLUMN_SCALE_CHANGED = "column_scale_changed"
    COLUMN_NULLABILITY_CHANGED = "column_nullability_changed"
    COLUMN_DEFAULT_CHANGED = "column_default_changed"
    DEFAULT_CONSTRAINT_NAME_CHANGED = "default_constraint_name_changed"
    COLUMN_COLLATION_CHANGED = "column_collation_changed"
    COMPUTED_PERSISTENCE_CHANGED = "computed_persistence_changed"
    IDENTITY_PROPERTY_CHANGED = "identity_property_changed"
    INDEX_KEY_COLUMNS_CHANGED = "index_key_columns_changed"
    INDEX_INCLUDE_COLUMNS_CHANGED = "index_include_columns_changed"
    INDEX_FILTER_CHANGED = "index_filter_changed"
    INDEX_UNIQUENESS_CHANGED = "index_uniqueness_changed"
    INDEX_TYPE_CHANGED = "index_type_changed"
    INDEX_PRIMARY_KEY_CHANGED = "index_primary_key_changed"
    CONSTRAINT_TYPE_CHANGED = "constraint_type_changed"
    CONSTRAINT_REFERENCE_CHANGED = "constraint_reference_changed"
    CHECK_COLUMN_CHANGED = "check_column_changed"
    CHECK_REPLICATION_FLAG_CHANGED = "check_replication_flag_changed"
    UNIQUE_CONSTRAINT_COLUMNS_CHANGED = "unique_constraint_columns_changed"
    FOREIGN_KEY_LOCAL_COLUMNS_CHANGED = "foreign_key_local_columns_changed"
    FOREIGN_KEY_REFERENCED_COLUMNS_CHANGED = "foreign_key_referenced_columns_changed"
    FOREIGN_KEY_ON_DELETE_CHANGED = "foreign_key_on_delete_changed"
    FOREIGN_KEY_ON_UPDATE_CHANGED = "foreign_key_on_update_changed"
    CHECK_EXPRESSION_CHANGED = "check_expression_changed"
    COMPUTED_EXPRESSION_CHANGED = "computed_expression_changed"
    IDENTITY_SEED_CHANGED = "identity_seed_changed"
    IDENTITY_INCREMENT_CHANGED = "identity_increment_changed"
    COLLATION_CHANGED = "collation_changed"
    DATABASE_COLLATION_CHANGED = "database_collation_changed"
    VIEW_DEFINITION_CHANGED = "view_definition_changed"
    STORED_PROCEDURE_DEFINITION_CHANGED = "stored_procedure_definition_changed"
    FUNCTION_DEFINITION_CHANGED = "function_definition_changed"
    SEQUENCE_PROPERTY_CHANGED = "sequence_property_changed"
    TRIGGER_DEFINITION_CHANGED = "trigger_definition_changed"
    TRIGGER_STATE_CHANGED = "trigger_state_changed"
    USER_DEFINED_TYPE_CHANGED = "user_defined_type_changed"
    TEMPORAL_METADATA_CHANGED = "temporal_metadata_changed"
    SCHEMA_CHANGED = "schema_changed"


@dataclass(frozen=True)
class ObjectId:
    type: str
    schema: str
    name: str
    subobject: str | None = None

    SEPARATOR: ClassVar[str] = "|"

    def __str__(self) -> str:
        if self.type.upper() == "SCHEMA" and not self.subobject:
            return f"{self.type}|{self.name}"
        base = f"{self.type}|{self.schema}.{self.name}"
        return f"{base}.{self.subobject}" if self.subobject else base

    @classmethod
    def parse(cls, value: str) -> "ObjectId":
        object_type, separator, qualified = value.partition(cls.SEPARATOR)
        if not separator:
            raise ValueError(f"invalid object identifier: {value!r}")
        parts = qualified.split(".")
        if object_type.upper() == "SCHEMA" and len(parts) == 1 and parts[0]:
            return cls(object_type, "", parts[0])
        if len(parts) < 2 or any(not part for part in parts[:2]):
            raise ValueError(f"invalid object identifier: {value!r}")
        return cls(object_type, parts[0], parts[1], ".".join(parts[2:]) or None)


@dataclass(frozen=True)
class ColumnDefinition:
    schema: str
    table: str
    name: str
    data_type: str | None = None
    max_length: int | None = None
    precision: int | None = None
    scale: int | None = None
    is_nullable: bool | None = None
    default: str | None = None
    collation: str | None = None
    is_computed: bool = False
    computed_expression: str | None = None
    is_persisted: bool | None = None
    is_identity: bool = False
    identity_seed: Any = None
    identity_increment: Any = None


@dataclass(frozen=True)
class IndexDefinition:
    schema: str
    table: str
    name: str
    type: str | None = None
    key_columns: tuple[str, ...] = ()
    include_columns: tuple[str, ...] = ()
    filter: str | None = None
    is_unique: bool = False
    is_primary_key: bool = False


@dataclass(frozen=True)
class ConstraintDefinition:
    schema: str
    table: str
    name: str
    type: str = ""
    columns: tuple[str, ...] = ()
    expression: str | None = None
    reference: str | None = None


@dataclass(frozen=True)
class ModuleDefinition:
    schema: str
    name: str
    type: str
    definition: str | None = None


class FindingLifecycle(StrEnum):
    NEW = "NEW"
    EXISTING = "EXISTING"
    RESOLVED = "RESOLVED"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class CollectionSectionStatus:
    status: CollectionStatus
    error: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {"status": self.status.value, "error": self.error}


class Credentials:
    __slots__ = ("username", "password", "client_secret", "access_token", "token")

    def __init__(
        self,
        username: str | None = None,
        password: str | None = None,
        client_secret: str | None = None,
        access_token: str | None = None,
        token: str | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self.client_secret = client_secret
        self.access_token = access_token
        self.token = token

    def __repr__(self) -> str:
        return "Credentials(username={!r}, secrets=[REDACTED])".format(self.username)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Credentials) and all(
            getattr(self, name) == getattr(other, name) for name in self.__slots__
        )


@dataclass(frozen=True)
class ConnectionConfig:
    """Non-secret connection settings plus credentials used only at connect time."""

    base_connection_string: str
    credentials: Credentials = field(default_factory=Credentials, repr=False)

    @classmethod
    def from_connection_string(cls, value: str) -> "ConnectionConfig":
        from .secrets import split_connection_string

        base, credentials = split_connection_string(value)
        return cls(base, credentials)

    def with_credentials(self, credentials: Credentials) -> "ConnectionConfig":
        return ConnectionConfig(self.base_connection_string, credentials)

    def resolved(self) -> str:
        from .secrets import append_credentials

        return append_credentials(self.base_connection_string, self.credentials)


@dataclass(frozen=True)
class DatabaseTarget:
    name: str
    connection: ConnectionConfig | str

    def __post_init__(self) -> None:
        if isinstance(self.connection, str):
            object.__setattr__(self, "connection", ConnectionConfig.from_connection_string(self.connection))

    @property
    def connection_string(self) -> str:
        """Resolve credentials only for the connection boundary."""
        connection = self.connection
        assert isinstance(connection, ConnectionConfig)
        return connection.resolved()


@dataclass
class Inventory:
    target: str
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    errors: list[dict[str, str]] = field(default_factory=list)
    status: CollectionStatus = CollectionStatus.SUCCESS
    sections: dict[str, CollectionSectionStatus] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def section_is_valid(self, section: CollectionSection) -> bool:
        state = self.sections.get(section.value)
        return state is None or state.status == CollectionStatus.SUCCESS

    def as_report(self) -> dict[str, Any]:
        from .secrets import redact_secrets

        return {
            "name": self.target,
            "status": self.status.value,
            "object_count": len(self.objects),
            "sections": {name: state.as_dict() for name, state in sorted(self.sections.items())},
            "errors": [
                {
                    key: redact_secrets(value) if key == "message" and isinstance(value, str) else value
                    for key, value in error.items()
                }
                for error in self.errors
            ],
            "metadata": {
                key: self.metadata[key]
                for key in sorted(self.metadata)
                if key in {"database_collation", "schema_version", "snapshot_digest", "timings"}
            },
        }


@dataclass(frozen=True)
class Finding:
    kind: str
    object_type: str
    object_name: str
    severity: str
    message: str
    left: Any = None
    right: Any = None
    targets: tuple[str, ...] = ()
    property: str | None = None
    expected: Any = None
    actual: Any = None
    lifecycle: FindingLifecycle | None = None
    planned: bool | None = None
    impact: dict[str, Any] | None = None
    rule: str | None = None

    @builtins.property
    def fingerprint(self) -> str:
        payload = {
            "kind": str(self.kind),
            "object_type": self.object_type,
            "object_name": self.object_name,
            "property": self.property,
        }
        return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        result = {
            "kind": self.kind,
            "object_type": self.object_type,
            "object_name": self.object_name,
            "severity": self.severity,
            "message": self.message,
            "left": self.left,
            "right": self.right,
            "targets": list(self.targets),
            "property": self.property,
            "expected": self.expected if self.expected is not None else self.left,
            "actual": self.actual if self.actual is not None else self.right,
            "fingerprint": self.fingerprint,
        }
        if self.lifecycle is not None:
            result["lifecycle"] = self.lifecycle.value
        if self.planned is not None:
            result["planned"] = self.planned
        if self.impact is not None:
            result["impact"] = self.impact
        if self.rule is not None:
            result["rule"] = self.rule
        return result
