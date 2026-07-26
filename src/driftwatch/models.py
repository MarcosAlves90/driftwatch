from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CollectionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class CollectionSection(str, Enum):
    OBJECTS = "objects"
    COLUMNS = "columns"
    INDEXES = "indexes"
    CONSTRAINTS = "constraints"


class ComparisonStrategy(str, Enum):
    BASELINE = "baseline"
    PAIRWISE = "pairwise"


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
            getattr(self, name) == getattr(other, name)
            for name in self.__slots__
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
        return self.connection.resolved()


@dataclass
class Inventory:
    target: str
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    errors: list[dict[str, str]] = field(default_factory=list)
    status: CollectionStatus = CollectionStatus.SUCCESS
    sections: dict[str, CollectionSectionStatus] = field(default_factory=dict)

    def section_is_valid(self, section: CollectionSection) -> bool:
        state = self.sections.get(section.value)
        return state is None or state.status == CollectionStatus.SUCCESS

    def as_report(self) -> dict[str, Any]:
        return {
            "name": self.target,
            "status": self.status.value,
            "object_count": len(self.objects),
            "sections": {name: state.as_dict() for name, state in sorted(self.sections.items())},
            "errors": self.errors,
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

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "object_type": self.object_type,
                "object_name": self.object_name, "severity": self.severity,
                "message": self.message, "left": self.left, "right": self.right,
                "targets": list(self.targets), "property": self.property,
                "expected": self.expected if self.expected is not None else self.left,
                "actual": self.actual if self.actual is not None else self.right}
