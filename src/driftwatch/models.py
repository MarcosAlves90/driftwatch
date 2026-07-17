from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DatabaseTarget:
    name: str
    connection_string: str


@dataclass
class Inventory:
    target: str
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    errors: list[dict[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    kind: str
    object_type: str
    object_name: str
    severity: str
    message: str
    left: Any = None
    right: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "object_type": self.object_type,
                "object_name": self.object_name, "severity": self.severity,
                "message": self.message, "left": self.left, "right": self.right}
