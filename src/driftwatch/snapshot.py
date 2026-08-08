"""Deterministic, credential-free schema snapshots with v1 compatibility."""

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import CollectionSection, CollectionSectionStatus, CollectionStatus, Inventory

SNAPSHOT_VERSION = 2
SUPPORTED_SNAPSHOT_VERSIONS = {1, 2}


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _structural_inventory(inventory: Inventory, *, version: int = SNAPSHOT_VERSION) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target": inventory.target,
        "objects": {key: inventory.objects[key] for key in sorted(inventory.objects)},
        "metadata": {
            key: inventory.metadata[key]
            for key in sorted(inventory.metadata)
            if key in {"database_collation", "schema_version", "dependency_coverage"}
        },
    }
    if version >= 2:
        result["object_metadata"] = {key: inventory.object_metadata[key] for key in sorted(inventory.object_metadata)}
        result["dependencies"] = sorted(
            inventory.dependencies,
            key=lambda item: (
                str(item.get("dependency", "")),
                str(item.get("dependent", "")),
                str(item.get("source", "")),
            ),
        )
        if inventory.observed_at is not None:
            result["observed_at"] = inventory.observed_at
    return result


def _payload(inventory: Inventory, origin: str | None = None, *, version: int = SNAPSHOT_VERSION) -> dict[str, Any]:
    structural = _structural_inventory(inventory, version=version)
    unsigned = {
        "snapshot_version": version,
        "origin": {"name": origin or inventory.target},
        "execution_id": hashlib.sha256(_canonical(structural).encode("utf-8")).hexdigest()[:16],
        "inventory": structural,
    }
    return {**unsigned, "digest": hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()}


def snapshot_dict(inventory: Inventory, origin: str | None = None) -> dict[str, Any]:
    if inventory.status != CollectionStatus.SUCCESS:
        raise ValueError("cannot snapshot an inventory without a complete collection")
    return _payload(inventory, origin)


def write_snapshot(inventory: Inventory, path: str | Path, origin: str | None = None) -> None:
    payload = snapshot_dict(inventory, origin)
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _validate_snapshot_header(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("snapshot_version") not in SUPPORTED_SNAPSHOT_VERSIONS:
        supported = ", ".join(map(str, sorted(SUPPORTED_SNAPSHOT_VERSIONS)))
        raise ValueError(f"snapshot version must be one of: {supported}")
    origin = payload.get("origin")
    if not isinstance(origin, dict) or not origin.get("name"):
        raise ValueError("snapshot origin.name is required")
    return payload


def _validate_inventory_shape(payload: dict[str, Any]) -> dict[str, Any]:
    inventory = payload.get("inventory")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("objects"), dict):
        raise ValueError("snapshot inventory.objects must be an object")
    for optional_mapping in ("metadata", "object_metadata"):
        if optional_mapping in inventory and not isinstance(inventory[optional_mapping], dict):
            raise ValueError(f"snapshot inventory.{optional_mapping} must be an object")
    if "dependencies" in inventory and not isinstance(inventory["dependencies"], list):
        raise ValueError("snapshot inventory.dependencies must be a list")
    return inventory


def _unsigned_payload(payload: dict[str, Any]) -> dict[str, Any]:
    unsigned = {key: payload[key] for key in ("snapshot_version", "origin", "inventory")}
    execution_id = payload.get("execution_id")
    if execution_id is not None:
        if not isinstance(execution_id, str) or not execution_id:
            raise ValueError("snapshot execution_id must be a non-empty string")
        unsigned["execution_id"] = execution_id
    return unsigned


def _validate_payload(payload: Any) -> dict[str, Any]:
    validated = _validate_snapshot_header(payload)
    _validate_inventory_shape(validated)
    expected = hashlib.sha256(_canonical(_unsigned_payload(validated)).encode("utf-8")).hexdigest()
    if validated.get("digest") != expected:
        raise ValueError("snapshot digest is invalid")
    return validated


def read_snapshot(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid snapshot file {path}: {exc}") from exc
    return _validate_payload(payload)


def inventory_from_snapshot(path: str | Path) -> Inventory:
    payload = read_snapshot(path)
    source = payload["origin"]["name"]
    structural = payload["inventory"]
    section_names = [
        CollectionSection.OBJECTS,
        CollectionSection.COLUMNS,
        CollectionSection.INDEXES,
        CollectionSection.CONSTRAINTS,
        CollectionSection.DATABASE,
    ]
    if payload["snapshot_version"] >= 2:
        section_names.append(CollectionSection.DEPENDENCIES)
    sections = {section.value: CollectionSectionStatus(CollectionStatus.SUCCESS) for section in section_names}
    metadata = {**structural.get("metadata", {}), "snapshot_digest": payload["digest"]}
    if payload["snapshot_version"] == 1 and "dependency_coverage" not in metadata:
        metadata["dependency_coverage"] = "unknown"
    return Inventory(
        target=source,
        objects=structural["objects"],
        status=CollectionStatus.SUCCESS,
        sections=sections,
        metadata=metadata,
        object_metadata=structural.get("object_metadata", {}),
        dependencies=structural.get("dependencies", []),
        observed_at=structural.get("observed_at"),
    )
