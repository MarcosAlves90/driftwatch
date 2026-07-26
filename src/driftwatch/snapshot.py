"""Deterministic, credential-free schema snapshots."""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any

from .models import CollectionSectionStatus, CollectionStatus, Inventory

SNAPSHOT_VERSION = 1


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _structural_inventory(inventory: Inventory) -> dict[str, Any]:
    return {
        "target": inventory.target,
        "objects": {key: inventory.objects[key] for key in sorted(inventory.objects)},
        "metadata": {
            key: inventory.metadata[key]
            for key in sorted(inventory.metadata)
            if key in {"database_collation", "schema_version"}
        },
    }


def _payload(inventory: Inventory, origin: str | None = None) -> dict[str, Any]:
    structural = _structural_inventory(inventory)
    unsigned = {
        "snapshot_version": SNAPSHOT_VERSION,
        "origin": {"name": origin or inventory.target},
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


def _validate_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("snapshot_version") != SNAPSHOT_VERSION:
        raise ValueError(f"snapshot version must be {SNAPSHOT_VERSION}")
    if not isinstance(payload.get("origin"), dict) or not payload["origin"].get("name"):
        raise ValueError("snapshot origin.name is required")
    inventory = payload.get("inventory")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("objects"), dict):
        raise ValueError("snapshot inventory.objects must be an object")
    unsigned = {key: payload[key] for key in ("snapshot_version", "origin", "inventory")}
    expected = hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()
    if payload.get("digest") != expected:
        raise ValueError("snapshot digest is invalid")
    return payload


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
    sections = {
        name: CollectionSectionStatus(CollectionStatus.SUCCESS)
        for name in ("objects", "columns", "indexes", "constraints")
    }
    return Inventory(
        target=source,
        objects=structural["objects"],
        status=CollectionStatus.SUCCESS,
        sections=sections,
        metadata={**structural.get("metadata", {}), "snapshot_digest": payload["digest"]},
    )
