import json
import os
from pathlib import Path

from .models import DatabaseTarget


def _resolve(value: str) -> str:
    if value.startswith("env:"):
        name = value[4:]
        resolved = os.getenv(name)
        if not resolved:
            raise ValueError(f"environment variable {name!r} is not set")
        return resolved
    return value


def load_targets(path: str | Path) -> list[DatabaseTarget]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    targets = raw.get("targets") if isinstance(raw, dict) else raw
    if not isinstance(targets, list) or len(targets) < 2:
        raise ValueError("config must contain at least two targets")
    result = []
    for item in targets:
        if not isinstance(item, dict) or not item.get("name") or not item.get("connection_string"):
            raise ValueError("each target needs name and connection_string")
        result.append(DatabaseTarget(item["name"], _resolve(item["connection_string"])))
    return result
