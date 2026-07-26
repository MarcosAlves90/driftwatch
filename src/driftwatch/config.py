import json
import os
from pathlib import Path

from .models import ComparisonStrategy, Credentials, DatabaseTarget


def _resolve(value: str) -> str:
    if value.startswith("env:"):
        name = value[4:]
        resolved = os.getenv(name)
        if not resolved:
            raise ValueError(f"environment variable {name!r} is not set")
        return resolved
    return value


def load_targets(path: str | Path) -> list[DatabaseTarget]:
    return load_config(path).targets


class DriftConfig:
    def __init__(
        self,
        targets: list[DatabaseTarget],
        baseline: str | None = None,
        strategy: ComparisonStrategy = ComparisonStrategy.PAIRWISE,
        workers: int = 4,
        connect_timeout: int = 30,
        query_timeout: int | None = None,
    ) -> None:
        self.targets = targets
        self.baseline = baseline
        self.strategy = strategy
        self.workers = workers
        self.connect_timeout = connect_timeout
        self.query_timeout = query_timeout


def load_config(path: str | Path, *, min_targets: int = 2) -> DriftConfig:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    targets = raw.get("targets") if isinstance(raw, dict) else raw
    if not isinstance(targets, list) or len(targets) < min_targets:
        raise ValueError(f"config must contain at least {min_targets} target(s)")
    result = []
    for item in targets:
        if not isinstance(item, dict) or not item.get("name") or not item.get("connection_string"):
            raise ValueError("each target needs name and connection_string")
        result.append(DatabaseTarget(item["name"], _resolve(item["connection_string"])))
    baseline = raw.get("baseline") if isinstance(raw, dict) else None
    if baseline is not None and baseline not in {target.name for target in result}:
        raise ValueError(f"baseline target {baseline!r} is not configured")
    configured_strategy = raw.get("strategy") if isinstance(raw, dict) else None
    if configured_strategy is None:
        strategy = ComparisonStrategy.BASELINE if baseline else ComparisonStrategy.PAIRWISE
    else:
        try:
            strategy = ComparisonStrategy(configured_strategy.casefold())
        except (AttributeError, ValueError) as exc:
            raise ValueError("strategy must be 'baseline' or 'pairwise'") from exc
    if strategy == ComparisonStrategy.BASELINE and baseline is None:
        raise ValueError("baseline strategy requires a baseline target")
    workers = raw.get("workers", 4) if isinstance(raw, dict) else 4
    connect_timeout = raw.get("connect_timeout", 30) if isinstance(raw, dict) else 30
    query_timeout = raw.get("query_timeout") if isinstance(raw, dict) else None
    if not isinstance(workers, int) or not 1 <= workers <= 32:
        raise ValueError("workers must be an integer from 1 to 32")
    if not isinstance(connect_timeout, int) or connect_timeout < 1:
        raise ValueError("connect_timeout must be a positive integer")
    if query_timeout is not None and (not isinstance(query_timeout, int) or query_timeout < 1):
        raise ValueError("query_timeout must be a positive integer")
    return DriftConfig(result, baseline, strategy, workers, connect_timeout, query_timeout)


def _odbc_value(value: str) -> str:
    """Quote an ODBC value so semicolons and closing braces stay inside the value."""
    if not any(character in value for character in ";{}"):
        return value
    return "{" + value.replace("}", "}}") + "}"


def apply_cli_credentials(
    targets: list[DatabaseTarget], username: str | None, password: str | None
) -> list[DatabaseTarget]:
    if username is None and password is None:
        return targets
    if not username or password is None:
        raise ValueError("--username and a password source must be provided together")
    credentials = Credentials(username=username, password=password)
    return [DatabaseTarget(target.name, target.connection.with_credentials(credentials)) for target in targets]
