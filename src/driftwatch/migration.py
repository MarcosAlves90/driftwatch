"""Migration effect verification, intentionally separate from environment comparison."""

from dataclasses import dataclass
from typing import Callable, Iterable

from .diff import compare
from .models import Finding


@dataclass(frozen=True)
class MigrationEffect:
    finding: Finding
    classification: str

    def as_dict(self) -> dict:
        return {**self.finding.as_dict(), "classification": self.classification}


@dataclass(frozen=True)
class MigrationReport:
    effects: tuple[MigrationEffect, ...]
    expected: tuple[str, ...] = ()

    @property
    def unexpected(self) -> tuple[MigrationEffect, ...]:
        return tuple(item for item in self.effects if item.classification == "unexpected")

    @property
    def missing(self) -> tuple[str, ...]:
        return tuple(
            item for item in self.expected if not any(_matches(item, effect.finding) for effect in self.effects)
        )

    def as_dict(self) -> dict:
        return {
            "effect_count": len(self.effects),
            "added": [x.as_dict() for x in self.effects if x.finding.kind.startswith("missing_right")],
            "removed": [x.as_dict() for x in self.effects if x.finding.kind.startswith("missing_left")],
            "changed": [x.as_dict() for x in self.effects if x.finding.kind not in {"missing_left", "missing_right"}],
            "unexpected": [x.as_dict() for x in self.unexpected],
            "missing_expected": list(self.missing),
        }


def verify_migration(
    before, after, apply: Callable[[], None] | None = None, expected: Iterable[str] = ()
) -> MigrationReport:
    """Diff two controlled snapshots; `apply` is accepted for orchestration layers.

    The core never opens a connection or executes SQL itself. Callers capture
    before/after around an explicitly controlled transaction/environment.
    """
    if apply is not None:
        apply()
    findings = compare(before, after)
    expected_set = tuple(expected)
    effects = tuple(
        MigrationEffect(item, "expected" if any(_matches(spec, item) for spec in expected_set) else "unexpected")
        for item in findings
    )
    return MigrationReport(effects, expected_set)


def _matches(spec: str, finding: Finding) -> bool:
    return spec in {
        finding.fingerprint,
        finding.kind,
        finding.object_name,
        f"{finding.kind}:{finding.object_name}",
        f"{finding.kind}:{finding.object_name}:{finding.property or ''}",
    }


def run_migration_verification(
    capture: Callable[[], object], apply: Callable[[], None], expected: Iterable[str] = ()
) -> MigrationReport:
    """Capture, apply, and capture again in a caller-controlled environment."""
    before = capture()
    apply()
    after = capture()
    return verify_migration(before, after, expected=expected)
