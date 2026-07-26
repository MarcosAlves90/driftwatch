"""Migration effect verification, intentionally separate from environment comparison."""

from dataclasses import dataclass
from typing import Callable, Iterable

from .diff import compare
from .models import Finding, Inventory, Severity


@dataclass(frozen=True)
class MigrationEffect:
    finding: Finding
    classification: str

    def as_dict(self) -> dict:
        return {**self.finding.as_dict(), "classification": self.classification}


@dataclass(frozen=True)
class MigrationReport:
    effects: tuple[MigrationEffect, ...]
    expected: tuple[str | Finding, ...] = ()

    @property
    def unexpected(self) -> tuple[MigrationEffect, ...]:
        return tuple(item for item in self.effects if item.classification == "unexpected")

    @property
    def missing(self) -> tuple[str | Finding, ...]:
        return tuple(
            item for item in self.expected if not any(_matches(item, effect.finding) for effect in self.effects)
        )

    @property
    def findings(self) -> list[Finding]:
        """Return policy-ready findings while preserving effect classification."""
        from dataclasses import replace

        result = [replace(effect.finding, planned=effect.classification == "expected") for effect in self.effects]
        result.extend(
            Finding(
                kind="migration_expected_missing",
                object_type="MIGRATION",
                object_name=_spec_text(spec),
                severity=Severity.BREAKING.value,
                message=f"expected migration effect did not occur: {spec}",
                property="expected_effect",
                expected=_spec_text(spec),
                actual=None,
                planned=False,
            )
            for spec in self.missing
        )
        return result

    def as_dict(self) -> dict:
        return {
            "effect_count": len(self.effects),
            "added": [x.as_dict() for x in self.effects if x.finding.kind.startswith("missing_right")],
            "removed": [x.as_dict() for x in self.effects if x.finding.kind.startswith("missing_left")],
            "changed": [x.as_dict() for x in self.effects if x.finding.kind not in {"missing_left", "missing_right"}],
            "unexpected": [x.as_dict() for x in self.unexpected],
            "missing_expected": [_spec_text(item) for item in self.missing],
            "findings": [item.as_dict() for item in self.findings],
        }


def render_migration_text(report: MigrationReport) -> str:
    lines = [
        f"Migration effects: {len(report.effects)}",
        f"Expected: {sum(item.classification == 'expected' for item in report.effects)}",
        f"Unexpected: {len(report.unexpected)}",
        f"Missing expected: {len(report.missing)}",
    ]
    for effect in report.effects:
        finding = effect.finding
        lines.append(
            f"- {effect.classification} [{finding.severity}]: "
            f"{finding.kind} {finding.object_type}|{finding.object_name}"
        )
    for missing in report.missing:
        lines.append(f"- missing: {missing}")
    return "\n".join(lines) + "\n"


def verify_migration(
    before, after, apply: Callable[[], None] | None = None, expected: Iterable[str | Finding] = ()
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


def _matches(spec: str | Finding, finding: Finding) -> bool:
    if isinstance(spec, Finding):
        return spec.fingerprint == finding.fingerprint
    normalized = spec.casefold()
    candidates = {
        finding.fingerprint.casefold(),
        finding.kind.casefold(),
        finding.object_name.casefold(),
        f"{finding.kind}:{finding.object_name}".casefold(),
        f"{finding.kind}:{finding.object_name}:{finding.property or ''}".casefold(),
    }
    if normalized in candidates:
        return True
    operation, separator, object_name = normalized.partition(" ")
    return (
        separator == " "
        and object_name == finding.object_name.casefold()
        and {
            "add": "missing_right",
            "create": "missing_right",
            "drop": "missing_left",
            "remove": "missing_left",
            "change": finding.kind,
            "alter": finding.kind,
        }.get(operation)
        == finding.kind.casefold()
    )


def _spec_text(spec: str | Finding) -> str:
    return spec if isinstance(spec, str) else spec.fingerprint


def run_migration_verification(
    capture: Callable[[], Inventory],
    apply: Callable[[], None],
    expected: Iterable[str | Finding] = (),
    before_path: str | None = None,
    after_path: str | None = None,
) -> MigrationReport:
    """Capture, apply, and capture again in a caller-controlled environment."""
    from .snapshot import write_snapshot

    before = capture()
    if before_path:
        write_snapshot(before, before_path)
    apply()
    after = capture()
    if after_path:
        write_snapshot(after, after_path)
    return verify_migration(before, after, expected=expected)
