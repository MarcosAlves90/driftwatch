"""Declarative policy loading and post-diff evaluation."""

import fnmatch
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .models import ComparisonStrategy, Finding, FindingLifecycle, Severity


def _tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        items: list[str] = []
    elif isinstance(value, str):
        items = [value]
    elif isinstance(value, list) and all(isinstance(item, str) and item for item in value):
        items = value
    else:
        raise ValueError(f"policy {field_name} must be a string or list of strings")
    return tuple(items)


@dataclass(frozen=True)
class PolicyRule:
    pattern: str = "*"
    kinds: tuple[str, ...] = ()
    object_types: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    severity: Severity | None = None
    reason: str | None = None

    def matches(self, finding: Finding) -> bool:
        return (
            fnmatch.fnmatchcase(finding.object_name, self.pattern)
            and (not self.kinds or finding.kind in self.kinds)
            and (not self.object_types or finding.object_type in self.object_types)
            and (not self.targets or bool(set(self.targets).intersection(finding.comparison or finding.targets)))
        )


@dataclass(frozen=True)
class PolicyResult:
    findings: list[Finding]
    ignored: list[Finding]
    allowed: list[Finding]
    allowed_reasons: dict[str, str] | None = None

    @property
    def blocking_count(self) -> int:
        return len(self.findings)


@dataclass(frozen=True)
class Policy:
    version: int = 1
    fail_on: Severity = Severity.WARNING
    rules: dict[str, Severity] | None = None
    object_rules: tuple[PolicyRule, ...] = ()
    ignore: tuple[PolicyRule, ...] = ()
    allow: tuple[PolicyRule, ...] = ()
    baseline: str | None = None
    strategy: ComparisonStrategy | None = None
    max_report_findings: int = 100

    def rule_for(self, finding: Finding) -> str:
        for rule in self.object_rules:
            if rule.matches(finding) and rule.severity is not None:
                return f"object:{rule.pattern}"
        if finding.kind in (self.rules or {}):
            return f"kind:{finding.kind}"
        return "default"

    def severity_for(self, finding: Finding) -> Severity:
        for rule in self.object_rules:
            if rule.matches(finding) and rule.severity is not None:
                return rule.severity
        configured = (self.rules or {}).get(finding.kind)
        if configured is not None:
            return configured
        return Severity.parse(finding.severity)

    def evaluate(self, findings: list[Finding]) -> PolicyResult:
        visible: list[Finding] = []
        ignored: list[Finding] = []
        allowed: list[Finding] = []
        allowed_reasons: dict[str, str] = {}
        for finding in findings:
            severity = self.severity_for(finding)
            finding = replace(finding, severity=severity.value, rule=self.rule_for(finding))
            if any(rule.matches(finding) for rule in self.ignore):
                ignored.append(finding)
            elif any(rule.matches(finding) for rule in self.allow):
                allowed.append(finding)
                matched = next(rule for rule in self.allow if rule.matches(finding))
                if matched.reason:
                    allowed_reasons[finding.fingerprint] = matched.reason
                visible.append(finding)
            else:
                visible.append(finding)
        return PolicyResult(visible, ignored, allowed, allowed_reasons)

    def blocks(self, finding: Finding) -> bool:
        return Severity.parse(finding.severity).rank >= self.fail_on.rank

    def blocking(self, result: PolicyResult) -> list[Finding]:
        allowed = {finding.fingerprint for finding in result.allowed}
        return [
            finding
            for finding in result.findings
            if (
                finding.fingerprint not in allowed
                and finding.planned is not True
                and finding.lifecycle != FindingLifecycle.RESOLVED
                and self.blocks(finding)
            )
        ]


def _rule_from_item(item: Any, field_name: str, *, with_severity: bool) -> PolicyRule:
    if isinstance(item, str):
        item = {"pattern": item}
    if not isinstance(item, dict):
        raise ValueError(f"each policy {field_name} rule must be an object or pattern string")
    if not item.get("pattern", "*"):
        raise ValueError(f"each policy {field_name} rule needs a non-empty pattern")
    if with_severity and "severity" not in item:
        raise ValueError(f"each policy {field_name} rule needs a severity")
    severity = Severity.parse(item["severity"]) if with_severity else None
    return PolicyRule(
        pattern=item.get("pattern", "*"),
        kinds=_tuple(item.get("kinds", item.get("kind")), f"{field_name}.kinds"),
        object_types=_tuple(item.get("object_types", item.get("object_type")), f"{field_name}.object_types"),
        targets=_tuple(item.get("targets", item.get("target")), f"{field_name}.targets"),
        severity=severity,
        reason=item.get("reason"),
    )


def _rules(raw: Any, field_name: str, *, with_severity: bool) -> tuple[PolicyRule, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValueError(f"policy {field_name} must be a list")
    result: list[PolicyRule] = []
    seen: set[tuple[Any, ...]] = set()
    for item in raw:
        rule = _rule_from_item(item, field_name, with_severity=with_severity)
        identity = (rule.pattern, rule.kinds, rule.object_types, rule.targets)
        if identity in seen:
            raise ValueError(f"duplicate/conflicting policy {field_name} rule for {rule.pattern!r}")
        seen.add(identity)
        result.append(rule)
    return tuple(result)


def _load_policy_json(path: str | Path) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid policy file {path}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError("policy version must be 1")
    return raw


def _severity_rules(raw: dict[str, Any]) -> dict[str, Severity]:
    rules_raw = raw.get("rules", {})
    if not isinstance(rules_raw, dict):
        raise ValueError("policy rules must be an object")
    rules: dict[str, Severity] = {}
    for kind, severity in rules_raw.items():
        if not isinstance(kind, str) or not kind:
            raise ValueError("policy rule kinds must be non-empty strings")
        rules[kind] = Severity.parse(severity)
    return rules


def _object_rules_input(raw: dict[str, Any]) -> Any:
    configured = raw.get("object_rules")
    legacy = raw.get("objects")
    if configured is not None or not isinstance(legacy, dict):
        return configured
    return [
        {"pattern": pattern, **(rule if isinstance(rule, dict) else {"severity": rule})}
        for pattern, rule in legacy.items()
    ]


def _rule_identity(rule: PolicyRule) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    return (rule.pattern, rule.kinds, rule.object_types, rule.targets)


def _ensure_no_rule_conflicts(ignore: tuple[PolicyRule, ...], allow: tuple[PolicyRule, ...]) -> None:
    if {_rule_identity(rule) for rule in ignore} & {_rule_identity(rule) for rule in allow}:
        raise ValueError("policy ignore and allow rules conflict")


def _parse_strategy(raw: dict[str, Any]) -> ComparisonStrategy | None:
    strategy = raw.get("strategy")
    try:
        parsed = ComparisonStrategy(strategy.casefold()) if strategy else None
    except (AttributeError, ValueError) as exc:
        raise ValueError("policy strategy must be 'baseline' or 'pairwise'") from exc
    if parsed == ComparisonStrategy.BASELINE and not raw.get("baseline"):
        raise ValueError("baseline policy strategy requires a baseline")
    return parsed


def _positive_report_limit(raw: dict[str, Any]) -> int:
    value = raw.get("max_report_findings", 100)
    if not isinstance(value, int) or value < 1:
        raise ValueError("policy max_report_findings must be a positive integer")
    return value


def load_policy(path: str | Path | None) -> Policy:
    if path is None:
        return Policy()
    raw = _load_policy_json(path)
    object_rules = _rules(_object_rules_input(raw), "object_rules", with_severity=True)
    ignore = _rules(raw.get("ignore"), "ignore", with_severity=False)
    allow = _rules(raw.get("allow"), "allow", with_severity=False)
    _ensure_no_rule_conflicts(ignore, allow)
    return Policy(
        rules=_severity_rules(raw),
        object_rules=object_rules,
        ignore=ignore,
        allow=allow,
        fail_on=Severity.parse(raw.get("fail_on", "warning")),
        baseline=raw.get("baseline"),
        strategy=_parse_strategy(raw),
        max_report_findings=_positive_report_limit(raw),
    )
