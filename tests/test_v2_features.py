import hashlib
import json
from dataclasses import replace

import pytest

from driftwatch import cli
from driftwatch.dependency import (
    add_target_impact,
    dependency_coverage,
    dependency_view,
    graph_from_inventory,
)
from driftwatch.diff import compare, compare_all
from driftwatch.evidence import attach_evidence
from driftwatch.investigation import (
    dependency_report,
    explain_report,
    finding_from_dict,
    history_report,
    inspect_report,
    inventories_from_report,
    issue_from_dict,
    plan_report,
)
from driftwatch.issues import aggregate_issues, analyze_issues
from driftwatch.lifecycle import classify_findings
from driftwatch.models import (
    CollectionSection,
    CollectionSectionStatus,
    CollectionStatus,
    ComparisonStrategy,
    Finding,
    FindingLifecycle,
    Inventory,
    ObjectId,
    Severity,
    canonical_object_type,
)
from driftwatch.policy import Policy, load_policy
from driftwatch.query import select_findings
from driftwatch.remediation import plan_for_finding, render_remediation_text
from driftwatch.report import build_report, render_html, render_sarif, render_text
from driftwatch.snapshot import inventory_from_snapshot, read_snapshot, write_snapshot


def _inv(
    name,
    objects=None,
    *,
    deps=None,
    metadata=None,
    object_metadata=None,
    observed="2026-08-07T12:00:00+00:00",
):
    return Inventory(
        name,
        objects or {},
        sections={
            section.value: CollectionSectionStatus(CollectionStatus.SUCCESS)
            for section in CollectionSection
        },
        metadata=metadata or {"dependency_coverage": "complete"},
        object_metadata=object_metadata or {},
        dependencies=deps or [],
        observed_at=observed,
    )


def _column(length, nullable=True):
    return {
        "schema": "dbo",
        "table": "Users",
        "name": "email",
        "data_type": "varchar",
        "max_length": length,
        "precision": 0,
        "scale": 0,
        "is_nullable": nullable,
    }


def test_canonical_identity_and_analysis_metadata_do_not_create_drift():
    assert canonical_object_type("USER_TABLE") == "TABLE"
    assert str(ObjectId("USER_TABLE", "dbo", "Users")) == "TABLE|dbo.Users"
    assert ObjectId.parse("SQL_STORED_PROCEDURE|dbo.p").type == "PROCEDURE"
    left = _inv(
        "prod",
        {
            "USER_TABLE|dbo.Users": {
                "schema": "dbo",
                "name": "Users",
                "type": "USER_TABLE",
                "definition": None,
                "dependencies": ["VIEW|dbo.v"],
                "object_id": 1,
            }
        },
    )
    right = _inv(
        "dev",
        {
            "TABLE|dbo.Users": {
                "schema": "dbo",
                "name": "Users",
                "type": "TABLE",
                "definition": None,
                "dependencies": [],
                "object_id": 999,
            }
        },
    )
    assert compare(left, right) == []


def test_pairwise_findings_aggregate_into_one_issue_with_variants():
    inventories = [
        _inv("dev", {"COLUMN|dbo.Users.email": _column(100)}),
        _inv("qa", {"COLUMN|dbo.Users.email": _column(100)}),
        _inv("prod", {"COLUMN|dbo.Users.email": _column(50)}),
    ]
    findings = compare_all(inventories)
    assert len(findings) == 2
    issues = aggregate_issues(findings)
    assert len(issues) == 1
    assert len(issues[0].evidence) == 2
    assert {tuple(variant.targets) for variant in issues[0].variants} == {
        ("dev", "qa"),
        ("prod",),
    } or {tuple(variant.targets) for variant in issues[0].variants} == {
        ("dev",),
        ("qa",),
        ("prod",),
    }
    assert analyze_issues(issues)["issue_count"] == 1


def test_occurrence_identity_and_changed_lifecycle():
    old = Finding(
        "column_length_changed",
        "COLUMN",
        "dbo.Users.email",
        "breaking",
        "changed",
        targets=("prod", "dev"),
        comparison=("prod", "dev"),
        property="max_length",
        expected=255,
        actual=100,
    )
    current = replace(old, actual=50)
    assert old.issue_key == current.issue_key
    assert old.occurrence_id != current.occurrence_id
    previous = {
        "generated_at": "2026-08-06T00:00:00+00:00",
        "findings": [old.as_dict(enhanced=True)],
    }
    classified = classify_findings(
        [current], previous, observed_at="2026-08-07T00:00:00+00:00"
    )
    assert classified[0].lifecycle == FindingLifecycle.CHANGED
    assert classified[0].first_seen_at == "2026-08-06T00:00:00+00:00"
    resolved = classify_findings([], previous, observed_at="2026-08-08T00:00:00+00:00")
    assert resolved[0].lifecycle == FindingLifecycle.RESOLVED
    assert resolved[0].kind == old.kind
    assert resolved[0].issue_key == old.issue_key
    assert Policy(fail_on=Severity.INFO).blocking(
        Policy(fail_on=Severity.INFO).evaluate(resolved)
    ) == []


def test_dependency_graph_target_impact_and_views_are_explicit():
    prod = _inv(
        "prod",
        {"TABLE|dbo.Users": {}, "VIEW|dbo.v": {}},
        deps=[
            {
                "dependency": "USER_TABLE|dbo.Users",
                "dependent": "VIEW|dbo.v",
                "source": "catalog",
                "confidence": "catalog",
            }
        ],
    )
    dev = _inv("dev", {"TABLE|dbo.Users": {}})
    finding = Finding(
        "definition_mismatch",
        "TABLE",
        "dbo.Users",
        "warning",
        "changed",
        comparison=("prod", "dev"),
        targets=("prod", "dev"),
    )
    enriched = add_target_impact([finding], [prod, dev], 3)[0]
    assert enriched.impact is not None
    assert enriched.impact["blast_radius"] == 1
    assert enriched.impact["by_target"]["prod"]["affected_objects"] == ["VIEW|dbo.v"]
    assert dependency_view(prod, ObjectId("TABLE", "dbo", "Users"))["objects"] == [
        "VIEW|dbo.v"
    ]
    assert dependency_view(
        prod, ObjectId("VIEW", "dbo", "v"), direction="dependencies"
    )["objects"] == ["TABLE|dbo.Users"]
    assert graph_from_inventory(prod).as_dict()["TABLE|dbo.Users"] == ["VIEW|dbo.v"]
    assert dependency_coverage(Inventory("old")) == "unknown"
    users = ObjectId("TABLE", "dbo", "Users")
    with pytest.raises(ValueError):
        dependency_view(prod, users, direction="bad")
    with pytest.raises(ValueError):
        dependency_view(prod, users, depth=-1)


def test_evidence_and_date_dependency_filters():
    prod = _inv(
        "prod",
        {"TABLE|dbo.Users": {}, "COLUMN|dbo.Users.email": _column(255)},
        object_metadata={
            "TABLE|dbo.Users": {
                "created_at": "2025-01-01T00:00:00+00:00",
                "modified_at": "2026-08-01T00:00:00+00:00",
            }
        },
    )
    dev = _inv(
        "dev",
        {"TABLE|dbo.Users": {}, "COLUMN|dbo.Users.email": _column(100)},
        object_metadata={
            "TABLE|dbo.Users": {
                "created_at": "2025-01-01T00:00:00+00:00",
                "modified_at": "2026-08-02T00:00:00+00:00",
            }
        },
    )
    finding = add_target_impact(compare(prod, dev), [prod, dev])[0]
    finding = attach_evidence([finding], [prod, dev])[0]
    assert finding.metadata is not None
    assert finding.metadata["by_target"]["prod"]["object"]["modified_at"].startswith(
        "2026-08-01"
    )
    assert select_findings([finding], modified_after="2026-07-01T00:00:00+00:00") == [
        finding
    ]
    assert select_findings([finding], modified_before="2020-01-01T00:00:00+00:00") == []
    assert select_findings([finding], properties=["MAX_LENGTH"]) == [finding]
    assert select_findings([finding], issue_keys=[finding.issue_key]) == [finding]


def test_snapshot_v2_preserves_provenance_and_reads_v1(tmp_path):
    inv = _inv(
        "prod",
        {"TABLE|dbo.Users": {"schema": "dbo", "name": "Users", "type": "TABLE"}},
        deps=[
            {
                "dependency": "TABLE|dbo.Users",
                "dependent": "VIEW|dbo.v",
                "source": "catalog",
            }
        ],
        object_metadata={"TABLE|dbo.Users": {"created_at": "2025-01-01"}},
    )
    path = tmp_path / "v2.json"
    write_snapshot(inv, path)
    payload = read_snapshot(path)
    assert payload["snapshot_version"] == 2
    restored = inventory_from_snapshot(path)
    assert restored.dependencies == inv.dependencies
    assert restored.object_metadata == inv.object_metadata
    assert restored.observed_at == inv.observed_at

    structural = {"target": "prod", "objects": {"TABLE|dbo.Users": {}}, "metadata": {}}
    unsigned = {
        "snapshot_version": 1,
        "origin": {"name": "prod"},
        "execution_id": hashlib.sha256(
            json.dumps(
                structural,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()[:16],
        "inventory": structural,
    }
    legacy = {
        **unsigned,
        "digest": hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
    }
    legacy_path = tmp_path / "v1.json"
    legacy_path.write_text(json.dumps(legacy))
    old = inventory_from_snapshot(legacy_path)
    assert old.metadata["dependency_coverage"] == "unknown"

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"snapshot_version": 99}))
    with pytest.raises(ValueError, match="snapshot version"):
        read_snapshot(bad)


def test_remediation_plans_safe_column_index_constraint_and_manual():
    prod = _inv(
        "prod",
        {
            "COLUMN|dbo.Users.email": _column(255),
            "INDEX|dbo.Users.IX_Email": {
                "schema": "dbo",
                "table": "Users",
                "name": "IX_Email",
                "type": "NONCLUSTERED",
                "key_columns": ["email"],
                "include_columns": ["name"],
                "filter": None,
                "is_unique": True,
            },
        },
    )
    dev = _inv("dev", {"COLUMN|dbo.Users.email": _column(100)})
    column = compare(prod, dev)[0]
    plan = plan_for_finding(column, [prod, dev])
    assert plan.status == "AVAILABLE" and plan.risk == "low"
    assert "varchar(255)" in plan.sql[0]
    assert "Resolution: AVAILABLE" in render_remediation_text(plan)

    missing_index = compare(prod, dev)[-1]
    index_plan = plan_for_finding(missing_index, [prod, dev])
    assert any("CREATE UNIQUE NONCLUSTERED INDEX" in sql for sql in index_plan.sql)

    extra_index = compare(dev, prod)[-1]
    assert extra_index.kind == "missing_left"
    assert plan_for_finding(extra_index, [dev, prod]).status == "MANUAL_REVIEW_REQUIRED"

    table_drop = Finding(
        "missing_left",
        "TABLE",
        "dbo.Legacy",
        "warning",
        "extra",
        comparison=("prod", "dev"),
        targets=("prod",),
        actual={},
    )
    assert plan_for_finding(table_drop).risk == "destructive"

    unscoped = Finding("definition_mismatch", "TABLE", "dbo.Users", "warning", "changed")
    unscoped_plan = plan_for_finding(unscoped)
    assert unscoped_plan.status == "MANUAL_REVIEW_REQUIRED"
    assert unscoped_plan.preconditions == ()


def test_pairwise_report_requires_explicit_remediation_reference():
    prod = _inv("prod", {"COLUMN|dbo.Users.email": _column(255)})
    dev = _inv("dev", {"COLUMN|dbo.Users.email": _column(100)})
    findings = compare(prod, dev)
    issues = aggregate_issues(findings)
    report = build_report(
        [prod, dev],
        findings,
        {
            "selected_count": len(findings),
            "by_severity": {},
            "by_kind": {},
            "by_object_type": {},
        },
        strategy=ComparisonStrategy.PAIRWISE,
        issues=issues,
        enhanced=True,
    )
    assert "MANUAL_REVIEW_REQUIRED" in plan_report(report, issues[0].issue_key)
    assert "--desired-target" in plan_report(report, issues[0].issue_key)
    assert "AVAILABLE" in plan_report(
        report,
        issues[0].issue_key,
        desired_target="prod",
    )


def test_policy_can_scope_rules_to_target(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "allow": [
                    {
                        "pattern": "dbo.Users",
                        "targets": ["dev"],
                        "reason": "intentional",
                    }
                ],
            }
        )
    )
    policy = load_policy(path)
    finding = Finding(
        "missing_right",
        "TABLE",
        "dbo.Users",
        "critical",
        "missing",
        comparison=("prod", "dev"),
        targets=("dev",),
    )
    result = policy.evaluate([finding])
    assert result.allowed == [result.findings[0]]
    other = replace(finding, comparison=("prod", "qa"), targets=("qa",))
    assert policy.evaluate([other]).allowed == []


def _enhanced_report():
    prod = _inv(
        "prod",
        {
            "TABLE|dbo.Users": {},
            "COLUMN|dbo.Users.email": _column(255),
            "VIEW|dbo.ActiveUsers": {},
        },
        deps=[
            {
                "dependency": "TABLE|dbo.Users",
                "dependent": "VIEW|dbo.ActiveUsers",
                "source": "catalog",
            }
        ],
        object_metadata={
            "TABLE|dbo.Users": {
                "created_at": "2025-01-01",
                "modified_at": "2026-08-01",
            }
        },
    )
    dev = _inv(
        "dev",
        {"TABLE|dbo.Users": {}, "COLUMN|dbo.Users.email": _column(100)},
        object_metadata={
            "TABLE|dbo.Users": {
                "created_at": "2025-01-01",
                "modified_at": "2026-08-02",
            }
        },
    )
    findings = attach_evidence(
        add_target_impact(compare(prod, dev), [prod, dev]), [prod, dev]
    )
    findings = classify_findings(
        findings, None, observed_at="2026-08-07T00:00:00+00:00"
    )
    issues = aggregate_issues(findings)
    analysis = {
        "selected_count": len(findings),
        "by_severity": {"breaking": 1},
        "by_kind": {},
        "by_object_type": {},
    }
    report = build_report(
        [prod, dev],
        findings,
        analysis,
        issues=issues,
        issue_analysis=analyze_issues(issues),
        enhanced=True,
    )
    return report, findings, issues


def test_enhanced_report_sarif_html_and_investigation_commands(tmp_path):
    report, findings, issues = _enhanced_report()
    assert report["format_version"] == 2
    assert report["summary"]["issue_count"] == len(issues)
    assert report["targets"][0]["inventory"]["object_metadata"]

    sarif = tmp_path / "report.sarif"
    render_sarif(findings, str(sarif), issues=issues)
    data = json.loads(sarif.read_text())
    assert len(data["runs"][0]["results"]) == len(issues)
    assert "driftwatch/v2" in data["runs"][0]["results"][0]["fingerprints"]

    html = tmp_path / "report.html"
    render_html(findings, report["analysis"], str(html), issues=issues)
    assert "Blast radius" in html.read_text()

    text = inspect_report(report, "dbo.Users")
    assert "Metadata" in text and "Dependencies" in text and "Open issues" in text
    explanation = explain_report(report, issues[0].issue_key)
    assert "Problem" in explanation and "Recommended resolution" in explanation
    deps = dependency_report(report, "dbo.Users", target="prod")
    assert deps["results"][0]["objects"] == ["VIEW|dbo.ActiveUsers"]
    planned = plan_report(report, issues[0].issue_key, desired_target="prod")
    assert "Resolution:" in planned
    assert "NEW" in history_report(report, None, "dbo.Users")
    assert inventories_from_report(report)[0].objects
    assert finding_from_dict(report["findings"][0]).issue_key == findings[0].issue_key
    assert issue_from_dict(report["issues"][0]).issue_key == issues[0].issue_key


def test_cli_offline_inspect_explain_deps_plan_history(tmp_path, capsys):
    report, _, issues = _enhanced_report()
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))

    assert cli.main(["inspect", "dbo.Users", "--report", str(path)]) == 0
    assert "Object query" in capsys.readouterr().out
    assert cli.main(["explain", issues[0].issue_key, "--report", str(path)]) == 0
    assert "Recommended resolution" in capsys.readouterr().out
    assert cli.main(["deps", "dbo.Users", "--report", str(path), "--target", "prod"]) == 0
    assert "VIEW|dbo.ActiveUsers" in capsys.readouterr().out
    assert (
        cli.main(
            [
                "plan",
                issues[0].issue_key,
                "--report",
                str(path),
                "--desired-target",
                "prod",
            ]
        )
        == 0
    )
    assert "Resolution:" in capsys.readouterr().out
    assert cli.main(["history", "dbo.Users", "--report", str(path)]) == 0
    assert "NEW" in capsys.readouterr().out


def test_cli_validation_snapshot_and_error_paths(tmp_path, monkeypatch, capsys):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"targets": [{"name": "prod", "connection_string": "fixture"}]})
    )
    assert cli.main(["config", "validate", "--config", str(config)]) == 0
    assert "configuration is valid" in capsys.readouterr().out

    monkeypatch.setattr(
        cli, "collect", lambda target: _inv(target.name, {"TABLE|dbo.Users": {}})
    )
    snapshot = tmp_path / "snap.json"
    assert cli.main(["snapshot", "--config", str(config), "--output", str(snapshot)]) == 0
    assert snapshot.exists()
    assert cli.main(["config", "wrong", "--config", str(config)]) == 1
    assert "validate" in capsys.readouterr().err
    assert cli.main(["inspect", "--report", str(tmp_path / "missing.json")]) == 1


def test_text_grouped_issue_output(capsys):
    _, findings, issues = _enhanced_report()
    render_text(
        findings,
        {
            "selected_count": len(findings),
            "by_severity": {},
            "by_kind": {},
            "by_object_type": {},
        },
        None,
        issues=issues,
    )
    output = capsys.readouterr().out
    assert "Issues:" in output and "Distinct issues:" in output
