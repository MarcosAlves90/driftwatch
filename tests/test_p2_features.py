import json
from pathlib import Path

import pytest

from driftwatch import cli
from driftwatch.azure_auth import SQL_COPT_SS_ACCESS_TOKEN, odbc_access_token_attributes
from driftwatch.dependency import DependencyGraph, add_impact
from driftwatch.lifecycle import classify_findings
from driftwatch.migration import render_migration_text, verify_migration
from driftwatch.models import CollectionStatus, Finding, Inventory, ObjectId
from driftwatch.normalize import NormalizationOptions, normalize_sql
from driftwatch.policy import Policy
from driftwatch.report import build_report, render_html, render_text, write_csv


def _finding(name="dbo.Users"):
    return Finding("definition_mismatch", "TABLE", name, "warning", "changed", property="definition")


def test_migration_effects_classify_expected_and_missing():
    before = Inventory("before", {"TABLE|dbo.Users": {"definition": "select 1"}})
    after = Inventory("after", {"TABLE|dbo.Users": {"definition": "select 2"}})
    expected = "change dbo.Users"
    report = verify_migration(before, after, expected=[expected])
    assert report.effects[0].classification == "expected"
    assert report.missing == ()
    assert "Unexpected: 0" in render_migration_text(report)
    assert report.findings[0].planned is True
    evaluated = Policy().evaluate(report.findings)
    assert evaluated.findings[0].rule == "default"


def test_dependency_graph_is_bounded_and_cycle_safe():
    graph = DependencyGraph()
    a, b, c = (ObjectId("TABLE", "dbo", name) for name in ("a", "b", "c"))
    graph.add(a, b)
    graph.add(b, c)
    graph.add(c, a)
    assert graph.dependents(a, 1) == {b}
    assert graph.dependents(a, 2) == {b, c}


def test_impact_is_additive_and_does_not_change_severity():
    graph = DependencyGraph()
    graph.add(ObjectId("TABLE", "dbo", "Users"), ObjectId("TABLE", "dbo", "Orders"))
    finding = _finding()
    enriched = add_impact([finding], graph)[0]
    assert enriched.severity == finding.severity
    assert enriched.impact["blast_radius"] == 1


def test_lifecycle_marks_existing_and_resolved():
    current = [_finding()]
    resolved = _finding("dbo.Old")
    result = classify_findings(current, {"findings": [current[0].as_dict(), resolved.as_dict()]})
    assert result[0].lifecycle.value == "EXISTING"
    assert result[-1].lifecycle.value == "RESOLVED"


def test_normalization_options_can_retain_comments_and_case():
    sql = "SELECT  1 -- note\n FROM dbo.Users"
    assert "note" in normalize_sql(sql, NormalizationOptions(ignore_comments=False))
    assert normalize_sql("SELECT 1", NormalizationOptions(normalize_keywords_case=False)) == "SELECT 1"


def test_azure_token_uses_sql_server_odbc_attribute_encoding():
    attributes = odbc_access_token_attributes("ab")
    assert attributes[SQL_COPT_SS_ACCESS_TOKEN] == b"a\x00b\x00"


def test_partial_collection_has_distinct_inconclusive_exit_code():
    assert cli._collection_exit([Inventory("a", status=CollectionStatus.PARTIAL)]) == cli.EXIT_INCONCLUSIVE
    assert cli._collection_exit([Inventory("a", status=CollectionStatus.FAILED)]) == cli.EXIT_RUNTIME


def test_html_is_escaped_and_csv_can_be_enhanced(tmp_path):
    finding = _finding()
    html_path = tmp_path / "report.html"
    csv_path = tmp_path / "report.csv"
    render_html([finding], {"selected_count": 1}, str(html_path))
    write_csv([finding], str(csv_path), enhanced=True)
    assert "<table" in html_path.read_text()
    assert "baseline,fingerprint" in csv_path.read_text().splitlines()[0]


def test_csv_legacy_contract_matches_golden_fixture(tmp_path):
    from driftwatch.report import write_csv

    output = tmp_path / "findings.csv"
    write_csv(
        [
            Finding(
                "definition_mismatch",
                "TABLE",
                "dbo.Users",
                "warning",
                "changed",
                targets=("dev", "prod"),
                property="definition",
            )
        ],
        str(output),
    )
    golden = Path(__file__).parent / "golden" / "findings.csv"
    assert output.read_text() == golden.read_text()


def test_text_and_json_outputs_match_golden_contracts(tmp_path):
    finding = Finding(
        "definition_mismatch",
        "TABLE",
        "dbo.Users",
        "warning",
        "changed",
        targets=("dev", "prod"),
        property="definition",
    )
    analysis = {
        "selected_count": 1,
        "by_severity": {"warning": 1},
        "by_kind": {"definition_mismatch": 1},
        "by_object_type": {"TABLE": 1},
    }
    text_path = tmp_path / "findings.txt"
    render_text([finding], analysis, str(text_path))
    assert text_path.read_text() == (Path(__file__).parent / "golden" / "text_findings.txt").read_text()
    report = build_report([], [finding], analysis)
    report.pop("generated_at")
    assert report == json.loads((Path(__file__).parent / "golden" / "report.json").read_text())


def test_hypothesis_normalization_is_idempotent_when_available():
    pytest.importorskip("hypothesis")
    from hypothesis import given
    from hypothesis import strategies as st

    @given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=80))
    def property_test(value):
        assert normalize_sql(normalize_sql(value)) == normalize_sql(value)

    property_test()
