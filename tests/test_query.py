from driftwatch.models import Finding
from driftwatch.query import analyze_findings, select_findings


def _findings():
    return [
        Finding("missing_left", "TABLE", "dbo.Users", "warning", "only in prod", targets=("prod",)),
        Finding("definition_mismatch", "VIEW", "dbo.Active", "critical", "definitions differ", targets=("dev", "prod")),
        Finding("missing_right", "INDEX", "dbo.Users.IX_Id", "warning", "only in dev", targets=("dev",)),
    ]


def test_select_findings_composes_case_insensitive_filters_and_search():
    selected = select_findings(
        _findings(), kinds=["missing_left,missing_right"], targets=["PROD"], query="users"
    )
    assert [finding.object_name for finding in selected] == ["dbo.Users"]


def test_select_findings_matches_object_name_exactly():
    assert len(select_findings(_findings(), objects=["dbo.Active"])) == 1
    assert select_findings(_findings(), objects=["dbo.User"]) == []


def test_analyze_findings_returns_sorted_counts_and_empty_counts():
    assert analyze_findings(_findings()) == {
        "selected_count": 3,
        "by_severity": {"critical": 1, "warning": 2},
        "by_kind": {"definition_mismatch": 1, "missing_left": 1, "missing_right": 1},
        "by_object_type": {"INDEX": 1, "TABLE": 1, "VIEW": 1},
    }
    assert analyze_findings([]) == {
        "selected_count": 0,
        "by_severity": {},
        "by_kind": {},
        "by_object_type": {},
    }
