from driftwatch.models import Finding, Inventory
from driftwatch.report import build_report, render_text, write_csv, write_json


def test_report_contains_summary_and_never_connection_strings(tmp_path):
    report = build_report(
        [Inventory("dev", {"TABLE|dbo.users": {}}, [{"stage": "connect", "message": "login failed"}])],
        [Finding("missing_right", "TABLE", "dbo.users", "warning", "object is missing")],
    )
    output = tmp_path / "report.json"
    write_json(report, str(output))
    rendered = output.read_text()
    assert report["summary"] == {"finding_count": 1, "error_count": 1}
    assert "connection_string" not in rendered
    assert "login failed" in rendered


def test_report_adds_analysis_without_removing_existing_fields():
    report = build_report([], [], {"selected_count": 0, "by_kind": {}, "by_severity": {}, "by_object_type": {}})
    assert report["summary"] == {"finding_count": 0, "error_count": 0}
    assert report["analysis"]["selected_count"] == 0


def test_text_output_is_compact_and_csv_has_stable_columns(tmp_path, capsys):
    finding = Finding(
        "definition_mismatch", "VIEW", "dbo.Users", "warning", "definitions differ", targets=("dev", "prod")
    )
    analysis = {
        "selected_count": 1,
        "by_severity": {"warning": 1},
        "by_kind": {"definition_mismatch": 1},
        "by_object_type": {"VIEW": 1},
    }
    render_text([finding], analysis, None)
    assert "definitions differ" in capsys.readouterr().out
    output = tmp_path / "findings.csv"
    write_csv([finding], str(output))
    assert (
        output.read_text().splitlines()[0]
        == "kind,object_type,object_name,severity,property,message,targets,expected,actual,left,right"
    )
