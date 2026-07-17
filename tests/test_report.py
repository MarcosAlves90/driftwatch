from driftwatch.models import Finding, Inventory
from driftwatch.report import build_report, write_json


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
