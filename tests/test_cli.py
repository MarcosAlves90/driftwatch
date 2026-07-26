import json

from driftwatch import cli
from driftwatch.models import Finding, Inventory


def test_cli_reads_password_from_stdin_and_writes_report(monkeypatch, tmp_path, capsys):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "targets": [
                    {"name": "a", "connection_string": "Driver=fixture;Server=a"},
                    {"name": "b", "connection_string": "Driver=fixture;Server=b"},
                ]
            }
        )
    )
    output = tmp_path / "report.json"
    captured = []

    def fake_collect(target):
        captured.append(target.connection_string)
        return Inventory(target.name, {})

    monkeypatch.setattr(cli, "collect", fake_collect)
    monkeypatch.setattr(
        "sys.stdin", type("Input", (), {"isatty": lambda self: False, "readline": lambda self: "secret\n"})()
    )
    assert cli.main(["--config", str(config), "--username", "alice", "--password-stdin", "--output", str(output)]) == 0
    assert all("UID=alice;PWD=secret" in connection for connection in captured)
    assert "secret" not in output.read_text()
    assert capsys.readouterr().out == ""


def test_cli_filters_findings_and_renders_compact_text(monkeypatch, tmp_path, capsys):
    config = tmp_path / "config.json"
    config.write_text(
        '{"targets": [{"name": "dev", "connection_string": "fixture"}, {"name": "prod", "connection_string": "fixture"}]}'
    )
    monkeypatch.setattr(cli, "collect", lambda target: Inventory(target.name, {}))
    monkeypatch.setattr(
        cli,
        "compare_all",
        lambda inventories: [
            Finding("missing_left", "TABLE", "dbo.Users", "warning", "only in prod", targets=("prod",)),
            Finding(
                "definition_mismatch", "VIEW", "dbo.Active", "critical", "definitions differ", targets=("dev", "prod")
            ),
        ],
    )

    assert cli.main(["--config", str(config), "--severity", "critical"]) == 2
    rendered = capsys.readouterr().out
    assert "Findings: 1" in rendered
    assert "dbo.Active" in rendered
    assert "dbo.Users" not in rendered
