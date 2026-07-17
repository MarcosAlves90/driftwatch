import json

from driftwatch import cli
from driftwatch.models import Inventory


def test_cli_reads_password_from_stdin_and_writes_report(monkeypatch, tmp_path, capsys):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"targets": [
        {"name": "a", "connection_string": "Driver=fixture;Server=a"},
        {"name": "b", "connection_string": "Driver=fixture;Server=b"},
    ]}))
    output = tmp_path / "report.json"
    captured = []

    def fake_collect(target):
        captured.append(target.connection_string)
        return Inventory(target.name, {})

    monkeypatch.setattr(cli, "collect", fake_collect)
    monkeypatch.setattr("sys.stdin", type("Input", (), {"isatty": lambda self: False, "readline": lambda self: "secret\n"})())
    assert cli.main(["--config", str(config), "--username", "alice", "--password-stdin", "--output", str(output)]) == 0
    assert all("UID=alice;PWD=secret" in connection for connection in captured)
    assert "secret" not in output.read_text()
    assert capsys.readouterr().out == ""
