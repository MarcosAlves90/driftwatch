import json

from driftwatch.config import load_targets


def test_config_resolves_environment_reference(tmp_path, monkeypatch):
    monkeypatch.setenv("DRIFTWATCH_CONN", "Driver={ODBC Driver 18 for SQL Server};Server=x")
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"targets": [
        {"name": "a", "connection_string": "env:DRIFTWATCH_CONN"},
        {"name": "b", "connection_string": "env:DRIFTWATCH_CONN"},
    ]}))
    assert load_targets(path)[0].connection_string.startswith("Driver=")
