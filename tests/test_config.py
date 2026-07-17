import json

from driftwatch.config import apply_cli_credentials, load_targets


def test_config_resolves_environment_reference(tmp_path, monkeypatch):
    monkeypatch.setenv("DRIFTWATCH_CONN", "Driver={ODBC Driver 18 for SQL Server};Server=x")
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"targets": [
        {"name": "a", "connection_string": "env:DRIFTWATCH_CONN"},
        {"name": "b", "connection_string": "env:DRIFTWATCH_CONN"},
    ]}))
    assert load_targets(path)[0].connection_string.startswith("Driver=")


def test_cli_credentials_are_added_without_changing_target_name():
    targets = _load_targets_from_items([
        {"name": "a", "connection_string": "Driver={ODBC Driver 18 for SQL Server};Server=x"},
        {"name": "b", "connection_string": "Driver={ODBC Driver 18 for SQL Server};Server=y"},
    ])
    secured = apply_cli_credentials(targets, "alice", "s3;cret")
    assert "UID=alice" in secured[0].connection_string
    assert "PWD={s3;cret}" in secured[0].connection_string
    assert secured[0].name == "a"


def _load_targets_from_items(items):
    import tempfile

    path = tempfile.NamedTemporaryFile(mode="w+", suffix=".json")
    try:
        json.dump({"targets": items}, path)
        path.flush()
        return load_targets(path.name)
    finally:
        path.close()
