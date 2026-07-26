import json
import threading
import time

import pytest

from driftwatch.collector import collect_many
from driftwatch.github import annotations, job_summary
from driftwatch.models import DatabaseTarget, Finding, Inventory, ObjectId, Severity
from driftwatch.policy import load_policy
from driftwatch.report import render_sarif
from driftwatch.snapshot import inventory_from_snapshot, write_snapshot
from driftwatch import cli


def _finding(kind="missing_right", name="dbo.Users", severity="critical"):
    return Finding(kind, "TABLE", name, severity, "schema changed", targets=("prod", "staging"))


def test_policy_ignore_allow_and_threshold_are_applied_before_blocking(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "version": 1,
        "fail_on": "breaking",
        "rules": {"missing_right": "warning"},
        "ignore": ["audit.*"],
        "allow": [{"pattern": "dbo.temp_*", "kinds": ["missing_right"], "reason": "temporary migration"}],
    }))
    policy = load_policy(path)
    result = policy.evaluate([
        _finding(name="audit.Log"),
        _finding(name="dbo.temp_Users"),
        _finding(name="dbo.Users"),
    ])
    assert len(result.ignored) == 1
    assert len(result.allowed) == 1
    assert result.allowed_reasons[result.allowed[0].fingerprint] == "temporary migration"
    assert policy.blocking(result) == []


def test_policy_rejects_invalid_version_and_duplicate_rules(tmp_path):
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"version": 2}')
    with pytest.raises(ValueError, match="version"):
        load_policy(invalid)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(json.dumps({"version": 1, "ignore": ["audit.*", "audit.*"]}))
    with pytest.raises(ValueError, match="duplicate"):
        load_policy(duplicate)


def test_snapshot_is_deterministic_validated_and_credential_free(tmp_path):
    inventory = Inventory(
        "prod",
        {"TABLE|dbo.Users": {"definition": "select 1"}, "TABLE|dbo.Accounts": {"definition": "select 2"}},
        metadata={"database_collation": "Latin1_General_100_CI_AS", "connection_string": "PWD=secret"},
    )
    path = tmp_path / "schema.json"
    write_snapshot(inventory, path)
    raw = path.read_text()
    assert "secret" not in raw
    assert raw.index("Accounts") < raw.index("Users")
    restored = inventory_from_snapshot(path)
    assert restored.objects == inventory.objects
    path.write_text(raw.replace("select 1", "select 9"))
    with pytest.raises(ValueError, match="digest"):
        inventory_from_snapshot(path)


def test_collect_many_preserves_order_and_isolates_workers():
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake(target, *_args):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.01)
        with lock:
            active -= 1
        return Inventory(target.name)

    targets = [DatabaseTarget(name, "Server=fixture") for name in ("a", "b", "c", "d")]
    result = collect_many(targets, workers=2, collector=fake)
    assert [item.target for item in result] == ["a", "b", "c", "d"]
    assert 1 < peak <= 2


def test_typed_identifier_and_fingerprint_are_stable(tmp_path):
    identifier = ObjectId.parse("COLUMN|dbo.Users.email")
    assert identifier.schema == "dbo"
    assert identifier.subobject == "email"
    first = _finding()
    second = _finding()
    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 64
    output = tmp_path / "result.sarif"
    render_sarif([first], str(output))
    sarif = json.loads(output.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["fingerprints"]["driftwatch/v1"] == first.fingerprint


def test_github_renderers_are_bounded_and_escape_table_delimiters():
    finding = Finding("definition_mismatch", "VIEW", "dbo.v", "warning", "a | b")
    assert "\\|" in job_summary([finding])
    assert "::warning" in annotations([finding])


def test_cli_policy_is_loaded_before_collection_and_controls_exit_code(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"targets": [
        {"name": "a", "connection_string": "fixture"},
        {"name": "b", "connection_string": "fixture"},
    ]}))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "fail_on": "critical"}))
    called = []

    def fake_collect(target):
        called.append(target.name)
        return Inventory(target.name, {"TABLE|dbo.Users": {"definition": target.name}})

    monkeypatch.setattr(cli, "collect", fake_collect)
    assert cli.main(["check", "--config", str(config), "--policy", str(policy)]) == 0
    assert called == ["a", "b"]
    bad_policy = tmp_path / "bad-policy.json"
    bad_policy.write_text('{"version": 2}')
    called.clear()
    assert cli.main(["check", "--config", str(config), "--policy", str(bad_policy)]) == 1
    assert called == []
