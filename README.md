# Driftwatch

Python CLI for finding schema drift and anomalies across multiple SQL Server connections, including Azure SQL when supported by the ODBC driver.

## Usage

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
driftwatch --config examples/config.json --format json --output report.json
```

By default, Driftwatch prints a compact human-readable summary. Use filters
and search to focus an investigation instead of reading the complete report:

```bash
driftwatch --config examples/config.json \
  --severity warning --kind missing_left --query users
```

Filters can be repeated or comma-separated. They combine across dimensions;
values within one option are alternatives. Available options are
`--kind`, `--severity`, `--target`, `--object`, and `--query`.

For multiple environments, choose an explicit comparison strategy and
reference target:

```bash
driftwatch --config examples/config.json \
  --strategy baseline --baseline prod
```

`baseline` compares every other target with the reference. `pairwise` compares
every combination. A failed or partial collection is reported as an
operational problem and its invalid sections are never interpreted as schema
drift.

Choose an output format explicitly when integrating with another tool:

```bash
driftwatch --config examples/config.json --format text
driftwatch --config examples/config.json --format json --output report.json
driftwatch --config examples/config.json --format csv --output findings.csv
```

For CI, policy files control severity, ignores, and explicit exceptions:

```bash
driftwatch check --config examples/config.json \
  --policy examples/policy.json --fail-on breaking --workers 4
```

Create a deterministic schema snapshot for Git review, then compare a live
configuration against it later:

```bash
driftwatch snapshot --config examples/config.json --target prod \
  --snapshot-output schemas/prod.json
driftwatch check --config examples/config.json --snapshot schemas/prod.json \
  --format sarif --fail-on breaking
```

The CLI also exposes `compare`, `snapshot`, `explain`, `inspect`, and
`config validate` intents. `--summary-only` emits aggregate totals and
`--quiet` suppresses stdout while preserving exit codes. Use `--previous` to
classify findings as NEW, EXISTING, or RESOLVED and `--format html` for a
self-contained review report.

Migration verification is deliberately controlled by the caller: capture
before/after inventories around a migration in an ephemeral or approved
database, then call `driftwatch.migration.verify_migration` to compare the
semantic effect and expected fingerprints. Driftwatch never applies a
migration to an implicit database.

Snapshots contain normalized schema metadata and a content digest, never
connection strings or credentials. Their structural content is sorted so
small schema changes produce focused Git diffs. A reusable composite action is
available at `.github/actions/driftwatch/action.yml`.

The summary includes totals grouped by severity, finding kind, and object
type. Semantic findings include the changed property, expected value, actual
value, and impact severity (`info`, `warning`, `breaking`, or `critical`). JSON
retains the existing report fields and adds analysis, comparison, collection
status, and semantic metadata; filtered JSON contains only the selected
findings.

The configuration file is JSON. Use `env:VARIABLE_NAME` to keep credentials out of the file:

```json
{
  "targets": [
    {"name": "dev", "connection_string": "env:DRIFTWATCH_DEV"},
    {"name": "prod", "connection_string": "env:DRIFTWATCH_PROD"}
  ]
}
```

Credentials can also be supplied for every configured target through the CLI. Prefer standard input so the password is not exposed in shell history or the process list:

```bash
printf '%s\n' "$DRIFTWATCH_PASSWORD" | driftwatch \
  --config examples/config.json \
  --username app_user \
  --password-stdin \
  --format json \
  --output report.json
```

`--password PASSWORD` is supported for automation but may be visible to other local users through the process list. CLI credentials override/add `UID` and `PWD` in memory and are never written to reports.

Exit code `0` means no finding meets the configured threshold, `2` means at
least one non-allowed finding meets `--fail-on` (default `warning`), `1` means
a configuration or failed-collection error, and `3` means a partial,
inconclusive collection. Connection failures and partial sections appear in
the report, and connection strings are never included.

## Docker

```bash
docker build -t driftwatch .
docker run --rm -v "$PWD:/work" -w /work --env-file .env driftwatch --config examples/config.json --format json --output report.json
```

The MVP compares schema metadata; it does not compare data or apply changes.

See [local setup](docs/SETUP.md), the [CLI reference](docs/CLI.md),
[testing strategy](docs/TESTING.md), and [architecture overview](docs/architecture/README.md)
for details.
