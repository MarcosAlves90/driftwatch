# Driftwatch

Driftwatch is a Python CLI for detecting **schema drift and structural anomalies across multiple SQL Server databases**, including Azure SQL when supported by the configured ODBC driver.

It is designed for local investigations, automated CI checks, reproducible schema snapshots, and migration verification—without modifying the databases it inspects.

## Features

- Compare schemas across multiple SQL Server targets.
- Detect missing, extra, and semantically different database objects.
- Classify findings by severity: `info`, `warning`, `breaking`, or `critical`.
- Compare environments using baseline or pairwise strategies.
- Filter findings by kind, severity, target, object, or free-text query.
- Export results as text, JSON, CSV, HTML, or SARIF.
- Enforce CI policies with ignores, exceptions, and severity thresholds.
- Create deterministic schema snapshots suitable for Git review.
- Track findings as `NEW`, `EXISTING`, or `RESOLVED`.
- Report failed and partial collections without misclassifying them as drift.
- Keep connection strings and credentials out of reports and snapshots.
- Verify the semantic effect of migrations without applying them automatically.

## Installation

Driftwatch requires Python and a compatible SQL Server ODBC driver.

For development:

```bash
python -m venv .venv
source .venv/bin/activate

pip install -e '.[dev]'
```

Then run:

```bash
driftwatch --config examples/config.json
```

By default, Driftwatch prints a compact human-readable summary.

## Quick Start

Compare the targets defined in a configuration file:

```bash
driftwatch --config examples/config.json
```

Export the report as JSON:

```bash
driftwatch \
  --config examples/config.json \
  --format json \
  --output report.json
```

Driftwatch compares schema metadata only. It does not compare table data or automatically apply schema changes.

## Configuration

Configuration is defined in JSON.

```json
{
  "targets": [
    {
      "name": "dev",
      "connection_string": "env:DRIFTWATCH_DEV"
    },
    {
      "name": "prod",
      "connection_string": "env:DRIFTWATCH_PROD"
    }
  ]
}
```

Use `env:VARIABLE_NAME` to resolve connection strings from environment variables instead of storing credentials in the configuration file.

For example:

```bash
export DRIFTWATCH_DEV='...'
export DRIFTWATCH_PROD='...'

driftwatch --config examples/config.json
```

Connection strings are never included in generated reports.

## Comparing Environments

When more than two environments are configured, select how comparisons should be generated.

### Baseline comparison

Compare every target against a reference environment:

```bash
driftwatch \
  --config examples/config.json \
  --strategy baseline \
  --baseline prod
```

For example:

```text
dev     ──┐
staging ──┼──> prod
qa      ──┘
```

This is typically useful when `prod` represents the expected schema.

### Pairwise comparison

Compare every target with every other target:

```bash
driftwatch \
  --config examples/config.json \
  --strategy pairwise
```

This is useful when there is no authoritative reference environment.

Failed or incomplete schema collections are reported as operational problems. Invalid sections are never interpreted as schema drift.

## Filtering Findings

Use filters to narrow an investigation instead of inspecting the entire report.

```bash
driftwatch \
  --config examples/config.json \
  --severity warning \
  --kind missing_left \
  --query users
```

Available filters:

```text
--kind
--severity
--target
--object
--query
```

Filters may be repeated or comma-separated.

Values within the same filter are treated as alternatives, while different filter dimensions are combined.

For example:

```bash
driftwatch \
  --config examples/config.json \
  --severity warning,breaking \
  --object table \
  --query customer
```

## Output Formats

Driftwatch supports multiple output formats depending on the intended workflow.

Human-readable output:

```bash
driftwatch \
  --config examples/config.json \
  --format text
```

JSON:

```bash
driftwatch \
  --config examples/config.json \
  --format json \
  --output report.json
```

CSV:

```bash
driftwatch \
  --config examples/config.json \
  --format csv \
  --output findings.csv
```

HTML:

```bash
driftwatch \
  --config examples/config.json \
  --format html \
  --output report.html
```

SARIF is available for integrations with CI and code scanning workflows.

The report summary includes totals grouped by:

- severity;
- finding kind;
- object type.

Semantic findings include the changed property, expected value, actual value, and impact severity.

JSON reports retain the standard report fields while including analysis, comparison, collection status, and semantic metadata.

When filters are applied, JSON output contains only the selected findings.

## CI Policy Checks

Use `driftwatch check` to enforce schema policies in CI:

```bash
driftwatch check \
  --config examples/config.json \
  --policy examples/policy.json \
  --fail-on breaking \
  --workers 4
```

Policy files can define:

- severity rules;
- ignored findings;
- explicit exceptions.

This allows known differences to be documented while unexpected drift still fails the build.

A reusable GitHub composite action is available at:

```text
.github/actions/driftwatch/action.yml
```

## Schema Snapshots

Create deterministic snapshots that can be stored and reviewed in Git:

```bash
driftwatch snapshot \
  --config examples/config.json \
  --target prod \
  --snapshot-output schemas/prod.json
```

Then compare a live environment against that snapshot later:

```bash
driftwatch check \
  --config examples/config.json \
  --snapshot schemas/prod.json \
  --format sarif \
  --fail-on breaking
```

Snapshots contain normalized schema metadata and a content digest.

They never contain connection strings or credentials.

Snapshot structure is deterministically sorted so that small schema changes produce focused Git diffs instead of large serialization changes.

## Tracking Changes Over Time

Provide a previous report to distinguish newly introduced drift from existing differences:

```bash
driftwatch \
  --config examples/config.json \
  --previous previous-report.json
```

Findings are classified as:

```text
NEW
EXISTING
RESOLVED
```

This is useful in CI pipelines where teams want to block newly introduced drift without immediately failing on known historical differences.

## Migration Verification

Driftwatch can verify the semantic effect of a migration by comparing inventories captured before and after it.

Migration execution itself remains controlled by the caller.

A typical workflow is:

```text
1. Capture the schema before the migration.
2. Apply the migration to an ephemeral or explicitly approved database.
3. Capture the resulting schema.
4. Compare both inventories.
5. Verify expected semantic fingerprints.
```

Verification is available through:

```python
driftwatch.migration.verify_migration
```

Driftwatch never applies a migration to an implicit database.

This separation keeps database mutation explicit and makes migration verification suitable for controlled CI environments.

## Credentials

Credentials may be resolved directly from environment-based connection strings:

```json
{
  "connection_string": "env:DRIFTWATCH_PROD"
}
```

They may also be supplied through the CLI.

For interactive or CI usage, prefer standard input:

```bash
printf '%s\n' "$DRIFTWATCH_PASSWORD" | driftwatch \
  --config examples/config.json \
  --username app_user \
  --password-stdin \
  --format json \
  --output report.json
```

Driftwatch also supports:

```text
--password PASSWORD
```

However, command-line passwords may be visible to other local users through the process list or shell tooling.

CLI-provided credentials override or add `UID` and `PWD` in memory only. They are never persisted into reports.

## Exit Codes

Driftwatch uses explicit exit codes so CI systems can distinguish drift from operational failures.

| Code | Meaning |
|---:|---|
| `0` | No finding meets the configured failure threshold. |
| `1` | Configuration error or failed schema collection. |
| `2` | At least one non-allowed finding meets `--fail-on`. |
| `3` | Collection was partial or inconclusive. |

The default `--fail-on` severity is:

```text
warning
```

Connection failures and partial sections are included in reports, but connection strings are never exposed.

## CLI Commands

The CLI provides dedicated commands for different workflows:

```text
compare
snapshot
check
explain
inspect
config validate
```

Additional useful options include:

```text
--summary-only
```

Emit aggregate totals without the complete finding list.

```text
--quiet
```

Suppress stdout while preserving exit-code behavior.

```text
--previous
```

Compare findings with a previous report and classify them as `NEW`, `EXISTING`, or `RESOLVED`.

## Docker

Build the image:

```bash
docker build -t driftwatch .
```

Run Driftwatch against files in the current directory:

```bash
docker run --rm \
  -v "$PWD:/work" \
  -w /work \
  --env-file .env \
  driftwatch \
  --config examples/config.json \
  --format json \
  --output report.json
```

## Safety Model

Driftwatch is intentionally read-oriented.

It:

- inspects schema metadata;
- reports differences;
- generates snapshots and reports;
- verifies externally executed migrations.

It does not:

- compare table data;
- automatically repair schema drift;
- implicitly execute migrations;
- persist database credentials in reports or snapshots.

Database mutations remain explicit operations controlled by the caller.

## Documentation

For more details, see:

- [Local setup](docs/SETUP.md)
- [CLI reference](docs/CLI.md)
- [Testing strategy](docs/TESTING.md)
- [Architecture overview](docs/architecture/README.md)
