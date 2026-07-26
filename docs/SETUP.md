# Local setup

Driftwatch is a Python 3.11+ CLI. It connects to SQL Server through `pyodbc`
and does not persist credentials or findings.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

On Windows, activate the environment with `.venv\\Scripts\\activate`.

## Configure targets

Create a JSON file with at least two targets. Keep connection strings in
environment variables whenever they contain credentials:

```json
{
  "targets": [
    {"name": "dev", "connection_string": "env:DRIFTWATCH_DEV"},
    {"name": "prod", "connection_string": "env:DRIFTWATCH_PROD"}
  ]
}
```

The configured ODBC driver must be installed on the host. Set the referenced
environment variables before running the CLI.

## Run

Use the default text output for investigation:

```bash
driftwatch --config examples/config.json --severity warning --query users
```

Use `--format json` or `--format csv` when another program will consume the
result. See [CLI reference](CLI.md) for all options and exit codes.

## Test

```bash
pytest -q
python -m compileall -q src tests
```

The SQL Server integration test is opt-in through
`DRIFTWATCH_TEST_CONN_A` and `DRIFTWATCH_TEST_CONN_B`.
