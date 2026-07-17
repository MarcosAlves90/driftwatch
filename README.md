# Driftwatch

Python CLI for finding schema drift and anomalies across multiple SQL Server connections, including Azure SQL when supported by the ODBC driver.

## Usage

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
driftwatch --config examples/config.json --output report.json
```

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
  --output report.json
```

`--password PASSWORD` is supported for automation but may be visible to other local users through the process list. CLI credentials override/add `UID` and `PWD` in memory and are never written to reports.

Exit code `0` means no findings, `2` means differences/anomalies were found, and `1` means a configuration error. Connection or collection failures appear in the report and connection strings are never included.

## Docker

```bash
docker build -t driftwatch .
docker run --rm -v "$PWD:/work" -w /work --env-file .env driftwatch --config examples/config.json --output report.json
```

The MVP compares schema metadata; it does not compare data or apply changes.
