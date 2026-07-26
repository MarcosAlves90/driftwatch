# CLI reference

## Invocation

```text
driftwatch [check|compare|snapshot|explain|inspect|config validate|migration verify] [--config PATH] [--output PATH]
           [--format text|json|csv|sarif]
           [--strategy baseline|pairwise] [--baseline TARGET]
           [--policy PATH] [--fail-on info|warning|breaking|critical]
           [--workers N] [--connect-timeout SECONDS] [--query-timeout SECONDS]
           [--kind VALUE] [--severity VALUE] [--target VALUE]
           [--object VALUE] [--query TEXT] [--summary-only] [--quiet]
           [--username USER] [--password PASSWORD | --password-stdin]
```

`--config` is required and must contain at least two targets. `--output` writes
the selected format to a file; without it, output goes to stdout.

The JSON configuration may also contain `strategy` and `baseline` keys. CLI
options override those values. Setting a baseline without a strategy selects
the baseline strategy.

The configuration can also contain `workers` (1–32), `connect_timeout`, and
`query_timeout` in seconds. CLI values override the file. The default worker
limit is 4 and the default connection timeout is 30 seconds.

`snapshot` requires `--snapshot-output` (or `--output`) and exactly one target;
use `--target` to select it from a multi-target config. `check --snapshot PATH`
uses the snapshot as expected state and compares every configured live target
against it.

## Policy

Policies are versioned JSON files. They can set `fail_on`, finding-kind
severities, object-specific severity rules, exact/glob `ignore` patterns, and
restricted `allow` exceptions:

```json
{
  "version": 1,
  "fail_on": "breaking",
  "rules": {"index_removed": "warning"},
  "ignore": ["dbo.__EFMigrationsHistory", "audit.*"],
  "allow": [{"pattern": "dbo.temp_*", "kinds": ["missing_right"], "reason": "migration"}]
}
```

Policy validation happens before collection. Ignored findings are excluded
from blocking evaluation; allowed findings remain visible and are counted
separately in JSON reports. Collection failures always return exit code 1.

## Collection reliability

Every target reports `SUCCESS`, `PARTIAL`, or `FAILED`, with independent status
and error information for objects, columns, indexes, and constraints. Failed
inventories are excluded from comparison. In a partial inventory, only sections
that succeeded on both sides are compared.

## Selection

`--kind`, `--severity`, `--target`, and `--object` accept repeated or
comma-separated values. Values within one option use OR semantics. Different
options use AND semantics. Matching is case-insensitive.

`--query` performs a case-insensitive substring search across finding kind,
object type, object name, severity, message, and target names. It combines with
the dimension filters.

## Formats

- `text` (default): compact totals grouped by severity, finding kind, and
  object type, followed by one line per selected finding. Semantic changes
  include the affected property and expected/actual values; raw definitions
  are not printed in this mode.
- `json`: the existing report fields plus additive `analysis` metadata. The
  `findings` array contains only selected findings.
- `csv`: one row per selected finding with stable columns, including property,
  expected, and actual values. Complex values are JSON-encoded in their cells.
- `sarif`: SARIF 2.1.0 results with stable Driftwatch fingerprints.
- `html`: escaped, self-contained static report for human review.

Findings use impact severities `info`, `warning`, `breaking`, and `critical`.
Column, index, constraint, foreign-key, and object-definition differences are
classified by specialized comparison logic rather than one generic dictionary
comparison.

## JSON compatibility

Reports contain both `format_version` and `schema_version`, currently `1`.
Consumers should ignore unknown fields and treat missing optional fields as
absent. Adding optional fields is backward-compatible; changing field meaning,
removing fields, or changing required types requires a new major schema
version. Findings include a stable `fingerprint` derived from semantic
identity, kind, and property rather than timestamps or values.

## Exit codes

- `0`: no findings, including when filters select none.
- `2`: at least one finding meets the configured `--fail-on` threshold.
- `1`: configuration, credential, or collection error.

`--previous REPORT.json` adds `NEW`, `EXISTING`, and `RESOLVED` lifecycle
labels. `explain --report REPORT.json --fingerprint HASH` prints one finding;
`inspect` prints the selected report subset. `config validate --config PATH`
validates configuration without connecting to a database.

`migration verify --before BEFORE.json --after AFTER.json` compares two
controlled snapshots and accepts repeated `--expected-effect` identifiers.
It returns `2` when an effect is unexpected or an expected effect is missing;
it never applies SQL itself.

Connection and collection failures are reported without including connection
strings.
