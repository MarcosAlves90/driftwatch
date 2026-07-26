# CLI reference

## Invocation

```text
driftwatch --config PATH [--output PATH] [--format text|json|csv]
           [--kind VALUE] [--severity VALUE] [--target VALUE]
           [--object VALUE] [--query TEXT]
           [--username USER] [--password PASSWORD | --password-stdin]
```

`--config` is required and must contain at least two targets. `--output` writes
the selected format to a file; without it, output goes to stdout.

## Selection

`--kind`, `--severity`, `--target`, and `--object` accept repeated or
comma-separated values. Values within one option use OR semantics. Different
options use AND semantics. Matching is case-insensitive.

`--query` performs a case-insensitive substring search across finding kind,
object type, object name, severity, message, and target names. It combines with
the dimension filters.

## Formats

- `text` (default): compact totals grouped by severity, finding kind, and
  object type, followed by one line per selected finding. Raw definitions are
  not printed in this mode.
- `json`: the existing report fields plus additive `analysis` metadata. The
  `findings` array contains only selected findings.
- `csv`: one row per selected finding with stable columns. Complex `left` and
  `right` values are JSON-encoded in their cells.

## Exit codes

- `0`: no findings, including when filters select none.
- `2`: at least one finding remains after filtering.
- `1`: configuration or credential input error.

Connection and collection failures are reported without including connection
strings.
