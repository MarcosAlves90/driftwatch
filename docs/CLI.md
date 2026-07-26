# CLI reference

## Invocation

```text
driftwatch --config PATH [--output PATH] [--format text|json|csv]
           [--strategy baseline|pairwise] [--baseline TARGET]
           [--kind VALUE] [--severity VALUE] [--target VALUE]
           [--object VALUE] [--query TEXT]
           [--username USER] [--password PASSWORD | --password-stdin]
```

`--config` is required and must contain at least two targets. `--output` writes
the selected format to a file; without it, output goes to stdout.

The JSON configuration may also contain `strategy` and `baseline` keys. CLI
options override those values. Setting a baseline without a strategy selects
the baseline strategy.

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

Findings use impact severities `info`, `warning`, `breaking`, and `critical`.
Column, index, constraint, foreign-key, and object-definition differences are
classified by specialized comparison logic rather than one generic dictionary
comparison.

## Exit codes

- `0`: no findings, including when filters select none.
- `2`: at least one finding remains after filtering.
- `1`: configuration, credential, or collection error.

Connection and collection failures are reported without including connection
strings.
