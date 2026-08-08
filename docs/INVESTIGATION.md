# Investigation and remediation workflow

Driftwatch v2 keeps the database boundary read-only while making schema drift easier to investigate and resolve.

## Data model

Driftwatch normalizes SQL Server catalog types before creating object identities. For example, `USER_TABLE` becomes `TABLE`, and SQL stored procedure/function catalog types become `PROCEDURE` and `FUNCTION`. The original SQL Server type is retained as provenance metadata rather than participating in structural identity.

Collected state is separated into three concerns:

- **structure**: fields that participate in drift comparison;
- **metadata**: provenance such as SQL Server object ID, raw catalog type, creation date, and modification date;
- **dependencies**: directed catalog evidence with source and confidence.

This prevents diagnostic metadata from creating false structural drift.

## Findings and issues

A `Finding` is one comparison observation. An `Issue` groups equivalent observations across comparisons.

Two stable identifiers are exposed:

- `issue_key`: identifies the conceptual problem using kind, canonical object identity, and property;
- `occurrence_id`: identifies the exact observation, including comparison targets and expected/actual values.

This allows pairwise comparisons to retain all evidence without presenting the same logical problem as several unrelated alerts.

Lifecycle values are `NEW`, `EXISTING`, `CHANGED`, and `RESOLVED`. A changed expected/actual value remains the same issue but receives a different occurrence ID.

## Dates

Reports can include:

- `created_at`: catalog creation date reported by SQL Server;
- `modified_at`: catalog modification date reported by SQL Server;
- `observed_at`: when Driftwatch collected the inventory;
- `first_seen_at` and `last_seen_at`: report-history observations for an issue.

`modified_at` is catalog evidence, not proof of when a specific drift was introduced. Driftwatch does not infer an introduction time from it.

## Dependency coverage

Dependency edges are collected conservatively. Successful `sys.sql_expression_dependencies` collection is reported as `partial`, because dynamic SQL and other runtime relationships cannot be proven complete from that catalog alone. Collection failures are reported as `unavailable`, not as an empty dependency graph.

Impact is computed independently for every comparison target. This avoids using one environment's graph as evidence for another environment.

## Investigation commands

Generate an enhanced report first:

```bash
driftwatch check --config examples/config.json --format json --output report.json
```

Inspect one object:

```bash
driftwatch inspect dbo.Users --report report.json
```

Explain an issue or finding:

```bash
driftwatch explain <issue-key> --report report.json
```

Traverse dependencies:

```bash
driftwatch deps dbo.Users --report report.json --direction dependents --dependency-depth 3
```

View lifecycle history:

```bash
driftwatch history dbo.Users --report current.json --previous previous.json
```

Filters can also select property, lifecycle, issue ID, creation/modification date, and dependency impact.

## Remediation planning

`plan` creates a conservative remediation plan from report evidence:

```bash
driftwatch plan <issue-key> --report report.json --desired-target prod
```

Plans can contain preconditions, proposed SQL, risk, confidence, verification steps, and manual notes. Driftwatch does **not** execute the generated SQL.

Deterministic plans are available only when the report contains enough evidence. Ambiguous or destructive cases return `MANUAL_REVIEW_REQUIRED` instead of guessing. Database mutation remains the responsibility of the normal migration process, and `migration verify` can then verify the observed effect.

## Compatibility

- legacy report serialization remains available through the existing Python reporting API;
- enhanced CLI reports use report/schema version 2;
- snapshot version 2 stores provenance and dependency evidence;
- snapshot version 1 remains readable;
- the legacy finding fingerprint remains available for SARIF/report compatibility.

## Quality gate

CI requires at least 90% package coverage. The SQL Server integration job additionally verifies canonical table identity, catalog dates, dependency evidence, and severity against a real SQL Server instance.
