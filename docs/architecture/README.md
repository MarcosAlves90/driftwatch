# Architecture overview

Driftwatch is a single-process Python CLI. It loads configuration, collects
schema metadata from each SQL Server target, compares inventories into
`Finding` values, then applies policy, filters, and search before rendering
output. Snapshots enter the same inventory boundary as live collections.

Each inventory has an overall `SUCCESS`, `PARTIAL`, or `FAILED` status and
section statuses for objects, columns, indexes, constraints, and database
metadata. Specialized
differs produce property-level findings with expected/actual values and impact
severity. Failed sections are excluded from schema comparison.

The presentation layer is format-neutral: text, JSON, CSV, and SARIF all consume the
same selected findings. Aggregate analysis is computed from that same selection,
so counts and details cannot describe different result sets.

There is no persistent database, web service, queue, or implicit migration
writer. The tool operates in memory for one invocation; versioned schema
snapshots provide the durable Git contract, and controlled before/after
snapshots provide migration effects and file-based lifecycle history.

```mermaid
flowchart LR
  Config["Config + credentials"] --> Collect["SQL Server collectors"]
  Collect --> Compare["Baseline, pairwise, or snapshot comparison"]
  Snapshot["Validated snapshot"] --> Compare
  Compare --> Select["Filter + search"]
  Policy["Versioned policy"] --> Select
  Select --> Analyze["Aggregate analysis"]
  Select --> Analyze["Impact + lifecycle + policy"]
  Analyze --> Render["Text / JSON / CSV / HTML / SARIF / GitHub"]
  Analyze --> Render
```
