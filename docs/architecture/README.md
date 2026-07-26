# Architecture overview

Driftwatch is a single-process Python CLI. It loads configuration, collects
schema metadata from each SQL Server target, compares inventories into
`Finding` values, then applies filters and search before rendering output.

Each inventory has an overall `SUCCESS`, `PARTIAL`, or `FAILED` status and
section statuses for objects, columns, indexes, and constraints. Specialized
differs produce property-level findings with expected/actual values and impact
severity. Failed sections are excluded from schema comparison.

The presentation layer is format-neutral: text, JSON, and CSV all consume the
same selected findings. Aggregate analysis is computed from that same selection,
so counts and details cannot describe different result sets.

There is no persistent database, web service, queue, or migration writer. The
tool operates in memory for one invocation; historical and cross-run analysis
are intentionally outside the current scope.

```mermaid
flowchart LR
  Config["Config + credentials"] --> Collect["SQL Server collectors"]
  Collect --> Compare["Baseline or pairwise comparison"]
  Compare --> Select["Filter + search"]
  Select --> Analyze["Aggregate analysis"]
  Select --> Render["Text / JSON / CSV"]
  Analyze --> Render
```
