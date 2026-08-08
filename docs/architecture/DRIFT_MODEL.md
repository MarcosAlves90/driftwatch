# Drift model

The analysis pipeline is intentionally single-process and read-oriented:

```text
Config / snapshot
      |
      v
Canonical inventory
  | structure
  | provenance metadata
  ` dependency evidence
      |
      v
Comparison observations (Finding)
      |
      +--> target-aware impact
      +--> lifecycle / policy / filters
      |
      v
Issue aggregation
      |
      +--> inspect / explain / deps / history
      `--> conservative remediation plan
```

## Invariants

1. One logical SQL object has one canonical `ObjectId` regardless of raw SQL Server catalog type.
2. Provenance and dependency evidence do not create structural drift by themselves.
3. Pairwise evidence is never discarded when equivalent observations are grouped into an issue.
4. `issue_key` is conceptual identity; `occurrence_id` is exact observation identity.
5. Dependency completeness is explicit. Missing evidence is not evidence of absence.
6. Impact is computed against each target's own dependency graph.
7. Remediation planning is read-only; Driftwatch never implicitly executes DDL.
8. Destructive or under-specified remediation is reported for manual review rather than synthesized as safe SQL.

These invariants keep the new investigation layer additive to the existing comparison engine rather than turning Driftwatch into a stateful service or migration executor.
