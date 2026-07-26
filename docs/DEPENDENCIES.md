# Dependency and impact analysis

The dependency graph is an in-memory, conservative structure keyed by
`ObjectId`. Foreign-key relationships collected from SQL Server become edges;
module references may be added only when a caller has reliable catalog data.
Unknown relationships are omitted rather than guessed.

`DependencyGraph.dependents()` and `.dependencies()` support bounded traversal.
`impact_for_finding()` reports direct dependents, indirect dependents, total
blast radius, and affected object IDs without changing the finding severity.
