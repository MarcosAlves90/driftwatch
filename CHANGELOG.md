# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

- Compact text output for interactive investigations.
- Finding filters for kind, severity, target, and object name.
- Case-insensitive finding search with `--query`.
- Aggregate analysis and `text`, `json`, and `csv` output formats.
- CLI, setup, and architecture documentation.
- Explicit collection status (`SUCCESS`, `PARTIAL`, `FAILED`) and per-section
  collection errors.
- Baseline and pairwise comparison strategies.
- Property-level semantic findings with impact-based severity.
- Complete foreign-key and index metadata collection.
- Literal-safe SQL normalization and expanded secret redaction.
- Versioned JSON policies with fail-on thresholds, ignore/allow rules, and
  explicit policy outcomes.
- Deterministic, digest-validated schema snapshots and snapshot-vs-database
  comparison.
- Bounded parallel collection with configurable workers and connection/query
  timeouts.
- Check, UNIQUE, computed, identity, collation, default, view, procedure, and
  function metadata coverage.
- SARIF output, GitHub summaries/annotations, stable report versions, and
  finding fingerprints.
