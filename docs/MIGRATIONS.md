# Migration effect verification

Migration verification is separate from normal environment comparison. A
caller owns the controlled execution environment and captures inventories
before and after the migration. The core then compares semantic metadata:

```python
from driftwatch.migration import verify_migration

report = verify_migration(before, after, expected=[expected_finding_fingerprint])
print(report.as_dict())
```

For already captured snapshots, the same contract is available from the CLI:

```bash
driftwatch migration verify --before before.json --after after.json \
  --expected-effect column_data_type_changed:dbo.users.email
```

Effects are classified as `expected` or `unexpected`; expected fingerprints
that do not occur are listed as missing. The API accepts an optional callback
for orchestration, but it does not choose a database, commit a transaction, or
execute SQL itself. This prevents an analysis command from mutating a target
implicitly.

Use the existing policy engine to decide which unexpected effects block CI.
