# SQL parser evaluation

The P2 comparison does not replace normalization with a parser dependency.
T-SQL includes SQL Server-specific constructs, quoted identifiers, module
definitions, and compatibility-level differences; selecting a parser without
proven dialect coverage would create false positives and make the fallback
less safe.

The current decision is to keep the literal-safe textual normalizer, expose
`NormalizationOptions`, and retain a fallback boundary where a future parser
can canonicalize only constructs it proves it understands. The property and
literal-preservation tests are the acceptance gate for any future parser.
