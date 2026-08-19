# list-valued-map fixture — the contract scripts/docket-run must satisfy

This fixture has no `docket.ncl`/`docs` of its own: `c-list-valued-map`
(the DAG's DK0 IBC) is a property of `scripts/docket-run` itself — the
successor to `writing/sovereign-signon-brief:scripts/docket-test`, whose
single-string `CLAIMS` table is exactly the defect
`.ledger/tech-debt/2026-08-04-one-claim-cannot-name-several-tests.yaml`
files: one claim id cannot register the several tests that jointly close
a conjunctive requirement. The fix, per that record's signpost, is a
`CLAIMS` value that expands to a **list**, run in sequence, all required
green — not a single joined shell command (`a && b`), which would satisfy
this fixture's black-box exit codes without the underlying data structure
actually being list-shaped; that structural half is a merge-gate review
obligation, not something an exit code can observe from outside.

`scripts/docket-fixtures/run` invokes `scripts/docket-run` directly (no
docket in the loop) with two claim ids it expects the implementation to
register in its `CLAIMS` table:

| claim id                    | CLAIMS value (list, ≥2 entries)         | expected `docket-run` exit |
| :--------------------------- | :--------------------------------------- | :-------------------------- |
| `list-valued-both-green`     | two commands, both exit 0                | `0`                          |
| `list-valued-one-failing`    | two commands, the second exits nonzero   | nonzero                     |

Today `scripts/docket-run` does not exist, so both invocations fail with
"command not found" — a nonzero exit either way, which happens to satisfy
`list-valued-one-failing`'s expectation by accident and `list-valued-both-green`'s
not at all. `scripts/docket-fixtures/run` asserts both independently, so
the suite reads red for the right reason: `list-valued-both-green` is the
sub-case that cannot pass until `scripts/docket-run` is actually built.
