# go/ — Go Implementation (deprioritized, reference only)

**Alignment to parent:** dormant sibling implementation of the root goal's
protocol. Deprioritized — **not permanent**: it will be revived once an
eml implementation exists in Go. Until then, all protocol work is
Rust-only (`rs/`).

## What an agent must know

- **Do not "fix" parity here.** go/ predates the EML/EMT refactor
  (frozen ~2026-05-27) and has no counterpart to `principal_tree`,
  `semantic_tree`, or the storage engine. Divergence is expected and
  known, not a finding.
- **Red golden tests are expected.** `go test ./go/...` fails most
  digest-checked golden categories against the Rust-canonical corpus
  (commit-path PR/SR derivation predates the tree refactor). Do not
  treat this as a regression signal, and do not regenerate fixtures to
  match Go.
- The working tree may carry reference-only checkouts from other branches;
  do not merge or commit them.
- `login/` (repo root) is a separate, isolated Go module — a design
  reference for SPEC §17 auth flows, not wired to this package.

## Unknowns

- **U1 — Revival trigger.** Revive when a Go eml implementation exists;
  scope then is a re-port of the post-EMT core. Grounding: nrd 2026-07-06.
  Signpost: Go eml crate/module published or started.

## Spec Pointers

- Protocol: `/SPEC.md`; corpus: `tests/README.md` (Go consumes the same
  golden corpus when revived).
