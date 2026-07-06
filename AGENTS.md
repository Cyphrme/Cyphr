# Cyphr — Agent Orientation

Cyphr is a self-certifying identity and state protocol: every principal is
an append-only, signed commit chain whose state roots are Merkle-derived,
verifiable by anyone from published roots. This repository holds the
protocol specification, a language-agnostic test corpus, and the
implementations.

## Goal

Deliver a production-ready **Rust** implementation of the Cyphr Protocol:
the `rs/cyphr` protocol core, the durable storage stack (content-addressed
blob store + rebuildable index + eml commit log), and the `cyphr-server`
HTTP authority — hardened to the point that the server can be implemented
cleanly, with all protocol behavior pinned by the shared golden corpus.

**Status: WIP.** A server-readiness campaign is being scoped; the durable
record lives in `.ledger/log/` and forge issues #16/#23. The server crate
is a working scaffold, not the finished authority.

## Structure

| Path | Role |
| :--- | :--- |
| `SPEC.md` | Protocol specification (see Invariants: ownership) |
| `rs/` | Rust workspace — **all active work happens here** (`rs/AGENTS.md`) |
| `go/` | Go implementation — deprioritized, reference only (`go/AGENTS.md`) |
| `login/` | Isolated Go module; design reference for SPEC §17 auth, unwired |
| `docs/` | Specs, ADRs, models — read `docs/AGENTS.md` before trusting any of it |
| `tests/` | Language-agnostic corpus: `intents/*.toml` → `golden/**/*.json` (see `tests/README.md`) |
| `.ledger/` | Predicate flight recorder (sub-repo); campaign history lives here |

Operational entrypoint: `cd rs && cargo test --workspace` (green, ~3 min).

## Requirements

- **R1 — Server readiness.** Portable third-party proof verification,
  sound crash recovery, typed error surface, per-principal write
  serialization must exist before the real server is built.
  Grounding: forge issues #19/#23/#27/#31/#32.
  Signpost: satisfied when the server-readiness campaign CLOSEs with those
  findings mitigated.
- **R2 — Corpus-pinned behavior.** Every protocol behavior change
  regenerates and commits the golden corpus (`rs/fixture-gen` from
  `tests/intents/`); Rust is the canonical generator.
  Grounding: `tests/README.md`, `rs/cyphr/tests/golden_fixtures.rs`.
  Signpost: a protocol-touching diff without a corpus regen is a defect.
- **R3 — KV index.** The query index is to be replaced with arbitrary KV
  index tables over the durable store plus a meta-table tracking them,
  behind the existing `Indexer` trait seam.
  Grounding: nrd decision 2026-07-06 (forge #18/#23 comments).
  Signpost: defeated only if nrd reverses it; in-repo docs recording the
  older KV→SQLite decision are superseded, not authority.

## Invariants

- **I1 — Source of truth.** The BLAKE3 content-addressed blob store is the
  sole source of truth; the eml Merkle log and the index are rebuildable
  caches. Grounding: forge issue #26. Signpost: any design that makes log
  or index authoritative violates this.
- **I2 — Single-writer per principal.** Within one principal, history is a
  strongly-ordered, single-writer signed chain; a fork is detected, never
  merged. Across principals there are no relationships; multi-master is an
  anti-goal. Grounding: #26/#27. Signpost: any reconciliation/merge logic
  for concurrent same-principal writes violates this.
- **I3 — SPEC.md ownership.** `SPEC.md` is Zamicol's; changes go only via
  PR to the `zami` branch (currently PR #5, open/draft — the in-tree
  working copy may be checked out to that branch's version for reference;
  do not commit or merge it). Other `docs/specs/*.md` are not his.
  Grounding: standing rule; campaign ledger. Signpost: nrd says otherwise.
- **I4 — Core stays consumer-agnostic.** `rs/cyphr` gains protocol-shaped
  API (e.g. portable proofs), never server-specific hacks.
  Grounding: original server-plan constraint, reaffirmed by survey.
  Signpost: a `cyphr` change motivated only by one consumer's convenience.
- **I5 — No unjustified panics.** Production code must not panic at
  runtime without an explicit, stated justification. Grounding: forge #37.
  Signpost: any new `.unwrap()`/`.expect()` in non-test code without a
  justification comment.
- **I6 — Plans are legacy.** `docs/plans/*.md` are never plan-of-record;
  the campaign workflow (forge issues + `.ledger/`) supersedes them.
  Grounding: nrd 2026-07-06. Signpost: n/a — do not update them as plans.

## Unknowns

- **U1 — Intra-commit ordering.** The wire format has no intra-commit
  ordering primitive; recovery must currently guess (permutation search in
  reindex). Resolution: nrd/Zami decision — wire-format field vs
  arrow-chain-derived order. Grounding: `rs/cyphr-storage/src/engine/mod.rs`
  (`permutations` in `reindex`).
- **U2 — Live-principal concurrency.** `CloneableLog` is sound only under
  fresh-`Principal`-per-call; the server's shape (long-lived principals,
  concurrent requests) needs either external per-principal serialization
  or a genuinely async chain. Resolution: API-sufficiency design node.
  Grounding: `rs/cyphr/src/commit_root.rs` (`CloneableLog` design note).
- **U3 — Replay cost.** Every write replays full principal history from
  cold storage; caching strategy undecided. Resolution: same node as U2.
  Grounding: `load_principal` in `rs/cyphr-storage/src/engine/mod.rs`.
- **U4 — Auth placement.** SPEC §17 authentication (login, bearer tokens)
  is greenfield; presumed the campaign *after* server-readiness.
  Resolution: nrd scoping call. Grounding: REVIEW Q3.
- **U5 — EMT→EML conversion.** One-way, permanent conversion of the PT's
  EMT to an EML is a standing design ask, unscoped. Resolution: nrd
  scoping call. Grounding: nrd note 2026-07-06.

## Spec Pointers

- Protocol: `SPEC.md` (§1–12 canonical; §13+ partly aspirational — see
  `docs/AGENTS.md`)
- Machine specs: `docs/specs/*.md`; ADR: `docs/adr/0001-*.md`
- Test corpus pipeline: `tests/README.md`
- Process law: predicate rules/ambient via `.ledger/` installation
  (hooks in `.git/hooks` → `nrdxp/predicate`)
