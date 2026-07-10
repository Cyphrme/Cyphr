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

**Status: WIP.** The server-readiness campaign CLOSEd 2026-07-10 (25 DAG
nodes, meta-PR #43 merged); the durable record lives in `.ledger/log/` and
forge issues #16/#23/#41. Deferred scope for what's next (per I6, live in
`.scratch/server-readiness/PLAN.md`'s "Deferred" list, not `docs/plans/`):
auth (SPEC §17), replay-cost caching (F25/U2/U3), the cross-process
per-principal lease (#27's full scope), EMT→EML conversion (#40), and go/
revival.

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

## Working in this repo

- **Toolchain:** nix + direnv (`.envrc` → `use nix`) provides formatters
  and tooling; Rust pinned by `rs/rust-toolchain.toml`.
- **Entrypoint gate:** `cd rs && cargo test --workspace` (green, ~3 min).
- **Formatting:** `treefmt` from the repo root (nix shell) — covers
  rs/go/toml/md/json/yaml/nix/sh. CI enforces
  `nix-shell --run "treefmt --fail-on-change"`. `treefmt` is authoritative
  for Rust because it runs under the project's pinned nightly toolchain
  (`rs/rust-toolchain.toml`), which is what makes `rs/.rustfmt.toml`'s
  nightly-only options (import grouping, comment wrapping, etc.) take
  effect. A stable `cargo fmt --check` agrees with it today (forge #28,
  resolved by a full workspace reformat) but only warns-and-skips those
  nightly-only rules rather than enforcing them on new code — see
  `rs/AGENTS.md`.
- **CI** (`.github/workflows/ci.yml`): rust build/test/clippy(-D warnings),
  go build/test/vet (see `go/AGENTS.md` for expected state), treefmt,
  rustsec audit, `cargo check --all-features`. Releases:
  `release-{rs,go}.yml` on tags.
- **Commits:** conventional commits, enforced by the installed hooks
  (message validation + doc-link audit); commit at logical boundaries.

## Spec authority and the contradiction procedure

`SPEC.md` (this directory) is the protocol's sole normative source. The
machine specs (`docs/specs/*.md`) and the reference implementation are
downstream: they can and do encode stale draft designs, and their
constraint tags and MUST language make them look more authoritative than
they are. When artifacts disagree, the default reading is "downstream is
stale" — never amend SPEC.md to match downstream. Full design tenets:
`docs/AGENTS.md` "Protocol model".

Procedure when a contradiction surfaces during any work:

1. **Clear contradiction** (SPEC.md plainly says X, a machine spec or the
   implementation says not-X): fix it in the downstream artifact if it is
   in scope for your task; otherwise schedule the fix, or at minimum open
   a forge issue so it is tracked for visibility. Silent tolerance is the
   only wrong move.
2. **Non-obvious or unresolvable contradiction** (ambiguous prose, two
   plausible intents, or a case where SPEC.md itself may be wrong):
   escalate to the human operator. Do not resolve unilaterally and do not
   propose SPEC.md changes to make it match downstream; SPEC.md questions
   go to its author.

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
  Grounding: human operator decision 2026-07-06 (forge #18/#23 comments).
  Signpost: defeated only if the human operator reverses it; in-repo docs recording the
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
  Grounding: standing rule; campaign ledger. Signpost: the human operator says otherwise.
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
  Grounding: human operator directive 2026-07-06. Signpost: n/a — do not update them as plans.

## Unknowns

- **U1 — RESOLVED (2026-07-06): order retention is implementation work.**
  The wire format already carries intra-commit order (`txs` array); the
  storage engine discards it at ingest and brute-forces it back during
  reindex — that is a storage bug, not a spec gap (spec author's ruling,
  closed PR #39; tenets in `docs/AGENTS.md`). Fix: retain order at ingest,
  verify against `arrow` on replay, error on absent order, delete the
  permutation search (`rs/cyphr-storage/src/engine/mod.rs`). Both
  follow-up questions were answered by the spec author on the same
  thread: sequential visibility within a commit is ratified (see
  `docs/AGENTS.md` two-authorization-contexts tenet), and per-mutation
  `pre` in signed pays is a rejected old draft slated for removal (see
  `rs/AGENTS.md` traps).
- **U2 — Live-principal concurrency.** `CloneableLog` is sound only under
  fresh-`Principal`-per-call; the server's shape (long-lived principals,
  concurrent requests) needs either external per-principal serialization
  or a genuinely async chain. Resolution: API-sufficiency design node.
  Grounding: `rs/cyphr/src/commit_root.rs` (`CloneableLog` design note).
- **U3 — Replay cost.** Every write replays full principal history from
  cold storage; caching strategy undecided. Resolution: same node as U2.
  Grounding: `load_principal` in `rs/cyphr-storage/src/engine/mod.rs`.
- **U4 — RESOLVED (2026-07-06): auth is the next campaign.** SPEC §17
  authentication (login, bearer tokens, server principal) is new code
  surface and begins when server implementation begins; the current
  campaign is foundation hardening only. Grounding: human operator
  ruling 2026-07-06.
- **U5 — RESOLVED (2026-07-06): EMT→EML conversion is tracked feature
  work.** One-way, permanent conversion of the PT's EMT to an EML is a
  supported-mode design goal, deferred to a future feature campaign.
  Grounding: forge issue #40.

## Spec Pointers

- Protocol: `SPEC.md` (§1–12 canonical; §13+ partly aspirational — see
  `docs/AGENTS.md`)
- Machine specs: `docs/specs/*.md`; ADR: `docs/adr/0001-*.md`
- Test corpus pipeline: `tests/README.md`
- Process law: predicate rules/ambient via `.ledger/` installation
  (hooks in `.git/hooks` → `nrdxp/predicate`)
