# Cyphr — Agent Orientation

Cyphr is a self-certifying identity and state protocol: every principal is
an append-only, signed commit chain whose state roots are Merkle-derived,
verifiable by anyone from published roots. This repository holds the
protocol specification, a language-agnostic test corpus, and the
implementations.

## Goal

Deliver a polished, complete **Rust** MVP of the Cyphr Protocol, gossip
included, covering SPEC feature Levels 1–4 (static key, key replacement,
multi-key commits, arbitrary data; Level 5 rules, weights, timelocks and
multi-sig are out and the limit is documented). The MVP is:

- **Sovereign.** No server, witness or peer is an authority. Each party
  makes signed claims about itself only; every verifier chooses whose
  claims it accepts, and every verdict names those choices. Gossip moves
  claims between parties, and a conflict is evidence that no central party
  resolves.
- **Complete.** Authentication and sign-on (SPEC §17) are in scope, as is
  client-to-client gossip. A single peer is allowed, with a warning.
- **Proven by realistic scenarios.** "Done" means multi-peer end-to-end
  scenarios (forks, partitions, rotation, sign-on to a separate relying
  party) plus property tests, not one demo.
- **Extensible.** Foundations are chosen so later levels and backends
  attach without reworking what exists.

The Rust workspace holds the protocol core (`rs/cyphr`), the durable
storage stack (content-addressed blob store, rebuildable index, eml commit
log), the `cyphr-server` HTTP server and the `cyphr-cli` client; a
hardware-backed keystore crate is planned (see `rs/AGENTS.md`).

**Status: WIP.** Earlier campaigns delivered server readiness (portable
proofs, crash recovery, typed errors, per-principal write serialization)
and server receipts (response envelope, signed receipts, equivocation
evidence). The current campaign builds the MVP on an integration branch
(`campaign/mvp-close`) that merges onward to `server`, then `master`,
only at its end. The Roadmap section
of PR #23 is the candidate list for what comes after.

## Structure

| Path       | Role                                                                                    |
| :--------- | :-------------------------------------------------------------------------------------- |
| `SPEC.md`  | Stale reference copy of the protocol spec; the normative text is `zami` at `be0663f`    |
| `rs/`      | Rust workspace — **all active work happens here** (`rs/AGENTS.md`)                      |
| `go/`      | Go implementation — deprioritized, reference only (`go/AGENTS.md`)                      |
| `docs/`    | Specs, ADRs, models — read `docs/AGENTS.md` before trusting any of it                   |
| `tests/`   | Language-agnostic corpus: `intents/*.toml` → `golden/**/*.json` (see `tests/README.md`) |
| `scripts/` | `docket-run` (claim evaluator indirection) and `docket-fixtures/` (docket gate tests)   |

## Working in this repo

- **Toolchain:** nix + direnv (`.envrc` → `use nix`) provides formatters
  and tooling; Rust pinned by `rs/rust-toolchain.toml`.
- **Test scope:** a worker runs only the tests pertinent to its change
  (`cargo test -p <crate>`, or the one test target). The full suite,
  `cd rs && cargo test --workspace`, runs once, at the merge gate.
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
- **CI** (`.github/workflows/ci.yml`, on push and pull request to
  `main`/`master`, and manual dispatch):
  - `rust`: `cargo build`, `cargo test`, `cargo clippy --all-targets -- -D warnings`
    on ubuntu and macos;
  - `fuzz`: 60-second smoke runs of `fuzz_coz_parser` and `fuzz_reindex`
    (nightly);
  - `fmt`: `treefmt --fail-on-change`;
  - `fixture-freshness`: regenerates `tests/golden` from `tests/intents`
    and fails on any diff (the enforcement of R2);
  - `rust-audit` (rustsec) and `rust-msrv` (`cargo check --all-features`).

  Go is not built in CI until it is revived. Releases: `release-rs.yml`
  on tags.

- **Docket is a local merge gate, not a CI step.** `docket` binds a claim
  in prose to the check that closes it. The maintainer runs
  `docket check --corpus .` at each merge and a non-zero exit blocks the
  merge; CI does not run it, because the tool is still evolving. Setup,
  the pinned invocation and the registered genres are in `docs/AGENTS.md`
  and `docket.ncl`. Docs-first stays light: where a behavior is new, write
  its claims under `docs/architecture/` before implementing if that removes
  ambiguity, but never block progress on documentation.
- **Commits:** conventional commits, enforced by the installed hooks
  (message validation + doc-link audit); commit at logical boundaries.

## Spec authority and the contradiction procedure

The normative protocol specification is `SPEC.md` on the spec author's
`zami` branch, pinned at commit `be0663f`
(`git show be0663f:SPEC.md`). The `SPEC.md` in this directory is a stale
reference copy: it predates `be0663f` and its section numbers differ, so
never cite it or reason from it. Cite SPEC by its `be0663f` section and
link to
`https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md`.
The machine specs (`docs/specs/*.md`) and the reference implementation are
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

- **R1 — MVP scope.** A polished, complete Rust MVP for SPEC Levels 1–4,
  gossip and sign-on included, proven by realistic multi-peer scenarios
  (see Goal). Grounding: the decided scope: a refined, polished product with every
  essential piece, gossip included, limited to Levels 1–4. Signpost: a
  deliverable that is a demo rather than a scenario suite, or that adds
  Level 5 scope, departs from this.
- **R2 — Corpus-pinned behavior.** Every protocol behavior change
  regenerates and commits the golden corpus (`rs/fixture-gen` from
  `tests/intents/`); Rust is the canonical generator.
  Grounding: `tests/README.md`, `rs/cyphr/tests/golden_fixtures.rs`; the
  CI job `fixture-freshness`.
  Signpost: a protocol-touching diff without a corpus regen is a defect.
- **R3 — KV index.** The query index is to be replaced with arbitrary KV
  index tables over the durable store plus a meta-table tracking them,
  behind the existing `Indexer` trait seam. Status: built in
  `rs/cyphr-index-fjall` (one fjall keyspace per logical index plus a
  `meta` keyspace recording which index keyspaces exist and the schema
  version); the SQLite backend is retired.
  Grounding: human operator decision 2026-07-06 (comments on forge issue #18 and PR #23).
  Signpost: defeated only if the human operator reverses it; in-repo docs recording the
  older KV→SQLite decision are superseded, not authority.

### Standards every change meets

- **R4 — Sovereign authority.** No server, witness or peer is an
  authority. A party's claims bind only itself; a verifier decides whose
  claims to accept and its verdict names that choice. The principal
  resolves its own forks (SPEC §15.8); until it does, its state is
  Error, and no peer or client drops a branch or picks one. Grounding:
  the decided model that each party claims only about itself and every
  verifier chooses; SPEC §15.2, §15.8. Signpost: any
  component that decides trust on a verifier's behalf, or any fork
  "resolution" by a third party.
- **R5 — A generic mechanism with strong defaults.** Roots, key backends
  and policy are the user's choice behind one interface each; third
  parties can add backends, and behavior and custody labels are
  consistent across them. Defaults are strong (hardware where available).
  Grounding: forge issue #201. Signpost: a policy baked into a mechanism,
  or a backend that needs a special case in a consumer.
- **R6 — Nothing that can change is hard-coded.** Algorithms, KDFs and
  hashes are recorded alongside what they protect (the way Coz names
  `alg`) and are swappable without a format change; an unknown version or
  kind is refused, never guessed. Argon2 is no exception. Grounding: forge
  issue #201. Signpost: a literal algorithm or parameter in code with no
  record in the data it protects.
- **R7 — Every platform, anyone.** The design is platform-generic,
  WebAssembly included: a passphrase root works everywhere and passkeys
  are an option. Hardware-only paths always have a flagged fallback.
  Grounding: forge issue #201. Signpost: a capability with no path on some supported platform.
- **R8 — Best practice everywhere; formal reasoning on the security
  path.** Code is idiomatic, and every design choice cites the practice it
  follows from a primary source, or states its departure and the concrete
  attacker that justifies it. Security-critical nodes (transport, keystore
  and keychain, sign-on, signer seam, trust boundaries) carry this in
  their acceptance criteria. Where the formal model states precisely what
  a security practice states informally, the formal statement becomes the
  acceptance property. Grounding: the decided rule that best practice is
  never neglected anywhere in the security-critical chain.
  Signpost: a security mechanism with no cited practice, or a departure
  with no named attacker.
- **R9 — Honest claims.** Custody is never reported as verified.
  Keys held without hardware carry a self-claim of software-held, which
  every verdict reports; that is an admission, not a defect to hide. A
  hardware claim counts as backed only where an attestation supports it,
  and each key slot records whether it is securely shreddable so the
  claim stays falsifiable. Grounding: forge issue #201. Signpost: any
  verdict or label stronger than its evidence.
- **R10 — Append-only keychain and principal chain.** Keys are
  destroyed; entries are never deleted. Removals and retirements are new
  entries. Retiring a device is the same as losing one: a removal entry
  plus rotation. Secure shred is offered where a backend supports it and
  is the default there, but never replaces rotation. Short-lived
  credentials bound exposure and do not replace revocation. This scopes
  the keychain and each principal's chain; SPEC §16.2 separately lets
  third-party services discard user data they hold. Grounding: forge issue
  #201; I2. Signpost: a keychain or principal-chain design that deletes
  or rewrites an entry.
- **R11 — The minimal formulation that extends cleanly.** Choose the
  smallest foundation that later levels and backends can extend. Cut what
  has no consumer. Signpost: a mechanism added for one hypothetical
  future use, or a foundation that a later level would have to reshape.
  Grounding: the decided requirement to choose a foundation that can be
  extended cleanly.
- **R12 — Self-contained public text.** Committed text is readable
  without the conversation that produced it. It states the design and its
  open questions, not the history of discussion or dropped alternatives,
  and it may cite public forge issues and published primary sources.
  Grounding: the decided writing rule for public text. Signpost: a
  committed file that is unreadable without the conversation that
  produced it.
- **R13 — Testing standard.** Every test backs a stated claim, and most
  claims are end-to-end scenarios (multi-peer, forks, partitions,
  rotation, sign-on). Exactly three kinds earn a place without a scenario:
  property tests for invariants, golden vectors for byte-exact formats,
  and fuzzing for parsers of untrusted input. A unit test is allowed only
  where a scenario cannot reach the case cheaply, and the test states that
  reason. Every test is shown red before the implementation exists. At
  merge, a test that backs no claim is cut. Grounding: the decided testing
  standard (unit-testing everything wastes time and tokens;
  meaningful scenarios from end to end are what the protocol needs).
  Signpost: a test whose failing state you cannot describe, or a unit test
  with no stated reason.
- **R14 — Keychain direction.** Keys live in hardware wherever it is
  available (Secure Enclave, TPM 2.0, PKCS#11 tokens) by default, and the
  keychain holds any Coz algorithm a backend can hold, each backend
  reporting what it supports. The fallback for hosts without hardware is
  flagged as software-held (R9). A key that cannot be exported signs
  through a trait, so the signer seam in the Coz Rust library is required;
  that change is upstream in Cyphrme/coz-rust. The keychain is a private
  Cyphr principal stored as one encrypted file, each entry inside it an
  encrypted Coz message; roots of trust are plural (a hardware root per
  device behind a user gate, an offline recovery code) and the last root
  cannot be removed. The root model must be able to express a k-of-n
  threshold root, which the MVP does not build (SLIP-0039 is the practice
  to follow when it is). Grounding: forge issue Cyphrme/Cyphr#201 (design
  and requirements); the Coz encryption proposal Cyphrme/Coz#41 (entry
  format). Signpost: a keystore design that makes private-key bytes
  reachable to Cyphr code, or hard-codes one root type.

## Invariants

- **I1 — Source of truth.** The BLAKE3 content-addressed blob store,
  including each principal's EML commit-tree keyspaces, is the record —
  the sole source of truth. The EML commit tree is record structure with
  a tested reconstruction property (disaster recovery from blob content,
  not disposability): its bytes can be rebuilt if lost, but losing them
  is a recovery event, not a routine operation, unlike the index. The
  index alone is a rebuildable cache: the sole derived-class member,
  safely and routinely disposable. Grounding: ADR-0002 (`SPEC.md:114`,
  `:333-339`, `:587-588`), superseding forge issue #26's framing.
  Signpost: any design that makes the index authoritative, or that
  treats deleting the EML keyspaces as a routine operation, violates
  this.
- **I2 — Single-writer per principal.** Within one principal, history is a
  strongly-ordered, single-writer signed chain; a fork is detected, never
  merged. Across principals there are no relationships; multi-master is an
  anti-goal. Grounding: #26/#27. Signpost: any reconciliation/merge logic
  for concurrent same-principal writes violates this.
- **I3 — SPEC.md ownership.** `SPEC.md` is Zamicol's; changes go only via
  PR to the `zami` branch (currently PR #5, open/draft). The normative
  text is that branch pinned at `be0663f`; the in-tree copy is a stale
  reference copy — do not edit, commit or merge it, and do not cite it.
  Other `docs/specs/*.md` are not his.
  Grounding: standing rule. Signpost: the human operator says otherwise.
- **I4 — Core stays consumer-agnostic.** `rs/cyphr` gains protocol-shaped
  API (e.g. portable proofs), never server-specific hacks.
  Grounding: original server-plan constraint, reaffirmed by survey.
  Signpost: a `cyphr` change motivated only by one consumer's convenience.
- **I5 — No unjustified panics.** Production code must not panic at
  runtime without an explicit, stated justification. Grounding: forge #37.
  Signpost: any new `.unwrap()`/`.expect()` in non-test code without a
  justification comment.
- **I6 — No plan documents.** Plans are never kept in the tree; the
  campaign workflow (forge issues and git history) is the plan of record.
  Grounding: human operator directive 2026-07-06. Signpost: a plan
  document committed under `docs/`.
- **I7 — No tags in hash inputs.** Hash inputs carry no domain
  separation, prefixes or kind tags, and agents do not propose adding
  them. This is a settled maintainer decision, not an open design
  question. It concerns what is hashed, not how a digest is labeled:
  SPEC's Digest Labeling recommends algorithm-prefixed labels such as
  `SHA256:<b64ut>` on identifiers, and that stays. Grounding: the
  maintainer decision. Signpost: a change or proposal that adds a tag,
  prefix or separator to a hash input.

## Unknowns

Each open unknown stays open until its signpost fires; none may be
resolved unilaterally.

- **U1 — RESOLVED: order retention is implementation work.** The wire
  format already carries intra-commit order (`txs` array); the storage
  engine discards it at ingest and brute-forces it back during reindex —
  that is a storage bug, not a spec gap (the spec author's answer, closed
  PR #39; tenets in `docs/AGENTS.md`). Fix: retain order at ingest,
  verify against `arrow` on replay, error on absent order, delete the
  permutation search (`rs/cyphr-storage/src/engine/mod.rs`). Sequential
  visibility within a commit is ratified (`docs/AGENTS.md`
  two-authorization-contexts tenet), and per-mutation `pre` in signed pays
  is a rejected old draft slated for removal (`rs/AGENTS.md` traps).
- **U2 — Live-principal concurrency.** The rule is one writer per
  principal log. Inside one process the engine enforces it with a lock
  per principal (`principal_locks` in `rs/cyphr-storage/src/engine/mod.rs`):
  writers to the same principal queue, writers to different principals do
  not contend. A second process on the same data directory is refused by
  the store's exclusive lock; the cross-process per-principal lease
  (#27's full scope) does not exist. Reads of one principal also queue
  behind that principal's lock. Grounding: the same file. Signpost: a
  requirement for more than one server process on one data directory.
- **U3 — Replay cost: RESOLVED for the write path.** The engine keeps each
  principal's verified state between uses (`Kept` in the same file) and
  checks only what arrives, so a write no longer replays full history on
  every push; losing the kept state costs one replay (I1). Commit logs
  share one fixed keyspace triplet scoped by principal and generation, so
  a new principal no longer creates keyspaces. Not resolved: the kept
  state is in memory and holds 128 principals by default
  (`DEFAULT_KEPT_CAPACITY`), each as large as its history, so a principal
  evicted by a busier set replays once on its next use; and a principal
  that embeds another is kept as its replay built it, so a write follows
  the embedded principal to its current tip. Signpost: a latency or
  throughput requirement the scenario suite cannot meet.
- **U4 — EMT→EML conversion.** A one-way, permanent conversion of the
  PT's EMT to an EML is a supported-mode design goal, deferred. Grounding:
  forge issue #40. Signpost: the campaign after the MVP.
- **U5 — Transport.** Decided: Noise NN, with each side signing the
  Noise handshake hash with a key of its own principal
  (`rs/cyphr-client/src/transport.rs`, feature `noise`). No long-lived
  key exists outside Cyphr: the Noise keys are per-handshake ephemerals,
  which is why the static-key patterns (XX and the rest) were rejected.
  Open: nothing at the pattern level; the transport ships behind the
  `noise` feature and TLS remains the reverse proxy's job for the HTTP
  routes. Signpost: a transport requirement NN cannot meet.
- **U6 — Keychain design details.** The Coz-encryption entry envelope,
  P-256 ECDH key wrapping, padding, device-to-device sync (including two
  devices writing at once), and recovery. Whether the Coz encryption
  design is Zamicol's to decide is itself open. Grounding: forge
  issues Cyphrme/Cyphr#201 and Cyphrme/Coz#41. Signpost: the keystore
  nodes are blocked until the requirements in #201 are agreed.
- **U7 — Restore watermark.** A restored store holds a valid older
  prefix of the keychain chain, so the chain tip alone cannot reveal
  rollback; a witness recorded outside the store (another enrolled device,
  a sync peer holding the tip digest, or a hardware monotonic counter) is
  needed. Which is adopted is open. Signpost: the peer-restore node.
- **U8 — Passphrase root defaults.** Default KDF method and parameters for
  the passphrase root (recorded per R6). Which vendor attestation roots
  the client offers as choices is likewise open. Signpost: the keystore
  nodes.
- **U9 — Witness currency and identity binding.** Open questions from
  forge issues #139, #152 and #154. #139 asks whether a witness's signed
  tip attestation asserts anything about how current the state is, whether
  the claim should be scoped to the last verified sync time, whether
  gossip is a liveness holder or only propagation, what witness agreement
  means and how many witnesses suffice, and where these semantics belong
  in the specification. #152 records that a genuine report replayed by an
  on-path party still passes a witness's comparison and reports health;
  it is gated on #139. #154 asks the storage engine to reject a
  submission whose derived genesis differs from the identifier it is
  stored under, after enumerating every legitimate producer of a mismatch.
  Signpost: #139's answer determines #152's fix; #154's mismatch check
  must not land before that producer enumeration.
- **U11 — Recovery admission as trust root.** Whether each recovery
  admission is a fresh trust root: admitting a recovery agent imports
  that agent's own genesis into what the account's validity rests on, and
  whether every out-of-band exercise counts as a new admission or
  admitting the agent once settles it is decided neither by the
  specification nor by the sign-on document. It bears on how many parties
  the sign-on claim "the person presenting the key is the person the
  account is for" rests on. Grounding:
  `docs/architecture/path-a-sovereign-sign-on.md` (What is open).
  Signpost: the SPEC author's answer, or a design that must count the
  parties row 6 rests on.
- **U10 — Questions for the SPEC author.** Not to be resolved here (see
  the contradiction procedure): where the custody self-claim lives (a
  `key/create` field or a Level 4 data action); gossip's discovery claim
  form, view-statement meaning and naked-revoke marking, and whether a
  verifier that sees two branches each carrying a resolution stays in
  Error; the forge issue #200 text fixes and the "active by position"
  sentence; moving timestamp monotonicity into §4; the semantics of §7.6
  reuse. Signpost: the author's answer on the `zami` branch PR.

## Spec Pointers

- Protocol: `SPEC.md` at `be0663f` on the `zami` branch (§1–12
  canonical; §13+ partly aspirational — see `docs/AGENTS.md`); the
  in-tree `SPEC.md` is a stale reference copy
- Machine specs: `docs/specs/*.md`; ADR: `docs/adr/0001-*.md`
- Test corpus pipeline: `tests/README.md`
- Docs claim gate and doc traps: `docs/AGENTS.md`
