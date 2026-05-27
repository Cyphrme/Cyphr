# SPEC: Multihash Simplification

<!--
  SPEC document produced by /spec Create mode.
  Source: EML formalization (log.rs, storage.rs), Cyphr state tree (state.rs,
  principal.rs), state-tree.md spec.
  Authority: SPEC.md — this document constrains the multihash implementation
  to align with EML-proven patterns.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Cyphr multihash computation — the mechanism by which
Multihash Merkle Root (MHMR) variants are computed, threaded through state
trees, and persisted. Pre-dates the EML formalization and contains patterns
that the EML's formal proofs have shown to be unnecessarily complex.

**Cross-references:**
[`state-tree.md`](state-tree.md) (MHMR computation, sort order, promotion),
[`storage-engine.md`](storage-engine.md) (digest indexing, format_multihash),
EML [`log.rs`](https://github.com/Cyphrme/eml/blob/main/src/log.rs) (Hasher
trait, epoch tracking, algorithm lifecycle).

**Criticality Tier:** High — multihash is load-bearing for principal identity.

## Constraints

### Invariants

**[hasher-trait]**: All protocol hash operations MUST be abstracted behind a
`Hasher` trait (analogous to EML's `eml::Hasher`). The current triple-dispatch
match over `HashAlg::{Sha256, Sha384, Sha512}` in `hash_sorted_concat_bytes`,
`hash_concat_bytes`, and `hash_bytes` (state.rs:355–437) MUST be replaced.
Adding a new hash algorithm MUST require implementing a single trait, not
modifying multiple match arms.
`VERIFIED: unverified`

**[dataroot-multihash]**: `DataRoot` MUST use `MultihashDigest`, not
single-algorithm `Cad`. `compute_dr()` MUST take `algs: &[HashAlg]` and
produce per-algorithm variants, consistent with all other state nodes (KR, AR,
SR, PR, CR, TR). The current asymmetry where DR is silently coerced into
multihash computations in `compute_sr()` is a correctness risk.
`VERIFIED: unverified`

**[single-alg-set]**: `PrincipalCore` MUST NOT maintain both `hash_alg` and
`active_algs` as independent fields. There MUST be a single source of truth
for the active algorithm set. If a "primary" algorithm is needed, it MUST be
derived deterministically from the ordered set (e.g., `active_algs[0]` via
`BTreeSet` ordering), not stored separately.
`VERIFIED: unverified`

**[digest-length-validation]**: `MultihashDigest` construction MUST validate
that each variant's byte length matches its declared algorithm (SHA-256 → 32,
SHA-384 → 48, SHA-512 → 64). Invalid lengths MUST be rejected at construction
time (parse, don't validate).
`VERIFIED: unverified`

**[eml-for-commit-tree]**: The Commit Tree (CT) MUST use an EML `Log` instance
instead of hand-rolled per-algorithm MALT management. The current
`BTreeMap<HashAlg, malt::Log>` in `CommitTrees` with manual replay logic in
`finalize_commit()` (principal.rs:1109–1146) MUST be replaced. The EML already
provides: algorithm epoch tracking, null constants for pre-activation, frontier
stacks, O(log N) append, consistency/inclusion proofs, and formal correctness
guarantees. This was always the intended migration path.
`VERIFIED: unverified`

**[state-newtype-trait]**: The state newtypes (`KeyRoot`, `AuthRoot`,
`StateRoot`, `PrincipalRoot`, `PrincipalGenesis`, `CommitID`) SHOULD be unified
via a shared `StateDigest` trait (or derive macro) providing `as_multihash()`
and `get()` accessors. The current ~100 lines of identical boilerplate across
six types SHOULD be eliminated.
`VERIFIED: unverified`

**[algorithm-epoch-tracking]**: Algorithm lifecycle (activation, deactivation,
resumption) SHOULD be tracked as persistent epoch metadata, analogous to the
EML's `AlgState` epoch vectors. This enables cold-start algorithm history
recovery from storage without full commit chain replay.
`VERIFIED: unverified`

## Rationale

### EML Formal Insights Applied to Cyphr

The EML formalization proved that multi-algorithm append-only structures can
be handled with a single shared topology where algorithms are *views*, not
parallel structures. The key insights:

1. **One structure, N views** — EML appends data once; each algorithm sees the
   same tree with null constants filling positions outside its active window.
   Cyphr currently builds N parallel computations instead.

2. **Hasher as the abstraction boundary** — EML's `Hasher` trait
   (`leaf()`, `node()`, `empty()`, `null()`, `hash()`) eliminates all
   algorithm-specific branching from computation logic. New algorithms are a
   single `impl Hasher`.

3. **Epoch tracking is essential** — the EML stores algorithm epochs
   persistently, enabling reconstruction without replay. Cyphr currently
   re-derives the algorithm set from the key tree at every commit, losing
   history.

4. **The MALT IS the EML** — `finalize_commit()`'s per-algorithm MALT
   management (create, replay, append) is a manual reimplementation of what
   EML does generically with proofs and formal guarantees.

### Scope

These constraints apply to the protocol-core `cyphr` crate (`rs/cyphr/`).
Storage-layer implications are captured in `storage-engine.md`
([digest-index-completeness], [async-storage], [streaming-write]).

## Verification

| Constraint                  | Method      | Result | Detail                                         |
| :-------------------------- | :---------- | :----- | :--------------------------------------------- |
| [hasher-trait]              | agent-check | pass   | `CyphrHasher` trait implemented in `rs/cyphr/src/hasher.rs` and integrated in `state.rs` |
| [dataroot-multihash]        | agent-check | pass   | `DataRoot` uses `MultihashDigest`; `compute_dr` takes algorithm set |
| [single-alg-set]            | agent-check | pass   | `hash_alg` field removed; primary algorithm derived dynamically |
| [digest-length-validation]  | agent-check | pass   | Exact digest lengths matching algorithm requirements enforced on constructor |
| [eml-for-commit-tree]       | agent-check | pass   | EML `Log` used to manage Commit Tree (CT) and epoch metadata |
| [state-newtype-trait]       | agent-check | pass   | Unified six state types with `StateDigest` trait in `state.rs` |
| [algorithm-epoch-tracking]  | agent-check | pass   | Epoch transitions tracked and reconstructed via EML storage |


## Implications

### For Implementation

- **[hasher-trait]**: Define `trait CyphrHasher` with `hash(&self, data: &[u8])
  -> Vec<u8>` and `output_size() -> usize`. Replace match arms with generic
  functions. Mirrors EML's `Hasher` trait.

- **[eml-for-commit-tree]**: Replace `CommitTrees` with a single `eml::Log`
  instance using `eml-storage-fjall` for persistence. The shared Fjall
  keyspace (per storage-engine.md § Shared Keyspace Cooperation) enables
  co-location. Algorithm add/remove/resume is handled by EML's
  `add_algorithm()` / `remove_algorithm()` / `resume_algorithm()`.

- **[dataroot-multihash]**: Change `DataRoot(pub Cad)` to
  `DataRoot(pub MultihashDigest)`. Update `compute_dr()` signature to
  `compute_dr(actions, algs: &[HashAlg]) -> DataRoot`.

- **[single-alg-set]**: Remove `hash_alg: HashAlg` from `PrincipalCore`.
  Add `fn primary_alg(&self) -> HashAlg` that returns `self.active_algs[0]`.

### For Testing

- **Hasher trait**: Property test that all `CyphrHasher` impls produce
  correct output sizes and are deterministic.
- **EML migration**: Golden test that EML-derived CR matches MALT-derived CR
  for existing test fixtures.
- **DataRoot**: Multi-algorithm test with ES256 + ES384 keys verifying DR
  produces variants for both.

### Migration Order

1. `[hasher-trait]` — prerequisite for everything; pure refactor, no semantic
   change
2. `[dataroot-multihash]` + `[digest-length-validation]` — type-level fixes
3. `[single-alg-set]` + `[state-newtype-trait]` — cleanup
4. `[eml-for-commit-tree]` + `[algorithm-epoch-tracking]` — the big migration
