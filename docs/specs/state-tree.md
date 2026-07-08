# SPEC: State Tree and Digest Computation

<!--
  SPEC document produced by /spec Apply mode.
  Source: SPEC.md §2.1–2.2, §9, §20
  Authority: SPEC.md (Zamicol and nrdxp) — this document does NOT replace SPEC.md.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.

  See: .agent/workflows/spec.md for the full protocol specification.
-->

## Domain

**Problem Domain:** Cyphr state tree computation — the hierarchical Merkle
structure that derives all protocol identifiers (PG, PR, SR, AR, KR, RR, DR, CR,
TR) and the multihash mechanism that makes those identifiers algorithm-agnostic.

**Target System:** `SPEC.md` §2.1–2.2 (Core Concepts and Terminology), §9
(State Calculation), §20 (Multihash Identifiers).

**Model Reference:**
[`principal-state-model.md`](../models/principal-state-model.md)
(produced prior to SPEC.md's recent structural changes — model re-audit pending)

**Criticality Tier:** High — this is a cryptographic identity protocol. Digest
computation errors compromise identity integrity.

## Constraints

### Type Declarations

Types are declared inline; the formal model predates recent SPEC.md changes and
will be re-audited separately.

```
TYPE Digest       = Opaque[N]                       -- N-byte cryptographic hash output
TYPE B64ut        = String                           -- RFC 4648 base64url, no padding, canonical
TYPE HashAlg      = SHA256 | SHA384 | SHA512         -- Coz-defined hash algorithms
TYPE KeyAlg       = ES256 | ES384 | ES512 | Ed25519  -- Coz-defined signing algorithms
TYPE Node         = Key | Nonce | Embedding | Rule | DataAction
TYPE MerkleTree   = Leaf Digest | Branch MerkleTree MerkleTree
TYPE MultihashId  = Map<HashAlg, Digest>             -- one variant per supported algorithm

-- State identifiers (all are Digest values computed via MR)
TYPE PG = Digest    -- Principal Genesis (immutable, first PR)
TYPE PR = Digest    -- Principal Root (top-level, evolves per commit)
TYPE SR = Digest    -- State Root (intermediate: MR(AR, DR?))
TYPE CR = Digest    -- Commit Root (EMLR of commit tree)
TYPE AR = Digest    -- Auth Root
TYPE KR = Digest    -- Key Root
TYPE RR = Digest    -- Rule Root (Level 5+)
TYPE DR = Digest    -- Data Root (Level 4+)
TYPE TR = Digest    -- Transaction Root (commit ID): MR(TMR, TCR)
TYPE TMR = Digest   -- Transaction Mutation Root
TYPE TCR = Digest   -- Transaction Commit Root

-- Trees (underlying data structures behind the digest identifiers)
TYPE PT            -- Principal Tree
TYPE AT            -- Auth Tree
TYPE KT            -- Key Tree
TYPE RT            -- Rule Tree (Level 5+)
TYPE DT            -- Data Tree (Level 4+)
```

### Invariants

**[digest-encoding]**: All digest binary values MUST be encoded as `b64ut`
(RFC 4648 base64 URL alphabet, canonical encoding, no padding). Non-canonical
encodings MUST be rejected.
`VERIFIED: agent-check`

**[identifier-is-cid]**: All identifiers (PG, PR, SR, AR, KR, RR, DR, CR, TR,
`tmb`, nonces) MUST be cryptographic digest Content Identifiers (CIDs) encoded
as b64ut, providing both addressing and integrity of the reference.
`VERIFIED: agent-check`

**[mr-sort-order]**: Cyphr's state digests split into two ordering classes.
**Fixed two-cell nodes** — Principal Root (PR, root of PT), Auth Root (AR,
root of AT), and State Root (SR, root of ST) — are each computed over a tree
whose shape never varies (always exactly two cells) and MUST use fixed
positional role order, never lexical sort: PT cell 0 = SR, cell 1 = CR; AT
cell 0 = KR, cell 1 = RR; ST cell 0 = AR, cell 1 = DR. **Variable-width
nodes** keep their own already-defined order instead: Key Root (KR, root of
KT) MUST sort lexically (opaque byte comparison); Data Root (DR) MUST sort by
`now` then `czd` (DR is a flat computed value, not yet backed by a real tree
instance — see SPEC.md §3.7.8). Commit tree (CT) is an Epoch Merkle Log (EML)
and uses append-only (array) order, not lexical sort. See `transactions.md`
[commit-finality-arrow].
`VERIFIED: agent-check, updated 2026-07-03 per two-class ordering correction`

**[pg-immutable]**: The Principal Genesis (PG) MUST NOT change after genesis
(Level 3+). PG is the first PR computed at genesis commit. No operation MAY
alter it. Levels 1–2 do not have a PG (see [level-1-2-identity]).
`VERIFIED: agent-check — updated 2026-03-09 per B-2`

**[alg-alignment]**: Inside a coz, all digest references in `pay` (including
`id`, `tmb`, nonces) MUST be aligned with the hash algorithm associated with
`alg`, unless the reference is explicitly labeled with a different algorithm
prefix.
`VERIFIED: agent-check`

**[digest-alg-from-coz]**: The hash algorithm for digest computation inside a
coz is determined by Coz's `alg` field and its associated hash algorithm (see
§20.1 Algorithm Mapping). The `alg` field in `pay` MUST determine the hash
algorithm for all unlabeled digest values in that coz.
`VERIFIED: agent-check`

**[nonce-bit-length]**: A nonce's bit length MUST match the declared algorithm's
output size (e.g., a nonce declared as SHA-256 MUST be exactly 256 bits).
`VERIFIED: agent-check`

**[nonce-indistinguishable]**: Unless explicitly revealed, nonces MUST be
indistinguishable from key thumbprints and other digest values. The protocol
MUST NOT expose whether a node is a nonce or another node type without explicit
reveal.
`VERIFIED: agent-check`

**[nonce-injection-bounds]**: Although transaction nonces construct intermediate
state parameters, a nonce MUST NOT arbitrarily introduce hashing algorithms that
are entirely unsupported by the `multi-hash-multi-root` key space. The legitimate
algorithm set is dictated explicitly by the active key capabilities (and their
acceptable cross-algorithm conversion paths), never arbitrarily extended by nonces.
`VERIFIED: agent-check`

**[mhmr-equivalence]**: All MHMR variants of a given node MUST be considered
equivalent references to the same logical state. The protocol MUST NOT enforce
a relative strength ordering between algorithm variants.
`VERIFIED: agent-check`

### Transitions

**[implicit-promotion]**: When a component of a state tree level contains
exactly **one node**, that node's digest value MUST be promoted to the parent
level without additional hashing. Promotion MUST be applied recursively.

- **PRE**: Exactly one child digest exists at the given tree level.
- **POST**: Parent digest == child digest (no hashing). If the parent also has
  exactly one child after promotion, recursion applies upward.
  `VERIFIED: agent-check`

**Corollary — [level-1-2-identity]**: For Levels 1 and 2 (single-key
principal): `tmb` == KR == AR == SR == PR via recursive implicit
promotion of the single key's thumbprint. Levels 1–2 do not have a commit
chain or a PG.
`VERIFIED: agent-check — updated 2026-04-07 per SPEC §5.1`

**[state-computation]**: When computing a new state digest after a mutation:

1. **Collect** all component digests at the current tree level (including
   embedding/nonce nodes if present). Absent components (e.g., no RR at
   Level < 5) MUST be excluded from collection.
2. **Sort** collected digests in lexical byte order (per [mr-sort-order]).
3. **Apply implicit promotion** if exactly one digest remains (per
   [implicit-promotion]).
4. **Compute Merkle root** via binary Merkle tree of the sorted digests.

- **PRE**: Component digests are valid, correctly computed from their subtrees.
- **POST**: New state digest is deterministic and reproducible from the same
  component digests.
  `VERIFIED: agent-check`

**[conversion]**: SUPERSEDED 2026-07-08 — see resolution note below. No
per-child re-hashing step exists. A component's H-variant is produced by
exactly one of two mechanisms:

1. **Exact match**: if a native H-variant of the component already exists,
   it is used directly, unconverted.
2. **Fold**: otherwise, ALL existing variants of the component (regardless of
   their native algorithm) have their raw digest bytes concatenated in a
   defined sort order, and the concatenation is hashed **once**, under H.
   Mismatched-algorithm children are never individually re-hashed into a
   pretend-native H digest before folding — their raw bytes simply
   participate as one of potentially several inputs to the single fold hash.

A **degenerate case** of the fold (not a separate conversion step): if the
component has exactly one existing variant total (of any algorithm), that
variant's raw bytes are returned as-is for any requested H — genesis
promotion, no hashing at all.

- **PRE**: A component's H-variant is requested; the component has one or
  more existing variants, possibly under algorithms other than H.
- **POST**: The H-variant is either the existing native H digest (exact
  match), the single existing variant's raw bytes (genesis promotion, len==1),
  or `H(concat(sorted raw variant bytes))` (general fold, len>1). No
  intermediate per-child re-hash under H ever occurs.
  `VERIFIED: rs/cyphr/src/multihash.rs — MultihashDigest::arrow_component_bytes`

> [!NOTE]
> **Resolution (2026-07-08, settled)**: This constraint previously required
> re-hashing a mismatched-algorithm child under the target algorithm before
> folding it into a parent digest. That is superseded: confirmed directly
> against the `eml` sibling repo's `polydigest::root::combined_root` /
> `nary_mr` (commit `2bde639`) and the spec author's ruling on forge issue
> #51 (see F31/F37 in `.ledger/state/findings.yaml`), the actual rule folds
> each component's raw, un-converted variant bytes together under whichever
> algorithm is requested — there is no standalone per-child conversion
> sub-step, and no requirement that the target algorithm match any existing
> variant. `rs/cyphr/src/multihash.rs`'s `arrow_component_bytes` (landed via
> N20/N21/N22, PRs #52/#56) implements this general fold, not merely the
> single-variant degenerate case.

**[mhmr-computation]**: For each supported hash algorithm H at a given commit,
implementations MUST compute an MHMR variant for every state node:

1. Collect child digests.
2. Sort in lexical byte order (opaque bytes).
3. If exactly one child: implicit promotion (no hashing, per
   [implicit-promotion]).
4. If multiple children: concatenate sorted child digest bytes in order, then
   compute H(concatenated bytes).

- **PRE**: Set of supported hash algorithms is determined by active keys in
  KR plus any nonce-injected algorithms.
- **POST**: One digest variant per supported H, all considered equivalent
  (per [mhmr-equivalence]).
  `VERIFIED: agent-check`

**[alg-set-evolution]**: When an algorithm is removed from support (e.g., a key
using that algorithm is deleted), implementations MUST stop computing that
algorithm's MHMR variant for new commits. When an algorithm is added,
implementations MUST begin computing its MHMR variant.

- **PRE**: Active key set changes (key/create or key/delete/revoke).
- **POST**: The set of MHMR variants computed for the next commit reflects
  exactly the algorithms supported by the post-mutation key set.
  `VERIFIED: agent-check`

### Forbidden States

**[no-empty-mr]**: A state digest MUST NOT be computed from zero child digests.
Every state level that participates in the tree MUST have at least one child
node. (Absent state components — e.g., no RR at Level < 5 — are excluded
entirely, not represented as empty.)
`VERIFIED: agent-check`

> [!NOTE]
> **Empty state representation (partially resolved)**: SPEC.md §9.1 and the
> SR formula (`MR(AR, DR?, ...)`) use `?` notation indicating absent components
> are excluded from the Merkle root computation (not included as zero-length or
> sentinel values). The boundary conditions for "first introduction" of DT/RT
> (Level 4, Level 5) still need confirmation from Zami.

**[no-circular-state]**: The state computation dependency graph MUST be acyclic.
KR → AR → SR (excludes CR), TR (from transaction cozies) → CR (EMLR of TRs),
PR = EMT-root(SR, CR) [cell 0 = SR, cell 1 = CR]. AR and SR MUST NOT depend on
TR or CR. The `arrow` field in the commit transaction covers `MR(pre, fwd,
TMR)` where `fwd` is SR, not PR, precisely because PR depends on CR which
depends on TR which includes the commit.
`VERIFIED: agent-check, rewritten 2026-07-02 per EMT/EML realignment, B-4, §4.2/§3.3`

**[no-non-canonical-b64ut]**: A b64ut string that uses padding characters (`=`),
non-URL-safe characters (`+`, `/`), or non-canonical encoding MUST be rejected.
Implementations MUST NOT accept non-canonical b64ut.
`VERIFIED: agent-check`

### Behavioral Properties

**[deterministic-state]**: Given the same set of component digests at any tree
level, the computed state digest MUST be identical regardless of the
implementation, platform, or language computing it. The combination of
[mr-sort-order], [state-computation], and [conversion] ensures cross-platform
determinism.

- **Type**: Safety
  `VERIFIED: agent-check`

**[promotion-recursive-termination]**: Recursive implicit promotion MUST
terminate. Since the state tree has finite depth (PR → {SR, CR}, SR → {AR, DR},
AR → {KR, RR}), promotion recurses at most through the tree height.

- **Type**: Safety
  `VERIFIED: agent-check`

**[mhmr-no-rehash-children]**: When computing an MHMR, inner child digests MUST
be fed directly into the parent hash function as raw bytes, without any
per-child pre-hashing step — including children whose native algorithm
differs from the target H. The one and only hash operation is the single
fold hash over the concatenated raw bytes of all children (per [conversion]);
there is no separate "convert this one mismatched child first" step.

- **Type**: Safety
  `VERIFIED: rs/cyphr/src/multihash.rs — MultihashDigest::arrow_component_bytes`

> [!NOTE]
> **Resolution (2026-07-08)**: Previously phrased as an exception carve-out
> for converted children (implying a distinct per-child re-hash sub-step).
> Superseded alongside [conversion] — see that constraint's resolution note.

## State Formulas

These formulas summarize the computation rules. Each line is normative and
constrained by the invariants and transitions above.

```
KR       = MR(tmb₀, tmb₁?, embedding?, nonce?, ...)
AR       = MR(KR, RR)                                    -- Auth Root: AT's root, cell 0 = KR, cell 1 = RR (positional); RR absent at Level < 5 (Singleton Promotion: AR = KR)
AR_alg   = H(KR_alg ∥ RR_alg)                            -- when RR is present (cells 0-1 both populated)
SR       = MR(AR, DR)                                    -- State Root: ST's root, cell 0 = AR, cell 1 = DR (positional); DR absent at Level < 4 (Singleton Promotion: SR = AR)
SR_alg   = H(AR_alg ∥ DR_alg)                            -- when DR is present (cells 0-1 both populated)
DR       = MR(czd₀, czd₁, ..., nonce?)                 -- Level 4+, sorted by `now` then `czd`; flat computed value, not yet a real tree instance
TR       = MR(TMR, TCR)                                 -- Transaction Root (commit ID)
CR       = EMLR(TR₀, TR₁, ...)                          -- Commit Root (EML root of commit tree)
PR       = EMT(SR, CR, ...)                             -- Principal Root: PT's EMT root; cell 0 = SR, cell 1 = CR (positional; cells ≥ 2 are PT embeddings); CR absent at Level 1-2
PR_alg   = H(SR_alg ∥ CR_alg)                            -- when only cells 0-1 are populated (no embeddings)
PG       = first PR at genesis commit (Level 3+ only, immutable)
```

**Commit Finality (resolved):** A commit is finalized by a `commit/create`
transaction containing `arrow = MR(pre, fwd, TMR)`. The `arrow` field covers
everything except the commit transaction itself. `fwd` is SR (not PR) because
PR depends on CR which depends on TR which includes the commit. See
`transactions.md` [commit-finality-arrow].

> [!NOTE]
> **DR Sort Order**: SPEC.md §9.6 states DR is "sorted by `now` and secondarily
> `czd`". This overrides the general [mr-sort-order] (lexical byte order) for
> DR specifically.

## Algorithm Mapping

Per SPEC.md §20.1 and Coz, each key algorithm implies a hash algorithm:

| Key Algorithm | Hash Algorithm | Digest Size | Source   |
| :------------ | :------------- | :---------- | :------- |
| ES256         | SHA-256        | 32 bytes    | Coz v1.0 |
| ES384         | SHA-384        | 48 bytes    | Coz v1.0 |
| ES512         | SHA-512        | 64 bytes    | Coz v1.0 |
| Ed25519       | SHA-512        | 64 bytes    | Coz v1.0 |

This mapping is governed by Coz and inherited by Cyphr. Changes to this
mapping are governed by Coz's algorithm governance (§20, bottom: "Algorithm
governance is delegated to Coz").

> [!NOTE]
> **PLACEHOLDER — Algorithm Rank**: SPEC.md §20.7 describes a default rank
> order for tie-breaking when multiple algorithms compete. The rank is described
> as "a tiebreaker only and not a security indicator" with future `alg/rank`
> transactions noted as out-of-scope. Formalization deferred until the rank
> semantics are finalized.

## Formal Specification

<!-- Tier 2+ formalization is structured for but not populated in this pass.
     The constraint set above is structured to support direct translation to
     Alloy (signatures/facts/predicates) or TLA+ (state predicates/actions).
     A subsequent pass may add formal notation here. -->

## Verification

| Constraint                        | Method      | Result | Detail                                                         |
| :-------------------------------- | :---------- | :----- | :------------------------------------------------------------- |
| [digest-encoding]                 | agent-check | pass   | b64ut requirement is explicit in SPEC.md §2.2.2                |
| [identifier-is-cid]               | agent-check | pass   | Explicit in SPEC.md §2.2.3                                     |
| [mr-sort-order]                   | agent-check | pass   | SPEC.md §9.1 step 2; commit exception per array-order decision; PT/AT/ST use positional order (SPEC.md §3.7 step 2, §3.7.1, §3.7.2, §3.7.5, §12.2.1); KT/DR keep their own order |
| [pg-immutable]                    | agent-check | pass   | SPEC.md §2.3.2, §9.2 (Level 3+ per §5.1)                       |
| [alg-alignment]                   | agent-check | pass   | Explicit in SPEC.md §2.2.2, §4.1.0                             |
| [digest-alg-from-coz]             | agent-check | pass   | Explicit in SPEC.md §2.2.2                                     |
| [nonce-bit-length]                | agent-check | pass   | Explicit in SPEC.md §2.2.8                                     |
| [nonce-indistinguishable]         | agent-check | pass   | Explicit in SPEC.md §2.2.8, §4.6                               |
| [mhmr-equivalence]                | agent-check | pass   | Explicit in SPEC.md §20.4, §20.6                               |
| [implicit-promotion]              | agent-check | pass   | Explicit in SPEC.md §2.2.5, §9.1 step 3, §20.5 step 2          |
| [level-1-2-identity]              | agent-check | pass   | SPEC.md §5.1, §3.1, §3.2 (no PR per §5.1)                      |
| [state-computation]               | agent-check | pass   | Explicit in SPEC.md §9.1 (four-step algorithm)                 |
| [conversion]                      | agent-check | superseded | Citation was stale (§20.2 is now "Golden Message" post-renumbering); corrected rule verified against SPEC.md §12.2.1 (MHMR, "Important Properties") and `rs/cyphr/src/multihash.rs` — see resolution note above |
| [mhmr-computation]                | agent-check | pass   | SPEC.md §12.2.1 (citation corrected; §20.5 no longer exists)   |
| [alg-set-evolution]               | agent-check | pass   | SPEC.md §12.2 (citation corrected; §20.6 no longer exists)     |
| [no-empty-mr]                     | agent-check | pass   | Inferred from SPEC.md §9.1 (collect requires ≥1)               |
| [no-circular-state]               | agent-check | pass   | Follows from §4.2 CR/PR definitions                            |
| [no-non-canonical-b64ut]          | agent-check | pass   | Explicit in SPEC.md §2.2.2 ("errors on non-canonical")         |
| [deterministic-state]             | agent-check | pass   | Follows from sort + promotion + MR rules                       |
| [promotion-recursive-termination] | agent-check | pass   | Follows from finite tree depth                                 |
| [mhmr-no-rehash-children]         | agent-check | superseded | Citation was stale (§20.5 no longer exists); corrected rule verified against SPEC.md §12.2.1 step 3 and `rs/cyphr/src/multihash.rs` — see resolution note above |

## Implications

### For Implementation (`/core`)

- **Cross-language parity**: The [deterministic-state] and [mr-sort-order]
  combination means Go and Rust implementations MUST produce identical digests
  for identical inputs. This is the foundational parity requirement.
- **Implicit promotion**: Implementations MUST handle the single-child case
  before computing any Merkle root. This is a common source of bugs — the
  single-key Level 1/2 case where `tmb` promotes all the way to PG.
- **No per-child conversion step**: [conversion] does not re-hash individual
  mismatched-algorithm children before folding. A component with 2+ existing
  variants folds ALL of their raw bytes together in one single hash operation
  under the target H; a component with exactly one existing variant (any
  algorithm) promotes its raw bytes directly for any requested H. There is no
  intermediate H(child_bytes) step performed on a single child in isolation.
- **MHMR variants per commit**: At each commit, the implementation must
  enumerate the active algorithm set and compute all variants. The algorithm
  set is determined post-mutation (after the commit's key changes are applied).

### For Testing

- **Parity test vectors**: Golden fixtures must verify that both implementations
  produce identical PG/PR/SR/AR/KR for the same input key set.
- **Promotion edge cases**: Test single-key, then add a second key (promotion
  stops), then remove it (promotion resumes).
- **Conversion cases**: Test mixed-algorithm key sets (e.g., ES256 + ES384)
  and verify MHMR variants for both SHA-256 and SHA-384.
- **b64ut rejection**: Test non-canonical encodings and verify they are rejected.

### For Model

- The formal model (`principal-state-model.md`) predates SPEC.md's MHMR and
  conversion sections. A model re-audit should verify that the model's state
  computation aligns with [state-computation], [conversion], and
  [mhmr-computation] as formalized here.
