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

**Problem Domain:** Cyphrpass state tree computation — the hierarchical Merkle
structure that derives all protocol identifiers (PR, PS, AS, KS, RS, DS, Commit
ID) and the multihash mechanism that makes those identifiers algorithm-agnostic.

**Target System:** `SPEC.md` §2.1–2.2 (Core Concepts and Terminology), §9
(State Calculation), §20 (Multihash Identifiers).

**Model Reference:**
[`principal-state-model.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/models/principal-state-model.md)
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
TYPE PR = Digest    -- Principal Root (immutable, first PS)
TYPE PS = Digest    -- Principal State (top-level, evolves per commit)
TYPE CS = Digest    -- Commit State (PT components excluding CommitID)
TYPE AS = Digest    -- Auth State
TYPE KS = Digest    -- Key State
TYPE RS = Digest    -- Rule State (Level 5+)
TYPE DS = Digest    -- Data State (Level 4+)
TYPE CommitID = Digest

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

**[identifier-is-cid]**: All identifiers (PR, PS, AS, KS, RS, DS, Commit ID,
`tmb`, nonces) MUST be cryptographic digest Content Identifiers (CIDs) encoded
as b64ut, providing both addressing and integrity of the reference.
`VERIFIED: agent-check`

**[mr-sort-order]**: When computing a Merkle root for state tree nodes (KS, AS,
PS, DS), child digests MUST be sorted in lexical byte order (opaque byte
comparison). **Exception:** Commit ID computation uses array order (see
`transactions.md` [commit-id-computation]).
`VERIFIED: agent-check — updated 2026-03-09 per array-order decision`

**[pr-immutable]**: The Principal Root (PR) MUST NOT change after genesis
(Level 3+). PR is the first PS computed at genesis commit. No operation MAY
alter it. Levels 1–2 do not have a PR (see [level-1-2-identity]).
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
principals): `tmb` == KS == AS == PS via recursive implicit promotion of the
single key's thumbprint. Levels 1–2 do not have PR (no commit chain exists).
`VERIFIED: agent-check — updated 2026-03-09 per B-2, SPEC §5.1`

**[state-computation]**: When computing a new state digest after a mutation:

1. **Collect** all component digests at the current tree level (including
   embedding/nonce nodes if present). Absent components (e.g., no RS at
   Level < 5) MUST be excluded from collection.
2. **Sort** collected digests in lexical byte order (per [mr-sort-order]).
3. **Apply implicit promotion** if exactly one digest remains (per
   [implicit-promotion]).
4. **Compute Merkle root** via binary Merkle tree of the sorted digests.

- **PRE**: Component digests are valid, correctly computed from their subtrees.
- **POST**: New state digest is deterministic and reproducible from the same
  component digests.
  `VERIFIED: agent-check`

**[conversion]**: When a child node uses a different hash algorithm than the
target algorithm H being computed, the child's digest value MUST be converted:
the child's raw digest bytes are fed into H to produce an H-length digest. This
conversion happens at the node level; the parent node is NOT REQUIRED to know
the child's original algorithm.

- **PRE**: Child digest exists, computed under some algorithm H_child where
  H_child ≠ H.
- **POST**: Converted digest = H(child_digest_bytes). The converted digest
  participates in the parent's Merkle root computation under H.
  `VERIFIED: agent-check`

**[mhmr-computation]**: For each supported hash algorithm H at a given commit,
implementations MUST compute an MHMR variant for every state node:

1. Collect child digests.
2. Sort in lexical byte order (opaque bytes).
3. If exactly one child: implicit promotion (no hashing, per
   [implicit-promotion]).
4. If multiple children: concatenate sorted child digest bytes in order, then
   compute H(concatenated bytes).

- **PRE**: Set of supported hash algorithms is determined by active keys in
  KS plus any nonce-injected algorithms.
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
node. (Absent state components — e.g., no RS at Level < 5 — are excluded
entirely, not represented as empty.)
`VERIFIED: agent-check`

> [!NOTE]
> **PLACEHOLDER — Empty state representation**: SPEC.md does not fully specify
> how empty DT or RT interact with implicit promotion at levels where they are
> first introduced. The semantic is that absent components are excluded from the
> Merkle root computation (not included as zero-length or sentinel values), but
> the boundary conditions for "first introduction" of DT/RT need confirmation
> from Zami. See sketch gap #7.

**[no-circular-state]**: The state computation dependency graph MUST be acyclic.
AS feeds into CS and PS, but MUST NOT depend on CommitID or CS. The dependency
order is: KS → AS → CS (excludes CommitID), CommitID (from czds) → PS (includes
CommitID). (SPEC.md §4.2: CS = PT components except CommitID; §3.3: CS = MR(AS, ...)).
`VERIFIED: agent-check — rewritten 2026-03-09 per B-4, §4.2/§3.3`

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
terminate. Since the state tree has finite depth (PR → PS → AS → KS/RS, with DT
and Commit ID as siblings), promotion recurses at most through the tree height.

- **Type**: Safety
  `VERIFIED: agent-check`

**[mhmr-no-rehash-children]**: When computing an MHMR, inner child digests MUST
be fed directly into the parent hash function as raw bytes, without re-hashing
under the target algorithm, UNLESS the child requires conversion (per
[conversion]), in which case the child's digest is hashed once under the target H.

- **Type**: Safety
  `VERIFIED: agent-check`

## State Formulas

These formulas summarize the computation rules. Each line is normative and
constrained by the invariants and transitions above.

```
KS       = MR(tmb₀, tmb₁?, embedding?, nonce?, ...)
AS       = MR(KS, RS?, embedding?, ...)                -- nil components excluded
CS       = MR(AS, DS?, embedding?, ...)                 -- Level 3+, PT minus CommitID
DS       = MR(czd₀, czd₁, ..., nonce?)                 -- Level 4+, sorted by `now` then `czd`
CommitID = MR(czd₀, czd₁?, embedding?, ...)             -- array order (not lexical sort)
PS       = MR(AS, CommitID?, DS?, embedding?, ...)       -- CommitID absent at Level 1-2
PR       = first PS at genesis commit (Level 3+ only, immutable)
```

**Commit Finality (resolved):** A commit is finalized by having
`"commit":<CS>` appear in the last coz of the commit (SPEC.md §4.2). CS is
computed from all PT components except CommitID. This serves as the
forward-reference finality signal (analogous to git's tree root in a commit).
See `transactions.md` [commit-finality].

> [!NOTE]
> **DS Sort Order**: SPEC.md §9.6 states DS is "sorted by `now` and secondarily
> `czd`". This overrides the general [mr-sort-order] (lexical byte order) for
> DS specifically.

## Algorithm Mapping

Per SPEC.md §20.1 and Coz, each key algorithm implies a hash algorithm:

| Key Algorithm | Hash Algorithm | Digest Size | Source   |
| :------------ | :------------- | :---------- | :------- |
| ES256         | SHA-256        | 32 bytes    | Coz v1.0 |
| ES384         | SHA-384        | 48 bytes    | Coz v1.0 |
| ES512         | SHA-512        | 64 bytes    | Coz v1.0 |
| Ed25519       | SHA-512        | 64 bytes    | Coz v1.0 |

This mapping is governed by Coz and inherited by Cyphrpass. Changes to this
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
| [mr-sort-order]                   | agent-check | pass   | SPEC.md §9.1 step 2; commit exception per array-order decision |
| [pr-immutable]                    | agent-check | pass   | SPEC.md §2.3.2, §9.2 (Level 3+ per §5.1)                       |
| [alg-alignment]                   | agent-check | pass   | Explicit in SPEC.md §2.2.2, §4.1.0                             |
| [digest-alg-from-coz]             | agent-check | pass   | Explicit in SPEC.md §2.2.2                                     |
| [nonce-bit-length]                | agent-check | pass   | Explicit in SPEC.md §2.2.8                                     |
| [nonce-indistinguishable]         | agent-check | pass   | Explicit in SPEC.md §2.2.8, §4.6                               |
| [mhmr-equivalence]                | agent-check | pass   | Explicit in SPEC.md §20.4, §20.6                               |
| [implicit-promotion]              | agent-check | pass   | Explicit in SPEC.md §2.2.5, §9.1 step 3, §20.5 step 2          |
| [level-1-2-identity]              | agent-check | pass   | SPEC.md §5.1, §3.1, §3.2 (no PR per §5.1)                      |
| [state-computation]               | agent-check | pass   | Explicit in SPEC.md §9.1 (four-step algorithm)                 |
| [conversion]                      | agent-check | pass   | Explicit in SPEC.md §20.2                                      |
| [mhmr-computation]                | agent-check | pass   | Explicit in SPEC.md §20.5                                      |
| [alg-set-evolution]               | agent-check | pass   | Explicit in SPEC.md §20.6                                      |
| [no-empty-mr]                     | agent-check | pass   | Inferred from SPEC.md §9.1 (collect requires ≥1)               |
| [no-circular-state]               | agent-check | pass   | Follows from §4.2 CS/PS definitions                            |
| [no-non-canonical-b64ut]          | agent-check | pass   | Explicit in SPEC.md §2.2.2 ("errors on non-canonical")         |
| [deterministic-state]             | agent-check | pass   | Follows from sort + promotion + MR rules                       |
| [promotion-recursive-termination] | agent-check | pass   | Follows from finite tree depth                                 |
| [mhmr-no-rehash-children]         | agent-check | pass   | Explicit in SPEC.md §20.5 step 3, Important Properties         |

## Implications

### For Implementation (`/core`)

- **Cross-language parity**: The [deterministic-state] and [mr-sort-order]
  combination means Go and Rust implementations MUST produce identical digests
  for identical inputs. This is the foundational parity requirement.
- **Implicit promotion**: Implementations MUST handle the single-child case
  before computing any Merkle root. This is a common source of bugs — the
  single-key Level 1/2 case where `tmb` promotes all the way to PS.
- **Conversion order**: [conversion] specifies H(child_bytes), not
  H(H(child_bytes)). Double-hashing during conversion is a specification
  violation.
- **MHMR variants per commit**: At each commit, the implementation must
  enumerate the active algorithm set and compute all variants. The algorithm
  set is determined post-mutation (after the commit's key changes are applied).

### For Testing

- **Parity test vectors**: Golden fixtures must verify that both implementations
  produce identical PR/PS/AS/KS for the same input key set.
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

### Open Questions (for Zami / sketch)

1. **Empty state boundary** (placeholder above): When DT or RT is first
   introduced (Level 4, Level 5), what is its initial representation? Is it
   absent (excluded from MR) until explicitly created, or does it start as
   some sentinel?
2. **Nonce injection scope**: §20.5 says nonces can inject algorithms. Can a
   nonce inject an algorithm that no key supports and no conversion path
   exists for? What are the bounds?
