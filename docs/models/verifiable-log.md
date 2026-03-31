# MODEL: Merkle Append-Only Log Tree (MALT)

<!--
  Formal domain model of the MALT verifiable log data structure.

  See: .agent/personas/sdma.md for the applied modeling toolkit.
  See: .sketches/2026-03-20-daolfmt-verifiable-log.md for the exploratory sketch.

  Normative reference: RFC 9162 §2.1 (Certificate Transparency v2.0 Merkle Tree).
-->

## Domain Classification

**Problem Statement:** Formalize MALT — a generic, append-only
Merkle tree conforming to RFC 9162 §2.1 — as a standalone, reusable data
structure. The model captures the tree's inductive construction, algebraic
invariants, proof semantics, and the generic hash abstraction enabling
both single-algorithm and multi-algorithm (MHMR) usage.

**Domain Characteristics:**

- **Deterministic construction** — tree shape is uniquely determined by the
  number of leaves. Given the same inputs and hash function, any conforming
  implementation produces the same root.
- **Append-only monotonicity** — leaves are never removed or modified; the
  tree only grows.
- **Constructive proofs** — inclusion and consistency proofs are computed
  from the tree's concrete structure. They are witnesses: hash paths that
  any verifier can independently check.
- **Parametric hash abstraction** — the tree is generic over the hash
  function, enabling multi-algorithm (MHMR) usage without coupling to any
  specific hash scheme.

---

## Formalism Selection

| Aspect                | Detail                                                                                                                                                                                                                                             |
| :-------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Primary Formalism** | Initial Algebra (Inductive Type Definition)                                                                                                                                                                                                        |
| **Supporting Tools**  | Equational laws, Constructive proof theory                                                                                                                                                                                                         |
| **Rationale**         | The tree is a concrete, deterministic data structure built inductively from inputs. There is no hidden state — the tree IS the data. Proofs are constructive witnesses. This is the domain of algebra (construction), not coalgebra (observation). |

**Supporting: Equational Laws.** The tree's invariants are algebraic
equations verified by structural induction: determinism, append-only
monotonicity, domain separation, and left-fill.

**Supporting: Constructive Proof Theory.** Inclusion and consistency proofs
are Curry-Howard witnesses — a proof is a term (a list of hashes), and
verification is type-checking (recomputing the root from the path).

**Alternatives Considered:**

| Formalism      | Why Not                                                                      |
| :------------- | :--------------------------------------------------------------------------- |
| Coalgebra      | No hidden state. The tree is fully inspectable, not observed through a root. |
| Session types  | No multi-party protocol. Purely local computation.                           |
| Linear logic   | No resource linearity concerns. Leaves are freely readable.                  |
| Ologs          | Captures ontology but not behavioral properties (proofs).                    |
| Hyperdoctrines | Overkill — invariants are simple equational laws.                            |

**Dual Relationship to Principal-State-Model (MALT as algebra):**

| MALT (algebra)                   | Principal (coalgebra)        |
| :------------------------------- | :--------------------------- |
| Construction-first               | Observation-first            |
| Tree IS the data                 | PS hides the data            |
| Deterministic from inputs        | Same PS ≠ same internals     |
| Proofs are witnesses (terms)     | Behavior must be bisimulated |
| Verified by structural induction | Verified by coinduction      |

When integrated, the tree root (algebraic output) feeds the principal's
observation functor (coalgebraic input) — the standard algebra→coalgebra
interface.

---

## Model

### 1. Hash Abstraction

The tree is parameterized by a hash abstraction `H` that defines three
operations and one type:

```
H = {
  Digest   : Type,                                -- output type
  leaf     : Bytes → Digest,                      -- H(0x00 || data)
  node     : Digest × Digest → Digest,            -- H(0x01 || left || right)
  empty    : Digest                                -- H("")
}
```

**Constraints on H:**

```
C-COLLISION:  H is collision-resistant (standard cryptographic assumption)
C-DOMAIN:    ∀ d, l, r: leaf(d) ≠ node(l, r)     -- domain separation
C-PURE:      All operations are pure and deterministic
```

`C-DOMAIN` follows from the `0x00`/`0x01` prefix convention when `H` is
a standard cryptographic hash. The constraint is stated explicitly because
the tree's security depends on it — not on the specific prefix values.

**MHMR instantiation:** For multi-algorithm usage, `Digest` is a product
type containing one hash per algorithm. Each operation computes all
algorithms independently:

```
Digest_MHMR = { alg_1: Bytes, alg_2: Bytes, ..., alg_n: Bytes }

leaf_MHMR(d) = { alg_i: H_i(0x00 || d) | i ∈ 1..n }
node_MHMR(l, r) = { alg_i: H_i(0x01 || l.alg_i || r.alg_i) | i ∈ 1..n }
```

The algorithms never cross — each runs independently through the same tree
topology.

---

### 2. Tree Construction (Initial Algebra)

#### 2.1 Inductive Definition

The Merkle Tree Hash (MTH) is defined inductively over an ordered list of
inputs `D = {d[0], d[1], ..., d[n-1]}`:

```
MTH : List(Bytes) → Digest

MTH([])     = H.empty                                           -- T-EMPTY
MTH([d])    = H.leaf(d)                                         -- T-LEAF
MTH(D_n)    = H.node(MTH(D[0:k]), MTH(D[k:n]))    for n > 1   -- T-NODE
```

Where `k = largest_pow2_lt(n)` — the largest power of 2 strictly less
than n.

#### 2.2 Split Function

```
largest_pow2_lt : ℕ_{>1} → ℕ
largest_pow2_lt(n) = 2^(⌊log₂(n-1)⌋)
```

Properties:

```
S-BOUNDS:    ∀ n > 1:  k < n ≤ 2k        where k = largest_pow2_lt(n)
S-POWER:     ∀ n > 1:  ∃ m: k = 2^m      (k is always a power of 2)
S-DETERM:    ∀ n > 1:  k is unique        (one valid split per n)
```

The split ensures the left subtree is always a complete binary tree of
size `k` (a power of 2), and the right subtree handles the remainder
`n - k` recursively. This produces the **left-filled** shape.

#### 2.3 Shape Theorem

**Theorem (Deterministic Shape):** The tree topology is uniquely determined
by the leaf count n.

_Proof sketch:_ By structural induction on n. For n ≤ 1, the shape is
trivially unique (empty or single leaf). For n > 1, `S-DETERM` gives a
unique split k. The left subtree has k leaves (unique shape by inductive
hypothesis, and specifically is a complete binary tree since k is a power
of 2). The right subtree has n-k leaves (unique by inductive hypothesis).
∎

**Corollary (Implementation Parity):** Two conforming implementations
given the same `H` and the same ordered inputs MUST produce identical
roots.

---

### 3. Incremental Append

The tree supports efficient incremental construction via a frontier stack.
The stack holds the roots of the maximal complete subtrees along the right
edge of the tree.

#### 3.1 State

```
LogState = {
  size   : ℕ,              -- number of leaves appended
  stack  : List(Digest)     -- frontier (right-edge subtree roots)
}

initial_state = { size = 0, stack = [] }
```

#### 3.2 Append Operation

```
append(state, data) → LogState:
  let hash = H.leaf(data)
  push hash to state.stack
  let merge_count = count_trailing_ones(state.size)
  repeat merge_count times:
    right = pop state.stack
    left  = pop state.stack
    push H.node(left, right) to state.stack
  state.size += 1
  return state
```

Where `count_trailing_ones(n)` counts the number of consecutive 1-bits
starting from the least significant bit of n.

#### 3.3 Root Extraction

```
root(state) → Digest:
  if state.size = 0: return H.empty
  let r = copy of state.stack
  while |r| > 1:
    right = pop r
    left  = pop r
    push H.node(left, right) to r
  return r[0]
```

#### 3.4 Append Invariants

```
A-EQUIV:  ∀ inputs D:
            root(fold append over D from initial_state) = MTH(D)
            -- incremental construction equals batch construction

A-STACK:  ∀ state with size = n:
            |state.stack| = popcount(n)
            -- stack size equals number of 1-bits in the binary
            -- representation of n

A-COST:   ∀ append with pre-append size n:
            merge_count ≤ ⌊log₂(n + 1)⌋
            amortized merge_count = O(1)
```

`A-EQUIV` is the fundamental correctness property — incremental and batch
construction are observationally equivalent.

`A-STACK` gives the stack bound. A tree of 1000 leaves has at most
`popcount(1000) = 6` stack entries.

---

### 4. Inclusion Proofs

An inclusion proof demonstrates that a specific leaf exists in a tree of
known size and root.

#### 4.1 Proof Structure

```
InclusionProof = {
  index     : ℕ,            -- 0-based leaf index
  tree_size : ℕ,            -- size of the tree for which the proof is valid
  path      : List(Digest)  -- sibling hashes from leaf to root
}
```

#### 4.2 Proof Generation

```
PATH : ℕ × List(Bytes) → List(Digest)

PATH(m, [d])  = []                                                   -- P-BASE
PATH(m, D_n)  = PATH(m, D[0:k]) ++ [MTH(D[k:n])]     for m < k     -- P-LEFT
PATH(m, D_n)  = PATH(m-k, D[k:n]) ++ [MTH(D[0:k])]   for m ≥ k    -- P-RIGHT
```

Where `k = largest_pow2_lt(n)`.

#### 4.3 Proof Verification

Given a leaf hash, index, tree size, proof path, and expected root:

```
verify_inclusion(H, hash, index, tree_size, path, root) → Bool:
  if index ≥ tree_size: return false
  let fn = index, sn = tree_size - 1, r = hash
  for each p in path:
    if sn = 0: return false
    if LSB(fn) = 1 or fn = sn:
      r = H.node(p, r)
      while LSB(fn) = 0 and fn ≠ 0:
        fn = fn >> 1
        sn = sn >> 1
    else:
      r = H.node(r, p)
    fn = fn >> 1
    sn = sn >> 1
  return sn = 0 and r = root
```

#### 4.4 Inclusion Invariants

```
I-SOUND:    ∀ m < n:
              verify_inclusion(H, H.leaf(D[m]), m, n, PATH(m, D), MTH(D))
              = true
              -- a correctly generated proof always verifies

I-COMPLETE: ∀ m, n, path, root:
              verify_inclusion(H, hash, m, n, path, root) = true
              ⟹ hash is the m-th leaf of the tree with root root
              -- a verifying proof guarantees inclusion (under C-COLLISION)

I-SIZE:     ∀ m < n:
              |PATH(m, D_n)| ≤ ⌈log₂(n)⌉
              -- proof size is at most logarithmic (leaves on the
              -- rightmost edge of an incomplete tree may sit at
              -- shallower depth than the maximum)
```

---

### 5. Consistency Proofs

A consistency proof demonstrates that a tree of size m is a prefix of a
tree of size n — the append-only property holds between two tree heads.

#### 5.1 Proof Structure

```
ConsistencyProof = {
  old_size : ℕ,            -- size of the older tree
  new_size : ℕ,            -- size of the newer tree
  path     : List(Digest)  -- intermediate hashes
}
```

#### 5.2 Proof Generation

```
PROOF(m, D_n) = SUBPROOF(m, D_n, true)

SUBPROOF(m, D_m, true)   = []                                          -- C-SAME
SUBPROOF(m, D_m, false)  = [MTH(D_m)]                                  -- C-HASH
SUBPROOF(m, D_n, b)      = SUBPROOF(m, D[0:k], b) ++ [MTH(D[k:n])]
                            for m ≤ k                                   -- C-LEFT
SUBPROOF(m, D_n, b)      = SUBPROOF(m-k, D[k:n], false) ++ [MTH(D[0:k])]
                            for m > k                                   -- C-RIGHT
```

Where `k = largest_pow2_lt(n)`.

#### 5.3 Proof Verification

Given old_root, old_size, new_root, new_size, and the consistency path:

```
verify_consistency(H, old_size, new_size, path, old_root, new_root) → Bool:
  if old_size = 0 or old_size ≥ new_size: return false    -- DOMAIN GUARD
  if |path| = 0: return false
  if old_size is a power of 2: prepend old_root to path
  let fn = old_size - 1, sn = new_size - 1
  while LSB(fn) = 1:
    fn = fn >> 1
    sn = sn >> 1
  let fr = path[0], sr = path[0]
  for each c in path[1..]:
    if sn = 0: return false
    if LSB(fn) = 1 or fn = sn:
      fr = H.node(c, fr)
      sr = H.node(c, sr)
      while LSB(fn) = 0 and fn ≠ 0:
        fn = fn >> 1
        sn = sn >> 1
    else:
      sr = H.node(sr, c)
    fn = fn >> 1
    sn = sn >> 1
  return sn = 0 and fr = old_root and sr = new_root
```

#### 5.4 Consistency Invariants

```
K-SOUND:    ∀ 0 < m < n:
              verify_consistency(H, m, n, PROOF(m, D_n),
                                 MTH(D[0:m]), MTH(D_n))
              = true
              -- a correctly generated proof always verifies

K-APPEND:   ∀ 0 < m < n:
              verify_consistency(H, m, n, proof, old_root, new_root) = true
              ⟹ the first m leaves of the n-leaf tree are identical
                 to the leaves of the m-leaf tree
              -- consistency means append-only (under C-COLLISION)

K-SIZE:     ∀ 0 < m < n:
              |PROOF(m, D_n)| ≤ ⌈log₂(n)⌉ + 1
              -- proof size is logarithmic
```

---

### 6. Derived Invariants

These properties are consequences of the model, derivable from the
definitions above.

#### D1. Deterministic Root

```
∀ D, H:  MTH(H, D) is unique
```

The root is a pure function of the ordered inputs and the hash
abstraction. No randomness, no ordering ambiguity.

#### D2. Prefix Preservation

```
∀ D_m, D_n where D[0:m] = D'[0:m]:
  for any ancestor of leaf m where the path to m branches right,
  the left child subtree has the same hash in both trees
```

The restriction to right-branching ancestors is essential: when the path
branches left, the left child contains leaf m and may differ between
trees (the newer tree may have additional leaves in that subtree). When
the path branches right, the left child is a fully populated power-of-2
subtree of older elements — stable across appends. This is why
consistency proofs work.

#### D3. Monotone Log State

```
∀ state, data:
  let state' = append(state, data) in
  state'.size = state.size + 1
  ∧ state'.size > 0
  ∧ ∄ operation that decreases size
```

The log state is monotonically non-decreasing. There is no remove, no
truncate, no reset (except re-initialization).

#### D4. Stack-Root Correspondence

```
∀ state:
  root(state) = MTH(all_leaves_appended_so_far)
```

This is `A-EQUIV` restated — the incremental stack always represents the
same tree as batch construction.

#### D5. Domain Separation Security

```
∀ leaf_data, l, r:
  H.leaf(leaf_data) ≠ H.node(l, r)
```

From `C-DOMAIN`. This prevents second-preimage attacks where an attacker
constructs a leaf whose hash equals an interior node's hash, and is the
reason for the `0x00`/`0x01` prefix convention.

---

## Validation

### Internal Consistency

| Check                                   | Result | Detail                                                   |
| :-------------------------------------- | :----- | :------------------------------------------------------- |
| MTH is total for all finite input lists | PASS   | Three cases cover n=0, n=1, n>1 exhaustively             |
| Split function is total for n > 1       | PASS   | `largest_pow2_lt` is well-defined for all n > 1          |
| Append preserves A-EQUIV                | PASS   | Stack-based construction mirrors recursive definition    |
| A-STACK bound holds                     | PASS   | Binary representation argument; merge clears trailing 1s |
| A-COST bound holds at boundary          | PASS   | n=2^k−1 yields merge_count=k ≤ ⌊log₂(2^k)⌋ = k           |
| Inclusion proof size is bounded         | PASS   | ≤ ⌈log₂(n)⌉; rightmost leaves may have shorter paths     |
| Consistency proof size is logarithmic   | PASS   | At most ⌈log₂(n)⌉ + 1 nodes by SUBPROOF recursion        |
| I-SOUND: generated proofs verify        | PASS   | Follows from PATH/verify_inclusion being inverse walks   |
| K-SOUND: generated proofs verify        | PASS   | Follows from SUBPROOF/verify_consistency duality         |
| Consistency domain guard                | PASS   | old_size=0 or old_size≥new_size rejected before bitops   |
| Hash abstraction is minimal             | PASS   | Three operations + one type; no unnecessary structure    |
| MHMR instantiation satisfies C-DOMAIN   | PASS   | Per-algorithm prefixes maintain domain separation        |

### External Adequacy

| Property                    | Captured? | Detail                                                   |
| :-------------------------- | :-------- | :------------------------------------------------------- |
| RFC 9162 §2.1 MTH           | ✓         | Verbatim definition adapted for generic H                |
| RFC 9162 §2.1.2 root verify | ✓         | `A-EQUIV` + stack algorithm §3                           |
| RFC 9162 §2.1.3 inclusion   | ✓         | Generation and verification algorithms §4                |
| RFC 9162 §2.1.4 consistency | ✓         | Generation and verification algorithms §5                |
| Domain separation           | ✓         | `C-DOMAIN` constraint on H                               |
| Generic hash abstraction    | ✓         | §1 parameterizes over H                                  |
| MHMR compatibility          | ✓         | §1 MHMR instantiation shows fat-node construction        |
| Incremental append          | ✓         | §3 with O(log n) worst-case, O(1) amortized              |
| Append-only (no remove)     | ✓         | D3 — no operation decreases size                         |
| Tiling                      | ✗         | Explicitly out of scope (future concern)                 |
| Signed tree heads           | ✗         | Application-layer concern, not the tree's responsibility |
| Persistence / storage       | ✗         | Callers provide storage                                  |

### Minimality

The model uses an inductive type definition with equational laws. This is
the simplest formalism that captures the domain's essential structure. No
categorical, coalgebraic, or linear-logic machinery is needed — the tree
is a deterministic function from inputs to outputs with verifiable
algebraic properties.

---

## Implications

### For Implementation

- The hash abstraction (§1) maps directly to a Rust trait or Go interface
  parameterizing `Digest`, `leaf`, `node`, and `empty`.
- The incremental append (§3) is the core data structure — the stack-based
  algorithm is the implementation's heart.
- Proof generation (§4–5) requires access to all leaf hashes (or cached
  intermediate node hashes). Storage of leaf hashes is necessary.
- `A-EQUIV` is the primary correctness test: incremental construction must
  equal batch construction for all inputs.
- MHMR is a consumer-side concern — the library provides the generic
  interface, Cyphrpass provides the fat hasher.

### For Cyphrpass Integration

- The tree root serves as CR (Commit Root) in the principal's state tree.
- Consistency proofs subsume state jumping and witness resync.
- Inclusion proofs enable selective disclosure of individual commits.
- The algebraic tree output feeds the coalgebraic principal model — the
  standard algebra→coalgebra interface.

### For Testing

- `A-EQUIV` — verify incremental equals batch for randomized input lists.
- `I-SOUND` — generate inclusion proofs and verify they pass.
- `K-SOUND` — generate consistency proofs and verify they pass.
- `D5` — verify domain separation holds for the concrete hash
  instantiations.
- Cross-language parity — same inputs, same H, same roots across Rust and
  Go implementations.

### Storage Requirement

Proof generation requires access to historical leaf data. The frontier
stack stores only `popcount(n)` intermediate roots — once a merge occurs,
the child hashes are consumed by the non-invertible `H.node` function and
lost. Generating an inclusion proof for an early leaf requires intermediate
nodes that were evicted from the stack long ago.

**Consequence:** Implementations must maintain an O(n) persistent store of
raw leaf data (or at minimum, leaf hashes). The `LogState` stack is a
computational frontier for O(1) amortized appends, not a data source for
proofs. Callers provide this storage — the library does not prescribe the
storage mechanism.

### MHMR Algorithm Addition

When a new hash algorithm is added mid-history, the tree must be
backfilled for the new algorithm. Because cryptographic hash functions are
pre-image resistant, `H_new(data)` cannot be derived from `H_old(data)`.
Backfill requires access to the original raw leaf bytes: initialize a
fresh computation for the new algorithm and sequentially process all
prior leaves.

**Consequence:** The persistent store must retain original leaf bytes (not
just leaf hashes) to support cryptographic agility. This is an
implementation constraint, not a model constraint — the model's hash
abstraction is parameterized at construction time.
