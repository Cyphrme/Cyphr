# EonEalmEml — EON/EALM instantiated for eml's real log

This package plugs `Cyphrme/eml`'s real k-ary Merkle commitment into the
abstract `EonEalm.Commitment` structure the core EON/EALM development
(`../lean/`) is proved over, so that Result 2 (EALM) and Result 3 (EON)
hold not just for an idealized binding commitment but for eml's actual
positional Merkle log. See [`../eon-ealm.md`](../eon-ealm.md) for what
EON/EALM says in prose, and [`../lean/README.md`](../lean/README.md)
for the core package this one depends on.

## What is proved

`EonEalm.endurance_iff_monotone` and `EonEalm.eon_trilemma_impossibility`
are universally quantified over *any* `EonEalm.Commitment Comm` — so
once this package discharges that structure's three obligations
(`binding`, `soundness`, `completeness`) for eml's log, the two results
specialize immediately, with no new proof content beyond the concrete
commitment:

- **`EonEalmEml.eml_endurance_iff_monotone`** — EALM holds for eml's
  entry-level log: a record-determined, NP claim admits an
  enduring-sound scheme over eml's commitment iff it is monotone.
- **`EonEalmEml.eml_eon_trilemma_impossibility`** — the EON
  impossibility holds for eml's log: for a claim that is record-
  determined, NP, and non-monotone, no scheme over eml's commitment is
  both offline and eternal.

Both are **conditional** on three hypotheses eml's own machinery
already carries, plus one new one this bridge introduces:

- **`hH : ¬ NodeHashCollision`** — no two distinct child-digest lists
  hash to the same node value (eml's own collision-freedom hypothesis).
- **`hN : ¬ CollapseAmbiguity`** — no non-uniform child list collapses
  to the same value a uniform (all-equal) list of the same value would
  produce (eml's own hypothesis guarding the null/empty-node collapse
  case).
- **`hk : 2 ≤ k`** — the tree's arity is at least 2 (eml's own
  well-formedness precondition on `karyRoot`).
- **`hleaf : Function.Injective leafDigest`** — this bridge's one named
  addition: an injective map from `EonEalm`'s abstract entry type to
  eml's `Digest`, needed because `EonEalm.Entry` carries no hash of its
  own. It is a named, explicit hypothesis on every theorem in this
  module — never folded silently into the core.

## Why a separate package

Two gaps had to be closed to connect `EonEalm.Commitment`'s abstract
obligations to eml's concrete lemmas; both are documented in
`EonEalmEml/Bridge.lean`'s module doc-comment in full and summarized
here:

1. **`EonEalm.Entry` is opaque** — it carries no hash, so composing
   with eml's `karyRoot : List Digest → Digest` needs an entry-to-leaf-
   digest embedding. `leafDigest` (above) is exactly that embedding,
   carried as a named hypothesis rather than derived, since no
   hypothesis-free map is available without collapsing distinct
   entries.
2. **`karyRoot` is not unconditionally injective** — null-collapse
   makes different-length all-empty inputs map to the same root
   independent of any collision. The fix is choosing the commitment's
   codomain as `Digest × Nat` (root paired with record length) rather
   than `Digest` alone — the same fix eml's own
   `karyRoot_inj_of_length` lemma already requires (its docstring notes
   "tree_size pins injectivity"). This is a choice of codomain, not a
   weakening of `EonEalm.Commitment.binding`'s statement, which stays
   unconditional (`C w = C w' → w = w'`).

A further consequence of eml's own lemma boundaries: `EonEalm.Commitment
.completeness` demands a certifying proof for *every* prefix relation
`w₀ ⊑ w`, but eml's `AcceptsConsistency`/`consistency_completeness`
machinery only covers genuine mid-log growth (`0 < oldSize < newSize`
— there is no boundary subtree to climb from an empty log, and no
witness to construct across a no-op extension). `VC` here is
accordingly a three-way disjunction — reflexive (`w₀ = w`), from-empty
(`w₀ = []`), or genuine growth via eml's own machinery verbatim — none
of which widens what `EonEalm.Commitment` requires or narrows what eml
proves.

## Files

| File | Contents |
| :-- | :-- |
| `EonEalmEml/Bridge.lean` | `emlCommitment`: the `EonEalm.Commitment (Digest × Nat)` instance over eml's k-ary root, discharging `binding`, `soundness`, and `completeness` against eml's `EMLProof.KaryConsistency` lemmas. |
| `EonEalmEml.lean` | The two specialized headline theorems (`eml_endurance_iff_monotone`, `eml_eon_trilemma_impossibility`), each a direct application of the core theorem to `emlCommitment`. |

## Build and verify

This package requires both `EonEalm` (`../lean`, path-required, no
Mathlib) and `Cyphrme/eml`'s Lean proofs (`EMLProof`, which does depend
on Mathlib) as a sibling checkout — see `lakefile.toml`'s `[[require]]`
entries. It is a local, unshipped bridge: deliberately not wired into
either corpus's own build, so `EonEalm` stays Mathlib-free and
`EMLProof` stays untouched.

```sh
export PATH="$HOME/.elan/toolchains/leanprover--lean4---v4.29.1/bin:$PATH"
lake build
```

The Mathlib dependency pulled in via `EMLProof` makes this build
noticeably heavier than the core package's; a clean exit with no
`sorry`/error output is the green signal.

## Trusted computing base

Verified by direct `#print axioms` inspection: both specialized
theorems depend on Lean's three built-ins (`propext`, `Classical.choice`,
`Quot.sound`), `EonEalm`'s own model parameters (`EonEalm.Context`,
`EonEalm.Context.inhabited`, `EonEalm.Entry`), and eml's own foundational
axioms (`Digest`, `Digest.nonempty`, `H`, `digestToBytes` —
`Cyphrme/eml` `proofs/lean/EMLProof/Foundations.lean`). No axiom beyond
this set appears; no `sorry` anywhere in this package.

## Related

- [`../lean/README.md`](../lean/README.md) — the core package this
  bridge instantiates.
- [`../eon-ealm.md`](../eon-ealm.md) — the prose statement of what
  EON/EALM proves and why.
