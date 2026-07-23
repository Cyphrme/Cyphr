# EonEalm — mechanized EON/EALM core

This package mechanizes the **EON/EALM** formal result in Lean 4: a
characterization of which claims about an append-only record admit
evidence that can be verified **offline** (no record access, no oracle,
no clock) and, among those, which admit evidence that **endures**
forever without re-verification. See
[`../eon-ealm.md`](../eon-ealm.md) for the prose statement — names,
results, the CAP/CALM correspondence, and the escapes. This file is the
reviewer's entry point into the Lean development itself.

## What is proved

Three headline theorems, all zero-`sorry`:

- **`EonEalm.snapshot_characterization`** (Result 1, the Surety Ceiling)
  — a claim admits a scheme with snapshot-sound evidence iff it is
  record-determined and its record-only projection is in NP.
- **`EonEalm.endurance_iff_monotone`** (Result 2, EALM) — restricted to
  claims clearing that ceiling, a claim admits a scheme with
  enduring-sound evidence iff it is monotone (truth preserved under
  record extension, same context).
- **`EonEalm.eon_trilemma_impossibility`** (Result 3, EON) — for a
  claim that clears the ceiling but is non-monotone, no scheme is both
  offline and eternal.

All three are stated over **Layer L**: an abstract commitment
satisfying only a binding axiom (`C(w) = C(w') → w = w'`), not a
concrete hash. `EonEalm/Commitment.lean`'s `idCommitment` witnesses that
this axiom is satisfiable without any cryptography (`C := id`), and
`docs/models/lean-eml-bridge/` separately instantiates the same
abstract `Commitment` structure against eml's real k-ary Merkle
commitment — see [`../lean-eml-bridge/README.md`](../lean-eml-bridge/README.md).

## File guide

| File | Contents |
| :-- | :-- |
| `EonEalm/Model.lean` | D0–D2: the entry alphabet, records as lists over it, the prefix extension order `⊑` (reflexive/transitive/antisymmetric, proved directly — no Mathlib `Preorder`), ambient contexts, worlds, and claims as predicates over worlds. |
| `EonEalm/Axes.lean` | D3–D4: `Determined` (context-independence) and `Monotone` (same-context preservation under extension) — the two orthogonal axes the results are built from. |
| `EonEalm/Commitment.lean` | D6: the `Commitment` structure (a commitment function, its binding axiom, an extension-verification relation `VC` with soundness/completeness), plus `idCommitment` as the non-cryptographic non-vacuity witness. |
| `EonEalm/Schemes.lean` | D5: `Scheme` (verifier only, no bundled prover — see the correction note below), `NPMembership`, and the E1/E2a/E2b soundness definitions, with the mechanical fact that enduring-soundness implies snapshot-soundness. |
| `EonEalm/Result1.lean` | Result 1, both directions, `snapshot_characterization`. |
| `EonEalm/CollisionExtraction.lean` | The general shape of the collision-extraction reduction Layer C uses to discharge soundness against a real hash (accepting forgery ⟹ hash collision), stated for an arbitrary not-assumed-binding commitment function. |
| `EonEalm/Result2.lean` | Result 2, both directions, `endurance_iff_monotone`. |
| `EonEalm/Result3.lean` | Result 3, `eon_trilemma_impossibility`, a direct corollary of Result 2's forward direction. |
| `EonEalm.lean` | Root module: imports the above, orients the reader, and documents scope decisions (the corrected E1, what's out of scope and why). |

## A note on E1's correction

An earlier draft of this statement bundled a polynomial-time *prover*
into a scheme's data, with completeness stated as that prover always
succeeding. Composed with a polynomial-time verifier, that prover would
itself be a polynomial-time decider — and since Result 1's backward
direction is claimed for *every* determined NP claim, that would force
an unconditional `P = NP`. The corrected form, encoded throughout this
package, states completeness (E1) as bare **existence** of an accepting
certificate — never an efficient search procedure. See
`EonEalm/Schemes.lean`'s module doc-comment for the full argument.

## Build and verify

```sh
# lean-toolchain pins the exact version (leanprover/lean4:v4.29.1); point
# PATH at the matching elan toolchain before invoking lake:
export PATH="$HOME/.elan/toolchains/leanprover--lean4---v4.29.1/bin:$PATH"
lake build
```

`lake build` resolves dependencies from `lake-manifest.json` and
elaborates every file; a clean exit with no `sorry`/error output is the
green signal.

To re-check the axiom footprint of a headline theorem directly:

```sh
echo 'import EonEalm
#print axioms EonEalm.snapshot_characterization
#print axioms EonEalm.endurance_iff_monotone
#print axioms EonEalm.eon_trilemma_impossibility' | lake env lean --stdin
```

## Trusted computing base

Verified by direct `#print axioms` inspection: the three headline
theorems depend only on Lean's three built-in axioms —

- `propext` (propositional extensionality)
- `Classical.choice`
- `Quot.sound`

— plus this package's own abstract model parameters: `EonEalm.Entry`
(the entry alphabet, D0), `EonEalm.Context` and
`EonEalm.Context.inhabited` (the ambient-context type and its
non-emptiness, D1). `EonEalm.Context.nontrivial` (`|Ξ| ≥ 2`) is declared
for model faithfulness but is not yet load-bearing in any proved
theorem. No Mathlib dependency; no axiom beyond the four above appears
anywhere in the development.

## Scope

**Not mechanized, by design** (see `EonEalm.lean`'s doc-comment for the
full reasoning on each): polynomial-time complexity bounds (Layer C
territory), succinctness of certificates, the Łoś–Tarski
∃⁺-implies-monotone lemma (used only as informal justification for one
illustrative example, not a proof target), and an interactive-verifier
definition for the "drop Offline" corner. None of these carries a
`sorry`-stubbed theorem — each is either not yet a well-posed Layer-L
question or would require a model extension that does not exist yet;
inventing a placeholder statement for any of them was judged worse than
leaving the gap explicit.
