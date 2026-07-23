import EonEalm.Result1

/-!
# Collision extraction — the Layer C soundness pattern

The source statement's own accounting: "the collision-extraction lemma (Layer C
soundness: accepting forgery ⟹ extracted collision) — the crypto transport, in-target
(F5); plugs into eml's positional-soundness development."

Rendered here as the general `accepts → φ ∨ ∃ collision` shape: replay Result 1's own
witness/checker verifier against an **arbitrary** commitment function `Cw` — not
assumed binding — and show acceptance forces either a genuine witness at exactly the
claimed record, or a `Cw`-collision. This mirrors the `¬NodeHashCollision` hypothesis
pattern of `Cyphrme/eml` `EMLProof.KaryConsistency.consistency_soundness` (accept ⟹
genuine prefix, modulo an explicit collision hypothesis) rather than assuming an
unconditional binding axiom the way `EonEalm.Commitment`'s Layer-L `Commitment.binding`
does — Layer C is exactly where that idealization gets discharged.

**Concrete instantiation.** This theorem gives the *general shape* eml's concrete
soundness theorems instantiate. The concrete instantiation against eml's actual
`karyRoot`/`AcceptsConsistency`/`NodeHashCollision` machinery (`Cyphrme/eml`
`proofs/lean/EMLProof/KaryConsistency.lean`) is carried out in the sibling package
`docs/models/lean-eml-bridge/` — kept separate because eml's Lean package depends on
Mathlib (`v4.29.1`, pinned in its own `lakefile.toml`) and this core stays Mathlib-free.
See that package's `EonEalmEml/Bridge.lean` for the completed, `sorry`-free
instantiation.
-/

namespace EonEalm

/-- `Cw` has no collision: it is genuinely injective. The hypothesis the concrete Layer-C
    constructions (eml's `¬NodeHashCollision ∧ ¬CollapseAmbiguity`) discharge instead of
    assuming outright. -/
def NoCollision {Comm : Type} (Cw : Record → Comm) : Prop := ∀ w w', Cw w = Cw w' → w = w'

/-- The collision-extraction reduction: replaying Result 1's `(w, t)` witness/checker
    verifier against an arbitrary (not-assumed-binding) `Cw`, an accepting `(w', t)`
    against target `target` either exhibits a genuine NP witness for `target` itself
    (`w' = target`) or a `Cw`-collision between `w'` and `target`. STABLE, fully proved —
    no cryptographic hypothesis is needed for *this* general shape; `NoCollision` only
    becomes load-bearing once this is composed with a scheme's soundness obligation
    (as `EonEalm.Commitment.soundness` does for the idealized, unconditionally-binding
    Layer-L case). -/
theorem collision_extraction_reduction {Comm : Type} (Cw : Record → Comm)
    (Witness : Type) (Chk : Record → Witness → Prop) (φ' : Record → Prop)
    (hφ' : ∀ w, φ' w ↔ ∃ t, Chk w t) (target : Record) (c : Record × Witness)
    (hacc : Cw c.1 = Cw target ∧ Chk c.1 c.2) :
    φ' target ∨ (c.1 ≠ target ∧ Cw c.1 = Cw target) := by
  obtain ⟨heq, hchk⟩ := hacc
  by_cases hc : c.1 = target
  · left
    rw [hφ']
    exact ⟨c.2, hc ▸ hchk⟩
  · right
    exact ⟨hc, heq⟩

/-- Under `NoCollision Cw`, the reduction's right disjunct is impossible, so acceptance
    forces the genuine witness — the "no forgery without a collision" reading. STABLE. -/
theorem collision_extraction_reduction_of_noCollision {Comm : Type} (Cw : Record → Comm)
    (Witness : Type) (Chk : Record → Witness → Prop) (φ' : Record → Prop)
    (hφ' : ∀ w, φ' w ↔ ∃ t, Chk w t) (hnc : NoCollision Cw) (target : Record)
    (c : Record × Witness) (hacc : Cw c.1 = Cw target ∧ Chk c.1 c.2) : φ' target := by
  rcases collision_extraction_reduction Cw Witness Chk φ' hφ' target c hacc with h | ⟨hne, heq⟩
  · exact h
  · exact absurd (hnc c.1 target heq) hne

end EonEalm
