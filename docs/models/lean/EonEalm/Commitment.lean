import EonEalm.Model

/-!
# Commitment — D6, Layer L

Abstract commitment `C` with a **binding axiom** and an extension-verification relation
`VC`, bundled as a `Commitment` structure so a scheme can be built generically over any
instance. Deliberately **not** a set of bare top-level axioms (unlike
`EMLProof.Foundations`'s single fixed `H`): D6 requires that `C = id` be a valid
instance (binding **without** compression — F5: binding-with-compression is
unsatisfiable), which only typechecks as a genuine non-vacuity witness if `Commitment`
is a first-class structure with multiple inhabitants, not a global axiom. `idCommitment`
below is exactly that witness.
-/

namespace EonEalm

/-- D6 (Layer L): an abstract commitment scheme over codomain `Comm` — the commitment
    function, its binding axiom, and the extension-verification relation `VC` with its
    soundness/completeness obligations. `VC h₀ h π` reads "`π` certifies that the record
    committing to `h₀` is a prefix of the record committing to `h`." -/
structure Commitment (Comm : Type) where
  /-- The extension-proof witness type. -/
  VCProof : Type
  /-- D6: the commitment function, poly-time-computable at Layer C (not modeled here). -/
  C : Record → Comm
  /-- The extension-verification relation itself. -/
  VC : Comm → Comm → VCProof → Prop
  /-- D6 binding axiom: `C(w) = C(w′) ⟹ w = w′`. The *only* axiom licensed on `C` —
      do NOT additionally assume compression (F5). -/
  binding : ∀ w w', C w = C w' → w = w'
  /-- D6 VC-soundness: an accepting extension proof forces the genuine prefix relation.
      At Layer C this is discharged by collision extraction (accepting forgery ⟹
      extracted hash collision); see `EonEalm.CollisionExtraction` for the abstract
      shape of that transport. -/
  soundness : ∀ w₀ w h₀ h π, VC h₀ h π → h₀ = C w₀ → h = C w → w₀ ⊑ w
  /-- D6 VC-completeness: every genuine extension has a certifying proof. -/
  completeness : ∀ w₀ w, w₀ ⊑ w → ∃ π, VC (C w₀) (C w) π

/-- F5's non-vacuity witness: `Comm := Record`, `C := id`. Binding is `rfl`-immediate;
    `VC` is the extension relation itself (no cryptography, no compression — id realizes
    Layer L). Confirms the `Commitment` structure's axioms are jointly satisfiable. -/
noncomputable def idCommitment : Commitment Record where
  VCProof := Unit
  C := id
  binding := fun _ _ h => h
  VC := fun h₀ h _ => h₀ ⊑ h
  soundness := fun _w₀ _w _h₀ _h _π hvc h₀eq heq => by
    simp only [id] at h₀eq heq; rw [h₀eq, heq] at hvc; exact hvc
  completeness := fun w₀ w hext => ⟨(), by simpa using hext⟩

end EonEalm
