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

/-! ## P1a — a computable commitment witness (Trust Trichotomy Probe P1)

`idCommitment` above is `noncomputable` and the corpus carries zero `Decidable`
instances, so it cannot witness the COMP stratum's "`VC` decidable" requirement
(`.scratch/trichotomy/statement-draft.md` §3.3). `⊑` (`Ext`) is a bare `∃`, not
decidable in general over an abstract `Entry`; under `[DecidableEq Entry]` a
prefix check is a standard structural walk, so this section adds a genuinely
computable decision procedure for `⊑` and a computable `Commitment` built on it —
additive only, `idCommitment` itself is untouched. -/

/-- Decision procedure for `⊑` given decidable equality on `Entry`: `w` is a
    prefix of `w'` iff they agree element-wise up to `w`'s length. -/
def extDec [DecidableEq Entry] : Record → Record → Bool
  | [], _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => if a = b then extDec as bs else false

theorem extDec_iff [DecidableEq Entry] :
    ∀ w w' : Record, extDec w w' = true ↔ w ⊑ w'
  | [], w' => by simp [extDec, Ext]
  | _ :: _, [] => by
      simp only [extDec, Bool.false_eq_true, false_iff]
      rintro ⟨u, hu⟩
      simp at hu
  | a :: as, b :: bs => by
      simp only [extDec]
      split
      · rename_i hab
        subst hab
        rw [extDec_iff as bs]
        constructor
        · rintro ⟨u, hu⟩
          exact ⟨u, by simp [hu]⟩
        · rintro ⟨u, hu⟩
          exact ⟨u, by simpa using hu⟩
      · rename_i hab
        simp only [Bool.false_eq_true, false_iff]
        rintro ⟨u, hu⟩
        simp at hu
        exact hab hu.1.symm

/-- `⊑` is decidable given decidable equality on `Entry` — the computability
    fact P1a needs. -/
instance instDecidableExt [DecidableEq Entry] (w w' : Record) : Decidable (w ⊑ w') :=
  decidable_of_iff (extDec w w' = true) (extDec_iff w w')

/-- P1a's computable commitment witness: same F5 shape as `idCommitment`
    (`C := id`, no compression) but under `[DecidableEq Entry]`, where `VC`
    resolves through `instDecidableExt` rather than being merely propositional. -/
def idCommitmentComp [DecidableEq Entry] : Commitment Record where
  VCProof := Unit
  C := id
  binding := fun _ _ h => h
  VC := fun h₀ h _ => h₀ ⊑ h
  soundness := fun _w₀ _w _h₀ _h _π hvc h₀eq heq => by
    simp only [id] at h₀eq heq; rw [h₀eq, heq] at hvc; exact hvc
  completeness := fun w₀ w hext => ⟨(), by simpa using hext⟩

/-- `idCommitmentComp`'s `VC` is decidable — the non-vacuity witness for P1's
    COMP-stratum antecedent on `Γ`. -/
instance instDecidableIdCommitmentCompVC [DecidableEq Entry]
    (h₀ h : Record) (π : Unit) : Decidable (idCommitmentComp.VC h₀ h π) := by
  show Decidable (h₀ ⊑ h)
  infer_instance

end EonEalm
