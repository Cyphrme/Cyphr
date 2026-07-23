import EonEalm.Result2

/-!
# Trust Trichotomy — Probe P1 (COMP stratum, ⟸ direction)

Mechanizes `.scratch/trichotomy/statement-draft.md` §3.3's Probe P1: the ⟸
direction of `EonEalm.endurance_iff_monotone` (Result 2) at the **COMP**
stratum, where the vacuous `NPMembership` (`EonEalm.Schemes.lean:40-41` —
`Witness := Unit`, `Chk w _ := ψ w`) is replaced by a genuine decidability
condition on `Chk` and on the commitment's `VC`.

Refuter A's proof-term trace (`.ledger/trichotomy/break-round-1-consolidated.md`)
predicted survival: `EonEalm.enduringScheme`'s proofs perform only classical
∃-elimination over `Prop`s, never inspecting decidability, so `Decidable`
instances bolt on for free. This file tests that prediction directly.

## Why no Mathlib

`EonEalm` itself carries no Mathlib dependency (`Model.lean`'s module
doc-comment), and this package inherits that discipline. Two COMP-stratum
notions the source statement names in Mathlib's vocabulary are instead spelled
out by hand:

- **`Countable Entry`** — probed empirically: `Countable` does not elaborate
  as a binder annotation without importing Mathlib (`invalid binder
  annotation, type is not a class instance`). `EntryEncodable` below states
  the same content directly, as an injection into `Nat`.
- **`Decidable (Γ.VC h₀ h π)` / `Decidable (Chk w t)`** — ordinary `Prop`
  hypotheses rather than instance-implicit binders, resolved locally via
  `haveI` at the one call site that needs them, to avoid depending on
  typeclass search finding a Pi-typed instance argument.

## P1b is carried, not consumed (an honest disclosure, not a defect)

Per the dispatch: P1b (`Entry` encodability) is a **local hypothesis in this
package**, never an axiom added to `EonEalm.Model`. It is threaded into
`trichotomy_P1`'s signature below (as `_hEntry`) to match the COMP stratum's
official shape ("`Proof`/`Comm` encodable as finite strings", statement
draft §1.4) — but the Lean proof term does **not** consume it: deriving
"`Record`/`Proof` are actually encodable" from "`Entry` is encodable" needs a
List/product encodability closure (a Gödel-style pairing development), which
is exactly the Mathlib-shaped machinery this package declines to import or
reprove from scratch. This mirrors the corpus's own precedent
(`EonEalm.Result2.endurance_forces_monotone` carries `hd`/`hnp` unused, "so
the signature matches" — see that theorem's doc-comment) rather than being a
new irregularity. What IS mechanically checked, and is the actual COMP-stratum
content the construction produces, is `Decidable (S.V h c)` for the
constructed scheme's verifier.
-/

namespace Trichotomy

open EonEalm

/-- P1b, spelled out directly (no Mathlib `Countable`): `Entry` admits an
    injection into `Nat`. Carried as a hypothesis on `trichotomy_P1` per the
    dispatch's mandate; see the module doc-comment for why the proof term
    does not need to eliminate it. -/
def EntryEncodable : Prop := ∃ enc : Entry → Nat, ∀ a b, enc a = enc b → a = b

/-- **Probe P1** (COMP stratum, ⟸ direction). Given a commitment `Γ` whose
    `VC` is decidable and a determined, monotone claim `φ` whose Σ₁-witness
    checker `Chk` is decidable, `φ` admits an enduring-sound scheme whose
    verifier is itself decidable — the COMP-stratum reading of
    `EonEalm.endurance_construction`, with the vacuous `NPMembership` replaced
    by the real decidability conditions `hChkDec`/`hVCDec`. -/
theorem trichotomy_P1
    {Comm : Type} (Γ : Commitment Comm)
    (φ : Claim) (hd : Determined φ)
    (Witness : Type) (Chk : Record → Witness → Prop)
    (hnp : ∀ w, determinedProj φ hd w ↔ ∃ t, Chk w t)
    (hm : Monotone φ)
    (hChkDec : ∀ w t, Decidable (Chk w t))
    (hVCDec : ∀ h₀ h π, Decidable (Γ.VC h₀ h π))
    (_hEntry : EntryEncodable) :
    ∃ S : Scheme Γ φ, EnduringSound S ∧ Nonempty (∀ h c, Decidable (S.V h c)) := by
  -- `∀ h c, Decidable (S.V h c)` is `Type`-valued (`Decidable` is data, not a
  -- `Prop`), so it cannot sit as a bare conjunct inside the `∃`'s `Prop`;
  -- `Nonempty` is the standard Prop-level "a decision procedure exists" wrapper.
  refine ⟨enduringScheme Γ φ hd Witness Chk hnp,
    enduringScheme_enduringSound Γ φ hd hm Witness Chk hnp, ⟨fun h c => ?_⟩⟩
  haveI := hChkDec c.1 c.2.1
  haveI := hVCDec (Γ.C c.1) h c.2.2
  -- `enduringScheme`'s `V h c := Chk c.1 c.2.1 ∧ Γ.VC (Γ.C c.1) h c.2.2`
  -- (certificate type `Record × Witness × Γ.VCProof`, right-associated, so
  -- `c.2.2 : Γ.VCProof` directly). `show` unfolds the `def`-hidden `V` to
  -- this defeq form so instance search can see the `∧` shape.
  show Decidable (Chk c.1 c.2.1 ∧ Γ.VC (Γ.C c.1) h c.2.2)
  infer_instance

/-! ## Non-vacuity — P1's antecedent is jointly satisfiable

Refuter A flagged (round 1) that v0.1's non-vacuity witness (`idCommitment`)
was false as written: `noncomputable`, zero `Decidable` instances. This
section exhibits a concrete antecedent, built from P1a's `idCommitmentComp`
(`EonEalm.Commitment`) and a trivial claim, showing `trichotomy_P1` is not
vacuous — relative to `Entry` admitting decidable equality and an encoding,
which is as concrete as this package can get given `Entry` is `EonEalm`'s own
abstract axiom, not a type this package can instantiate. -/

/-- The trivial claim `⊤`: determined and monotone for free, and Σ₁ via the
    unit checker `Chk w _ := True` — a decidable witness relation. Needs
    neither `DecidableEq Entry` nor `EntryEncodable`, so it sits outside
    `NonVacuity`'s section variables. -/
def trivialClaim : Claim := fun _ _ => True

theorem trivialClaim_determined : Determined trivialClaim := fun _ _ _ => Iff.rfl

theorem trivialClaim_monotone : Monotone trivialClaim := fun _ _ _ _ _ => trivial

theorem trivialClaim_hnp :
    ∀ w, determinedProj trivialClaim trivialClaim_determined w ↔ ∃ _ : Unit, True :=
  fun _ => ⟨fun _ => ⟨(), trivial⟩, fun _ => trivial⟩

section NonVacuity

variable [DecidableEq Entry] (hEntry : EntryEncodable)

include hEntry in
/-- P1's antecedent is satisfiable: `idCommitmentComp` for `Γ`, `trivialClaim`
    for `φ`, decidable throughout. -/
theorem trichotomy_P1_nonvacuous :
    ∃ S : Scheme idCommitmentComp trivialClaim,
      EnduringSound S ∧ Nonempty (∀ h c, Decidable (S.V h c)) :=
  trichotomy_P1 idCommitmentComp trivialClaim trivialClaim_determined Unit
    (fun _ _ => True) trivialClaim_hnp trivialClaim_monotone
    (fun _ _ => inferInstance) (fun _ _ _ => inferInstance) hEntry

end NonVacuity

end Trichotomy
