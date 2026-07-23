import EonEalm.Result2

/-!
# Trust Trichotomy — Probe P1 (DEC stratum, an iff)

Mechanizes `.scratch/trichotomy/statement-draft.md` §3.3's Probe P1: both
directions of `EonEalm.endurance_iff_monotone` (Result 2) at the **DEC**
stratum, where the vacuous `NPMembership` (`EonEalm.Schemes.lean:40-41` —
`Witness := Unit`, `Chk w _ := ψ w`) is replaced by a genuine decidability
condition on `Chk` and on the commitment's `VC`.

**DEC, not COMP (statement draft §1.4, §6.6).** The stratum tower is
`ALL ⊃ DEC ⊃ COMP ⊃ POLY`. `Decidable` here is Lean's own constructive
branch-decision over the abstract `Entry` axiom — a mechanization-internal
waypoint, not a Turing-computability claim. Every COMP checker is DEC, but a
DEC checker over a possibly non-encodable type is not automatically COMP.
Reaching COMP from what this file proves needs two further, currently
unproven things: (i) an **encodability-closure lemma** lifting an
`Entry → Nat` injection to `Record`/`Proof` (a Gödel-style List/product
pairing development this package declines to import or reprove), and (ii) a
`Decidable`→computable **bridge**, which is meta-theoretic — true for
kernel-definable instances, but not a theorem expressible inside this corpus
(§6.6). Neither is assumed or discharged below; this file proves the DEC
result and no more, in both directions (§3.3, §6.2).

Refuter A's proof-term trace (`.ledger/trichotomy/break-round-1-consolidated.md`)
predicted survival: `EonEalm.enduringScheme`'s proofs perform only classical
∃-elimination over `Prop`s, never inspecting decidability, so `Decidable`
instances bolt on for free. This file tests that prediction directly.

## Why no Mathlib

`EonEalm` itself carries no Mathlib dependency (`Model.lean`'s module
doc-comment), and this package inherits that discipline. The one
DEC-stratum notion the source statement names in Mathlib's vocabulary,
`Decidable (Γ.VC h₀ h π)` / `Decidable (Chk w t)`, is spelled out as ordinary
`Prop` hypotheses rather than instance-implicit binders, resolved locally via
`haveI` at the one call site that needs them, to avoid depending on
typeclass search finding a Pi-typed instance argument.
-/

namespace Trichotomy

open EonEalm

/-- **Probe P1** (DEC stratum, ⟸ direction). Given a commitment `Γ` whose
    `VC` is decidable and a determined, monotone claim `φ` whose Σ₁-witness
    checker `Chk` is decidable, `φ` admits an enduring-sound scheme whose
    verifier is itself decidable — the DEC-stratum reading of
    `EonEalm.endurance_construction`, with the vacuous `NPMembership` replaced
    by the real decidability conditions `hChkDec`/`hVCDec`. This is
    Lean-`Decidable` — a constructive branch-decision over the abstract
    `Entry` axiom — not a Turing-computability claim (§6.6); the COMP
    reading additionally needs the encodability-closure lemma and the
    `Decidable`→computable bridge, neither proven nor assumed here. -/
theorem trichotomy_P1
    {Comm : Type} (Γ : Commitment Comm)
    (φ : Claim) (hd : Determined φ)
    (Witness : Type) (Chk : Record → Witness → Prop)
    (hnp : ∀ w, determinedProj φ hd w ↔ ∃ t, Chk w t)
    (hm : Monotone φ)
    (hChkDec : ∀ w t, Decidable (Chk w t))
    (hVCDec : ∀ h₀ h π, Decidable (Γ.VC h₀ h π)) :
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
vacuous — relative to `Entry` admitting decidable equality, which is as
concrete as this package can get given `Entry` is `EonEalm`'s own abstract
axiom, not a type this package can instantiate. -/

/-- The trivial claim `⊤`: determined and monotone for free, and Σ₁ via the
    unit checker `Chk w _ := True` — a decidable witness relation. Needs no
    `DecidableEq Entry` instance, so it sits outside `NonVacuity`'s section
    variable. -/
def trivialClaim : Claim := fun _ _ => True

theorem trivialClaim_determined : Determined trivialClaim := fun _ _ _ => Iff.rfl

theorem trivialClaim_monotone : Monotone trivialClaim := fun _ _ _ _ _ => trivial

theorem trivialClaim_hnp :
    ∀ w, determinedProj trivialClaim trivialClaim_determined w ↔ ∃ _ : Unit, True :=
  fun _ => ⟨fun _ => ⟨(), trivial⟩, fun _ => trivial⟩

section NonVacuity

variable [DecidableEq Entry]

/-- P1's antecedent is satisfiable: `idCommitmentComp` for `Γ`, `trivialClaim`
    for `φ`, decidable throughout. -/
theorem trichotomy_P1_nonvacuous :
    ∃ S : Scheme idCommitmentComp trivialClaim,
      EnduringSound S ∧ Nonempty (∀ h c, Decidable (S.V h c)) :=
  trichotomy_P1 idCommitmentComp trivialClaim trivialClaim_determined Unit
    (fun _ _ => True) trivialClaim_hnp trivialClaim_monotone
    (fun _ _ => inferInstance) (fun _ _ _ => inferInstance)

end NonVacuity

/-! ## The DEC biconditional — §6.2's upgrade

The ⟸ direction (`trichotomy_P1` above) is one leg of `EonEalm.endurance_iff_
monotone` read at DEC. The other leg — a decidable-verifier enduring-sound
scheme forces `Determined`, a decidable Σ₁-checker, and `Monotone` — is the
F6 argument (`EonEalm.snapshot_characterization_np`) surviving decidability,
exactly as §6.2 proposed: `fun w t => S.V (Γ.C w) t` is decidable whenever
`S.V` is, and it inherits the same ↔ that makes `S.Proof` an NP-witness type
at ALL. `DecMembership` packages this as the DEC-stratum analogue of
`NPMembership`, carrying the extra decidability conjunct. -/

/-- DEC-stratum analogue of `NPMembership`: a Σ₁-witness checker whose ↔ is
    the same shape as `NPMembership`'s, plus a `Decidable` instance for the
    checker itself. `Decidable` is `Type`-valued (data, not a `Prop`), so —
    exactly as in `trichotomy_P1`'s conclusion — the decidability conjunct is
    `Nonempty`-wrapped to fit inside this `Prop`. Still Lean-`Decidable`, not
    Turing-computable (§6.6). -/
def DecMembership (ψ : Record → Prop) : Prop :=
  ∃ (Witness : Type) (Chk : Record → Witness → Prop),
    Nonempty (∀ w t, Decidable (Chk w t)) ∧ ∀ w, ψ w ↔ ∃ t, Chk w t

/-- **Probe P1, ⟹ direction** (DEC stratum). Any enduring-sound scheme whose
    verifier is decidable forces `φ` to be determined, `Monotone`, and
    `DecMembership` at its determined projection — the F6 argument
    (`EonEalm.snapshot_characterization_np`'s construction, `Chk w t :=
    S.V (Γ.C w) t`) reproduced here so the extracted `Chk` is the concrete
    term `hVDec` supplies decidability for, not an opaque existential
    witness. `Determined` and `Monotone` are the same two derivations
    `EonEalm.snapshot_characterization_determined` /
    `EonEalm.Result2.endurance_forces_monotone` perform, generic over any
    `Scheme`/`(Enduring)SnapshotSound`, so they compose from the imported
    lemmas rather than re-deriving EON/EALM's core. -/
theorem trichotomy_P1_forward {Comm : Type} {Γ : Commitment Comm} {φ : Claim}
    (S : Scheme Γ φ) (hsound : EnduringSound S)
    (hVDec : Nonempty (∀ h c, Decidable (S.V h c))) :
    ∃ hd : Determined φ, DecMembership (determinedProj φ hd) ∧ Monotone φ := by
  have hssound : SnapshotSound S := enduringSound_snapshotSound hsound
  have hd : Determined φ := snapshot_characterization_determined S hssound
  obtain ⟨hVDecFun⟩ := hVDec
  have hiff : ∀ w, determinedProj φ hd w ↔ ∃ t, S.V (Γ.C w) t := by
    intro w
    constructor
    · intro hφproj
      have hφ : φ w default := (determinedProj_iff hd w default).mp hφproj
      exact S.completeness w default hφ
    · rintro ⟨t, ht⟩
      exact (determinedProj_iff hd w default).mpr (hssound w t ht default)
  have hmono : Monotone φ := by
    intro w w' ξ hφ hww'
    obtain ⟨c, hc⟩ := S.completeness w ξ hφ
    exact hsound w c hc w' ξ hww'
  exact ⟨hd, ⟨S.Proof, fun w t => S.V (Γ.C w) t, ⟨fun w t => hVDecFun (Γ.C w) t⟩, hiff⟩, hmono⟩

/-- **The DEC biconditional** (§6.2's upgrade, `TT-end(DEC)` as a full iff).
    Fixing a commitment `Γ` whose `VC` is decidable, `φ` admits an
    enduring-sound scheme with a decidable verifier iff `φ` is `Determined`,
    `DecMembership` at its determined projection, and `Monotone` — DEC now
    matches ALL's shape (`EonEalm.endurance_iff_monotone`) at the decidable
    waypoint, not just the ⟸ leg. -/
theorem trichotomy_DEC_iff {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hVCDec : ∀ h₀ h π, Decidable (Γ.VC h₀ h π)) :
    (∃ S : Scheme Γ φ, EnduringSound S ∧ Nonempty (∀ h c, Decidable (S.V h c))) ↔
      ∃ hd : Determined φ, DecMembership (determinedProj φ hd) ∧ Monotone φ := by
  constructor
  · rintro ⟨S, hsound, hVDec⟩
    exact trichotomy_P1_forward S hsound hVDec
  · rintro ⟨hd, hdec, hm⟩
    obtain ⟨Witness, Chk, ⟨hChkDec⟩, hnp⟩ := hdec
    exact trichotomy_P1 Γ φ hd Witness Chk hnp hm hChkDec hVCDec

end Trichotomy
