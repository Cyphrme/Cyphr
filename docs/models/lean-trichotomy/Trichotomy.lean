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

/-! ## A contentful non-vacuity witness — the inclusion claim

`trichotomy_P1_nonvacuous` above witnesses P1's antecedent with `trivialClaim`
(`⊤`), determined and monotone for free precisely because it asserts nothing.
The canonical **contentful** witness — surety's own worked example, and
EON/EALM's Result-1 paradigm case — is the inclusion claim: "entry `e`
appears in the record". It is determined (membership doesn't read the
context), monotone (list-append never removes a membership witness), and its
determined projection is `DecMembership` given `[DecidableEq Entry]` — so it
satisfies `trichotomy_DEC_iff`'s antecedent with a genuine claim, not a
degenerate one. -/

/-- The inclusion claim: `e` appears in the record `w`. Ignores the ambient
    context entirely. -/
def inclusionClaim (e : Entry) : Claim := fun w _ => e ∈ w

theorem inclusionClaim_determined (e : Entry) : Determined (inclusionClaim e) :=
  fun _ _ _ => Iff.rfl

/-- D4: list-append can only add entries, so a membership witness for `w`
    survives to any `w'` extending it. -/
theorem inclusionClaim_monotone (e : Entry) : Monotone (inclusionClaim e) := by
  intro w w' _ hmem hext
  obtain ⟨u, hu⟩ := hext
  rw [hu]
  exact List.mem_append_left u hmem

theorem inclusionClaim_hnp (e : Entry) :
    ∀ w, determinedProj (inclusionClaim e) (inclusionClaim_determined e) w ↔
      ∃ _ : Unit, e ∈ w :=
  fun _ => ⟨fun h => ⟨(), h⟩, fun ⟨_, h⟩ => h⟩

section NonVacuityContentful

variable [DecidableEq Entry]

/-- `inclusionClaim`'s determined projection is `DecMembership`, witnessed by
    the unit checker `Chk w _ := e ∈ w`. Decidability comes from
    `[DecidableEq Entry]` feeding Lean core's `DecidableEq → BEq` /
    `DecidableEq → LawfulBEq` instances (`Init.Prelude`/`Init.Core`), which in
    turn feed `List.Basic`'s `Decidable (a ∈ as)` instance — no Mathlib
    needed, consistent with this package's no-Mathlib discipline. -/
theorem inclusionClaim_decMembership (e : Entry) :
    DecMembership (determinedProj (inclusionClaim e) (inclusionClaim_determined e)) :=
  ⟨Unit, fun w _ => e ∈ w, ⟨fun _ _ => inferInstance⟩, inclusionClaim_hnp e⟩

/-- **The contentful non-vacuity witness.** The inclusion claim admits an
    enduring-sound scheme with a decidable verifier over `idCommitmentComp` —
    via `trichotomy_DEC_iff`'s ⟸ direction, so the DEC biconditional
    genuinely bites on a claim with real content, not just `trivialClaim`. -/
theorem trichotomy_DEC_nonvacuous_contentful (e : Entry) :
    ∃ S : Scheme idCommitmentComp (inclusionClaim e),
      EnduringSound S ∧ Nonempty (∀ h c, Decidable (S.V h c)) :=
  (trichotomy_DEC_iff idCommitmentComp (inclusionClaim e)
      (fun _ _ _ => inferInstance)).mpr
    ⟨inclusionClaim_determined e, inclusionClaim_decMembership e, inclusionClaim_monotone e⟩

end NonVacuityContentful

/-! ## TT-snap(DEC) — the snapshot-sound biconditional (§3.4's cheapest gap)

The snapshot analogue of `trichotomy_DEC_iff`: drop `EnduringSound`'s temporal
reach and the `Monotone` conjunct, since a snapshot-sound scheme need only
certify the record it is checked against, not endure past it.

**Obstruction found — reported, not silently absorbed.** The dispatch
predicted this leg is `trichotomy_P1` minus endurance, provable from exactly
`hChkDec`/`hVCDec`, no new hypothesis. That prediction does NOT survive
unchanged. `trichotomy_P1`'s (⟸) construction, `enduringScheme`, proves
`SnapshotSound` only by first proving `EnduringSound`
(`enduringSound_snapshotSound`), and `enduringScheme_enduringSound` needs
`Monotone` to bridge the certificate's record `c.1` to the record `w` actually
being checked (`Γ.soundness` only yields `c.1 ⊑ w`, an extension, not
`c.1 = w`) — so `enduringScheme` cannot supply a snapshot-only proof without
`Monotone` after all, exactly the kind of obstruction flagged as STOP-worthy.

The genuinely snapshot-only construction is `EonEalm.snapshotScheme`
(Result 1) instead: its verifier checks the certificate's record against `h`
by **raw equality** (`Γ.C c.1 = h`), never a `VC`-relation, precisely because
a snapshot verifier commits to *this* record, not one reached from an earlier
one by `Monotone`. But that equality check's decidability is
`Decidable (Γ.C c.1 = h)` — decidable equality *on `Comm`* at those two
points — which neither `hChkDec` (about `Chk`) nor `hVCDec` (about the
abstract relation `Γ.VC`, not `=`) supplies; `VC`-decidability says nothing
about deciding raw `Comm` equality. The honest fix adds exactly this one
hypothesis (`hCommDec`), spelled out the same way the file already spells out
`hChkDec`/`hVCDec` (a bare `Prop` hypothesis, resolved via `haveI`, per the
module doc-comment's rationale) — not a weakening (no conjunct dropped, no
`sorry`) and not `Monotone` returning, but a distinct, minimal, unavoidable
requirement specific to the snapshot-only construction. -/

/-- **TT-snap(DEC), ⟸ direction.** Given a determined claim `φ` whose Σ₁
    witness-checker `Chk` is decidable, and decidable equality on the
    commitment codomain `Comm` (`hCommDec` — the extra hypothesis this
    direction needs beyond `trichotomy_P1`'s, see the section doc-comment),
    `φ` admits a snapshot-sound scheme with a decidable verifier.
    `EonEalm.snapshotScheme` verbatim; no `Monotone` hypothesis anywhere. -/
theorem trichotomy_snap_P1
    {Comm : Type} (Γ : Commitment Comm)
    (φ : Claim) (hd : Determined φ)
    (Witness : Type) (Chk : Record → Witness → Prop)
    (hnp : ∀ w, determinedProj φ hd w ↔ ∃ t, Chk w t)
    (hChkDec : ∀ w t, Decidable (Chk w t))
    (hCommDec : ∀ a b : Comm, Decidable (a = b)) :
    ∃ S : Scheme Γ φ, SnapshotSound S ∧ Nonempty (∀ h c, Decidable (S.V h c)) := by
  refine ⟨snapshotScheme Γ φ hd Witness Chk hnp,
    snapshotScheme_snapshotSound Γ φ hd Witness Chk hnp, ⟨fun h c => ?_⟩⟩
  haveI := hChkDec c.1 c.2
  haveI := hCommDec (Γ.C c.1) h
  -- `snapshotScheme`'s `V h c := Γ.C c.1 = h ∧ Chk c.1 c.2` (certificate type
  -- `Record × Witness`, so `c.2 : Witness` directly, unlike `enduringScheme`'s
  -- right-associated triple). `show` unfolds the `def`-hidden `V`.
  show Decidable (Γ.C c.1 = h ∧ Chk c.1 c.2)
  infer_instance

/-- **TT-snap(DEC), ⟹ direction.** Any snapshot-sound scheme with a decidable
    verifier forces `φ` determined and `DecMembership` at its determined
    projection — `trichotomy_P1_forward` minus the `Monotone` conjunct (that
    conjunct's derivation there used `EnduringSound`'s reach past the
    certificate's own record; nothing here needs it). -/
theorem trichotomy_snap_P1_forward {Comm : Type} {Γ : Commitment Comm} {φ : Claim}
    (S : Scheme Γ φ) (hssound : SnapshotSound S)
    (hVDec : Nonempty (∀ h c, Decidable (S.V h c))) :
    ∃ hd : Determined φ, DecMembership (determinedProj φ hd) := by
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
  exact ⟨hd, ⟨S.Proof, fun w t => S.V (Γ.C w) t, ⟨fun w t => hVDecFun (Γ.C w) t⟩, hiff⟩⟩

/-- **The TT-snap(DEC) biconditional.** Fixing a commitment `Γ` with decidable
    equality on `Comm` (the obstruction the section doc-comment reports), `φ`
    admits a snapshot-sound scheme with a decidable verifier iff `φ` is
    `Determined` and `DecMembership` at its determined projection — the
    snapshot mirror of `trichotomy_DEC_iff`, with no `Monotone` conjunct on
    either side. -/
theorem trichotomy_snap_DEC_iff
    {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hCommDec : ∀ a b : Comm, Decidable (a = b)) :
    (∃ S : Scheme Γ φ, SnapshotSound S ∧ Nonempty (∀ h c, Decidable (S.V h c))) ↔
      ∃ hd : Determined φ, DecMembership (determinedProj φ hd) := by
  constructor
  · rintro ⟨S, hssound, hVDec⟩
    exact trichotomy_snap_P1_forward S hssound hVDec
  · rintro ⟨hd, hdec⟩
    obtain ⟨Witness, Chk, ⟨hChkDec⟩, hnp⟩ := hdec
    exact trichotomy_snap_P1 Γ φ hd Witness Chk hnp hChkDec hCommDec

/-! ## `npMembership_trivial` — the honesty lemma (§3.4's standing obligation)

`EonEalm.NPMembership` (`Schemes.lean:40-41`) is vacuously satisfiable for
*any* predicate — this is the in-code record of exactly why: it means the
mechanized Results 1–3 (built on `NPMembership`) sit at the ALL stratum, not
genuinely at NP, until a non-vacuous witness (the inclusion-claim strengthening
named in the statement draft, still unlanded) replaces it. -/

/-- **`NPMembership` is trivial**: every predicate `ψ` satisfies it, witnessed
    by `Unit` and `Chk w _ := ψ w` — the same construction the statement
    draft's honesty note names for `NPMembership` at `Schemes.lean:40-41`. -/
theorem npMembership_trivial (ψ : Record → Prop) : NPMembership ψ :=
  ⟨Unit, fun w _ => ψ w, fun _w => ⟨fun h => ⟨(), h⟩, fun ⟨_, h⟩ => h⟩⟩

end Trichotomy
