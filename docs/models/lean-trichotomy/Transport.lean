import EonEalm.Model
import EonEalm.Axes

/-!
# Transport — the R-conservation transport law (4.3-T), mechanized

Mechanization target: `.scratch/trichotomy/statement-draft.md` §4.3-T (the
transport law) and `.scratch/trichotomy/break-r2/refuter-transport.md` (the
ρ/π maps and the destroys-case typing it derived). **Out of scope**: the
entailment law (4.3-E, the `ψ`/`B(a)` map) — a wholly different formal shape
(Context-gated, not a claim-transport at all) that this file does not touch.

**Why a parameterized copy, not an edit to `EonEalm.Model`/`Axes`.**
`EonEalm.Model`'s `Entry` is a single fixed `axiom Entry : Type`
(`Model.lean:21`) — the whole EON/EALM core is built over one alphabet. The
transport law is a statement about TWO alphabets related by an inclusion
(`R ⊑ R'`, pinned as the coproduct `Entry_R' ≅ Entry_R ⊕ New`,
statement-draft §1.1). Parameterizing `EonEalm.Model` itself over `Entry`
would destabilize every downstream EON/EALM theorem for a fact only this
transport law needs. Instead, `RecordOf`/`ExtOf`/`DeterminedOf`/`MonotoneOf`
below are a parameterized COPY of `Model.lean`'s D0 and `Axes.lean`'s
D3/D4 — same definitions, same proofs, generic over an abstract entry-type
argument — reusing only `EonEalm.Context` unchanged (imported, never
copied): §1.1/§4.3-E's load-bearing fact that `Context` is never touched by
`R` is exactly what licenses sharing the one `Context` type across both
schemas rather than parameterizing it too.

**Scope honestly delivered vs. refuter-transport's prediction.** The
refuter predicted the preservation theorem is "the same shape as
`determinedProj_monotone`, `Axes.lean:38-42`" — a one-line argument once the
supporting order-preservation fact for `π` is in hand. That held: the
preservation theorem itself (`erasurePullback_monotone`/
`erasurePullback_determined` below) is exactly as short as predicted. What
is NOT a one-liner is the foundation the prediction was silent on: standing
up `RecordOf`/`ExtOf` generically (with their own `refl`/`trans` proofs) and
the coproduct machinery (`ι`, `ι̂`, `π`, `π ∘ ι̂ = id`, `π`'s
order-preservation) from scratch, since none of it exists anywhere in the
Lean corpus (statement-draft §1.1's scope fact, confirmed here directly).
That foundation is small (it mirrors `Model.lean`/`Axes.lean` line-for-line,
substituting the axiom for a parameter) but it is real work, not zero. -/

namespace Trichotomy.Transport

open EonEalm (Context)

/-! ## D0, parameterized — `EonEalm.Model.lean`'s `Record`/`Ext`, verbatim,
generic over an abstract entry-type argument instead of the fixed axiom. -/

/-- Records over an arbitrary entry alphabet `E` (`EonEalm.Model.Record`,
    parameterized). -/
abbrev RecordOf (E : Type) := List E

/-- The extension order, parameterized (`EonEalm.Model.Ext`, verbatim). -/
def ExtOf {E : Type} (w w' : RecordOf E) : Prop := ∃ u : List E, w' = w ++ u

@[inherit_doc] scoped infix:50 " ⊑ " => ExtOf

theorem extOf_refl {E : Type} (w : RecordOf E) : w ⊑ w := ⟨[], by simp⟩

theorem extOf_trans {E : Type} {w w' w'' : RecordOf E}
    (h1 : w ⊑ w') (h2 : w' ⊑ w'') : w ⊑ w'' := by
  obtain ⟨u, hu⟩ := h1
  obtain ⟨u', hu'⟩ := h2
  exact ⟨u ++ u', by rw [hu', hu, List.append_assoc]⟩

/-! ## D2–D4, parameterized — claims, determination, monotonicity
(`EonEalm.Model.Claim` / `EonEalm.Axes.Determined` / `.Monotone`, verbatim,
generic over `E`; `Context` itself is `EonEalm.Context`, unparameterized —
see the module doc-comment). -/

abbrev ClaimOf (E : Type) := RecordOf E → Context → Prop

def DeterminedOf {E : Type} (φ : ClaimOf E) : Prop := ∀ w ξ ξ', φ w ξ ↔ φ w ξ'

def MonotoneOf {E : Type} (φ : ClaimOf E) : Prop :=
  ∀ w w' ξ, φ w ξ → w ⊑ w' → φ w' ξ

section CoproductExtension

/-! ## The coproduct extension `R ⊑ R'` (statement-draft §1.1, §4.3-T)

Pinned as `Entry_R' ≅ Entry_R ⊕ New` (an inclusion `ι : Entry_R ↪ Entry_R'`)
— refuter-transport §1's confirmed reading, the only one under which the
named levers (signer, cosign, revocation entries) are "new entry kinds." -/

variable (EntryR New : Type)

/-- The enlarged alphabet `Entry_R'`. -/
abbrev EntryR' := EntryR ⊕ New

/-- The inclusion `ι : Entry_R ↪ Entry_R'`. -/
def iota : EntryR → EntryR' EntryR New := Sum.inl

/-- The record embedding `ι̂ : Record_R → Record_R'` — elementwise, preserves
    `++` for free (`List.map` always does). -/
def iotaHat (w : RecordOf EntryR) : RecordOf (EntryR' EntryR New) :=
  w.map (iota EntryR New)

/-- The erasure `π : Record_R' → Record_R` — strip `New`-tagged entries, map
    `Entry_R`-tagged ones back along `ι⁻¹` (trivial: they already are
    `Entry_R` values under `Sum.inl`). -/
def pi (w' : RecordOf (EntryR' EntryR New)) : RecordOf EntryR :=
  w'.filterMap fun e => match e with
    | Sum.inl a => some a
    | Sum.inr _ => none

theorem iotaHat_append (w u : RecordOf EntryR) :
    iotaHat EntryR New (w ++ u) = iotaHat EntryR New w ++ iotaHat EntryR New u := by
  simp [iotaHat]

theorem pi_append (w' u' : RecordOf (EntryR' EntryR New)) :
    pi EntryR New (w' ++ u') = pi EntryR New w' ++ pi EntryR New u' := by
  simp [pi, List.filterMap_append]

/-- `π` is `⊑`-order-preserving: `w' ⊑ w'' ⟹ π(w') ⊑ π(w'')` — the direct
    analogue of `EonEalm.ext_trans`'s shape (`Axes.lean:38-42`'s style,
    refuter-transport's predicted argument), and the sole fact the
    preservation theorem below needs. -/
theorem pi_monotone_ext {w' w'' : RecordOf (EntryR' EntryR New)}
    (h : w' ⊑ w'') : pi EntryR New w' ⊑ pi EntryR New w'' := by
  obtain ⟨u', hu'⟩ := h
  exact ⟨pi EntryR New u', by rw [hu', pi_append]⟩

/-- `ι̂` is `⊑`-order-preserving — the mirror of `pi_monotone_ext`, needed for
    the reflection direction below: embedding a pure-R extension along `ι̂`
    stays an extension after embedding. -/
theorem iotaHat_monotone_ext {w w' : RecordOf EntryR}
    (h : w ⊑ w') : iotaHat EntryR New w ⊑ iotaHat EntryR New w' := by
  obtain ⟨u, hu⟩ := h
  exact ⟨iotaHat EntryR New u, by rw [hu, iotaHat_append]⟩

/-- **Reflection**: `π ∘ ι̂ = id` — erasing `New`-entries after embedding a
    pure-R record is the identity, since every embedded entry is `Sum.inl`. -/
theorem pi_iotaHat (w : RecordOf EntryR) :
    pi EntryR New (iotaHat EntryR New w) = w := by
  induction w with
  | nil => rfl
  | cons a w ih => simp [pi, iotaHat, iota] at ih ⊢; exact ih

end CoproductExtension

section Transports

/-! ## 4.3-T's two transports and the preservation theorem -/

variable (EntryR New : Type)

/-- **Restriction** `ρ : Claim_R' → Claim_R` — "what does the R'-claim say
    about pure-R records." Always exists; needs nothing beyond `ι̂`. -/
def rho (φ' : ClaimOf (EntryR' EntryR New)) : ClaimOf EntryR :=
  fun w ξ => φ' (iotaHat EntryR New w) ξ

/-- **Erasure-pullback** `φ ↦ φ∘π : Claim_R → Claim_R'` — needs the
    coproduct (`π`). -/
def erasurePullback (φ : ClaimOf EntryR) : ClaimOf (EntryR' EntryR New) :=
  fun w' ξ => φ (pi EntryR New w') ξ

/-- **Preservation theorem, monotonicity half** (4.3-T; exactly the shape
    refuter-transport predicted, `Axes.lean:38-42`-style): erasure-pullback
    can never destroy `Monotone`. -/
theorem erasurePullback_monotone {φ : ClaimOf EntryR} (hm : MonotoneOf φ) :
    MonotoneOf (erasurePullback EntryR New φ) := by
  intro w' w'' ξ hφ hext
  exact hm (pi EntryR New w') (pi EntryR New w'') ξ hφ (pi_monotone_ext EntryR New hext)

/-- **Preservation theorem, determination half**: erasure-pullback inherits
    `Determined` for free — `π` never touches `ξ`. -/
theorem erasurePullback_determined {φ : ClaimOf EntryR} (hd : DeterminedOf φ) :
    DeterminedOf (erasurePullback EntryR New φ) :=
  fun w' ξ ξ' => hd (pi EntryR New w') ξ ξ'

/-! ## Reflection — Neutral cures are uninhabited off the complexity axis
(statement-draft §4.3-T's corollary, §4.3's "Neutral cures exist only on the
complexity axis"). The section `π ∘ ι̂ = id` (`pi_iotaHat`) means
erasure-pullback does not merely preserve `Determined`/`Monotone` — it
*reflects* their failure too: pull a witness back along `ι̂`, run the
preservation-direction argument on it, then erase along `π ∘ ι̂ = id` to land
exactly where it started. -/

/-- **Reflection, monotonicity half**: if the erasure-pullback of `φ` is
    `Monotone`, so was `φ` — the converse of `erasurePullback_monotone`, via
    `ι̂`'s order-preservation (`iotaHat_monotone_ext`) and the section
    `π ∘ ι̂ = id` (`pi_iotaHat`). -/
theorem erasurePullback_reflects_monotone {φ : ClaimOf EntryR}
    (hrefl : MonotoneOf (erasurePullback EntryR New φ)) : MonotoneOf φ := by
  intro w w' ξ hφ hext
  -- The `have`'s type ascription unfolds `erasurePullback` by defeq
  -- (delta+beta only — no induction, valid for a free variable); the
  -- further reduction `pi (iotaHat _) = _` is `pi_iotaHat`, a proved
  -- equality (by induction), not defeq, so it needs an explicit `rw`.
  have h1 : erasurePullback EntryR New φ (iotaHat EntryR New w) ξ := by
    show φ (pi EntryR New (iotaHat EntryR New w)) ξ
    rwa [pi_iotaHat]
  have h2 : φ (pi EntryR New (iotaHat EntryR New w')) ξ :=
    hrefl (iotaHat EntryR New w) (iotaHat EntryR New w') ξ h1
      (iotaHat_monotone_ext EntryR New hext)
  rwa [pi_iotaHat] at h2

/-- **Reflection, determination half**: if the erasure-pullback of `φ` is
    `Determined`, so was `φ` — instantiate at `ι̂ w` and erase back via
    `π ∘ ι̂ = id`. -/
theorem erasurePullback_reflects_determined {φ : ClaimOf EntryR}
    (hrefl : DeterminedOf (erasurePullback EntryR New φ)) : DeterminedOf φ := by
  intro w ξ ξ'
  -- Ascribed type unfolds `erasurePullback` by defeq (delta+beta); `at`
  -- doesn't apply to `show`, so the unfold is done via the `have`'s type
  -- annotation instead, then `pi_iotaHat` closes the rest by `rw`.
  have h : φ (pi EntryR New (iotaHat EntryR New w)) ξ ↔
      φ (pi EntryR New (iotaHat EntryR New w)) ξ' :=
    hrefl (iotaHat EntryR New w) ξ ξ'
  rwa [pi_iotaHat] at h

/-- Erasure-pullback preserves AND reflects `Monotone` — a π-coherent claim's
    monotonicity status is exactly its pre-image's, in both directions. -/
theorem erasurePullback_monotone_iff {φ : ClaimOf EntryR} :
    MonotoneOf (erasurePullback EntryR New φ) ↔ MonotoneOf φ :=
  ⟨erasurePullback_reflects_monotone EntryR New, erasurePullback_monotone EntryR New⟩

/-- Erasure-pullback preserves AND reflects `Determined` — a π-coherent
    claim's determination status is exactly its pre-image's, in both
    directions. -/
theorem erasurePullback_determined_iff {φ : ClaimOf EntryR} :
    DeterminedOf (erasurePullback EntryR New φ) ↔ DeterminedOf φ :=
  ⟨erasurePullback_reflects_determined EntryR New, erasurePullback_determined EntryR New⟩

/-- **Neutral cannot cure** (statement-draft §4.3's corollary from `π ∘ ι̂ =
    id`): since erasure-pullback both preserves and reflects determination and
    monotonicity, a Neutral (π-coherent) move cannot turn a `¬Determined` or
    `¬Monotone` claim into a fixed one — a π-coherent `φ' = φ∘π` inherits
    every determination and monotonicity failure of `φ` exactly, so a Neutral
    "cure" is uninhabited for those two axes; every genuine T1/T3 cure is
    entailment-shaped (4.3-E), never Neutral. -/
theorem neutral_cannot_cure {φ : ClaimOf EntryR} :
    (¬ DeterminedOf φ → ¬ DeterminedOf (erasurePullback EntryR New φ)) ∧
    (¬ MonotoneOf φ → ¬ MonotoneOf (erasurePullback EntryR New φ)) :=
  ⟨fun h hc => h ((erasurePullback_determined_iff EntryR New).mp hc),
   fun h hc => h ((erasurePullback_monotone_iff EntryR New).mp hc)⟩

end Transports

section DestroysCase

/-! ## The destroys-case, correctly typed (statement-draft §4.3-T,
refuter-transport §3's worked revocation lever): a concrete `φ'` that is
`ρ`-coherent but provably NOT `π`-coherent. -/

variable {EntryR : Type} (e : EntryR)

/-- New-kind alphabet for this lever: a revocation entry names which
    existing entry it revokes — one revocation kind per `EntryR` value
    (refuter-transport §3's reading). -/
abbrev Revoke (EntryR : Type) := EntryR

/-- `φ` over R: "`e` is present." Trivially `Determined` (`ξ` unused) and
    `Monotone` (list-append never removes a membership witness) — the
    corpus's monotone-determined cell. -/
def presentClaim : ClaimOf EntryR := fun w _ => e ∈ w

theorem presentClaim_determined : DeterminedOf (presentClaim e) :=
  fun _ _ _ => Iff.rfl

theorem presentClaim_monotone : MonotoneOf (presentClaim e) := by
  rintro w w' _ hφ ⟨u, rfl⟩
  exact List.mem_append_left u hφ

/-- `φ'` over R': "`e` is present and has never been revoked" — the
    statement's "e ∈ w' ∧ no later revocation of e," simplified to "no
    revocation of e anywhere in w'" (sufficient to exhibit the
    non-monotonicity the destroys-case names; the "later than last
    occurrence" reading only makes the failure easier to witness, never
    harder). -/
def revokedClaim (w' : RecordOf (EntryR' EntryR (Revoke EntryR))) (_ : Context) : Prop :=
  Sum.inl e ∈ w' ∧ Sum.inr e ∉ w'

/-- **ρ-coherent**: at `w' = ι̂(w)` (no revocation entries at all — every
    embedded entry is `Sum.inl`), `φ'` collapses to exactly `φ`. -/
theorem revokedClaim_rho_coherent (w : RecordOf EntryR) (ξ : Context) :
    revokedClaim e (iotaHat EntryR (Revoke EntryR) w) ξ ↔ presentClaim e w ξ := by
  simp only [revokedClaim, presentClaim, iotaHat, iota, List.mem_map]
  constructor
  · rintro ⟨⟨a, ha, haa⟩, -⟩
    cases haa
    exact ha
  · intro hin
    refine ⟨⟨e, hin, rfl⟩, ?_⟩
    rintro ⟨a, -, h⟩
    simp at h

/-- The witness record `[ι e]` — `e` present, nothing revoked yet. -/
def revokedWitness : RecordOf (EntryR' EntryR (Revoke EntryR)) := [Sum.inl e]

/-- Extending the witness by a single revocation of `e`. -/
def revokedExtended : RecordOf (EntryR' EntryR (Revoke EntryR)) :=
  revokedWitness e ++ [Sum.inr e]

theorem revokedWitness_ext_revokedExtended :
    revokedWitness e ⊑ revokedExtended e := ⟨[Sum.inr e], rfl⟩

/-- **NOT π-coherent**: `φ'` is not `Monotone` — the witness record has `e`
    present-and-unrevoked, but appending a single revocation of `e` flips it
    false. By the preservation theorem, `φ ∘ π` (erasure-pullback of the
    monotone `presentClaim`) IS `Monotone`; hence `φ' ≠ φ ∘ π`, the
    destroys-case's exact typing (ρ-coherent, not π-coherent). -/
theorem revokedClaim_not_monotone (ξ : Context) :
    ¬ MonotoneOf (revokedClaim (EntryR := EntryR) e) := by
  intro hmono
  have hwit : revokedClaim e (revokedWitness e) ξ := by
    constructor
    · simp [revokedWitness]
    · simp [revokedWitness]
  have hext := hmono (revokedWitness e) (revokedExtended e) ξ hwit
    (revokedWitness_ext_revokedExtended e)
  have hnotrevoked := hext.2
  exact hnotrevoked (by simp [revokedExtended])

/-- **The destroys-case, as a theorem**: `revokedClaim e` is ρ-coherent with
    `presentClaim e` (previous lemma) yet not equal to its erasure-pullback,
    since the erasure-pullback of a `Monotone` claim is always `Monotone`
    (the preservation theorem) while `revokedClaim e` provably is not. -/
theorem revokedClaim_not_pi_coherent (ξ : Context) :
    revokedClaim (EntryR := EntryR) e ≠
      erasurePullback EntryR (Revoke EntryR) (presentClaim e) := by
  intro heq
  have : MonotoneOf (revokedClaim (EntryR := EntryR) e) := by
    rw [heq]
    exact erasurePullback_monotone EntryR (Revoke EntryR) (presentClaim_monotone e)
  exact revokedClaim_not_monotone e ξ this

end DestroysCase

section EonEalmBridge

/-! ## Closing the seam (§6.4): the parameterized copy IS EON/EALM's own

The module doc-comment's fidelity claim — "same definitions, same proofs,
generic over an abstract entry-type argument" — is checked here directly
rather than asserted: at `E := EonEalm.Entry`, every parameterized notion
above is **definitionally** (not merely propositionally) equal to the
fixed-`Entry` original it copies, because substituting the one axiom for the
parameter is the *only* difference the copy introduces. Each bridge is
`rfl`: no unfolding lemma, no induction, nothing to diverge on. -/

theorem recordOf_entry_eq : RecordOf EonEalm.Entry = EonEalm.Record := rfl

theorem extOf_entry_eq : (ExtOf (E := EonEalm.Entry)) = EonEalm.Ext := rfl

theorem claimOf_entry_eq : ClaimOf EonEalm.Entry = EonEalm.Claim := rfl

theorem determinedOf_entry_eq :
    (DeterminedOf (E := EonEalm.Entry)) = EonEalm.Determined := rfl

theorem monotoneOf_entry_eq :
    (MonotoneOf (E := EonEalm.Entry)) = EonEalm.Monotone := rfl

end EonEalmBridge

section GenuinePayoff

/-! ## The genuine EON/EALM payoff (§6.4, closed)

The bridge above means `EntryR := EonEalm.Entry` is not merely "a stand-in
alphabet the same size as `Entry`" — it *is* `Entry`, so a hypothesis stated
as `EonEalm.Determined`/`EonEalm.Monotone` (an actual claim over actual
EON/EALM records) already has the type the transport theorems need, and
their conclusions already read as actual `EonEalm.Determined`/`Monotone`
statements. No restatement, no `▸`, no coercion: elaboration accepts
`hd : EonEalm.Determined φ` where `DeterminedOf φ` is expected because the
two are the same proposition. -/

/-- **Transport applies to genuine EON/EALM claims**: for any real
    `φ : EonEalm.Claim`, erasure-pullback along the coproduct extension
    `Entry ⊕ New` both preserves and reflects `EonEalm.Determined` and
    `EonEalm.Monotone` — the destroys-case (`revokedClaim_not_pi_coherent`)
    is the demonstration that this is the tightest true statement: preserved
    for π-coherent claims, and NOT provable for the wider ρ-coherent class
    the destroys-case inhabits. -/
theorem transport_applies_to_eonEalm (New : Type) {φ : EonEalm.Claim} :
    (DeterminedOf (erasurePullback EonEalm.Entry New φ) ↔ EonEalm.Determined φ) ∧
    (MonotoneOf (erasurePullback EonEalm.Entry New φ) ↔ EonEalm.Monotone φ) :=
  ⟨erasurePullback_determined_iff EonEalm.Entry New,
   erasurePullback_monotone_iff EonEalm.Entry New⟩

end GenuinePayoff

end Trichotomy.Transport
