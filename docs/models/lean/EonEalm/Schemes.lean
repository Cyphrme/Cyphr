import EonEalm.Axes
import EonEalm.Commitment

/-!
# Schemes — D5

A scheme `(C, V)` for a claim `φ`, plus **E1 stated as certificate existence, not an
efficient prover** — the round-2-verified correction to statement-v0.2's D5/E1 (team
correction, applied here; see below). `E3` (Offline / self-containedness) is not a
separate hypothesis to discharge: `Scheme.V`'s type, `Comm → Proof → Prop`, already
excludes record access, oracle access, interaction, a clock, and `ξ` — the signature
*is* the offline constraint ("a dial, not a gerrymander", statement-v0.2 D5). Poly-time
bounds (`V` poly-time, `|c| ≤ poly(|w|)`) are a Layer-C concern this Layer-L scaffold
does not encode, mirroring `EMLProof.Foundations`'s abstraction of `H` (no computability
constraint on the hash itself, only on where collision-resistance hypotheses are
discharged).

**Correction applied (P = NP defect).** The doc's original D5 bundled a poly-time
*prover* `P : Record → Proof` as part of a scheme, with E1 completeness stated as
`V(C(w), P(w)) = 1`. Composed with poly-time `C`/`V`, that prover function is itself a
poly-time decider for `φ̂` — since Result 1 (⟸) is claimed for *every* determined NP
`φ̂`, "a scheme exists" would force `φ̂ ∈ P` for arbitrary NP `φ̂`, i.e. an unconditional
`P = NP` obligation. The fix (verified, round-2): drop the bundled prover; state E1 as
bare **existence** of an accepting certificate,
`∀ (w, ξ) ⊨ φ, ∃ c, |c| ≤ poly(|w|) ∧ V(C(w), c) = 1` — an accepting certificate exists;
no efficient search procedure is asserted. The `snapshotScheme`/`enduringScheme`
constructions in `EonEalm.Result1`/`EonEalm.Result2` still *exhibit* `c` explicitly from
the NP witness, so nothing about the (⟸) constructions changes in substance — only the
bundled-prover field is gone, and NP-forcing (F6) survives unconditionally: `φ̂(w) ↔ ∃c,
V(C(w),c) = 1 ∧ |c| ≤ poly(|w|)` is exactly `φ̂ ∈ NP` from `V` poly-time and `|c|`
bounded alone, never from a poly prover. -/

namespace EonEalm

/-- Idealized (Layer L) "`ψ ∈ NP`": existence of a witness type and a checker whose
    ∃-closure is `ψ`. Poly-time boundedness is not modeled (see the module doc-comment);
    this captures the *shape* NP contributes to Result 1, not the complexity bound. Note
    this was already in ∃-certificate form (no bundled prover) before the D5/E1
    correction above — only `Scheme` needed the fix. -/
def NPMembership (ψ : Record → Prop) : Prop :=
  ∃ (Witness : Type) (Chk : Record → Witness → Prop), ∀ w, ψ w ↔ ∃ t, Chk w t

/-- D5 (corrected): a scheme `(V)` for `φ` over commitment `Γ`, with E1 in
    **∃-certificate form** — no bundled prover. -/
structure Scheme {Comm : Type} (Γ : Commitment Comm) (φ : Claim) where
  /-- The certificate type. -/
  Proof : Type
  /-- The verifier. -/
  V : Comm → Proof → Prop
  /-- E1 (Completeness), ∃-certificate form: an accepting certificate exists for every
      `(w, ξ) ⊨ φ`; no efficient prover is asserted. -/
  completeness : ∀ w ξ, φ w ξ → ∃ c, V (Γ.C w) c

/-- E2a (Snapshot soundness / context-independence). -/
def SnapshotSound {Comm : Type} {Γ : Commitment Comm} {φ : Claim} (S : Scheme Γ φ) : Prop :=
  ∀ w c, S.V (Γ.C w) c → ∀ ξ, φ w ξ

/-- E2b (Endurance — temporal). -/
def EnduringSound {Comm : Type} {Γ : Commitment Comm} {φ : Claim} (S : Scheme Γ φ) : Prop :=
  ∀ w c, S.V (Γ.C w) c → ∀ w' ξ, w ⊑ w' → φ w' ξ

/-- E2b ⟹ E2a via `w′ := w` (statement-v0.2 D5). STABLE, mechanical. -/
theorem enduringSound_snapshotSound {Comm : Type} {Γ : Commitment Comm} {φ : Claim}
    {S : Scheme Γ φ} (h : EnduringSound S) : SnapshotSound S :=
  fun w c hacc ξ => h w c hacc w ξ (ext_refl w)

end EonEalm
