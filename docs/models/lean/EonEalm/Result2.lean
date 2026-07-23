import EonEalm.Result1

/-!
# Result 2 — EALM: Endurance As Logical Monotonicity

Scoped inside Result 1's gate: for record-determined `φ` with `φ̂ ∈ NP`, `φ` admits an
**enduring** scheme iff `φ̂` is monotone (D4). STABLE (⟸ construction); ⚠ (⟹, A1′).

The (⟸) direction is the round-1-certified construction: `c := (w₀, t, π)` with
`w₀ := w` (E1's own witness point — "E1 with w₀ := w"), `t` an NP-witness for `φ̂(w₀)`,
`π` a reflexive VC-completeness proof `VC(C(w₀), C(w₀), π)`. Binding + VC-soundness
force `c.w₀ ⊑ w` for any *later* verification anchor `w`; monotonicity then lifts
`φ̂(c.w₀)` to `w` and, transitively, to any `w' ⊒ w` — the transport across the trust
boundary that Ahman et al. (POPL 2018)'s stable-predicate ⟹ recallable-witness result
performs *inside* the mechanization target (F5), via `Commitment.soundness`.
-/

namespace EonEalm

/-- (⟸) The round-1-certified enduring-scheme construction. `E1` exhibits `c` directly
    from the NP witness and the reflexive `VC`-completeness proof — no prover function
    is bundled (D5/E1 correction, see `EonEalm.Schemes`). -/
def enduringScheme {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hd : Determined φ) (Witness : Type) (Chk : Record → Witness → Prop)
    (hnp : ∀ w, determinedProj φ hd w ↔ ∃ t, Chk w t) : Scheme Γ φ where
  Proof := Record × Witness × Γ.VCProof
  V := fun h c => Chk c.1 c.2.1 ∧ Γ.VC (Γ.C c.1) h c.2.2
  completeness := fun w ξ hφ => by
    have hφ' : determinedProj φ hd w := (determinedProj_iff hd w ξ).mpr hφ
    obtain ⟨t, ht⟩ := (hnp w).mp hφ'
    obtain ⟨π, hπ⟩ := Γ.completeness w w (ext_refl w)
    exact ⟨(w, t, π), ht, hπ⟩

theorem enduringScheme_enduringSound {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hd : Determined φ) (hm : Monotone φ) (Witness : Type) (Chk : Record → Witness → Prop)
    (hnp : ∀ w, determinedProj φ hd w ↔ ∃ t, Chk w t) :
    EnduringSound (enduringScheme Γ φ hd Witness Chk hnp) := by
  intro w c hacc w' ξ hww'
  obtain ⟨hchk, hvc⟩ := hacc
  have hw0w : c.1 ⊑ w := Γ.soundness c.1 w (Γ.C c.1) (Γ.C w) c.2.2 hvc rfl rfl
  have hφ'c1 : determinedProj φ hd c.1 := (hnp c.1).mpr ⟨c.2.1, hchk⟩
  have hφc1 : φ c.1 ξ := (determinedProj_iff hd c.1 ξ).mp hφ'c1
  have hφw : φ w ξ := hm c.1 w ξ hφc1 hw0w
  exact hm w w' ξ hφw hww'

/-- (⟸) Endurance construction, packaged. STABLE. -/
theorem endurance_construction {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hd : Determined φ) (hm : Monotone φ) (hnp : NPMembership (determinedProj φ hd)) :
    ∃ S : Scheme Γ φ, EnduringSound S := by
  obtain ⟨Witness, Chk, hchk⟩ := hnp
  exact ⟨enduringScheme Γ φ hd Witness Chk hchk,
    enduringScheme_enduringSound Γ φ hd hm Witness Chk hchk⟩

/-- (⟹), ⚠ round-2 (A1′). Near-definitional per statement-v0.2 (E2b + E1) — but the
    *force* of the claim (E2b's canonicity as "endurance", paired with Result 1's
    characterization of what evidence additionally buys) is fresh, unattacked ground.
    Do not discharge past this `sorry` until round 2 clears A1′. -/
theorem endurance_forces_monotone {Comm : Type} {Γ : Commitment Comm} {φ : Claim}
    (hd : Determined φ) (hnp : NPMembership (determinedProj φ hd)) {S : Scheme Γ φ}
    (hsound : EnduringSound S) : Monotone φ := by
  sorry -- ⚠ round-2 (A1′): E2b canonicity + Result-1 pairing, fresh/unattacked

/-- Result 2, packaged as a single iff (statement-v0.2 §3). STABLE ⟸, ⚠ ⟹ (A1′) —
    the `sorry` lives entirely in `endurance_forces_monotone`. -/
theorem endurance_iff_monotone {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hd : Determined φ) (hnp : NPMembership (determinedProj φ hd)) :
    (∃ S : Scheme Γ φ, EnduringSound S) ↔ Monotone φ := by
  constructor
  · rintro ⟨S, hS⟩
    exact endurance_forces_monotone hd hnp hS
  · intro hm
    exact endurance_construction Γ φ hd hm hnp

end EonEalm
