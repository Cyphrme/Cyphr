import EonEalm.Schemes

/-!
# Result 1 — Snapshot Characterization (STABLE, both directions)

`φ` admits a snapshot scheme iff record-determined ∧ `φ̂ ∈ NP` (Layer L).
-/

namespace EonEalm

/-- (⟸) The witness/checker construction: `c := (w, t)`, `t` an NP-witness for `φ̂(w)`;
    `V` checks `C(w) = h ∧ Chk(w, t)`. Includes non-monotone determined claims
    (e.g. sparse-Merkle non-membership). E1 exhibits `c` directly from the NP witness —
    no prover function is bundled (D5/E1 correction, see `EonEalm.Schemes`). -/
def snapshotScheme {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hd : Determined φ) (Witness : Type) (Chk : Record → Witness → Prop)
    (hnp : ∀ w, determinedProj φ hd w ↔ ∃ t, Chk w t) : Scheme Γ φ where
  Proof := Record × Witness
  V := fun h c => Γ.C c.1 = h ∧ Chk c.1 c.2
  completeness := fun w ξ hφ => by
    have hφ' : determinedProj φ hd w := (determinedProj_iff hd w ξ).mpr hφ
    obtain ⟨t, ht⟩ := (hnp w).mp hφ'
    exact ⟨(w, t), rfl, ht⟩

theorem snapshotScheme_snapshotSound {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hd : Determined φ) (Witness : Type) (Chk : Record → Witness → Prop)
    (hnp : ∀ w, determinedProj φ hd w ↔ ∃ t, Chk w t) :
    SnapshotSound (snapshotScheme Γ φ hd Witness Chk hnp) := by
  intro w c hacc ξ
  obtain ⟨hCeq, hchk⟩ := hacc
  have hCw : c.1 = w := Γ.binding c.1 w hCeq
  have hchk' : Chk w c.2 := by rw [hCw] at hchk; exact hchk
  have hφ' : determinedProj φ hd w := (hnp w).mpr ⟨c.2, hchk'⟩
  exact (determinedProj_iff hd w ξ).mp hφ'

/-- (⟸) Snapshot Characterization, backward direction. STABLE. -/
theorem snapshot_characterization_backward {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hd : Determined φ) (hnp : NPMembership (determinedProj φ hd)) :
    ∃ S : Scheme Γ φ, SnapshotSound S := by
  obtain ⟨Witness, Chk, hchk⟩ := hnp
  exact ⟨snapshotScheme Γ φ hd Witness Chk hchk,
    snapshotScheme_snapshotSound Γ φ hd Witness Chk hchk⟩

/-- (⟹ determination) Any scheme's snapshot-soundness forces `φ` to be record-determined
    — `E1` gives an accepting `c`; `E2a` forces `φ(w,ξ′)` for every `ξ′`. STABLE. -/
theorem snapshot_characterization_determined {Comm : Type} {Γ : Commitment Comm} {φ : Claim}
    (S : Scheme Γ φ) (hsound : SnapshotSound S) : Determined φ := by
  intro w ξ ξ'
  constructor
  · intro h
    obtain ⟨c, hc⟩ := S.completeness w ξ h
    exact hsound w c hc ξ'
  · intro h
    obtain ⟨c, hc⟩ := S.completeness w ξ' h
    exact hsound w c hc ξ

/-- (⟹ NP, the F6 gift) `Chk(w,t) := V(C(w),t)` is (idealized) poly; `NP` is a
    *consequence* of any scheme existing (via E1's certificate existence, not an
    efficient prover), not an added scope condition. STABLE. -/
theorem snapshot_characterization_np {Comm : Type} {Γ : Commitment Comm} {φ : Claim}
    (hd : Determined φ) (S : Scheme Γ φ) (hsound : SnapshotSound S) :
    NPMembership (determinedProj φ hd) := by
  refine ⟨S.Proof, fun w t => S.V (Γ.C w) t, fun w => ⟨?_, ?_⟩⟩
  · intro hφproj
    have hφ : φ w default := (determinedProj_iff hd w default).mp hφproj
    exact S.completeness w default hφ
  · rintro ⟨t, ht⟩
    exact (determinedProj_iff hd w default).mpr (hsound w t ht default)

/-- Snapshot Characterization, packaged as a single iff (both directions; STABLE). -/
theorem snapshot_characterization {Comm : Type} (Γ : Commitment Comm) (φ : Claim) :
    (∃ S : Scheme Γ φ, SnapshotSound S) ↔
      ∃ hd : Determined φ, NPMembership (determinedProj φ hd) := by
  constructor
  · rintro ⟨S, hS⟩
    exact ⟨snapshot_characterization_determined S hS,
      snapshot_characterization_np (snapshot_characterization_determined S hS) S hS⟩
  · rintro ⟨hd, hnp⟩
    exact snapshot_characterization_backward Γ φ hd hnp

end EonEalm
