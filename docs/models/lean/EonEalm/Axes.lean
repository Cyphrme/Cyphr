import EonEalm.Model

/-!
# Axes — D3 (record-determined) and D4 (same-context monotone)

The two orthogonal axes statement-v0.2 §2 builds Results 1–3 from. D4 is the
**F2-corrected** version: `w ⊑ w'` lifts `φ(w,ξ)` to `φ(w',ξ)` holding the **same** `ξ`
on both sides — v0.1's `∀ξ'` version implied D3 at `w' = w` and collapsed the axes.

Lemma 1 (orthogonality, the 2×2 table with concrete example claims per cell) is not
mechanized here: it is an illustrative table over concrete instance claims, not a build
target the §6 order lists, and instantiating each cell would add scope beyond D0–D6.
D4′ (the syntactic ∃⁺ fragment / Łoś–Tarski) is likewise "Not mechanized" per the source
spec (`statement-v0.2.md` §6).
-/

namespace EonEalm

/-- D3 (Record-determined). `φ`'s truth does not depend on which ambient context `ξ`
    witnesses it. -/
def Determined (φ : Claim) : Prop := ∀ w ξ ξ', φ w ξ ↔ φ w ξ'

/-- The unique record-only projection `φ̂` of a determined claim (Ξ inhabited licenses
    picking any witness context). -/
noncomputable def determinedProj (φ : Claim) (_hd : Determined φ) : Record → Prop :=
  fun w => φ w default

theorem determinedProj_iff {φ : Claim} (hd : Determined φ) (w : Record) (ξ : Context) :
    determinedProj φ hd w ↔ φ w ξ :=
  hd w default ξ

/-- D4 (Monotone — same context; the F2 correction). -/
def Monotone (φ : Claim) : Prop := ∀ w w' ξ, φ w ξ → w ⊑ w' → φ w' ξ

/-- For a determined `φ`, monotonicity lifts along `⊑` on the record-only projection
    `φ̂` (statement-v0.2 D4, "For determined φ: φ̂(w) ∧ w ⊑ w′ ⟹ φ̂(w′)"). -/
theorem determinedProj_monotone {φ : Claim} (hd : Determined φ) (hm : Monotone φ)
    (w w' : Record) (h : determinedProj φ hd w) (hext : w ⊑ w') :
    determinedProj φ hd w' :=
  (determinedProj_iff hd w' default).mpr
    (hm w w' default ((determinedProj_iff hd w default).mp h) hext)

end EonEalm
