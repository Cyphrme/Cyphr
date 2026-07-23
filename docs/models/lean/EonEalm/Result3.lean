import EonEalm.Result2

/-!
# Result 3 — the EON trilemma, impossibility corner

No scheme for a record-determined, NP, **non-monotone** claim is both Offline (E3) and
Eternal (E2b, endurance). STABLE statement; ⚠ proof-of-impossibility (transitively, via
Result 2 ⟹ / A1′ — see the theorem's own doc-comment for why its proof is not
independently `sorry`'d).

Offline (E3) is not a separate hypothesis here: `Scheme.V : Comm → Proof → Prop`
already excludes record/oracle/clock/`ξ` access by its type (`EonEalm.Schemes`'s module
doc-comment) — every `Scheme` in this model is offline by construction. What remains to
state is the trilemma's impossibility content: non-monotone ⟹ no enduring scheme.

The **other two corners and the online corner (A3′)** are not mechanized: `{Offline,
expiring}` and `{Eternal-in-effect, online}` both require a D5 extension (an
interactive-verifier definition) that statement-v0.2 itself flags as absent
("no interactive-verifier definition in D5"). Faking a `sorry`'d statement against a
signature that does not yet exist would bake in an unreviewed resolution of exactly the
open question (A3′) — see `EonEalm`'s root doc-comment, Friction note.
-/

namespace EonEalm

/-- The EON trilemma's impossibility corner (statement-v0.2 §3, Result 3's slogan:
    "offline, unexpiring, non-monotone — pick two"). This theorem's own proof body is
    **not** `sorry`'d: it is a direct two-line consequence of
    `endurance_iff_monotone`'s forward direction. It is nonetheless incomplete —
    `#print axioms` on this theorem will report `sorryAx`, inherited transitively
    through `endurance_forces_monotone` (⚠ A1′). Per statement-v0.2 §6 item 5, writing
    this *exact* type is itself the mechanized content requested here ("mechanizing it
    is the cheapest stress-test of E3/E2b's exact form — Lean refuses any ambiguity
    about V's inputs"); discharging the inherited `sorry` waits on round 2 clearing
    A1′. -/
theorem eon_trilemma_impossibility {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hd : Determined φ) (hnp : NPMembership (determinedProj φ hd)) (hnm : ¬ Monotone φ) :
    ¬ ∃ S : Scheme Γ φ, EnduringSound S := by
  intro hex
  exact hnm ((endurance_iff_monotone Γ φ hd hnp).mp hex)

end EonEalm
