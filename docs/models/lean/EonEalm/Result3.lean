import EonEalm.Result2

/-!
# Result 3 — the EON trilemma, impossibility corner

No scheme for a record-determined, NP, **non-monotone** claim is both Offline (E3) and
Eternal (E2b, endurance). STABLE statement; the proof-of-impossibility is now
`sorry`-free (A1′ retired — see `EonEalm.Result2`'s `endurance_forces_monotone`),
since it is a direct consequence of `endurance_iff_monotone`'s forward direction.

Offline (E3) is not a separate hypothesis here: `Scheme.V : Comm → Proof → Prop`
already excludes record/oracle/clock/`ξ` access by its type (`EonEalm.Schemes`'s module
doc-comment) — every `Scheme` in this model is offline by construction. What remains to
state is the trilemma's impossibility content: non-monotone ⟹ no enduring scheme.

The **other two corners and the online corner (A3′)** are not mechanized: `{Offline,
expiring}` and `{Eternal-in-effect, online}` both require a D5 extension (an
interactive-verifier definition) that the source statement itself flags as absent
("no interactive-verifier definition in D5"). Faking a `sorry`'d statement against a
signature that does not yet exist would bake in an unreviewed resolution of exactly the
open question (A3′) — see `EonEalm`'s root doc-comment, Scope and limitations section.
-/

namespace EonEalm

/-- The EON trilemma's impossibility corner (Result 3's slogan: "offline, unexpiring,
    non-monotone — pick two"). A direct two-line consequence of
    `endurance_iff_monotone`'s forward direction, now `sorry`-free end to end —
    `#print axioms` on this theorem reports only `propext`/`Classical.choice`/
    `Quot.sound` plus the model's own parameters (`Entry`/`Context`/
    `Context.inhabited`), no `sorryAx`. Per the source statement's own accounting,
    writing this *exact* type was itself part of the requested mechanized content
    ("mechanizing it is the cheapest stress-test of E3/E2b's exact form — Lean refuses
    any ambiguity about V's inputs"). -/
theorem eon_trilemma_impossibility {Comm : Type} (Γ : Commitment Comm) (φ : Claim)
    (hd : Determined φ) (hnp : NPMembership (determinedProj φ hd)) (hnm : ¬ Monotone φ) :
    ¬ ∃ S : Scheme Γ φ, EnduringSound S := by
  intro hex
  exact hnm ((endurance_iff_monotone Γ φ hd hnp).mp hex)

end EonEalm
