import EonEalm.Model
import EonEalm.Axes
import EonEalm.Commitment
import EonEalm.Schemes
import EonEalm.Result1
import EonEalm.CollisionExtraction
import EonEalm.Result2
import EonEalm.Result3

/-!
# EonEalm — the EON/EALM formal core

Mechanization target: [`../eon-ealm.md`](../eon-ealm.md), the EON/EALM prose statement.
Layer L (logical, idealized-binding) only — Layer C (the crypto instantiation) is
carried in the source statement as a constructive collision-extraction reduction, whose
*general shape* this package mechanizes (`EonEalm.CollisionExtraction`); a concrete
Layer-C instantiation against eml's real log is carried separately in
`docs/models/lean-eml-bridge/` (see Scope and limitations, below).

**D5/E1 correction applied (a P = NP defect, verified).** The source statement's D5
bundled a poly-time *prover* as scheme data; composed with poly-time `C`/`V` that
prover is itself a poly-time decider, so "a snapshot scheme exists for every determined
NP `φ̂`" (Result 1 ⟸, claimed unconditionally) would force `P = NP`. This package
encodes the corrected D5/E1 from the start: `EonEalm.Scheme` has **no bundled prover**,
only a verifier `V`, and E1 (`Scheme.completeness`) is stated as **certificate
existence** — `∀ (w,ξ) ⊨ φ, ∃ c, V(C(w),c)` — never as a total prover function. See
`EonEalm.Schemes`'s module doc-comment for the full correction; `EonEalm.Result1` and
`EonEalm.Result2`'s constructions exhibit `c` explicitly from the NP witness, unaffected
in substance by the correction (and simplified by it — no classical
totalization/`Option`-wrapping was needed once completeness stopped requiring a total
function).

**Two named results mirror CAP / CALM** (prose names only — never baked into an
identifier, by design):
* **EON trilemma** — *Eternal, Offline, Now: pick two* (CAP-analog; the impossibility;
  `EonEalm.eon_trilemma_impossibility`).
* **EALM — Endurance As Logical Monotonicity** (CALM-analog; the dissolution;
  `EonEalm.endurance_iff_monotone`).

The **Surety Ceiling** (`EonEalm.snapshot_characterization`, Result 1) gates *whether*
evidence can exist; **EALM** (Result 2) gates *how long / where* it speaks; the **EON
trilemma** (Result 3) is their composition's impossibility corner.

## Module map (mirrors `../eon-ealm.md`'s model and results sections)
* `EonEalm.Model` — D0 (records, extension order `⊑`), D1 (worlds), D2 (claims).
* `EonEalm.Axes` — D3 (record-determined), D4 (same-context monotone, the F2
  correction).
* `EonEalm.Commitment` — D6: abstract commitment `C` (binding axiom only, no
  compression — F5), the `VC` extension-verification relation, and `idCommitment` as
  the `C = id` non-vacuity witness F5 requires.
* `EonEalm.Schemes` — D5: `Scheme`, `NPMembership` (idealized), E1/E2a/E2b, and
  `EonEalm.enduringSound_snapshotSound` (E2b ⟹ E2a via `w′ := w`).
* `EonEalm.Result1` — **Result 1, STABLE, both directions.**
* `EonEalm.CollisionExtraction` — the collision-extraction reduction's general shape
  (build-order item 3), STABLE.
* `EonEalm.Result2` — **Result 2, STABLE, both directions.** A1′ retired: `⟹`
  (`endurance_forces_monotone`) is a direct consequence of E1 + E2b, no separate
  hypothesis needed.
* `EonEalm.Result3` — the EON trilemma's impossibility corner, `sorry`-free.

## TCB
Three axioms beyond Lean's built-ins (`propext`, `Classical.choice`, `Quot.sound`):
`EonEalm.Entry` (D0's abstract entry alphabet), `EonEalm.Context` and
`EonEalm.Context.inhabited` (D1's ambient contexts). `EonEalm.Context.nontrivial`
(`|Ξ| ≥ 2`) is declared per D1 but not yet load-bearing in any proved theorem — kept for
model faithfulness, not currently discharged by any lemma. `EonEalm.Commitment` is a
*structure*, not a global axiom set, precisely so `idCommitment` can witness `C = id` as
one inhabitant among possibly others (F5's non-vacuity requirement) — verify with
`#print axioms EonEalm.snapshot_characterization` /
`EonEalm.endurance_construction`: both report only the four items above, `sorryAx`-free.

## Scope and limitations
1. **eml plug-in.** `Cyphrme/eml` `proofs/lean/EMLProof/KaryConsistency.lean` has the
   real positional-soundness development (`consistency_soundness`, hypotheses
   `¬NodeHashCollision`, `¬CollapseAmbiguity`) this package's `Commitment.soundness`
   field and `CollisionExtraction.collision_extraction_reduction` are shaped to
   instantiate. The concrete instantiation (a `Commitment (Digest × Nat)` built from
   `karyRoot`/`AcceptsConsistency`) is carried out in a separate sibling package,
   `docs/models/lean-eml-bridge/` — deliberately not wired into this core's own build
   (it needs eml's Mathlib-dependent proofs, and this core stays Mathlib-free), but
   complete and `sorry`-free. See that package's README for the two gaps it closes and
   the conditional hypotheses under which `EonEalm.endurance_iff_monotone` and
   `EonEalm.eon_trilemma_impossibility` hold for eml's real log.
2. **A2′ (expiry/present-inference), A3′ (the online corner), A4-legacy (ξ-mutation vs
   D4), A4′ (R3.1 recursion), R3.2 (accountability) carry no Lean stub at all**, by
   deliberate choice rather than oversight. Each of these five is either (a) a question
   about whether an *existing* Layer-L definition (`EnduringSound` for A2′) is the right
   rendering — not expressible as a further theorem inside the model it already defines
   — or (b) requires a **model extension** this package's D0–D6 signature does not yet
   have (an interactive-verifier definition for A3′; a meta-record layer for A4′/R3.2;
   A4-legacy's exact open question is itself unclear from the source statement, and a
   wrong formalization would silently resolve the ambiguity rather than flag it).
   Manufacturing a `sorry`'d theorem against a guessed type for any of these would risk
   baking in an unreviewed answer to a question that is still genuinely open — the FORM
   discipline this package follows bars stating an unfalsifiable placeholder
   (`sorry : True`) and bars inventing a proof past a ⚠ joint; the same restraint applies
   to inventing the joint's *statement*. Flagged here as an open question for a future
   extension rather than silently dropped.
3. **`NPMembership` and `Scheme` do not encode poly-time bounds.** Layer L's own
   "poly-time" content (`E1`'s `|P(w)| ≤ poly(|w|)`, `Chk` poly-time) is Layer C
   territory this package does not model at all — mirrors `EMLProof.Foundations`'s
   abstraction of `H` (no computability constraint on the primitive itself, only on
   where collision-resistance hypotheses are discharged). See `../eon-ealm.md`'s "Not
   modeled, by design" section — flagged here in case a future extension needs the
   complexity bound to be load-bearing somewhere Layer L currently elides it.

## Not mechanized (unchanged by this package — see `../eon-ealm.md`'s "Not modeled, by design" section)
Łoś–Tarski (D4′, the ∃⁺ ⟹ monotone lemma); Lemma 1 (orthogonality — an illustrative
2×2 table over concrete instance claims, not a build-order target); Ahman's F* skeleton
(reproved natively above, not imported); the Layer-C probabilistic framing (paper-only,
O-S2).
-/
