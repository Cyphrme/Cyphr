import EonEalm.Model
import EonEalm.Axes
import EonEalm.Commitment
import EonEalm.Schemes
import EonEalm.Result1
import EonEalm.CollisionExtraction
import EonEalm.Result2
import EonEalm.Result3

/-!
# EonEalm — the EON/EALM formal core (SCAFFOLD, round-2 in progress)

Mechanization target: `Cyphrme/Cyphr` `.ledger/ealm/statement-v0.2.md`. Layer L
(logical, idealized-binding) only — Layer C (the crypto instantiation) is carried in
the source spec as a constructive collision-extraction reduction, whose *general
shape* this scaffold mechanizes (`EonEalm.CollisionExtraction`) without wiring a
concrete Layer-C instantiation (see Friction, below).

**D5/E1 correction applied (P = NP defect, round-2-verified).** The source spec's D5
bundled a poly-time *prover* as scheme data; composed with poly-time `C`/`V` that
prover is itself a poly-time decider, so "a snapshot scheme exists for every determined
NP `φ̂`" (Result 1 ⟸, claimed unconditionally) would force `P = NP`. This scaffold
encodes the corrected D5/E1 from the start: `EonEalm.Scheme` has **no bundled prover**,
only a verifier `V`, and E1 (`Scheme.completeness`) is stated as **certificate
existence** — `∀ (w,ξ) ⊨ φ, ∃ c, V(C(w),c)` — never as a total prover function. See
`EonEalm.Schemes`'s module doc-comment for the full correction; `EonEalm.Result1` and
`EonEalm.Result2`'s constructions exhibit `c` explicitly from the NP witness, unaffected
in substance by the correction (and simplified by it — no classical
totalization/`Option`-wrapping was needed once completeness stopped requiring a total
function).

**Two named results mirror CAP / CALM** (prose names only — never baked into an
identifier, per the dispatch's naming constraint):
* **EON trilemma** — *Eternal, Offline, Now: pick two* (CAP-analog; the impossibility;
  `EonEalm.eon_trilemma_impossibility`).
* **EALM — Endurance As Logical Monotonicity** (CALM-analog; the dissolution;
  `EonEalm.endurance_iff_monotone`).

The **Surety Ceiling** (`EonEalm.snapshot_characterization`, Result 1) gates *whether*
evidence can exist; **EALM** (Result 2) gates *how long / where* it speaks; the **EON
trilemma** (Result 3) is their composition's impossibility corner.

## Module map (mirrors statement-v0.2 §1–§3)
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

## Friction (for round 2 / the architect)
1. **eml plug-in not wired (build-order item 3).** `Cyphrme/eml`
   `proofs/lean/EMLProof/KaryConsistency.lean` has the real positional-soundness
   development (`consistency_soundness`, hypotheses `¬NodeHashCollision`,
   `¬CollapseAmbiguity`) this scaffold's `Commitment.soundness` field and
   `CollisionExtraction.collision_extraction_reduction` are shaped to instantiate. The
   concrete instantiation (a `Commitment Digest` built from `karyRoot`/
   `AcceptsConsistency`) is **not attempted**: eml's Lean package requires Mathlib
   (`v4.29.1`), and a cross-repo path-dependency plus Mathlib build was judged out of
   scope for this scaffold's time budget. This is an explicit scope decision, not a
   `sorry` — there is no in-repo theorem currently attempting it to mark incomplete.
2. **A2′ (expiry/present-inference), A3′ (the online corner), A4-legacy (ξ-mutation vs
   D4), A4′ (R3.1 recursion), R3.2 (accountability) carry no Lean stub at all**, by
   deliberate choice rather than oversight. Each of these five is either (a) a
   VALIDATE-phase question about whether an *existing* Layer-L definition
   (`EnduringSound` for A2′) is the right rendering — not expressible as a further
   theorem inside the model it already defines — or (b) requires a **model extension**
   this scaffold's D0–D6 signature does not yet have (an interactive-verifier
   definition for A3′; a meta-record layer for A4′/R3.2; A4-legacy's exact open
   question is itself unclear from the source spec, and a wrong formalization would
   silently resolve the ambiguity rather than flag it). Manufacturing a `sorry`'d
   theorem against a guessed type for any of these would risk baking in an unreviewed
   answer to the very question round 2 needs to adjudicate — the FORM discipline this
   scaffold follows bars stating an unfalsifiable placeholder (`sorry : True`) and bars
   inventing a proof past a ⚠ joint; the same restraint applies to inventing the joint's
   *statement*. Flagged here for the architect/round-2 rather than silently dropped.
3. **`NPMembership` and `Scheme` do not encode poly-time bounds.** Layer L's own
   "poly-time" content (`E1`'s `|P(w)| ≤ poly(|w|)`, `Chk` poly-time) is Layer C
   territory this scaffold does not model at all — mirrors `EMLProof.Foundations`'s
   abstraction of `H` (no computability constraint on the primitive itself, only on
   where collision-resistance hypotheses are discharged). Flagging in case round 2
   needs the complexity bound to be load-bearing somewhere Layer L currently elides it.

## Not mechanized (per statement-v0.2 §6, unchanged by this scaffold)
Łoś–Tarski (D4′, the ∃⁺ ⟹ monotone lemma); Lemma 1 (orthogonality — an illustrative
2×2 table over concrete instance claims, not a build-order target); Ahman's F* skeleton
(reproved natively above, not imported); the Layer-C probabilistic framing (paper-only,
O-S2).
-/
