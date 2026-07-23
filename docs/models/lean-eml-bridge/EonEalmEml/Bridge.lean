import EonEalm
import EMLProof.KaryConsistency

/-!
# EonEalmEml.Bridge — the entry-level `EonEalm.Commitment` instance over eml's real log

Instantiates `EonEalm.Commitment` (`docs/models/lean/EonEalm/Commitment.lean`) with
`Cyphrme/eml`'s positional k-ary Merkle commitment (`EMLProof.KaryConsistency`), so that
`EonEalm.endurance_iff_monotone` (EALM) and `EonEalm.eon_trilemma_impossibility` (EON)
— both universally quantified over *any* `Commitment Comm` — hold **for eml's real log**,
conditional on eml's own no-collision hypotheses plus one named leaf-hash hypothesis.
This is the entry-level bridge design (rather than a full re-derivation inside
`EMLProof` itself) — see "The two gaps this closes" below for the rationale.
Deliberately **not** wired into either corpus's own build — a separate package (see the
sibling `lakefile.toml`) so `EonEalm` stays Mathlib-free and `EMLProof` stays untouched.

## The two gaps this closes

**Gap 1 (`Entry` is opaque).** `EonEalm.Entry` carries no hash, so composing with eml's
`karyRoot : List Digest → Digest` needs an entry→leaf-digest embedding. None is
derivable from either corpus — a constructible-without-hypothesis map (constant,
`Classical.choice`) would collapse distinct entries, the exact fake fit `EonEalm`'s FORM
discipline forbids. Resolution: `leafDigest` below, a **named hypothesis** (injective
under `¬NodeHashCollision`, the standard leaf-collision-resistance assumption — a sibling
of eml's own node-collision hypothesis), carried explicitly on every theorem in this
module, never folded into the clean `EonEalm` core. (Named `leafDigest`, not `leafHash`:
`NEML.leafHash : List UInt8 → Digest` already names eml's own raw-bytes leaf hash — a
different map at a different domain — so reusing the name would shadow it under
`open NEML`.)

**Gap 2 (`karyRoot` is not unconditionally injective).** Null-collapse makes
`karyRoot k (replicate 3 emptyHash) = karyRoot k (replicate 5 emptyHash)` —
collision-independent, so `¬NodeHashCollision` alone cannot rescue an unconditional
`binding`. Resolution: `Comm := Digest × Nat`, root paired with the trusted tree-size —
exactly the `hlen` hypothesis `EMLProof.karyRoot_inj_of_length` needs, matching eml's own
docstring ("tree_size pins injectivity"). A legitimate non-weakening choice of codomain,
not a relaxation of `EonEalm.Commitment.binding`'s statement (still unconditional
`C w = C w' → w = w'` — the codomain just carries more information than `Digest` alone).

## `VC`'s three cases

`EonEalm.Commitment.completeness` demands a certifying `π` for **every** `w₀ ⊑ w`, but
eml's `AcceptsConsistency`/`consistency_completeness` machinery only covers the genuine
*mid-log* growth case (`0 < oldSize < newSize`) — by design: there is no boundary subtree
to climb from when the old log is empty (`(frontierForSizeT k 0).getLast? = none`), and
no proof obligation at all when the log does not grow. Rather than stretch eml's lemmas
past their domain, `VC` below is a three-way disjunction, each disjunct discharged by a
different closed-form argument:
1. `h₀ = h` — the reflexive case (`w₀ = w`, forced by `binding`'s injectivity argument,
   the same one `Commitment.binding` uses). Load-bearing: `enduringScheme` calls
   `Γ.completeness w w (ext_refl w)`.
2. `h₀.2 = 0` — the from-empty case (`w₀ = []`, forced by `List.length_eq_zero` alone —
   no collision hypothesis needed, since `[] ⊑ w` unconditionally for any `w`).
3. `AcceptsConsistency …` — genuine mid-log growth, eml's own machinery verbatim.

None of the three widens what `EonEalm.Commitment` requires or narrows what eml proves;
they are exactly the case split eml's own lemma boundaries impose.
-/

namespace EonEalmEml

open EonEalm NEML

variable (k : Nat) (hk : 2 ≤ k)

/-- The consistency-proof witness data `AcceptsConsistency` threads through, packaged as
    one `VCProof` type: the boundary-subtree root, its climb path to the new frontier,
    the new frontier's peaks, and which peak the boundary climbs into. -/
structure ConsistencyWitness where
  boundaryHash : Digest
  peakPath : List ProofStep
  newPeaks : List Digest
  splitIndex : Nat

noncomputable instance : Inhabited ConsistencyWitness := ⟨⟨default, [], [], 0⟩⟩

variable (leafDigest : Entry → Digest)

/-- D6's commitment function: the k-ary root over entry leaf-digests, paired with the
    record length (Gap-2's fix). -/
noncomputable def C (record : Record) : Digest × Nat :=
  (karyRoot k (record.map leafDigest), record.length)

/-- The extension-verification relation: reflexive / from-empty / a genuine eml
    consistency proof (see the module doc-comment for why three cases). Does not depend
    on `leafDigest` — `AcceptsConsistency` already operates on digests. -/
noncomputable def VC (h₀ h : Digest × Nat) (π : ConsistencyWitness) : Prop :=
  h₀ = h ∨ h₀.2 = 0 ∨
    AcceptsConsistency k h₀.2 h.2 π.boundaryHash π.peakPath π.newPeaks π.splitIndex h₀.1 h.1

variable (hleaf : Function.Injective leafDigest) (hH : ¬ NodeHashCollision)
  (hN : ¬ CollapseAmbiguity)

include hk hleaf hH hN in
/-- D6 binding, discharged: `karyRoot_inj_of_length` (using the length component `C`
    carries) plus `leafDigest`'s injectivity recovers entry-level injectivity from
    digest-level injectivity, conditional on `¬NodeHashCollision ∧ ¬CollapseAmbiguity`. -/
theorem binding : ∀ w w', C k leafDigest w = C k leafDigest w' → w = w' := by
  intro w w' heq
  simp only [C, Prod.mk.injEq] at heq
  obtain ⟨hroot, hlen⟩ := heq
  have hlen' : (w.map leafDigest).length = (w'.map leafDigest).length := by
    simpa using hlen
  have hmapEq :=
    karyRoot_inj_of_length k hk (w.map leafDigest) (w'.map leafDigest) hlen' hroot hH hN
  exact (List.map_injective_iff.mpr hleaf) hmapEq

include hk hleaf hH hN in
/-- D6 VC-soundness, discharged case-by-case on `VC`'s three disjuncts: reflexive via
    `binding` + `ext_refl`; from-empty via `List.length_eq_zero`; genuine growth via
    `consistency_append_only` transported from digest-level prefix to entry-level prefix
    through `leafDigest`'s injectivity. -/
theorem soundness : ∀ w₀ w h₀ h π, VC k h₀ h π →
    h₀ = C k leafDigest w₀ → h = C k leafDigest w → w₀ ⊑ w := by
  intro w₀ w h₀ h π hvc heq0 heq
  rcases hvc with hEq | hZero | hAccepts
  · -- reflexive: h₀ = h forces w₀ = w via the same injectivity `binding` uses.
    have hCeq : C k leafDigest w₀ = C k leafDigest w := heq0 ▸ heq ▸ hEq
    have hw0w := binding k hk leafDigest hleaf hH hN w₀ w hCeq
    exact hw0w ▸ ext_refl w
  · -- from-empty: h₀.2 = 0 forces w₀ = [], and [] ⊑ w unconditionally.
    have hlen0 : w₀.length = 0 := by
      have hz : (C k leafDigest w₀).2 = 0 := heq0 ▸ hZero
      simpa [C] using hz
    have hw0nil : w₀ = [] := List.length_eq_zero_iff.mp hlen0
    exact hw0nil ▸ ⟨w, by simp⟩
  · -- genuine growth: consistency_append_only, transported through leafDigest injectivity.
    have hacc : AcceptsConsistency k (w₀.map leafDigest).length (w.map leafDigest).length
        π.boundaryHash π.peakPath π.newPeaks π.splitIndex
        (karyRoot k (w₀.map leafDigest)) (karyRoot k (w.map leafDigest)) := by
      have hh0 : h₀.2 = (w₀.map leafDigest).length := by simp [heq0, C]
      have hh : h.2 = (w.map leafDigest).length := by simp [heq, C]
      have hh01 : h₀.1 = karyRoot k (w₀.map leafDigest) := by simp [heq0, C]
      have hh1 : h.1 = karyRoot k (w.map leafDigest) := by simp [heq, C]
      rwa [hh0, hh, hh01, hh1] at hAccepts
    have hprefix := consistency_append_only k (w₀.map leafDigest) (w.map leafDigest)
      π.boundaryHash π.peakPath π.newPeaks π.splitIndex hacc hH hN
    obtain ⟨t, ht⟩ := hprefix
    have htakeW : (w.map leafDigest).take w₀.length = w₀.map leafDigest := by
      rw [← ht]; exact List.take_left' (by simp)
    have htake' : (w.take w₀.length).map leafDigest = w₀.map leafDigest := by
      rw [List.map_take]; exact htakeW
    have hw0 : w.take w₀.length = w₀ := (List.map_injective_iff.mpr hleaf) htake'
    have hfinal := List.take_append_drop w₀.length w
    rw [hw0] at hfinal
    exact ⟨w.drop w₀.length, hfinal.symm⟩

include hk in
/-- D6 VC-completeness, discharged case-by-case: reflexive (`u = []`) and from-empty
    (`w₀ = []`) close by `VC`'s first two disjuncts directly; genuine growth invokes
    `consistency_completeness`, the honest-witness case eml's machinery is built for. -/
theorem completeness : ∀ w₀ w, w₀ ⊑ w →
    ∃ π : ConsistencyWitness, VC k (C k leafDigest w₀) (C k leafDigest w) π := by
  intro w₀ w hext
  obtain ⟨u, hu⟩ := hext
  by_cases hu0 : u = []
  · subst hu0
    simp only [List.append_nil] at hu
    subst hu
    exact ⟨default, Or.inl rfl⟩
  · by_cases hw00 : w₀ = []
    · refine ⟨default, Or.inr (Or.inl ?_)⟩
      simp [C, hw00]
    · have hu0' : 0 < u.length := List.length_pos_iff.mpr hu0
      have hold : 0 < w₀.length := List.length_pos_iff.mpr hw00
      have hnew : w₀.length < w.length := by
        rw [hu, List.length_append]; omega
      have hnew' : w₀.length < (w.map leafDigest).length := by
        rw [List.length_map]; exact hnew
      have hoc := consistency_completeness k hk (w.map leafDigest) w₀.length hold hnew'
      have hcellsplit : (w.map leafDigest).take w₀.length = w₀.map leafDigest := by
        rw [hu, List.map_append]; exact List.take_left' (by simp)
      rw [hcellsplit] at hoc
      refine ⟨⟨honestBoundaryHash k (w.map leafDigest) w₀.length,
        honestPeakPath k (w.map leafDigest) w₀.length,
        honestNewPeaks k (w.map leafDigest),
        honestSplitIndex k (w.map leafDigest) w₀.length⟩, Or.inr (Or.inr ?_)⟩
      simpa [C, List.length_map] using hoc

/-- The entry-level bridge: `EonEalm.Commitment` instantiated with eml's real k-ary log,
    conditional on `¬NodeHashCollision ∧ ¬CollapseAmbiguity` (eml's own hypotheses) and
    `leafDigest`'s injectivity (this bridge's one named addition). -/
noncomputable def emlCommitment : Commitment (Digest × Nat) where
  VCProof := ConsistencyWitness
  C := C k leafDigest
  VC := VC k
  binding := binding k hk leafDigest hleaf hH hN
  soundness := soundness k hk leafDigest hleaf hH hN
  completeness := completeness k hk leafDigest

end EonEalmEml
