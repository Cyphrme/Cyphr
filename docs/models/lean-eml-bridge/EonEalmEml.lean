import EonEalmEml.Bridge

/-!
# EonEalmEml — EALM/EON specialized to eml's real entry-level log

The headline theorems: `EonEalm.endurance_iff_monotone` (EALM) and
`EonEalm.eon_trilemma_impossibility` (EON) are universally quantified over any
`EonEalm.Commitment Comm`, so once `EonEalmEml.Bridge.emlCommitment` discharges that
structure's three obligations for eml's real k-ary log, these two specializations follow
by direct application — no new proof content, only the concrete `Γ`. See
`EonEalmEml.Bridge`'s module doc-comment for what `emlCommitment` assumes and why.
-/

namespace EonEalmEml

open EonEalm NEML

variable (k : Nat) (hk : 2 ≤ k) (leafDigest : Entry → Digest)
  (hleaf : Function.Injective leafDigest) (hH : ¬ NodeHashCollision) (hN : ¬ CollapseAmbiguity)
  (φ : Claim) (hd : Determined φ) (hnp : NPMembership (determinedProj φ hd))

include hd hnp in
/-- **EALM holds for eml's real entry-level log** (see `../eon-ealm.md`'s Result 2),
    conditional on eml's own no-collision hypotheses and `leafDigest`'s injectivity. -/
theorem eml_endurance_iff_monotone :
    (∃ S : Scheme (emlCommitment k hk leafDigest hleaf hH hN) φ, EnduringSound S) ↔ Monotone φ :=
  endurance_iff_monotone (emlCommitment k hk leafDigest hleaf hH hN) φ hd hnp

include hd hnp in
/-- **The EON trilemma's impossibility corner holds for eml's real entry-level log**,
    conditional on the same hypotheses. -/
theorem eml_eon_trilemma_impossibility (hnm : ¬ Monotone φ) :
    ¬ ∃ S : Scheme (emlCommitment k hk leafDigest hleaf hH hN) φ, EnduringSound S :=
  eon_trilemma_impossibility (emlCommitment k hk leafDigest hleaf hH hN) φ hd hnp hnm

end EonEalmEml
