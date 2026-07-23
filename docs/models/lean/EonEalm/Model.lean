/-!
# Model — D0 (Records), D1 (Worlds), D2 (Claims)

Layer L (logical, idealized-binding) only; see the root module `EonEalm` for the
Layer L / Layer C split and the STABLE/⚠ partition this package follows.

No Mathlib dependency: the extension order `⊑` is the list-prefix relation, defined
and proved reflexive/transitive/antisymmetric directly rather than borrowed from a
`Preorder`/`List.IsPrefix` typeclass — keeping the trust base as small as
`EMLProof.Foundations` keeps eml's (four structural axioms; see the Scope and
limitations note in `EonEalm`'s root doc-comment for why this module does not import
`EMLProof` directly).
-/

namespace EonEalm

/-- D0: the entry alphabet Σ, abstract (countable, poly-time-computable length measure
    |·| — the length measure itself is not modeled at Layer L; it is Layer C's proof-size
    bound, `E1`'s `|P(w)| ≤ poly(|w|)` clause, and this package does not encode
    complexity bounds at all, per the root module's Scope and limitations note). -/
axiom Entry : Type

/-- D0: record space R = Σ*, records are finite lists of entries; (R, ⊑) is a poset with
    least element `[]`. -/
abbrev Record := List Entry

/-- D0 extension order ⊑ = prefix order (what a Merkle log realizes; the sub-multiset
    CRDT variant is `[choice]`-deferred per the source statement, not modeled here). -/
def Ext (w w' : Record) : Prop := ∃ u : List Entry, w' = w ++ u

@[inherit_doc] scoped infix:50 " ⊑ " => Ext

theorem ext_refl (w : Record) : w ⊑ w := ⟨[], by simp⟩

theorem ext_trans {w w' w'' : Record} (h1 : w ⊑ w') (h2 : w' ⊑ w'') : w ⊑ w'' := by
  obtain ⟨u, hu⟩ := h1
  obtain ⟨u', hu'⟩ := h2
  exact ⟨u ++ u', by rw [hu', hu, List.append_assoc]⟩

theorem ext_antisymm {w w' : Record} (h1 : w ⊑ w') (h2 : w' ⊑ w) : w = w' := by
  obtain ⟨u, hu⟩ := h1
  obtain ⟨u', hu'⟩ := h2
  have hlen : w.length = w'.length := by
    have := congrArg List.length hu'
    simp only [hu, List.length_append] at this ⊢
    omega
  have : u = [] := by
    have hlu : w.length + u.length = w'.length := by rw [hu]; simp
    have : u.length = 0 := by omega
    exact List.length_eq_zero_iff.mp this
  rw [hu, this, List.append_nil]

/-- D1: ambient contexts Ξ — authorship facts, intentions, key custody, other artifacts.
    Inhabited (licenses D3's non-vacuity) and non-trivial (`|Ξ| ≥ 2`, so D3's
    "record-determined" is a genuine restriction rather than vacuously true). No order is
    imposed on Ξ. -/
axiom Context : Type
axiom Context.inhabited : Nonempty Context
axiom Context.nontrivial : ∃ ξ ξ' : Context, ξ ≠ ξ'

noncomputable instance : Inhabited Context := ⟨Classical.choice Context.inhabited⟩

/-- D1: worlds = R × Ξ. -/
abbrev World := Record × Context

/-- D2: a claim is a predicate over worlds. Semantic — syntax re-enters only one-way via
    D4′ (not mechanized here; see `EonEalm`'s root doc-comment). -/
abbrev Claim := Record → Context → Prop

end EonEalm
