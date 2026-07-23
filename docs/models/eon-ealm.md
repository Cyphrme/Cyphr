# MODEL: EON / EALM — Evidence Endurance Under Offline Verification

<!--
  Promoted prose statement for the mechanized EON/EALM formal core.
  Mechanization: docs/models/lean/ (core, no Mathlib) and
  docs/models/lean-eml-bridge/ (eml instantiation). See docs/models/lean/README.md
  and docs/models/lean-eml-bridge/README.md for the reviewer's build-and-verify path.
-->

## Domain Classification

**Problem statement:** for a claim about a record (a log, a document, a
chain of commits), when can a party who verifies **offline** — with no
access to the record itself, no oracle, no clock, no re-query — hold
evidence that stays valid **forever**? EON/EALM answers this in general,
not for any one hash scheme or log format.

**Domain characteristics:**

- **Two independent claim properties.** Whether a claim's truth depends
  on context outside the record (*determination*) and whether a claim's
  truth persists as the record grows (*monotonicity*) are orthogonal —
  neither implies the other.
- **Verification is a dial, not a spectrum.** "Offline" is not "hard to
  break online verification" — it is a hard closure on the verifier's
  inputs: exactly a commitment digest and a certificate, nothing else.
- **The result is a characterization, not a workaround.** EON/EALM does
  not propose a scheme that evades the trade-off; it proves exactly
  which claims admit which kind of evidence, and why the rest cannot.

---

## Names

- **EON — Eternal, Offline, Now.** The impossibility. Stated the way CAP
  is *correctly* stated: a mutual incompatibility among three properties
  where one of them (**Now** — the claim is non-monotone, i.e., can flip
  from true to false as the record grows) is forced by the claim itself,
  so in practice you are trading the other two (**Eternal** vs.
  **Offline**). It is not three symmetric, freely tradeable corners —
  that reading is both an overclaim and the classic CAP misreading.
- **EALM — Endurance As Logical Monotonicity.** The dissolution
  (CALM-analog): among claims that can carry offline evidence at all,
  monotonicity is exactly the condition under which that evidence
  **endures** — stays valid without re-verification as the record grows.

**Composition.** The **Surety Ceiling** (Result 1) gates *whether*
evidence for a claim can exist at all — a claim needs to be
record-determined and its record-only projection needs to be in NP.
**EALM** (Result 2) then gates, among claims that clear that ceiling,
*how long* the evidence endures — exactly the monotone ones. **EON**
(Result 3) is their composition's impossibility corner: a claim that
clears the ceiling but is non-monotone cannot have evidence that is both
offline and eternal. The **anchor's authenticity** — that the commitment
digest a verifier trusts really is the log's own — sits outside this
model entirely, as the irreducible residual trust EON/EALM does not
discharge.

---

## The model (Layer L)

The mechanization presents two layers. **Layer L** is the logical,
idealized-binding layer — the one actually proved here, over an
abstract commitment satisfying a binding axiom. **Layer C** is the
computational instantiation — a real collision-resistant hash — carried
as a collision-extraction reduction (an accepting forgery implies a hash
collision) rather than as a further Layer-L theorem. The
`docs/models/lean-eml-bridge/` package instantiates Layer L concretely
against eml's real Merkle commitment; see
[`../lean-eml-bridge/README.md`](lean-eml-bridge/README.md).

**Records and worlds.** A record `w` is a finite sequence drawn from an
abstract entry alphabet; extension `w ⊑ w'` is the prefix order (what an
append-only log realizes). A world pairs a record with an **ambient
context** `ξ` — anything true about the world besides the record's
bytes (who authored an entry, what the current time is, what other
records exist). A **claim** is a predicate over worlds.

**The two axes (orthogonal).**

| | monotone | non-monotone |
| :-- | :-- | :-- |
| **record-determined** | inclusion ("entry x appears in w") — eternal evidence exists | "x is absent from w", "w has size n", "h is the current head" — no eternal scheme |
| **not record-determined** | genuineness ("e ∈ w was authored by A") — fails the determination gate | authorship of a future event — fails the determination gate |

A claim is **record-determined** if its truth does not depend on which
context witnesses it — it is a pure function of the record's bytes. A
claim is **monotone** if, holding the context fixed, truth is preserved
under extension: once true at `w`, still true at every `w' ⊒ w` in that
same context. Determination and monotonicity are independent axes; all
four cells above are inhabited.

**Evidence schemes.** A scheme for a claim is a pair `(C, V)`: a
commitment function `C` mapping records to digests, and a verifier `V`
whose *only* inputs are a digest and a certificate — no record access,
no oracle, no interaction, no context. That input signature is itself
the **Offline** property (E3); it is not a separate hypothesis to
satisfy, it is what "offline" means, and the mechanization enforces it
structurally by the verifier's type rather than by an added premise.

A scheme is required to be **complete** (E1): for every world satisfying
the claim, some certificate exists that `V` accepts against `C`'s
digest. No efficient prover is assumed — completeness only asserts a
certificate *exists*, never that one can be found in polynomial time.
(An earlier draft of this statement bundled a polynomial-time prover
into the scheme; composed with a polynomial-time verifier, that would
have made every scheme's existence collapse P and NP together. The
corrected form — bare existence of an accepting certificate — is what
the mechanization encodes throughout.)

Two soundness flavors matter:

- **Snapshot-sound (E2a):** an accepting certificate forces the claim to
  hold at the committed record, for *every* context. (This is a
  *derived* fact, not a separate axiom: because the verifier's inputs
  exclude context entirely, its verdict is a pure function of the
  digest and certificate, so an honestly-accepted certificate is
  accepted under every context — soundness in one context forces it in
  all of them.)
- **Enduring-sound (E2b):** an accepting certificate forces the claim to
  hold not just at the committed record but at *every* extension of it,
  in every context. Enduring soundness implies snapshot soundness
  (taking the extension to be trivial); the converse does not hold.

---

## The three results

**Result 1 — Snapshot Characterization (the Surety Ceiling).** A claim
admits a scheme with snapshot-sound evidence **if and only if** it is
record-determined and its record-only projection is in NP.

- The *if* direction is constructive: given an NP witness for the
  record-only claim, the certificate is the record itself paired with
  that witness.
- The *only if* direction has two parts. Determination is forced: if the
  claim's truth varied with context at a fixed record, a certificate
  honestly accepted in one context would (by snapshot-soundness) force
  the claim true in every context, including one where it is false —
  contradiction. This is the formal core of the ceiling: **a claim that
  is not a pure function of the record admits no evidence scheme at
  all**, independent of any computational assumption. NP-membership then
  follows for free: the acceptance check itself is a polynomial-time NP
  witness-checker for the record-only projection.

**Result 2 — EALM (the dissolution).** Restricting to claims that clear
Result 1's ceiling (record-determined, NP), such a claim admits a scheme
with **enduring**-sound evidence **if and only if** it is monotone.

- The *if* direction reuses Result 1's certificate at the point it was
  issued, plus a proof that the committed record is a genuine prefix of
  any later verification point; monotonicity then lifts the claim from
  the certified record forward to every extension. This transports
  Ahman, Bickford, Sozeau et al.'s stable-implies-recallable-witness
  result (POPL 2018) *across a trust boundary* — from an
  omniscient-observer setting into one where only a binding commitment,
  not the record itself, is available — using exactly the commitment's
  binding property to perform the transport.
- The *only if* direction is close to definitional: an accepting
  certificate's enduring-soundness lifts the claim to every extension in
  the same context, which is monotonicity's statement verbatim. Its
  shortness is not a weakness in the result — the substance of EALM is
  the *pairing* with Result 1 (monotonicity characterizes what evidence
  *additionally* buys, once existence is already settled) and the
  explicit *if*-direction construction, not the difficulty of this
  direction.

**Result 3 — the EON trilemma (the impossibility).** For a claim that
clears the Surety Ceiling but is **non-monotone**, no scheme is both
offline and eternal (enduring-sound). The proof is a two-line corollary
of Result 2's *only if* direction: an offline scheme with eternal
soundness would make the claim monotone by Result 2 — contradicting the
hypothesis that it is not. This is intentionally almost no new content
beyond Result 2 restated as a negative; its value is as a
**characterization** of exactly which claims sit where, not as a
surprising no-go theorem.

**The three escapes, once a claim is non-monotone (heterogeneous, not
symmetric corners):**

- **Drop Eternal** — snapshot or expiring evidence, valid about the
  committed record forever, silent about the present: Merkle inclusion
  proofs, signed tree heads, OCSP staples, X.509 `NotAfter`.
- **Drop Offline** — online re-proof against a fresh anchor: Certificate
  Transparency's operational mode, witness-cosigned checkpoints. For a
  non-monotone claim this is *not* a distinct "eternal" mode in its own
  right — it is repeated Result-1 snapshots plus a separate
  anchor-authentication protocol, wearing endurance's vocabulary.
  Formalizing that interactive-verifier layer is future work (see
  below); it models the *server's* freshness endpoint, not this proof.
- **Drop Now** — weaken the claim to a monotone one and prove that
  instead: OpenTimestamps proves "this record existed by this time," a
  monotone claim, not "this is the current state," which is not. This
  is not a same-claim trade — you prove a strictly easier claim. That is
  exactly why EON is CAP-shaped: non-monotonicity ("Now") is *forced by
  the claim you must evidence*, the way a network partition is forced by
  the environment; given that, you trade Offline against Eternal.

### The CAP / CALM correspondence

EON/EALM has a genuine structural correspondence to CAP/CALM — CALM's
"monotone" and EALM's "monotone" are literally the same notion
(preservation under extension) — but no functor or involution between
the two is exhibited, so it is a correspondence to note, not a duality
to claim.

- **EALM ↔ CALM** (both dissolutions): CALM says coordination-free
  consistency holds exactly for monotone programs (the *agreement*
  plane); EALM says offline-eternal evidence exists exactly for monotone
  claims (the *evidence* plane). Same left-hand side, different
  qualifier.
- **EON ↔ CAP** (both impossibilities): Now corresponds to Partition
  (the condition that is forced), Offline to Availability, Eternal to
  Consistency.
- **Two honest asymmetries.** CALM is *constructive* — you can refactor
  a program toward monotonicity; EALM is *diagnostic* — a claim's
  freshness-dependence is a fixed fact about the claim, and the trade
  never heals. And CALM's directions are hard theorems in their own
  right; EALM's *only if* direction is close to definitional, with the
  weight carried by the constructions and the pairing with Result 1.

---

## Mechanization status

**Machine-checked, zero `sorry`, `docs/models/lean/`, no Mathlib
dependency:** Results 1, 2, and 3 (`EonEalm.snapshot_characterization`,
`EonEalm.endurance_iff_monotone`, `EonEalm.eon_trilemma_impossibility`),
the collision-extraction reduction's general shape, and `C = id` as a
second commitment instance witnessing that binding-without-compression
is satisfiable. See [`lean/README.md`](lean/README.md) for the
file-by-file guide.

**Trusted computing base:** Lean's three built-in axioms (`propext`,
`Classical.choice`, `Quot.sound`) plus the model's own abstract
parameters — the entry alphabet, the ambient-context type, and its
inhabitedness. No Mathlib and no axiom beyond these is used anywhere in
the core.

**Instantiated for eml's real log,** conditional on eml's own
collision-freedom hypotheses (`¬NodeHashCollision`, `¬CollapseAmbiguity`)
plus one named leaf-hash injectivity hypothesis:
`docs/models/lean-eml-bridge/`. See
[`lean-eml-bridge/README.md`](lean-eml-bridge/README.md).

**Not modeled, by design:**

- **Polynomial-time bounds.** Layer L's "NP" and "poly-time verifier"
  content is idealized as existence-of-a-checker; actual complexity
  bounds are Layer C's concern and are not encoded here.
- **Succinctness.** The general certificate constructed by Result 1/2 is
  linear in the record size; characterizing which claims admit
  logarithmic (succinct) certificates is future work.
- **The online corner.** No interactive-verifier definition exists in
  this model, so "drop Offline" (re-proof against a fresh anchor) is
  described in prose above but not mechanized as a fourth scheme kind.
- **The anchor-authenticity layer.** Whether "this digest is the log's
  own current head" is itself a claim admitting evidence is a further,
  recursive instance of this same model at the meta-record level (who
  signed the anchor, under what key), not something EON/EALM discharges
  for its own commitment.

## Related

- [`lean/README.md`](lean/README.md) — the core package's reviewer
  entry point (build instructions, file guide, TCB).
- [`lean-eml-bridge/README.md`](lean-eml-bridge/README.md) — the eml
  instantiation's reviewer entry point.
- [`verifiable-log.md`](verifiable-log.md) — the concrete Merkle log
  model (MALT) that eml's commitment realizes; EON/EALM's abstract
  commitment `C` and prefix order `⊑` are exactly what this log
  provides.
- [`principal-state-model.md`](principal-state-model.md) — the
  Cyphr principal state machine whose commit chain is the kind of
  record EON/EALM's claims range over.
