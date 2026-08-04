# The trust model: how this project types a claim

This document defines the vocabulary this repository's architecture documents use to type
a claim — the three axes a claim is measured on, the cells those axes produce, the party
kinds that cure a failing axis, and the cures available when a claim stops being true as
the record grows. Every term those documents borrow from the model is defined here.

The vocabulary comes from a formal trust taxonomy developed in a separate repository:

> Timothy DeHerrera, _Factoring Trust: A Machine-Checked Characterization of Where
> Verification Must End_, Cyphrpunk LLC, 2026.
> <https://github.com/nrdxp/factoring-trust>

That work is not part of this repository, but it is public, so every attribution below can
be checked against it. Its author is the same person as this repository's: a separate
repository does not mean an arm's-length one.

**What stands on its own here, and what does not.** The definitions below are
self-contained — a reader who never opens the source can type a claim with them. The
_results_ are not. That exactly three axes exhaust the failure modes, that two of the eight
nominal cells are empty, and that a non-monotone claim admits no offline, non-expiring,
present-tense certificate are the source's theorems, and this document defers to them
rather than re-deriving them. Where the text extends the model's vocabulary rather than
restating it, it says so.

**How a claim made here can be checked.** The source's Lean mechanization is frozen under
its `rc1` tag; its written paper is a work-in-progress draft that is not. So a mechanized
result is cited by its Lean theorem name, which is stable, and a point of prose is quoted
rather than cited by section — a section number in an unfrozen draft is the same unstable
handle this repository refuses for `SPEC.md`.

**Scope.** This is a lens for reasoning about what a Cyphr deployment trusts. It is not
part of the Cyphr protocol and not a proposal to one; `SPEC.md` is the normative source
for what the protocol requires, and nothing here changes it. The model bounds design
choices without making them — see [what the model does not settle](#what-the-model-does-not-settle).

## The world a claim is about

The model splits the world a claim can be about into two parts.

**Record** — what a verifier can see and replay: the append-only sequence of commits and
everything derivable from it.

**Context** — everything a verifier does not see: causal history, wall-clock time, key
custody, the existence of other records.

Wall-clock time sits in context, and that placement carries most of what follows. Time is
modelled, so it exists in the model — but it is modelled as exactly the thing an offline
check cannot reach. Currency is therefore not missing from the model; it is placed on the
side of the world a verifier has no access to.

## The three axes

A claim is measured on three axes, and they are asked in order rather than independently.

Determination is asked first. Certifiability is asked only of a determined claim: it is a
property of the record-only predicate a determined claim projects to, and where
determination fails there is no such predicate for it to range over. Monotonicity is
defined on the claim directly and is asked of every claim, determined or not — in the
source's words, it "is free everywhere."

The factoring is a machine-checked biconditional rather than a taxonomy someone proposed,
so there is no fourth failure mode waiting to be discovered
(`trichotomy_ALL_iff`, `snapshot_characterization`). Three qualifications travel with that
result and are easy to lose:

- **It holds above a floor.** The source grants two physical residuals rather than proving
  them: that the commitment binds, and that the verifier being run is the one that was
  specified. Everything below is stated above that floor.
- **The polynomial stratum is not proved.** The biconditional is stated across a tower of
  verifier strata and holds at the oracle and computable ones. At the polynomial stratum it
  is an open conjecture — not weakly proved, not proved under extra hypotheses, but not
  proved at all, with no predicate in the mechanization even encoding the time and size
  bounds it would need.
- **At the oracle stratum certifiability is vacuous.** Every record predicate satisfies it
  there, so at that stratum the _snapshot_ characterization collapses to determination
  alone (`snapshot_iff_determined_ALL`). The _enduring_ one does not: it still carries
  monotonicity as a separate conjunct (`trichotomy_ALL_iff`), so the collapse is a fact
  about one of the two soundness flavors rather than about the stratum as such. The
  certifiability axis has effective content at the computable stratum, which is where a
  real verifier lives.

### Determination (T1)

_Is the claim a function of the record alone?_

A determined claim's truth is fixed by the record. An undetermined claim's truth depends
on context the record does not carry — "this key belongs to Alice", "this person is who
she says she is". No evaluator settles an undetermined claim at any effort, because the
information it needs is not in the artifact being checked. The only remaining move is to
name a party and rest on their word.

Two things need keeping apart. That undetermined claims exist at all is unconditional and
mechanized. That a _particular_ genuineness or binding claim is one of them is not: the
source calls that reading "an explicit modeling hypothesis about the fiber over the
record, never a theorem." Typing a claim as undetermined is an assumption a design makes
and should state, not a result it inherits.

### Certifiability (T2)

_Is the record-only predicate semi-decidable at the verifier's computational power?_

Asked of a determined claim. A certifiable claim admits a certificate: something a
verifier runs a bounded check against. A determined claim that is not certifiable is
settled by the record as a matter of fact, with no artifact that demonstrates it to
someone who does not already hold the whole record.

The axis is relative to a stratum, and the constraint it imposes is on what the verifier
may consult — a committed value and a certificate, never the record or the context — not
on how large that certificate may be. Size bounds belong to the polynomial stratum, which
the source describes and does not mechanize.

### Monotonicity (T3)

_Does the claim stay true as the record grows?_

Asked of every claim, whether or not the earlier axes hold. A monotone claim, once true,
is never refuted by an append. A non-monotone claim can be true when it is checked and
false immediately after, with nothing in the record announcing the change — because the
thing that changed it is the append the checker has not seen. "This is the current head"
is the standard case: determined, certifiable, and refuted by the very next append.

## Cells

A claim's **cell** is its position once the three axis outcomes are fixed. The cell says
what the claim needs — an evaluator, a trusted party, or an accepted bound — and the
architecture documents cite it in a `cell` column.

An **evaluator** is a check anyone can run over the artifact presented, arriving at the
same answer independently. It is what discharges a claim without naming a trusted party,
and it is what a certificate is checked by. The architecture documents use the word in two
jobs: in prose, for that check, and as a machine-read `evaluator:` field naming the
concrete test that runs it. The second is an instance of the first.

Read the notation `n / Tk` as _cell n of the source's tabulation, where axis Tk is the one
that fails_. The failing axis carries the meaning; the number is an index into the table
below.

Three binary axes give eight nominal combinations. Six are inhabited; the last two are
empty by theorem, because a claim the record does not determine admits no evidence scheme
at any stratum, and those two rows posit one anyway (`undetermined_cell_empty`).

| cell             | determination | certifiability | monotonicity | what discharges it                                                |
| :--------------- | :------------ | :------------- | :----------- | :---------------------------------------------------------------- |
| `1 — verifiable` | holds         | holds          | holds        | an evaluator, and no trusted party                                |
| `2 / T3`         | holds         | holds          | **fails**    | one of [the three cures](#curing-a-non-monotone-claim)            |
| `3 / T2`         | holds         | **fails**      | holds        | a [voucher](#party-kinds), or restriction to a decidable subclass |
| `4 / T2+T3`      | holds         | **fails**      | **fails**    | a voucher, plus a freshness mechanism                             |
| `5 / T1`         | **fails**     | —              | holds        | an [attestor](#party-kinds)                                       |
| `6 / T1+T3`      | **fails**     | —              | **fails**    | an attestor, plus a freshness mechanism                           |
| 7                | **fails**     | posited        | holds        | empty by theorem                                                  |
| 8                | **fails**     | posited        | **fails**    | empty by theorem                                                  |

Certifiability is written `—` where determination fails: there is no record-only predicate
for the axis to range over. Monotonicity is asked everywhere, which is why cells 5 and 6
are distinct — they differ in nothing else.

**A hazard for anyone checking against the mechanization.** The Lean development numbers
the six inhabited cells in a different order than the written paper does. This repository's
documents use the paper's numbering. If you followed a theorem name to reach a result, you
are looking at the other numbering — do not "fix" either to match the other.

### Row-1 claims

A **Row-1 claim** occupies cell 1: determined, certifiable, and monotone. It names an
evaluator and no party. One self-contained certificate serves forever, offline, with no
coordination between anyone — that is what all three axes holding buys. "Row-1 claim" is
this project's name for the position; the source's verdict word for that cell is
**verifiable**.

A Row-1 claim left undischarged is **indefensible**. That word is this project's coinage
rather than the source's, and it is precise rather than rhetorical. Every other cell buys
its answer by giving something up: a party whose word cannot be re-run, a claim narrowed
to a moment, or an accepted expiry. Cell 1 gives up nothing _beyond the floor every cell
has already granted_ — the check is computable by anyone, from the record, once, and stays
true afterwards. So a Row-1 claim nobody runs has nothing on the other side of the ledger
past that shared floor: no party that was trusted, no bound that was accepted, no cost
that was paid. Naming what a system trusts is a defence; leaving a free check unrun is not
one.

### Labels outside the model

This repository's claim tables carry two labels the axes do not produce. They mark claims
that fall outside the taxonomy, and they are this project's labels rather than the
model's. A claim carrying one has no axis outcomes to report: its determination,
certifiability, and monotonicity columns are each written `—`.

**below the floor** — the claim is settled by a computation over the artifact presented,
before any question about the record arises. Verifying a signature over a message is the
standard case: the message carries everything the check needs. The axes ask how a claim
depends on the record and on unseen context; a claim with neither dependence sits below
where the taxonomy starts, and there is no trust residue to type.

The source has a **floor** too, and it means something else: the two physical residuals
every cell already stands on, a commitment's binding and a verifier's fidelity. Signature
verification lands at both floors, for different reasons — below this project's because
the check needs nothing but the message, at the source's because the scheme's forgery
resistance is granted rather than proved. The shared word is a collision, not an
agreement.

**decision** — the claim's truth is fixed by a party's own choice rather than by any state
of the world. Whether a principal is allowed to perform some operation is the relying
party's own rule: nothing to determine, certify, or preserve under growth, and nobody
trusted for it beyond the party making the decision.

This label is not the source's **elective**, and the two are easy to conflate. The source
reserves that word for trust a verifier could discharge but declines to: "the trichotomy
characterizes trust that is _forced_ — no scheme exists, at any stratum, for the claim in
question. It says nothing about _elective_ trust, where a verifier could check but chooses
reliance for cost or convenience." A `decision` claim is neither forced nor elective,
because no scheme is being declined — there is no fact of the matter to check.

## Party kinds

When an axis fails, the model names the kind of party whose admission cures it. That name
is the axis's **cure name**: what the model calls the party, as distinct from any role
name a Cyphr specification gives a component. There are three, one per axis. A participant
trusted for nothing carries none of them — its claims are discharged by an evaluator
instead.

**attestor** — cures a determination failure (T1). Its word cannot be reproduced: no check
anyone runs would arrive at the same answer independently, which is what makes it a
trusted party rather than an input. The source's umbrella term for this party kind is
**witness of history**, with "an admitted signer or attestor" as its instances.

The name `attestor` is overloaded, and the collisions are near rather than distant. This
repository's own server specifications use `attestor` for a keyed, bootstrapped server
tier that signs receipts (`docs/specs/server-identity.md`, `docs/specs/receipts.md`) — a
role name, not a cure name. The industry sense (RATS, TPM, SPIFFE) means evidence a system
produces about itself, and that sense is not the opposite of the cure name: those
frameworks address the _same_ failure. The source names them for exactly that reason,
observing that "provenance and attestation frameworks exist precisely because genuineness
is not recoverable from an artifact's bytes alone." What differs is the means. Industry
attestation produces evidence another party can re-run; the cure-name attestor's word
cannot be re-run, and that is what makes it trust rather than evidence. Two adjacent
things doing similar work under one word are harder to keep apart than two opposite ones,
which is why this collision is the dangerous kind.

**voucher** — cures a certifiability failure (T2) with "an admitted judgment" standing in
for a check no procedure can perform; the alternative is restricting the claim to a
decidable subclass. No claim in this repository's documents carries this cure today. It is
defined here because the model's inventory of cure parties is three rather than two, and
because a claim that an artifact's behaviour agrees with its source sits in cell 3 and
will need it.

This repository reserves **vouch** and **corroboration** for two species of _evidence_,
and the source draws the same line: "A corroboration is an admitted party's
re-verification of an artifact against its own committed content — a check anyone else
could re-run. A vouch is an admitted party's keyed judgment binding the artifact to the
principal it names — testimony, which no one can re-run." A _voucher_ is a party kind and
a _vouch_ is an evidence species; the shared root is not a shared referent.

**watcher** — cures a monotonicity failure (T3) by holding more than one view of the same
subject over time. A point observation cures nothing, no matter who signs it, and the
source says why: divergence between two views, once it exists, is permanent, so
_equivocation_ is affirmable — evidence of it endures once obtained — while _honesty_ is
only refutable, falsifiable at the next check and never provable forever. A single view
obtains neither.

The model's own name for the watcher's role is **liveness holder**, and it offers witness
quorums and gossip protocols as instances; "watcher" is this repository's name for the
party filling that role here. Mapping a deployment's participants onto the model's cure
categories is what the model is for rather than a reading imposed on it: every cell of its
table names the anchor a claim rests on and the minimal cure that discharges it.

The distinction from a witness is load-bearing: `SPEC.md` §2.2.16 defines a witness as a
client that keeps _a_ copy of an external principal's state. One copy faces the
monotonicity failure like any other single holder; what cures it is a party holding more
than one.

## Curing a non-monotone claim

A non-monotone claim admits **no offline, non-expiring, present-tense certificate** — not
as a matter of expense but as a matter of impossibility
(`eon_trilemma_impossibility`). A design wants three properties at once, and at most two
of them are available together:

- **Offline** — checked from the certificate alone, with no further interaction.
- **Eternal** — that certificate never expiring.
- **Now** — the claim being about the record's present state.

Three cures follow, one per property surrendered, and the source's cell table names these
three:

1. **A liveness holder** — a witness quorum or a gossip protocol: real ongoing
   coordination between parties, not a single signer. This gives up _offline_.
2. **Restriction to "as of t"** — the claim scoped to the last moment the party can
   actually vouch for, rather than to the moment its response was generated. This gives up
   _now_.
3. **An accepted expiry** — a window past which the certificate is no longer treated as
   saying anything about the present. This gives up _eternal_.

**The three are not symmetric.** Cures 2 and 3 land on corners the model realizes:
offline-and-eternal, and offline-and-present. Cure 1 lands on the corner the model has no
way to express, because it builds the offline constraint into the verifier's type — real
coordination is a cure the model can point at but cannot itself model.

**The list's completeness is an argument, not a theorem.** Each cure surrenders exactly
one of the three properties and there is no fourth property to surrender, so anything
resembling a fourth cure has either taken one of these three or claimed the corner the
impossibility rules out. That reasoning is this document's. What the source proves is
adjacent but different: it enumerates four _coordinate moves_ a repair can make —
re-expressing the claim over a different alphabet, strengthening the verifier or the
commitment, narrowing the claim, or admitting a new trusted fact — and grades their
exhaustiveness explicitly as model-relative, accounting "for every repair this model's
mechanized verdicts distinguish, not for every repair any model could admit."

The consequence for design is one the source states outright: whether a guarantee needs a
consensus mechanism is settled by where its claim sits, not by argument. A system with a
nameable authority can serve eternal offline evidence and needs no coordination for it,
while every "is this current" question is a coordination problem no artifact retires. So a
single party signing a statement about the present, with no expiry and no scoping,
produces an artifact shaped like the corner that does not exist. What makes such an
artifact unsound is not that it fails to prove currency — nothing proves currency alone —
but that it does not disclose which of the two reachable corners it actually occupies.

## What the model does not settle

Two lists, answering different questions. The first is what the model declines to choose;
the second is what it has not proved.

**What it leaves to the engineer.** The model bounds the design space without choosing
within it. It establishes that a currency claim needs one of the three cures and that a
bare unscoped signature is not one of them. It does not establish:

- **Which cure to adopt.** Real liveness, "as of t" scoping, and an accepted expiry are
  all legitimate under the model; choosing between them is an engineering decision.
- **What "current" means operationally** — how fresh is fresh enough, and for what
  purpose.
- **Anything below the axis level.** The model has no wire format, no protocol message,
  and no notion of a sequence number, a threshold, or a resync. It is a taxonomy over an
  append-only record and the structures built from it — including, in one of its worked
  instances, a chain of key events whose genesis is a single binding commitment, which is
  this repository's own subject matter. Of that instance the source proves that "under
  `Total`, the trust surface of a chain is _exactly_ the genesis binding and nothing
  else" — the totality condition is an antecedent, carried in the mechanization as an
  explicit hypothesis (`principal_trust_bounded`), not a detail of the statement's
  phrasing. The chain it mechanizes is structural, "with no hash function in it," so what
  the instance exercises is the accounting rather than the cryptography.
- **What a trust failure costs.** The model factors the residue by cause; it does not
  quantify what any particular failure is worth.

Each of those sits with `SPEC.md` and with this repository's own designs.

**What the source declares open.** These are not choices left to a designer but results
the model does not have, in its own words: "the polynomial stratum, the source-integrity
instance's frontier tightness results, and the floor's two residuals, which concern
physical realization rather than the model." Nothing in this repository closes any of
them. A design leaning on polynomial-time certifiability, or on the floor holding, is
leaning on something unproved rather than on something settled.
