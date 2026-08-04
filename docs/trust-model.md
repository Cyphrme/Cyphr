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
(`trichotomy_ALL_iff`, `snapshot_characterization`).

### Determination (T1)

_Is the claim a function of the record alone?_

A determined claim's truth is fixed by the record. An undetermined claim's truth depends
on context the record does not carry — "this key belongs to Alice", "this person is who
she says she is". No evaluator settles an undetermined claim at any effort, because the
information it needs is not in the artifact being checked. The only remaining move is to
name a party and rest on their word.

### Certifiability (T2)

_Can a true instance be exhibited by a finite artifact a verifier checks?_

Asked of a determined claim. A certifiable claim admits a certificate: something finite
that a verifier runs a bounded check against. A determined claim that is not certifiable
is settled by the record as a matter of fact, with no artifact that demonstrates it to
someone who does not already hold the whole record.

### Monotonicity (T3)

_Does the claim stay true as the record grows?_

Asked of every claim, whether or not the earlier axes hold. A monotone claim, once true,
is never refuted by an append. A non-monotone claim can be
true when it is checked and false immediately after, with nothing in the record announcing
the change — because the thing that changed it is the append the checker has not seen.
"This is the current head" is the standard case: determined, certifiable, and refuted by
the very next append.

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

When an axis fails, the model names the kind of party whose admission cures it. Two kinds
appear in this repository's documents. A participant trusted for nothing carries neither —
its claims are discharged by an evaluator instead.

**attestor** — cures a determination failure. Its word cannot be reproduced: no check
anyone runs would arrive at the same answer independently, which is what makes it a
trusted party rather than an input.

This repository uses "attestor" in that one sense. Two others circulate and neither is
meant here. This repository's own server specifications use `attestor` for a keyed,
bootstrapped server tier that signs receipts (`docs/specs/server-identity.md`,
`docs/specs/receipts.md`). The industry sense (RATS, TPM, SPIFFE) means evidence a system
produces about itself, which _is_ reproducible and is therefore the exact inverse of the
sense used here.

**watcher** — cures a monotonicity failure by holding more than one view of the same
subject over time. A point observation cures nothing, no matter who signs it, because
staleness is precisely what a single view cannot detect in itself.

The model's own name for the watcher's role is **liveness holder**, and it offers witness
quorums and gossip protocols as instances. "Watcher" is this repository's name for the
party filling that role here, and the mapping from this system's participants onto the
model's cure categories is this project's reading rather than something the model states.
The distinction from a witness is load-bearing: `SPEC.md` §2.2.16 defines a witness as a
client that keeps _a_ copy of an external principal's state. One copy faces the
monotonicity failure like any other single holder; what cures it is a party holding more
than one.

## Curing a non-monotone claim

A non-monotone claim admits **no offline, non-expiring, present-tense certificate** — not
as a matter of expense but as a matter of impossibility. A design wants three properties
at once, and at most two of them are available together:

- **Offline** — checked from the certificate alone, with no further interaction.
- **Eternal** — that certificate never expiring.
- **Now** — the claim being about the record's present state.

Three cures follow, and the model names these three and no others.

1. **A liveness holder** — a witness quorum or a gossip protocol: real ongoing
   coordination between parties, not a single signer. This gives up _offline_.
2. **Restriction to "as of t"** — the claim scoped to the last moment the party can
   actually vouch for, rather than to the moment its response was generated. This gives up
   _now_.
3. **An accepted expiry** — a window past which the certificate is no longer treated as
   saying anything about the present. This gives up _eternal_.

Each cure surrenders exactly one of the three properties, and there is no fourth property
to surrender. That is why the list is complete rather than merely long: anything that
looks like a fourth cure has either taken one of these three or claimed the corner the
impossibility rules out.

The consequence for design is narrow and sharp. A single party signing a statement about
the present, with no expiry and no scoping, produces an artifact shaped like the corner
that does not exist. What makes such an artifact unsound is not that it fails to prove
currency — nothing proves currency alone — but that it does not disclose which of the two
reachable corners it actually occupies.

## What the model does not settle

The model bounds the design space without choosing within it. It establishes that a
currency claim needs one of the three cures and that a bare unscoped signature is not one
of them. It does not establish:

- **Which cure to adopt.** Real liveness, "as of t" scoping, and an accepted expiry are
  all legitimate under the model; choosing between them is an engineering decision.
- **What "current" means operationally** — how fresh is fresh enough, and for what
  purpose.
- **Anything below the axis level.** The model has no wire format, no protocol message,
  and no notion of a sequence number, a threshold, or a resync. It is a taxonomy over an
  abstract append-only record.
- **What a trust failure costs.** The model factors the residue by cause; it does not
  quantify what any particular failure is worth.

Each of those sits with `SPEC.md` and with this repository's own designs.

## Where this vocabulary is used

`docs/architecture/path-a-sovereign-sign-on.md` types every claim crossing between
participants on the sign-on path, using the axes, cells, and party kinds defined here.
