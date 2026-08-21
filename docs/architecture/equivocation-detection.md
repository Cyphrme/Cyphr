# Equivocation detection

This page states how equivocation detection fits together: the parts
involved, the comparison at the center of it, how that comparison starts
and reaches an answer, and the requirements the arrangement must
satisfy. Everything defined elsewhere is cited, not restated.

A **fork** is two conflicting, independently signed claims about the
same principal at the same chain position —
[SPEC §15.7](../../SPEC.md#157-consensus-and-witnesses)'s "two or more
conflicting commits reference the same pre," the condition
[SPEC §15.7.1](../../SPEC.md#1571-invalid-forks-fork-detection-and-duplicitous-behavior)
names an invalid fork. A **split view** is the same event named for how
it looks from outside: one
identity, two irreconcilable answers, each plausible to whoever received
it. Fork and split view are one concept under two names, not two
concepts — a split view is what a fork looks like from outside, and
nothing below treats them separately.

## Parts

| Part              | Contribution                                                                                                                                                                                                    | Defined in                                                                                                                        |
| :---------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------- |
| Server (attestor) | Signs a tip report over each state it serves. On every accepted push, fans the committed blobs out to every witness registered for that principal.                                                              | [Server receipts](../specs/receipts.md); [SPEC §13.5.1](../../SPEC.md#1351-witness-registration); `rs/cyphr-server/src/fanout.rs` |
| Witness           | Registered by the principal to receive fanned-out commits. A witness is itself a server: it independently derives and signs its own tip report over what it receives, rather than merely relaying the sender's. | [SPEC §2.2.16](../../SPEC.md#2216-witnesses); [SPEC §13.5.1](../../SPEC.md#1351-witness-registration)                             |

## The comparison

Detecting a fork is a comparison, not an observation. A single signed
tip report, however honest, cannot show a split view by itself — the lie
is only visible across two independently obtained reports about the same
`pr` and `sequence`, and it takes a party holding both to see it.
Neither signing server can do this from its own report alone: each
knows only what it itself signed.

Two facts hold regardless of who or what runs the comparison:

- **Divergence is permanent.** Two signed, conflicting tip reports about
  the same chain position remain a conflict no matter what is signed
  afterward. Equivocation is affirmable: evidence of it, once obtained,
  endures.
- **Agreement proves nothing forward.** Honesty is only refutable: any
  number of consistent checks is compatible with a conflict at the next
  one. A comparison can convict; it can never certify.

The comparison itself is a pure function, pinned in
[the receipts specification's pinned predicate](../specs/receipts.md#the-pinned-predicate):
given two signed tip reports and the keys they were signed with, it
proves a conflict or rules one out. `rs/cyphr-server/src/consistency.rs`
implements it three ways — `check_cross_witness_consistency` (an
all-pairs sweep over a report set), `detect_fork_unverified` (a single
pair), and `format_disagreement_evidence` (renders a proven pair as
evidence) — and `rs/cyphr-server/tests/equivocation.rs` exercises the
underlying predicate. It is server-side code: it lives in the server's
own crate, not a client tool or a procedure a person runs by hand.

## Detection needs no watcher

Nothing about the comparison above requires a person, a client request,
or a role dedicated to running it. A server accumulates the material it
compares — its own signed tip report, and whatever a registered witness
signs and returns for the same principal — as an ordinary consequence of
accepting pushes and honoring witness registration
([SPEC §13.5.1](../../SPEC.md#1351-witness-registration)). The
comparison runs the moment a server holds two disagreeing reports about
the same principal and sequence: not on a schedule, not on request, and
not because a person or a dedicated watcher role asked it to. No such
role exists in this arrangement, and none is needed — the material a
comparison needs arrives as a side effect of work the server was already
doing.

## The answer carries the finding

Two designs were possible for how a finding, once made, reaches anyone
who consumes the server's answers. It could sit behind a dedicated
status check, at an address separate from the record itself, that a
client must know to ask for. Or it could ride along inside the answer a
server was already going to give — the same tip report, receipt, or
discovery response, carrying one more piece of content.

This document takes the second option: **a server's ordinary answer
about a principal it holds a live finding for carries the finding**,
without a separate request. This is a choice, not a given fact about the
system, and it is made for a concrete reason: a signal that sits behind
an address most integrations will never think to query is a signal
nobody reads, and a security signal nobody reads protects no one. The
cost is a one-time change to the shape of an answer, paid once, rather
than a recurring cost paid by every integration that has to remember a
second address exists.

This is what lets a record's owner learn of a fork without going
looking: reading her own record, the way she always would, is already
how she is told — nothing about that read changes except that a finding,
when one exists, is now part of what comes back. A service relying on
someone else's identity learns the same way, at the moment it would have
gotten any other answer about that identity — see
[what a relying service does](../use/detecting-a-split-view.md#a-service-relying-on-you-decides).

## What the finding contains

What rides along is not a bare boolean. The object a carried finding
holds is the same evidence
[a stranger needs to be convinced](../use/detecting-a-split-view.md#convince-a-stranger):
the two disagreeing tip reports, and the chain segment binding both
signing keys as active. Anyone who receives it can verify the conflict
offline, without asking the server that showed it to them anything
further, and without trusting the party that compared them.

## Resolution

A fork ends when the principal — not the server, not a witness — signs
a new commit whose `pre` names the chosen branch's tip, or a
`resync/create` PoP re-asserting the current tip
([SPEC §13, "Resync PoP"](../../SPEC.md#13-resync-pop)). Resolving
introduces no authority beyond what already governs an ordinary push:
the same signature check accepts or rejects the resolving commit, and
because a resolution is itself a commit, it reaches only servers the
principal has registered as a witness, by the same fanout as any other
push. A server the principal never registered with, or never otherwise
reaches, gets nothing and goes on serving the abandoned branch — a
property of how fanout scopes resolution, not a defect in it.

Once a server has processed the resolving commit, its ordinary answers
about the resolved sequence stop carrying the live finding. This does
not undo what the comparison already proved: a server's live finding and
the permanence of an already-kept proof are two different things — the
two original tip reports remain a valid proof, for as long as whoever
kept them holds onto them, regardless of what any server serves
afterward.

## Requirements

### [arch-detection-is-comparison]

Fork detection is comparison: it requires at least two independently
obtained tip reports about the same principal and sequence, held
together and evaluated against each other. A single tip report, or a
comparison run against only one, settles nothing — no verdict, proven or
ruled out, comes back. This is what stands behind a reader's ability to
[tell a proven conflict from an unproven one](../use/detecting-a-split-view.md#fixed-rule-decides-conflict).

```claim
kind: requirement
evaluator: test
```

### [arch-tip-reports-are-material]

What the comparison operates over is signed tip reports, as specified in
[the receipts specification](../specs/receipts.md) — tip against tip, no
other pairing. Two servers that sign identical tip reports for a
principal and sequence do not conflict, whatever else they separately
serve; two that sign different ones do, regardless of the chain data,
entities, or patches underneath. The tip report is the answer that gets
[kept](../use/detecting-a-split-view.md#keep-the-signed-answer), which is
why it is the unit the whole arrangement moves and compares.

```claim
kind: requirement
evaluator: test
```

### [arch-signing-stays-stateless]

Composing a signature over a tip report or receipt needs nothing from
fork bookkeeping: no receipt log, no comparison, no store of prior
findings consulted to make the signature valid. A server produces the
same valid, verifying signature whether or not it is currently tracking
any contested principal — what an answer's envelope carries alongside
that signature is composed separately, per `docs/specs/receipts.md`
`[receipts-r-stateless]`.

```claim
kind: requirement
evaluator: test
```

### [arch-evidence-is-portable]

The evidence retained is a complete proof on its own: it verifies
offline, against exactly
[what a verifier retains](../specs/receipts.md#what-a-verifier-retains)
— the two receipts and the chain segment binding both signing keys — by
a party that trusts neither the party that compared them nor the server.
The server's bare published identity is not that segment; per
`docs/specs/receipts.md` `[receipts-r-genesis-hint]` it is a hint toward
replaying the chain, not a substitute for having replayed it. Nothing in
this arrangement may make a verdict depend on server cooperation, on
private state held by whoever ran the comparison, or on anyone's
unverified word for it — the user-facing form of this requirement is the
reader's ability to
[convince a stranger](../use/detecting-a-split-view.md#convince-a-stranger).

```claim
kind: requirement
evaluator: test
```

### [arch-finding-never-clears]

A comparison's finding is one-directional. Conflicting reports are
permanent proof of equivocation; agreeing reports are not evidence of
honesty, and no number of them retracts an earlier finding. What
[stops appearing on a server's future answers once its principal
resolves the fork](#arch-resolution-clears-flag) is that server's live
finding, never the evidence itself.

```claim
kind: requirement
evaluator: test
```

### [arch-detection-is-automatic]

A server's comparison runs the moment it holds two disagreeing tip
reports about the same principal and sequence — delivered by the
witness registration and push fanout it already performs — not on a
schedule, not on request, and not because a person or a dedicated
watcher role asked it to. No client-facing "check for a fork" request
exists in this arrangement, and none is needed.

```claim
kind: requirement
evaluator: test
```

### [arch-answer-carries-contested]

A server's ordinary answer about a principal it holds a live finding for
— a tip report, a receipt, a discovery response, anything it would have
signed and returned regardless — carries the finding inline. No second
request and no separate endpoint is needed to learn it; this is
[the design choice this document makes](#the-answer-carries-the-finding),
stated here as the requirement that choice imposes.

```claim
kind: requirement
evaluator: test
```

### [arch-evidence-rides-with-flag]

What rides along is not a bare boolean. Wherever the finding is carried,
[the object it carries](#arch-evidence-is-portable) holds the two
disagreeing tip reports and the chain segment binding both signing keys,
so anyone who receives it can verify the conflict without asking the
server anything further — this is
[what the record's owner sees](../use/detecting-a-split-view.md#the-conflict-record)
too, not a summary of it.

```claim
kind: requirement
evaluator: test
depends: [arch-evidence-is-portable]
```

### [arch-owner-alone-resolves]

A fork ends only by the principal's own signature: a new commit whose
`pre` names the chosen branch's tip, or a `resync/create` PoP
re-asserting the current tip. Resolving introduces no authority beyond
what already governs an ordinary push — the same signature check accepts
or rejects it — and it reaches only servers the principal has registered
as a witness, by the same fanout as any other push. A server the
principal never registered with gets nothing and goes on serving the
abandoned branch.

```claim
kind: requirement
evaluator: test
```

### [arch-resolution-clears-flag]

Once a server has processed a principal's resolving commit, that
server's ordinary answers about the resolved sequence stop carrying
[the live finding](#arch-answer-carries-contested) — the same way any
other accepted push changes what a server serves next.
[The evidence of the original conflict does not go with it](#arch-finding-never-clears):
a server's live finding and the permanence of an already-kept proof are
two different things.

```claim
kind: requirement
evaluator: test
depends: [arch-answer-carries-contested]
because: [arch-finding-never-clears]
```
