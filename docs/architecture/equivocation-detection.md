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

| Part              | Contribution                                                                                                                                                                                                    | Defined in                                                                                       |
| :---------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------- |
| Server (attestor) | Signs a tip report at `/tip` and a commit receipt on every accepted push, and nothing else. On every accepted push, fans the committed blobs out to every witness registered for that principal.                | [Server receipts](../specs/receipts.md); [SPEC §13.5.1](../../SPEC.md#1351-witness-registration) |
| Witness           | Registered by the principal to receive fanned-out commits. A witness is itself a server: it independently derives and signs its own tip report over what it receives, rather than merely relaying the sender's. | [SPEC §13.5.1](../../SPEC.md#1351-witness-registration)                                          |

SPEC's own definition of a witness —
[SPEC §2.2.16](../../SPEC.md#2216-witnesses)'s "a client that keeps a
copy of an external principal's state and communicates state through
gossip" — is broader than the row above: it does not require a witness
to be a server, or to sign anything. That a witness here is itself a
server, independently deriving and signing its own tip report rather
than relaying the sender's, is this document's own design — narrower
than §2.2.16, not a restatement of it.

## The exchange

Detecting a fork is a negotiation between two server instances, not a
store of foreign views. Neither side needs to hold the other's chain:
each already has its own signed tip report — `pr`, `sequence`,
`commit_id`, and `roots` including the Commit Root `cr`
([the receipts specification's claim schema](../specs/receipts.md#claim-schema)).
What the two exchange, alongside those reports, is a consistency proof:
whichever side's `sequence` is higher — its Commit Tree already spans
both positions — proves its OWN Commit Root at the lower `sequence`
extends to its own Commit Root at its current `sequence`, compact and
self-contained, so settling the exchange never requires either side to
fetch or retain the other's chain.
[arch-behind-is-not-fork](#arch-behind-is-not-fork) states how that
proof's reconstructed root at the lower position is then checked
against the other side's own independently signed claim.

A consistency proof is a property of the Commit Tree specifically. The
Commit Tree (CT) is an [Epoch Merkle Log (EML)](../../SPEC.md#2211-eml)
— append-only, by construction — while the Principal Tree is instead an
[Epoch Merkle Tree (EMT)](../../SPEC.md#2212-emt), positionally mutable,
not append-only
([SPEC §3.7.7](../../SPEC.md#377-commit-root)'s `CR = EMLR(TR₀, TR₁?,
...)`). Extension is only a meaningful question over an append-only
structure, so what the exchange proves runs over CR at each side's
claimed `sequence`, never over PR.

[SPEC §4.4](../../SPEC.md#44-commit-tree) states the entitlement —
"Clients obtain inclusion and consistency proofs for specific
commits" — without restating how one is built or checked: that
machinery belongs to the EML layer the Commit Tree is built on
([SPEC Appendix 4](../../SPEC.md#appendix-4-external-tools-and-projects)'s
O(logN) Hash Transitions paper, related to RFC 9162's consistency
proofs for append-only logs), and Cyphr's Commit Tree computes and
verifies that proof directly, over the append-only EML layer just
described. A produced proof verifies
standalone against the two claimed roots and sizes alone — the property
that makes it a substitute for holding the chain rather than a
compressed copy of it. Those two roots and sizes — the proving side's own old and new Commit
Roots — are exactly what its signed tip reports supply, and supply as an
_authenticated_ pair: a consistency proof proves only the relationship
between two roots, never that either is genuine, so the tip report's
signature is what the exchange trusts for the side that produced the
proof, and the proof is what settles that side's own history. The other
side's claim at the overlap position needs its own signature the same
way — the consistency proof alone never reaches into it, which is why
[arch-behind-is-not-fork](#arch-behind-is-not-fork)'s comparison at that
position is a check between two independently signed claims, not
something the proof itself decides.

Two facts hold regardless of who or what runs the exchange:

- **Divergence is permanent.** Two signed, conflicting tip reports about
  the same chain position remain a conflict no matter what is signed
  afterward. Equivocation is affirmable: evidence of it, once obtained,
  endures.
- **Agreement proves nothing forward.** Honesty is only refutable: any
  number of consistent checks is compatible with a conflict at the next
  one. An exchange can convict; it can never certify.

Deciding the outcome from a tip-report pair and a consistency proof is a
pure function, pinned in
[the receipts specification's pinned predicate](../specs/receipts.md#the-pinned-predicate)
for the case where both sides claim the identical `sequence` — see
[arch-behind-is-not-fork](#arch-behind-is-not-fork) for the general
case across differing sequences. Because the predicate is pure and
verifier-side — it needs no server cooperation to run, only the two
claims and the keys that back them — the same predicate serves two
separate uses. The server runs it three ways as an automatic
consequence of the exchange described above: over a single pair to
settle one exchange, swept all-pairs across a set of reports to find
the first conflict, and rendered as an evidence document once a pair is
proven. None of those three server-side runs is triggered by a client
request or waits on one — what the exchange needs arrives as a side
effect of ordinary witness delivery, never on demand. The same
predicate is also available to anyone holding two tip reports on their
own, gathered outside any exchange a server ran —
[`cyphr audit equivocation`](../guides/publication-and-audit.md#checking-the-evidence)
runs it as a command, for exactly the case where no witness
relationship delivered the material automatically. Running the
predicate by hand over reports already held is not the excluded thing:
what is excluded is a client asking a server to go perform the exchange
on its behalf — no such request exists in this arrangement, and none is
needed, because the server never waits for one.

## Detection needs no watcher

Nothing about the exchange above requires a person, a client request,
or a role dedicated to running it. Witness registration and push
fanout already deliver, as an ordinary consequence of accepting a push,
a witness's own signed tip report and consistency proof for the same
principal to exchange against
([SPEC §13.5.1](../../SPEC.md#1351-witness-registration)). The exchange
runs on that delivery: not on a schedule, not on request, and not
because a person or a dedicated watcher role asked it to. No such role
exists in this arrangement, and none is needed — what an exchange needs
arrives as a side effect of work the server was already doing.

## The answer carries the finding

Two designs were possible for how a finding, once made, reaches anyone
who consumes the server's answers. It could sit behind a dedicated
status check, at an address separate from the record itself, that a
client must know to ask for. Or it could ride along inside the answer a
server was already going to give — the same tip report or receipt,
carrying one more piece of content.

This document takes the second option: **a server's ordinary answer
about a principal carries the fork proof its most recent exchange for
that principal produced**, without a separate request. This is a
choice, not a given fact about the system, and it is made for a concrete
reason: a signal that sits behind an address most integrations will
never think to query is a signal nobody reads, and a security signal
nobody reads protects no one. The cost is a one-time change to the shape
of an answer, paid once, rather than a recurring cost paid by every
integration that has to remember a second address exists.

This is what lets a record's owner learn of a fork without going
looking: reading her own record, the way she always would, is already
how she is told — nothing about that read changes except that a proof,
when the most recent exchange produced one, is now part of what comes
back. A service relying on
someone else's identity learns the same way, at the moment it would have
gotten any other answer about that identity — see
[what a relying service does](../use/detecting-a-split-view.md#a-service-relying-on-you-decides).

## What the finding contains

What rides along is not a bare boolean. The object a carried finding
holds is the two disagreeing tip reports — plus, when the two positions
differed, the higher side's consistency proof binding its own claimed
roots at each position, the reconstructed root
[arch-behind-is-not-fork](#arch-behind-is-not-fork) checks against the
lower side's signed one — exactly what
[the exchange](#the-exchange) produces on a fork outcome, nothing
assembled afterward. Anyone who receives it can verify offline that the
two signed claims conflict, without asking the server that showed it to
them anything further, and without trusting the party that compared
them. Turning that into
[proof a stranger with no prior trust in the server accepts](../use/detecting-a-split-view.md#convince-a-stranger)
takes one more thing only the receiving party can add: replaying the
server's own chain to bind each report's signing key to it, the same
step [verifying any single receipt](../guides/publication-and-audit.md#verifying-a-receipt-without-trusting-the-server-again)
already requires.

## While a fork stands

A proven fork changes what a server will accept from the contested
principal, not what it will say about it. New pushes for that principal
are refused for as long as the fork stands, because the principal's
consensus state is Error, and
[SPEC §15.5](../../SPEC.md#155-principal-consensus-states)'s Error state
is explicit: "No new transactions or actions are processed until
resolved." One push is exempt: [the principal's own resolving
commit](#resolution) — a commit whose `pre` names the tip of one of the
fork's own two contested branches, or a `resync/create` PoP re-asserting
one of those tips. A server checks an incoming push against the two
branch tips its own proven fork names before applying the Error-state
refusal to it, so that one shape of push gets through while every other
push for the principal keeps failing. Accepting it is what lifts the
refusal: [SPEC §15.8](../../SPEC.md#158-fork-resolution)'s "Witnesses
transition the principal's consensus state from Error back to Active
upon observing a valid resolution" names that same act. What clears that
check is a signature, not an identity: any push signed by the
principal's currently-active key can be that push — never a witness's
key, never the server's own. [Resolution](#resolution) states what
follows when that key is not only the owner's.

Answering queries is a different question, and the answer is no: a
server does not stop serving a contested principal, and it does not
pick a side while deciding.
[The answer carries the finding](#the-answer-carries-the-finding)
already establishes that ordinary answers keep coming, fork proof
attached. Read alone, a signed tip report's own claims name exactly one
commit and one set of roots — that is one branch, stated as what this
server currently signs; [SPEC
§15.7.1](../../SPEC.md#1571-invalid-forks-fork-detection-and-duplicitous-behavior)'s
"rejection of both branches until resolved" describes what a server does
with writes while a fork stands (covered above), not a separate claim
about how it answers reads. What keeps a read from presenting its one
named branch as settled is the fork proof riding along beside it: a
signature is a statement about the server that made it, not about the
world it describes ([what a receipt does and does not
establish](../guides/publication-and-audit.md#what-the-record-proves-and-what-it-does-not)),
and the attached proof is what tells the reader this same server has
also signed the opposite claim about the identical position — so the
answer can be read only as this server's current position, never as the
record's settled state, for as long as that proof keeps riding along
with it.

## Resolution

A fork ends when the principal — not the server, not a witness — signs
a new commit whose `pre` names the chosen branch's tip, or a
`resync/create` PoP re-asserting the current tip
([SPEC §13, "Resync PoP"](../../SPEC.md#13-resync-pop)). Resolving
introduces no authority beyond what already governs an ordinary push:
the same signature check accepts or rejects the resolving commit —
checked against the fork's own two branch tips rather than refused
outright the way every other push for the principal is, [while the fork
stands](#while-a-fork-stands) — and because a resolution is itself a
commit, it reaches only servers the
principal has registered as a witness, by the same fanout as any other
push. A server the principal never registered with, or never otherwise
reaches, gets nothing and goes on serving the abandoned branch — a
property of how fanout scopes resolution, not a defect in it.

Accepting that push and having something to apply it to are different
questions. When the resolving commit's `pre` names the tip this server
already signs, applying it is an ordinary state transition: the push
extends state the server already holds. When it instead names the
OTHER contested branch's tip — the one this server never held, since
[detecting the fork required neither side to hold the other's
chain](#the-exchange) — this server has no state on hand for that `pre`
to extend, and the resolving commit alone does not supply one: an
ordinary push's blob list carries only its own new commit, not the
branch behind it. What supplies the missing branch is a fetch: the
server retrieves the segment from the fork point forward from the
witness whose tip report named the chosen tip — the witness [the fork's
own evidence](#what-the-finding-contains) already identifies by
signature — and replays it the way [convincing a
stranger](../use/detecting-a-split-view.md#convince-a-stranger) already
requires of anyone reconstructing a chain they were not handed, checking
the replayed root against that witness's signed tip report before
trusting either. Only once that segment is in hand does the resolving
commit's `pre` name a root this server can check the push against. A
server that cannot reach that witness has nothing to apply the resolving
commit to; the push fails the way [any push that does not match the
state a server holds
does](../guides/publication-and-audit.md#detecting-a-split-view) — a
`409`, `protocol: state root mismatch` — not because the resolution is
invalid, but because this server has not yet constructed what it would
apply it to.

That signature check is where "the principal signs" bottoms out
throughout this section, and it is worth being precise about what it
verifies: a signature against the principal's currently-active key, not
an identity. It has no way to ask whose hand produced the signature. A
proven fork is often itself evidence that two valid signatures under
that same key already exist at one position — if the fork traces back to
a compromised key rather than a client retry, whoever holds the
compromised key can sign a resolving commit exactly as the record's
owner can, and this check accepts it exactly the same way. Because a
resolving commit only reaches the servers it reaches — registered
witnesses, or a server that separately fetches the segment in, as
described above — whichever resolving commit arrives first at a
given server is the one that server acts on: a server that receives the
owner's resolves to the owner's branch, one that receives an attacker's
resolves to the attacker's, and neither server's signature check can
tell the difference. That gap is not closed by anything in detection or
resolution — the remedy sits outside both, in [key revocation and
recovery](../../SPEC.md#14-recovery): once the compromised key is
revoked, the same check that let the attacker resolve the fork stops
accepting anything signed with it.

Once both sides of a proven fork have processed the resolving commit,
a fresh exchange between them settles as an extension, never a fork
again: the resolving commit's `pre` names the chosen tip, so its Commit
Root is a proven extension of it, and the consistency proof the
exchange produces reflects exactly that. An ordinary answer about the
resolved sequence stops carrying a fork proof because the exchange it
draws on no longer produces one — not because anything is deleted. This
does not undo what an earlier exchange already proved: a server's
current exchange outcome and the permanence of an already-kept proof
are two different things — the two original tip reports remain a valid
proof, for as long as whoever kept them holds onto them, regardless of
what any later exchange settles.

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

### [arch-behind-is-not-fork]

A comparison across two different `sequence` positions is not decided
by the tip reports alone. Given two servers' signed tip reports for the
same principal at sequences `m < n`, the higher-sequence side is the one
that can settle it: because its own Commit Tree already spans both
positions, it proves its OWN Commit Root at `m` — call it `CR'ₘ` —
extends to its own Commit Root at `n`, using a consistency proof over
its own tree alone ([the exchange](#the-exchange)). That proof
establishes only that the higher side's history is genuinely one line
from `m` to `n`; on its own it says nothing about the lower-sequence
server, until `CR'ₘ` is checked against what the lower side itself
signed for position `m`.

- If the proof over the higher side's own tree never runs to
  completion — a malformed exchange, a timeout, an internal error on
  either side — the comparison settles nothing either way: it is the
  absence of a comparison, the same as the single-report case
  [arch-detection-is-comparison](#arch-detection-is-comparison) already
  rules out, never a comparison that came back negative.
- If the proof completes and `CR'ₘ` equals the lower-sequence server's
  signed Commit Root at `m`, the lower-sequence server is simply
  behind — no conflict, and no further step follows.
- If the proof completes and `CR'ₘ` differs from the lower-sequence
  server's signed Commit Root at `m`, that is the fork: two
  independently authenticated claims about the identical position `m`
  disagree, which is exactly
  [arch-tip-reports-are-material](#arch-tip-reports-are-material)'s
  case.

At `m == n` this is already
[arch-tip-reports-are-material](#arch-tip-reports-are-material)'s case
directly — two roots claimed for the identical position, with no
extension to prove in either direction, so the reduction above is the
general rule collapsing to the base one, not an approximation of it.
[Checking the evidence](../guides/publication-and-audit.md#checking-the-evidence)
walks a party through both branches with reports they hold themselves.

A check that treats any two differing tip reports as a conflict,
without first asking whether the higher-sequence side's `CR'ₘ` was even
proven, cannot tell a merely-behind witness from a forked one. A check
that treats any two differing sequences as no conflict without
attempting that proof cannot tell a forked witness from a behind one
either. And a check that treats a proof attempt which never completed
as equivalent to one that completed and found `CR'ₘ` to differ
manufactures a fork finding out of an error condition — all three
confusions are what this claim rules out.

```claim
kind: requirement
evaluator: test
because: [arch-tip-reports-are-material]
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
resolves the fork](#arch-resolution-ends-fork) is that server's current
exchange outcome, never the evidence itself.

```claim
kind: requirement
evaluator: test
```

### [arch-detection-is-automatic]

A server exchanges tips and a consistency proof with a witness the
moment the two have material to exchange — delivered by the witness
registration and push fanout it already performs, never by a person, a
client, or a dedicated watcher role asking the server to run it.
Receiving a witness's tip report and consistency proof through that
channel is what triggers the exchange and produces its outcome
directly; no request that asks a server to perform this exchange exists
in this arrangement, and none is needed. This is a statement about the
server's own automatic use of the predicate, not about the predicate
itself: [the pinned predicate](../specs/receipts.md#the-pinned-predicate)
is a portable, stateless function anyone holding two tip reports can run
on their own, outside any server's exchange —
[`cyphr audit equivocation`](../guides/publication-and-audit.md#checking-the-evidence)
is exactly that command, for material a client gathered itself.

```claim
kind: requirement
evaluator: test
```

### [arch-answer-carries-contested]

A server's ordinary answer about a principal — a tip report or a
receipt, anything it would have signed and returned regardless —
carries the fork proof produced by its most recent
exchange for that principal, whenever that exchange's outcome was a
fork ([arch-behind-is-not-fork](#arch-behind-is-not-fork)). No second
request and no separate endpoint is needed to learn it; this is
[the design choice this document makes](#the-answer-carries-the-finding),
stated here as the requirement that choice imposes.

```claim
kind: requirement
evaluator: test
```

### [arch-evidence-rides-along]

What rides along is not a bare boolean assembled after the fact: it is
the same object
[arch-behind-is-not-fork](#arch-behind-is-not-fork)'s exchange produces
on a fork outcome — the two disagreeing tip reports, plus the higher
side's consistency proof when the two positions differed — carried
inline, unsummarized, so anyone who receives it can verify the two
claims conflict without asking the server anything further. This is
[what the record's owner sees](../use/detecting-a-split-view.md#the-conflict-record)
too, not a summary of it. Completing it into
[the evidence a verifier retains](#arch-evidence-is-portable) — binding
each report's signing key to the server's own chain — is the receiving
party's own replay step, not something the exchange adds.

```claim
kind: requirement
evaluator: test
depends: [arch-evidence-is-portable]
```

### [arch-fork-blocks-writes]

While a principal's consensus state is Error — a proven fork not yet
resolved — a server refuses every push for that principal except the one
that resolves the fork itself: a commit whose `pre` names one of the
fork's own contested branch tips, or a `resync/create` PoP re-asserting
one of them. [SPEC
§15.5](../../SPEC.md#155-principal-consensus-states)'s Error state is
explicit that no new transactions or actions are processed until
resolved, and [SPEC §15.8](../../SPEC.md#158-fork-resolution) is what
names the resolving push as the one whose acceptance checks the state
back to Active. This is a refusal on writes only:
[arch-answer-carries-contested](#arch-answer-carries-contested) already
establishes that ordinary answers about the principal keep coming, and
[what keeps neither branch served as settled](#while-a-fork-stands) is
the fork proof riding along with those answers — a signature is a
statement about the server that made it, never about the world — not a
second refusal layered on top of the one this claim states.

```claim
kind: requirement
evaluator: test
because: [arch-answer-carries-contested]
```

### [arch-active-key-resolves]

A fork ends only by a signature verifying under the principal's
currently-active key: a new commit whose
`pre` names the chosen branch's tip, or a `resync/create` PoP
re-asserting the current tip — the one push shape
[arch-fork-blocks-writes](#arch-fork-blocks-writes)'s refusal exempts
while the fork stands. Resolving introduces no authority beyond
what already governs an ordinary push — the same signature check accepts
or rejects it — and it reaches only servers the principal has registered
as a witness, by the same fanout as any other push. A server the
principal never registered with gets nothing and goes on serving the
abandoned branch.

```claim
kind: requirement
evaluator: test
```

### [arch-resolution-ends-fork]

Once both sides of a proven fork have processed the principal's
resolving commit — each receiving it through the same fanout as any
other push — a fresh exchange between them settles as an extension,
never a fork: the resolving commit's `pre` names the chosen tip, so its
Commit Root is a proven extension of it, and the consistency proof the
exchange produces reflects exactly that
([arch-behind-is-not-fork](#arch-behind-is-not-fork)). A server's
ordinary answers about the resolved sequence stop carrying
[a fork proof](#arch-answer-carries-contested) because its most recent
exchange no longer produces one, not because anything held from the
earlier exchange is deleted:
[the evidence of the original conflict persists regardless](#arch-finding-never-clears).

```claim
kind: requirement
evaluator: test
depends: [arch-answer-carries-contested]
because: [arch-finding-never-clears]
```
