<!--
  Provenance of the "watcher" term: defined in this document rather
  than imported. A fuller trust-model treatment (a draft
  docs/trust-model.md, on the branch writing/sovereign-signon-brief)
  defines the watcher among a full taxonomy of party kinds, and is
  under active revision there; porting a snapshot would fork a living
  document, and this page needs one term and two monotone facts, both
  short enough to state locally. If that document lands, its
  definition supersedes the one below and this page should cite it
  instead. The fuller vocabulary was not needed here — but a future
  architecture page for a network client will likely need at least the
  attestor party kind and the draft's offline/eternal/now trade-off,
  and should take them from that document rather than redefining them.
-->

# Equivocation detection

This page states how equivocation detection fits together: which
parties are involved, what each contributes, and the requirements the
arrangement must satisfy. Everything defined elsewhere is cited, not
restated; this page adds only the arrangement — and one term, the
watcher, defined here because no committed document yet carries it.

## Parties

| Party             | Contribution                                                                                       | Defined in                                    |
| :---------------- | :------------------------------------------------------------------------------------------------- | :-------------------------------------------- |
| Server (attestor) | Signs tip reports over the state it serves; issues them statelessly and retains nothing            | [Server receipts](../specs/receipts.md)       |
| Witness           | Keeps a copy of an external principal's state; communicates state through gossip                   | [SPEC §2.2.16](../../SPEC.md#2216-witnesses)  |
| Watcher           | Holds two or more independently obtained views of the same principal; runs the comparison; retains | This page                                     |

## The watcher

A **watcher** is the party that holds the comparison: it obtains views
of the same principal from more than one place or moment, keeps them,
and decides whether any two conflict.

The distinction from a witness is load-bearing. A witness, as
[SPEC §2.2.16](../../SPEC.md#2216-witnesses) defines it, keeps a copy
and moves state around; that makes it a source of views, not a judge
of them. Detecting a split view means comparing two views, and the
comparison belongs to whoever holds both — a single witness cannot
even detect that its own view is stale, because staleness is itself a
fact about two views. A watcher may well be built out of witnesses; it
is the holding of the comparison, not the keeping of a copy, that
makes it a watcher.

Two facts shape the role:

- **Divergence is permanent.** Two signed, conflicting tip reports
  about the same chain position remain a conflict no matter what is
  signed afterward. Equivocation is therefore affirmable: evidence of
  it, once obtained, endures.
- **Agreement proves nothing forward.** Honesty is only refutable:
  any number of consistent checks is compatible with a conflict at
  the next one. A watcher can convict; it can never certify.

## How the pieces fit

1. A server that is an attestor — keyed and bootstrapped; a keyless
   server signs nothing — signs a tip report over each view it
   serves, under the claim schema in
   [the receipts specification](../specs/receipts.md).
2. Issuance is stateless, by that specification's
   [rulings](../specs/receipts.md#rulings): the server signs and
   forgets, and whoever wants evidence later is the party that must
   retain the receipt. The receipt itself is the complete trust
   object.
3. Views reach the watcher from more than one vantage: by asking
   servers directly from network positions the server cannot
   correlate, or through the witness set —
   [witness registration](../../SPEC.md#1351-witness-registration) is
   the piece of that machinery that is built today.
4. The watcher compares retained tip reports pairwise under
   [the pinned predicate](../specs/receipts.md#the-pinned-predicate),
   and holds, per
   [what a verifier retains](../specs/receipts.md#what-a-verifier-retains),
   exactly two receipts and the chain segment binding their signing
   keys.
5. Nothing downstream consumes a verdict. The consensus machinery of
   [SPEC §15](../../SPEC.md#15-consensus) — proof-of-error, principal
   error states, fork detection — is design, not description: none of
   it is built, and this page must not be read as claiming otherwise.
   The [publication and audit guide](../guides/publication-and-audit.md#what-is-not-there-yet)
   states the same boundary at the operator level.

## Requirements

### [arch-watcher-holds-the-comparison]

Equivocation detection is the watcher's act. It requires at least two
independently obtained views of the same principal, held together by
one party who compares them. No server detects equivocation — its own
or another's — no single witness detects it, and no single fetch can.
This arrangement is what stands behind a reader's ability to
[decide a conflict for themselves](../use/detecting-a-split-view.md#decide-the-conflict-yourself).

```claim
kind: requirement
evaluator: review
because: [decide-the-conflict-yourself]
```

### [arch-tip-reports-are-the-material]

What the watcher compares is signed tip reports, as specified in
[the receipts specification](../specs/receipts.md) — tip against tip,
no other pairing. The rest of what a server serves (chain data,
entities, patches) is self-certifying content: verifiable in itself,
but not a statement of the server's view, and so not material for the
comparison. The tip report is the answer the reader
[keeps](../use/detecting-a-split-view.md#keep-the-signed-answer), which
is why it is the unit the whole arrangement moves and compares.

```claim
kind: requirement
evaluator: review
because: [keep-the-signed-answer]
```

### [arch-signing-stays-stateless]

Detection places no obligation on the server beyond signing what it
already serves. No receipt log, no comparison, no fork bookkeeping:
the signing path stays stateless, and the burden of retention rides
with the party that wants evidence. Whatever is later built to consume
evidence must be built beside this path, not into it.

```claim
kind: requirement
evaluator: review
```

### [arch-evidence-is-portable]

The evidence a watcher retains is a complete proof on its own: it
verifies offline, against nothing but the server's published identity,
by a party that trusts neither the watcher nor the server. Nothing a
build adds may make a verdict depend on server cooperation, on private
watcher state, or on trust in the watcher's own word — the user-facing
form of this requirement is the reader's ability to
[convince a stranger](../use/detecting-a-split-view.md#convince-a-stranger).

```claim
kind: requirement
evaluator: review
because: [convince-a-stranger]
```

### [arch-a-finding-convicts-never-clears]

A watcher's finding is one-directional. Conflicting reports are
permanent proof of equivocation; agreeing reports are not evidence of
honesty. Nothing that consumes a watcher's output may present the
absence of a finding as a clean bill.

```claim
kind: requirement
evaluator: review
```
