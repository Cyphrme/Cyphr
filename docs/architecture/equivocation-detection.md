# Equivocation detection

This page states how equivocation detection fits together: which parts
are built and live, which are implemented but wired to nothing, and the
requirements the arrangement must satisfy once it runs. Everything
defined elsewhere is cited, not restated.

A **fork** is two conflicting, independently signed claims about the
same principal at the same chain position —
[SPEC §15.7.1](../../SPEC.md#1571-invalid-forks-fork-detection-and-duplicitous-behavior)'s
"two or more conflicting commits reference the same pre." A **split
view** is the same event named for how it looks from outside: one
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

## What is built, and what runs nowhere

**Fanout is live.** `spawn_fanout` (`rs/cyphr-server/src/fanout.rs`) runs
after every accepted `/push` (`rs/cyphr-server/src/routes.rs`'s `push`
handler calls it unconditionally on success), delivering the committed
blobs to every witness the principal has registered
([SPEC §13.5.1](../../SPEC.md#1351-witness-registration)). This is what
gets a second, independently signed view of a push to somewhere other
than the server that first accepted it — the material the comparison
above needs.

**The comparison is not wired to it.** `check_cross_witness_consistency`,
`detect_fork_unverified`, and `format_disagreement_evidence` are `pub`,
tested, and called from no route, no background job, and nowhere else in
the server. A witness that receives a conflicting push over fanout has,
in its own crate, code that would prove the conflict, and nothing that
runs it.

So detection today is two built halves with nothing joining them: the
transport that would carry a second view to a comparing party works; the
comparison that party would run over what it received does not run
anywhere.

**Resolution reaches registered witnesses, and only them.** A fork ends
when the principal — not the server, not a witness — signs a new commit
whose `pre` names the chosen branch's tip, or a `resync/create` PoP
re-asserting the current tip
([SPEC §13, "Resync PoP"](../../SPEC.md#13-resync-pop)). Because a
resolution is itself a commit, `spawn_fanout` carries it to every server
the principal has registered as a witness, automatically, the same as
any other push. A server the principal never registered with, or never
otherwise reaches, gets nothing and goes on serving the abandoned
branch — that is the actual gap, narrower than "nothing carries a
resolution between servers."

**Nothing downstream consumes a proven conflict, wired or not.** The
consensus machinery of [SPEC §15](../../SPEC.md#15-consensus) —
proof-of-error, principal error states, fork-triggered state
transitions — is design, not description: none of it is built. The
[publication and audit guide](../guides/publication-and-audit.md#what-is-not-there-yet)
states the same boundary at the operator level.

## Requirements

### [arch-detection-is-comparison]

Fork/equivocation detection is comparison: it requires at least two
independently obtained tip reports about the same principal and
sequence, held together and evaluated against each other. No single tip
report detects it, no server detects its own or another's equivocation
by signing alone, and no witness holding only its own view can either.
This is what stands behind a reader's ability to
[tell a proven conflict from an unproven one](../use/detecting-a-split-view.md#a-conflict-is-decided-by-a-fixed-check).

```claim
kind: requirement
evaluator: review
because: [a-conflict-is-decided-by-a-fixed-check]
```

### [arch-tip-reports-are-the-material]

What the comparison operates over is signed tip reports, as specified in
[the receipts specification](../specs/receipts.md) — tip against tip, no
other pairing. The rest of what a server serves (chain data, entities,
patches) is self-certifying content: verifiable in itself, but not a
statement of the server's view, and so not material for the comparison.
The tip report is the answer that gets
[kept](../use/detecting-a-split-view.md#keep-the-signed-answer), which is
why it is the unit the whole arrangement moves and compares.

```claim
kind: requirement
evaluator: review
because: [keep-the-signed-answer]
```

### [arch-signing-stays-stateless]

Detection places no obligation on the server beyond signing what it
already serves. No receipt log, no comparison, no fork bookkeeping: the
signing path stays stateless, per `docs/specs/receipts.md`
`[receipts-r-stateless]`, and the burden of retention rides with the
party that wants evidence. Whatever is later built to run the
comparison must be built beside this path, not into it.

```claim
kind: requirement
evaluator: review
```

### [arch-evidence-is-portable]

The evidence retained is a complete proof on its own: it verifies
offline, against exactly
[what a verifier retains](../specs/receipts.md#what-a-verifier-retains)
— the two receipts and the chain segment binding both signing keys — by
a party that trusts neither the party that compared them nor the server.
The server's bare published identity is not that segment; per
`docs/specs/receipts.md` `[receipts-r-genesis-hint]` it is a hint toward
replaying the chain, not a substitute for having replayed it. Nothing a
build adds may make a verdict depend on server cooperation, on private
state held by whoever ran the comparison, or on anyone's unverified word
for it — the user-facing form of this requirement is the reader's
ability to
[convince a stranger](../use/detecting-a-split-view.md#convince-a-stranger),
and that page states where assembling the chain segment is not yet
possible with shipped tooling.

```claim
kind: requirement
evaluator: review
because: [convince-a-stranger]
```

### [arch-a-finding-convicts-never-clears]

A comparison's finding is one-directional. Conflicting reports are
permanent proof of equivocation; agreeing reports are not evidence of
honesty. Nothing that consumes a comparison's output may present the
absence of a finding as a clean bill.

```claim
kind: requirement
evaluator: review
```
