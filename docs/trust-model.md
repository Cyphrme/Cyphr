# The trust model: how this project types a claim

The model this repository's architecture documents use to type a claim is the one in
_Factoring Trust: A Machine-Checked Characterization of Where Verification Must End_
(Timothy DeHerrera, Cyphrpunk LLC, 2026), at
<https://github.com/nrdxp/factoring-trust>, commit `5f32fb6`. The paper is the authority
for the model: its definitions, its theorems and its names. This document does not restate
them. It records only how this project uses the paper's terms, and the labels this project
adds where a claim falls outside them.

Its author is the same person as this repository's. This is a lens for reasoning about
what a Cyphr deployment trusts, not part of the Cyphr protocol: `SPEC.md` is the normative
source for what the protocol requires, and nothing here changes it.

## Terms used here

All of these are the paper's.

- A claim is measured against three **conditions**: _determination_ (the information
  needed to decide it is fixed in the record), _certifiability_ (it can be checked at the
  verifier's power, given the context), and _monotonicity_ (growth of the record never
  revokes it).
- A claim that meets all three is **enduring**, and an evaluator anyone can run discharges
  it. A claim's **trust owed** is the set of conditions it fails.
- A claim owes one party per condition it fails: a **witness** for determination, a
  **voucher** for certifiability, a **watcher** for monotonicity.
- A failure can instead be **exited**: the claim's parameter is moved to a value at which
  it holds, or a different claim that holds is made in its place. The paper's exits for a
  non-monotone claim are the three corners of its EON result (eternal, offline, now): a
  claim "as of" a stated record gives up _now_, a verdict that expires gives up
  _eternal_, and re-checking against the growing record gives up _offline_.

The architecture documents state, for each claim they type, which conditions it fails and
so which party it owes, and which exit it takes where it takes one.

## Labels this project adds

Two labels mark claims the conditions do not describe. They are this project's, not the
paper's. A claim carrying one reports no condition outcomes: its determination,
certifiability and monotonicity columns are each written `—`.

**below the floor** — the claim is settled by a computation over the artifact presented,
before any question about the record arises. Verifying a signature over a message is the
standard case: the message carries everything the check needs. The paper has a floor too,
and it means something else: the two physical residuals every verdict stands on, a
commitment's binding and a verifier's fidelity. The shared word is a collision, not an
agreement.

**decision** — the claim's truth is fixed by a party's own choice rather than by any state
of the world. Whether a principal may perform some operation is the relying party's own
rule: nothing to determine, certify or preserve under growth, and nobody trusted for it
beyond the party making the decision. This is not the paper's elective trust, which a
verifier could discharge and declines to; for a `decision` claim no check is being
declined.

**indefensible** — a claim that owes nothing, and so has a free evaluator, left unchecked.
Naming what a system trusts is a defence; leaving a free check unrun is not one.

## Names that collide

The paper's **witness** is the party owed for a determination failure. It is not the
specification's witness, which `SPEC.md` §2.2.16 defines as "a client that keeps a copy of
an external principal's state and communicates state through gossip", and it is not this
repository's server mode `witness`. The paper's **watcher** is the party owed for a
monotonicity failure, and it holds the comparison between views that detecting staleness
needs. A single gossiping client, or a single server in witness mode, can receive
information that leaves its view less stale, but it cannot by itself detect that its own
view is stale, so it takes part in discharging that obligation rather than discharging it.

This repository's server specifications also call a keyed, bootstrapped server tier
`attestor` (`docs/specs/server-identity.md`, `docs/specs/receipts.md`). That is a role name
for a component. It is not one of the paper's parties.

The paper's **voucher** owes a certifiability failure. This repository reserves **vouch**
and **corroboration** for two species of evidence (a keyed judgment binding an artifact to
a principal, and a re-run check), so a _voucher_ is a party owed and a _vouch_ is a kind of
evidence; the shared root is not a shared referent.

## What the model does not settle

The model bounds the design space without choosing within it. It does not choose which exit
to take for a non-monotone claim, what "current" means operationally, or anything below the
level of conditions: it has no wire format, message, sequence number, threshold or resync.
Those sit with `SPEC.md` and with this repository's designs. The paper also states its own
open results and the grants its verdicts rest on; a design leaning on one of them is
leaning on something the paper does not close.
