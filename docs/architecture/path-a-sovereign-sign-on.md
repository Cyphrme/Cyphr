# Sovereign sign-on: who a website trusts when a person signs in

When someone signs in to a website with Cyphr, the website trusts three things it
cannot check: that the key presented belongs to the person the account is for, that
the key set it is checking against is complete, and that the key set is current. The
first is unavoidable and is what "sovereign" costs. The second and third are
unavoidable only when the website keeps the record itself — and no website does.

This document describes what a relying party does, in two parts. The first part reads
the decision procedure off the relying party this repository already contains, which is
co-located with the record it checks against. The second part establishes what changes
when the relying party is separated from that record, which is the ordinary deployment
and the one nothing here implements.

**Audience.** Someone deciding how to integrate Cyphr sign-in, and anyone deciding what
to build next. It answers how the pieces fit together, not what must be true bit by bit;
the normative source is `SPEC.md`.

## Participants

Each is described by what it is trying to accomplish. The **kind** column is the party
kind [the trust model](../trust-model.md#party-kinds) assigns — a **cure name**, "what the
model calls the party, as distinct from any role name a Cyphr specification gives a
component": an **attestor** cures a determination failure and its word cannot be
reproduced; a **watcher** cures a monotonicity failure by holding more than one view over
time. A participant trusted for nothing carries no kind — its claims are discharged by an
evaluator instead.

| participant                | what it is trying to accomplish                                                                                                                                                                                                                                                                                                                                                                                                           | kind                                                                                                |
| :------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------- |
| **The person**             | Prove she controls her account without a password and without an identity provider standing between her and the site.                                                                                                                                                                                                                                                                                                                     | **attestor** at enrollment — see below                                                              |
| **The relying party**      | Decide whether to serve this person as the holder of a particular account, and decide it again on every session.                                                                                                                                                                                                                                                                                                                          | none — it is the party doing the trusting                                                           |
| **The record authority**   | Serve a correct, replayable view of a principal's chain to anyone who asks.                                                                                                                                                                                                                                                                                                                                                               | none — it is _not_ sufficient for the claims that need one; see [the claim table](#the-claim-table) |
| **The recovery agent**     | Restore a person's control of her account after she loses her keys, having verified out of band that she is who she says.                                                                                                                                                                                                                                                                                                                 | **attestor** (cure-name sense)                                                                      |
| **The recovery authority** | Hold permissions delegated to it as an external account, and exercise them: initiate a freeze, and sign the recovery transaction that links a new Principal Root to the original genesis. `SPEC.md` §14.2: _"**External Recovery** Where some permissions are delegated to an external account, a **Recovery Authority**."_ §14.6: the new PR is _"manually linked to the original PG by the Recovery Authority's recovery transaction."_ | **attestor** (cure-name sense)                                                                      |
| **The watcher**            | Establish that the view of a principal one party holds is not a stale or partial one. **The specification names this participant; nothing implements it.** `SPEC.md` §13 is headed _"State Synchronization and Gossip // TODO"_ and its §13.7 _"Gossip"_ is a stub with an empty Prover and Verifier, so the protocol is unwritten rather than undesigned; `git grep -in gossip -- rs/ go/` returns no match.                             | **watcher**                                                                                         |

"Attestor" here is the cure name only — not the **server tier** this repository's own
specifications call `attestor` (`docs/specs/server-identity.md`, `docs/specs/receipts.md`),
and not the industry sense (RATS, TPM, SPIFFE), which addresses the _same_ failure by a
different means, its evidence being re-runnable where an attestor's word is not, so
["two adjacent things doing similar work under one word are harder to keep apart than two
opposite ones, which is why this collision is the dangerous kind"](../trust-model.md#party-kinds).

**Why the person is an attestor for her own account.** At enrollment nothing establishes
that the human presenting a key is the human the account is meant for. The relying party
takes her word, once, and binds the account to the key set from then on. That is a
determination failure cured by a party whose word cannot be re-run — the definition of an
attestor — and the party is the person herself. This is what "sovereign" means in
practice: no third party is interposed, and correspondingly no third party can be blamed
or appealed to. `SPEC.md` §17.5 states the design intent:

> In Cyphr, the principal's cryptographic keys are the sole authentication factor,
> verifiable by any party without a central authority.

The rest of this document is about what "verifiable by any party" costs when the party is
not the one keeping the record.

## Part 1 — the relying party that exists

`rs/cyphr-server/src/auth/` is a working relying party, routed at
`rs/cyphr-server/src/lib.rs:254-258` as `POST /auth/challenge` and `POST /auth/login`. It
is described here to fix a concrete referent, so that Part 2 is a delta rather than an
invention.

**It is co-located with the record.** It answers _is this key active for this principal_
from its own storage, in its own words at `rs/cyphr-server/src/auth/login.rs:429-441`:

> Load the _claimed_ principal and gate on it: key active in it, and it is Active.
> Reconstructed from stored state via the same engine the write path uses.

It never crosses a trust boundary to learn a key set, so it never faces the question the
rest of this document is about.

Only the behaviours a separated relying party must **inherit** or **break** are described.
Behaviours that are neither are named at the end of this part and left alone.

### What it checks, in order

**It binds the login to its own identity.** The login's `typ` carries an audience segment
naming the service the signer believes she is authenticating to, and the server checks it
against its own configured identity rather than against any transport detail
(`login.rs:171-179`). Without this, a malicious service can relay a login a person signed
for it to a victim service and collect her session there — the relay that WebAuthn closes
by binding the origin inside the signed client data. A separated relying party
**inherits** this unchanged, and needs it more, because it is exactly the party a relay
targets.

**It requires the signer to name the principal she claims.** The key's thumbprint is not
used to look up an account, because one key may belong to several principals; the signer
names the principal and the server verifies the key is active in _that_ one
(`login.rs:214-223`). A separated relying party **inherits** this, and it becomes harder:
it must map the person to a principal identifier without a local store to search.

**It verifies possession, activity, and lifecycle.** The signature must verify against the
named key; the key must be active in the claimed principal; the principal must be in an
Active lifecycle state (`login.rs:225-238`). The signature check is free — anyone can run
it. The activity and lifecycle checks are not: they require the principal's current state,
and a separated relying party **breaks** here. This is the pivot of the whole document.

**It refuses a key its holder disowned out of band.** A key recorded in the global
death-set is refused at login even when the chain still shows it active
(`login.rs:444-455`), because the holder declared it compromised by a route the chain does
not carry. A separated relying party **breaks** here too, and worse: the death-set is
state it does not have at all.

**It bounds replay.** Either a single-use nonce or a ±60-second timestamp window,
selected by whether the payload carries a challenge (`login.rs:457-466`). `SPEC.md` §17.3
gives both, as a two-row table reproduced here as it stands:

| Mechanism            | How it works                                          | Trade-off           |
| -------------------- | ----------------------------------------------------- | ------------------- |
| **Challenge nonce**  | Service issues unique 256-bit nonce per login attempt | Requires round-trip |
| **Timestamp window** | `now` must be within ±N seconds of server time        | Clock sync required |

A separated relying party **inherits** this unchanged: both mechanisms are local to the
exchange and need no record.

**It issues a session token bound to its kind.** On success the service signs a bearer
token with its own key, stamped with a fixed `typ` so that no other message the service
ever signs can be presented as a session (`token.rs:36`, `:87-115`). `SPEC.md` §17.4:

> The service signs the token with its own key. The principal verifies the token came from
> the expected service.

A separated relying party **inherits** this, and the token's terms matter more there —
see below.

**The token's terms are the damage bound.** The default lifetime is fifteen minutes and
there is no revocation list; a short expiry is the only invalidation mechanism
(`token.rs:19-24`, `:9-13`). Co-located, that bounds a compromised session to fifteen
minutes after the record changes. Separated, it is the _only_ bound that still functions,
because the record change may never be observed at all. A separated relying party
**breaks** the assumption this design rests on.

**It declines honestly when it cannot do the job.** A server with no signing identity
refuses both login and the challenge that precedes it, with the same error, rather than
issuing a nonce that can never be redeemed (`login.rs:366-400`). A separated relying party
**inherits** this as a pattern: a party that cannot establish a precondition should say so
rather than serve a session that silently means less than it appears to.

**The identifier survives key rotation.** A principal's genesis identifier does not change
when its keys do; rotation extends the chain and leaves the genesis untouched
(`docs/specs/server-identity.md:205-211`):

> **The PG is rotation-stable.** … rotation extends the chain with a `key/replace` commit
> and leaves the genesis untouched … and, at the next list item, **The current key is NOT
> the identity -- the chain is.**

A separated relying party **inherits** this, and it is what makes a durable account
binding possible at all.

### Described behaviours excluded, and why

Three behaviours of this module are real and are left out, because a separated relying
party neither inherits nor breaks them: the bearer-token admission knob on the write path
(`middleware.rs`), which is authorization to write rather than sign-on; the challenge
store's internal expiry and lock-recovery behaviour, which is one process's memory
management; and the byte-exact token golden vector, which guards the wire format against
silent drift. Discovering that a relying party already exists is a reason to write less,
not more.

## Part 2 — what breaks when the relying party is separated

Everything in this part follows from three calls
(`rs/cyphr-server/src/auth/login.rs:432-442`):

```rust
let genesis = state
    .engine
    .resolve_genesis(&parsed.pr, &[])
    .await
    .map_err(map_load_error)?;
let principal = state
    .engine
    .load_principal(&parsed.pr, genesis)
    .await
    .map_err(map_load_error)?;
authorize_login(&parsed, &principal)?;
```

Those are local calls. Every check Part 1 describes that needs the principal's key set —
activity, lifecycle, and the checks layered on them — reaches it through them, into
storage the relying party owns. An ordinary deployment is a website that
is not the record authority, and it is defined by the fact that it **cannot make that
call**. It must obtain the same key set over a channel it does not control.

This is the one thing the co-located relying party does that a separated one cannot, and
every difference between the two is downstream of it. Nothing in this repository
implements the separated case, and no test addresses it.

### How it would obtain the key set

The mechanism exists and is specified for a different consumer. A client pins a server's
genesis identifier on first contact and thereafter verifies every later key by replaying
the server's own chain through the public surface, rather than trusting what the server
asserts about itself (`docs/specs/server-identity.md:194-226`):

> **Pin the PG on first contact.** … This is the only moment trust is extended on faith;
> every later interaction verifies against the pinned value instead of re-trusting the
> network.

The same shape applies to a person's principal: pin the genesis identifier at enrollment,
then replay the chain from it to learn the current key set. Every step of that replay is
verifiable by the party doing it. **This is the part that works**, and it is what
`SPEC.md` §17.5's _"verifiable by any party without a central authority"_ delivers.

### What replay does not establish

Replay establishes that every commit the relying party _has_ is valid and follows from the
genesis it pinned. It does not establish that it has all of them.

This is not a hypothetical. This repository already contains a party that syncs another
principal's state over exactly such a channel, and its own module documentation states the
gap (`rs/cyphr-server/src/sync.rs`):

> **What this does not close: replay of a genuine response.** The check authenticates the
> _pairing_ of local state and signed report, not the report's _currency_. A response the
> authority genuinely signed at a moment when its tip equalled the witness's own state
> matches that state by construction, forever — an on-path party can hold such a response
> and keep serving it on every later poll … Nothing is forged or altered, so no comparison
> of wire fields against each other or against local state can distinguish it from a live
> response.

Nothing is forged. The relying party holds a genuine, correctly-signed, internally
consistent view. It is simply old, and no property of the view reveals that. A channel
that can lie by omission defeats any check the receiving party runs on what it received.

**The consequence for sign-on is direct.** Every check in Part 1 that needs the key set —
key activity, lifecycle state, out-of-band revocation — is evaluated against a view that
may be arbitrarily stale. A key the person revoked yesterday still authenticates today,
and the relying party has no way to notice.

### Why an expiry does not repair it

Attaching a maximum age to the view bounds the damage but does not close the claim. An
expiry cannot distinguish a view that is behind and catching up from one that is
permanently cut off, because both look identical from inside: no new commits. The relying
party can decline to serve after the deadline, which converts a silent failure into an
outage, but it cannot establish currency.

The claim _"the record I hold for this principal is canonical"_ fails monotonicity: it can
be true when evaluated and false after the record grows, with nothing in the record
announcing the change. Monotonicity failures are cured by a **watcher** — a party holding
more than one view over time — and never by an attestor, whose word is a point observation
of exactly the kind that goes stale. This is stated as [a requirement](#currency-unmet)
rather than designed here; see [what this document does not cover](#what-this-document-does-not-cover).

## The claim table

Every claim crossing between participants on this path, in two groups: claims about the
**record** — what a relying party concludes about a principal — and claims about the
**exchange** — what it concludes about the request in front of it. **Det/Cert/Mono** are
the three axes; a claim's **cell** is ["its position once the three axis outcomes are
fixed"](../trust-model.md#cells). A claim that holds on all three needs an evaluator and no
trusted party at all. Every row carries a requirement or a note saying why it has none.

### Claims about the record

| #   | claim                                                            |  Det   | Cert |  Mono  | cell            | trusted party                                               | a bad one yields                                                  |
| :-- | :--------------------------------------------------------------- | :----: | :--: | :----: | :-------------- | :---------------------------------------------------------- | :---------------------------------------------------------------- |
| 1   | This request was signed by key _K_                               |   —    |  —   |   —    | below the floor | none — evaluator: `coz::verify_json`, `login.rs:226`        | a forged sign-in is accepted                                      |
| 2   | This chain derives to identifier _P_                             |  yes   | yes  |  yes   | 1 — verifiable  | none — evaluator required; **none exists**, see row note    | a record is served under an identifier it does not belong to      |
| 3   | _P_'s identifier is the same one as last session                 |  yes   | yes  |  yes   | 1 — verifiable  | none — evaluator required; **none exists**, see row note    | the account silently becomes a different account after a rotation |
| 4   | _K_ is an active key of principal _P_                            |  yes   | yes  | **no** | 2 / T3          | **watcher** — none exists                                   | a revoked or lost key still signs in                              |
| 5   | The record I hold for _P_ is canonical — _P_ has not equivocated |  yes   | yes  | **no** | 2 / T3          | **watcher** — none exists                                   | a split or frozen view is served indefinitely                     |
| 6   | The person presenting _K_ is the person this account is for      | **no** |  —   |  yes   | 5 / T1          | the person at enrollment, the **recovery agent** thereafter | the account is served to the wrong human                          |
| 7   | _P_ may perform operation _X_                                    |   —    |  —   |   —    | decision        | the relying party itself                                    | over-authorization                                                |

**Rows 2 and 3 are [Row-1 claims](../trust-model.md#row-1-claims)**: determined,
certifiable and monotone, discharged by running something rather than by trusting someone.
Row 1 is not one — it sits `below the floor`, where "the message carries everything the
check needs" and there is no trust residue to type — but all three name no party. Row 1
carries no requirement of its own, and deliberately: verifying a signature over the bytes
presented is the precondition every path shares, and what this document has to say about it
is that satisfying it is not enough — which is what the exchange rows say.

**Row 2 is undischarged, and that is a defect rather than a design choice.** The storage
engine holds both the derived genesis and the identifier a record is filed under at the
moment of the write, and does not compare them; its own documentation names the same gap on
the read path — "storage never binds a derived genesis to the identifier it is filed under"
(`rs/cyphr-storage/src/engine/mod.rs:403-406`). That comment sends the reader elsewhere in
its own file for the tracking issue and nothing is there, so the durable handle is the issue
number, #154. A Row-1 claim left undischarged is
[indefensible](../trust-model.md#row-1-claims) — the check is free and nobody is running it.
Discharging it at every writer is a system-wide task beyond this path; the requirement here
is only that a relying party must not assume it.

**Row 3 has no evaluator, and the nearest candidate is about a different principal.**
`rotation_preserves_pg_and_swaps_active_key`
(`rs/cyphr-server/tests/server_principal.rs:243`) does assert that a genesis identifier
survives rotation, but it drives `ServerPrincipal::bootstrap` and `sp.rotate` — the
**server's** own chain. A person's principal rotates through the ordinary write path, and
the two golden fixtures that exercise `key/replace` both leave `pg` empty, which
`rs/cyphr/tests/golden_fixtures.rs:206` skips. Nothing checks that a person's identifier
survives her own rotation.

**Rows 4 and 5 are the same failure at two scopes.** Row 4 is about one principal's key
set going stale; row 5 is about the whole view being non-canonical. Both are cured by a
watcher and neither is cured by any party this system contains.

**Row 6 is Path A's determination claim and the one that cannot be engineered away.** No
evaluator decides that a human is a particular human. At enrollment the person's own
assertion is taken on faith; after a device loss the recovery agent's out-of-band
verification is taken on faith, and the specification deliberately declines to fix the
method. Naming this honestly is the entire value of typing it: a relying party that
believes row 6 is verifiable has misunderstood what it bought. Typing it `5 / T1` is a
modeling choice this project makes rather than a result the framework hands down: that
undetermined claims exist is mechanized, but reading a particular binding claim as one of
them is ["an explicit modeling hypothesis about the fiber over the record, never a
theorem"](../trust-model.md#determination-t1).

**Row 7 has no requirement, and that is a scope decision rather than an oversight.** Its
label is [`decision`](../trust-model.md#labels-outside-the-model) — "the claim's truth is
fixed by a party's own choice rather than by any state of the world" — so the action it
calls for is that the relying party decides, and this document does not. Such a claim
reports no axis outcomes, which is why all three columns read `—`. It is not the source's
`elective`, a claim a verifier could check and declines to: nothing is declined here,
because there is no fact of the matter to check, and this document uses "forced" in that
word's paired sense under [the forcing case](#the-forcing-case).

### Claims about the exchange

Row 1 — _this request was signed by key K_ — is **true of a relayed login and of a replayed
one**. The attack succeeds with the row satisfied, so what those attacks defeat is not a
claim about the record at all. Four requirements trace here rather than to rows 1 and 7.

| #   | claim                                        | Det | Cert |  Mono  | cell           | trusted party                                                                                                           | a bad one yields                                               |
| :-- | :------------------------------------------- | :-: | :--: | :----: | :------------- | :---------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------- |
| 8   | This assertion was made _to me_              | yes | yes  |  yes   | 1 — verifiable | none — evaluator: `login_rejects_mismatched_audience`, `rs/cyphr-server/tests/login.rs:636`                             | a login signed for one service is relayed to another           |
| 9   | This assertion is _fresh_ — challenge        | yes | yes  |  yes   | 1 — verifiable | none — evaluator: `login_rejects_replayed_challenge`, `rs/cyphr-server/tests/login.rs:578`                              | a captured login is replayed                                   |
| 10  | This assertion is _fresh_ — timestamp window | yes | yes  | **no** | 2 / T3         | none — an accepted expiry, plus clock agreement                                                                         | a captured login is replayed inside the window                 |
| 11  | This artifact _is a session token I issued_  | yes | yes  |  yes   | 1 — verifiable | none — evaluator: `verify_rejects_valid_signature_with_wrong_typ`, `rs/cyphr-server/src/auth/token.rs:412`              | another message the service signed is presented as a session   |
| 12  | A challenge I issue can be redeemed          | yes | yes  |  yes   | 1 — verifiable | none — evaluator: `keyless_login_and_challenge_share_the_same_rejection`, `rs/cyphr-server/tests/keyless_matrix.rs:431` | a person completes a challenge that can never become a session |

**Rows 9 and 10 are one claim under two mechanisms, and the two do not land in the same
cell.** A single-use challenge checks state the relying party issued and holds, so freshness
is determined, certifiable and monotone. A timestamp window is [an accepted
expiry](../trust-model.md#curing-a-non-monotone-claim) — the third of the three cures for a
non-monotone claim — resting additionally on clock agreement nothing in the record
establishes. One row cannot carry two cells without prose in an axis column, the defect row
7 just lost. **No exchange row names a trusted party**: rows 8, 9, 11 and 12 name
evaluators, and row 10 is discharged by an accepted bound rather than by a watcher — the one
exchange claim a relying party pays for instead of checking.

## The forcing case

_She loses her device._

**This section grounds the typing of rows 4, 5 and 6** — it is where determination and
monotonicity are forced rather than chosen. At Level 3+ a designated recovery agent signs a
`key/create` for her and the account survives, because _"the agent's authority derives from
the `recovery/create` delegation"_ (`docs/specs/recovery.md:98-100`). Her identifier
survives; at Level 1 it would not, and `SPEC.md` §14.1 says so — _"Note that sideband
recovery results in a new Principal identity."_ The account continues. Those mechanics are
here only to make the participant table's two recovery rows legible; they produce no
requirements.

**Is the case forced?** Yes, and at two layers, which is the honest reading rather than
one clean answer.

The first layer is determination and it is forced for every relying party. The agent
verified her identity out of band by a method the specification does not fix. The relying
party cannot re-run that verification — there is no scheme at any level that would let it —
and it cannot check-and-decline, because declining means locking out a person who has done
everything correctly. It must extend trust it cannot audit. That is row 6, cured by an
attestor, and it is the irreducible cost of not having an identity provider.

The second layer is monotonicity and it is forced only for a separated relying party. Her
old key is now revoked and her new key is now active — in the record. The separated party
may hold neither fact. Until it learns them, it will refuse her real key and accept the
key on the device she lost.

**Does it block the decision?** Yes, and the second layer blocks it in the dangerous
direction. The relying party is not merely under-informed; it is confidently wrong, and
its confidence is well-founded on everything it can see. Every signature verifies, every
commit chains, the view is internally consistent. There is no error to handle.

**What the party does when the answer is bad.** Co-located, the answer is already correct.
That a revoked key stops signing in is checkable, and is checked:
`revoked_key_refused_at_login_sibling_survives`
(`rs/cyphr-server/tests/naked_revoke.rs:939`) asserts the whole sequence — the key signs in
first, so the baseline is empirical rather than assumed; the revocation is accepted; the
key is then refused; and a sibling key of the same principal still signs in, so the
refusal is scoped to the key and not the account.

**The exposure bound is argued, not checked.** A session already issued survives at most one
token lifetime past the revocation — fifteen minutes by default, expiry being the only
invalidation (`token.rs:9-13`, `:19-24`). That is read from the code, not exercised:
`verify_token` (`rs/cyphr-server/src/auth/token.rs:125-149`) checks the signature, `typ` and
`exp` and nothing else, never reloading the principal or consulting the death-set, and no
test issues a token and verifies it across a revocation. The security-relevant half of this
paragraph is the un-evaluated half.

Separated, there is no such bound. The stale view never expires on its own, the fifteen
minutes restart on every fresh sign-in with the lost key, and the correct behaviour — the
one this document requires — is to bound the age of the view explicitly, refuse to serve
past that bound, and treat the refusal as an outage to be fixed rather than a security
event that has been handled.

## Requirements

Each is traceable to a row of [the claim table](#the-claim-table). Requirements in the
first group are satisfied by the relying party in this repository. The binding to a test
runs the other way round: a requirement never names a test, and a `docket:` marker comment
at the test names the requirement. Requirements in the second group are satisfied by
nothing here.

### [signon-audience-binding]

A relying party MUST verify that the audience named inside the signed login payload is its
own identity, and MUST NOT take the audience from any unsigned transport detail. Traces to
row 8. The MUST NOT clause is closed structurally rather than by a test, which is higher on
the evaluator hierarchy than one: `parse_login` derives the audience from the signed
payload's `typ` (`login.rs:171-173`) and compares it to the configured `server_audience`
(`login.rs:177`), so no transport value reaches the comparison and there is no path a test
could exercise.

```claim
kind: requirement
evaluator: test
```

### [signon-claimed-principal]

A relying party MUST verify the signing key against the principal the signer names, and
MUST NOT resolve a principal from the key's thumbprint. One key may be active in several
principals, so a thumbprint lookup is ambiguous by construction. Traces to rows 3 and 4.

```claim
kind: requirement
evaluator: test
```

### [signon-key-active-in-principal]

A relying party MUST refuse a sign-in whose key is not active in the claimed principal, and
MUST refuse a principal that is not in an active lifecycle state. The principal checked is
the one the signer named, per
[signon-claimed-principal](#signon-claimed-principal). Traces to row 4. The marker
registers the first conjunct, via `login_rejects_key_revoked_in_claimed_principal`; the
second is closed by `login_rejects_frozen_principal`
(`rs/cyphr-server/tests/login.rs:815`) and `login_rejects_deleted_principal` (`:853`),
neither of which carries a marker of its own.

```claim
kind: requirement
evaluator: test
because: [signon-claimed-principal]
```

### [signon-disowned-key]

A relying party MUST refuse a key its holder has disowned out of band, even when the
principal's chain still shows that key active. The refusal MUST be scoped to the key
rather than the principal. This extends
[signon-key-active-in-principal](#signon-key-active-in-principal) to a fact the chain does
not carry. Traces to row 4.

```claim
kind: requirement
evaluator: test
because: [signon-key-active-in-principal]
```

### [signon-replay-bound]

A relying party MUST bound signature replay, by a single-use challenge or by a bounded
acceptance window on the signed timestamp. Traces to rows 9 and 10 — one row per mechanism,
because the two do not land in the same cell. The marker registers the challenge arm; the
window arm is closed by `login_rejects_out_of_window_timestamp`
(`rs/cyphr-server/tests/login.rs:612`), which carries no marker of its own.

```claim
kind: requirement
evaluator: test
```

### [signon-token-kind-binding]

A session token MUST be bound to its kind inside the signature, so that no other message
the relying party signs can be presented as a session. Traces to row 11.

```claim
kind: requirement
evaluator: test
```

### [signon-honest-refusal]

A relying party that cannot complete sign-on MUST decline it, and MUST decline every step
leading to it with the same error, rather than completing early steps that cannot be
redeemed. Traces to row 12.

```claim
kind: requirement
evaluator: test
```

### [separated-key-set-by-replay]

A relying party that does not hold the record MUST obtain a principal's key set by
replaying the chain from an identifier pinned at enrollment, and MUST NOT trust a served
assertion about the current key. This is how a separated party satisfies
[signon-claimed-principal](#signon-claimed-principal) with no local store to search.
Traces to rows 2 and 3.

```claim
kind: requirement
evaluator: none
because: [signon-claimed-principal]
```

### [currency-unmet]

A relying party's obligation to hold a _current_ view of a principal is not met by
anything in the record. The replay of
[separated-key-set-by-replay](#separated-key-set-by-replay) establishes that what is held
is genuine, never that it is complete. The claim _"the record I hold for this principal is
canonical"_ fails monotonicity, and the party kind that cures a monotonicity failure is a
**watcher** — never an attestor, whose word is a point observation of exactly the kind that
goes stale. A relying party MUST state this obligation as unmet rather than treat a
successful replay as having met it. Traces to rows 4 and 5.

```claim
kind: requirement
evaluator: none
because: [separated-key-set-by-replay]
```

### [separated-staleness-not-absence]

A relying party MUST NOT treat "no update observed" as "no update exists". It MUST bound
the age of its view explicitly and refuse to serve past that bound. An expiry does not
establish currency — it converts a silent wrong answer into a refusal, which is an
improvement and not a cure for [currency-unmet](#currency-unmet). Traces to row 5.

```claim
kind: requirement
evaluator: none
because: [currency-unmet]
```

### [separated-session-window]

A relying party MUST treat session lifetime as the only bound on how long a repudiated key
retains access, and MUST set it against that exposure rather than against convenience. A
system with no revocation list has no other mechanism, and under
[currency-unmet](#currency-unmet) a separated party may never observe the repudiation at
all. Traces to row 4.

```claim
kind: requirement
evaluator: none
because: [currency-unmet]
```

### [determination-named-not-verified]

A relying party MUST record that the binding between a human and an account is trusted
rather than verified, and MUST identify the party trusted for it — the person at
enrollment, the recovery agent after a recovery. It MUST NOT present this binding as
discharged by signature verification, which establishes possession of a key and nothing
about who holds it. Traces to row 6.

```claim
kind: requirement
evaluator: none
```

### [identifier-binding-undischarged]

A relying party MUST NOT assume that a record served under an identifier derives to that
identifier. The check is free and verifiable, and the storage engine does not perform it.
Traces to row 2.

```claim
kind: requirement
evaluator: none
```

## Integration points

What this path integrates with, and who is trusted at each.

| integration point                                 | what it provides                                                                        | party trusted                                                                        |
| :------------------------------------------------ | :-------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------- |
| The login flow, either option                     | Proof that the signer possesses a key, bound to an audience and defended against replay | **the person** — for possession, verifiably; for identity, on faith                  |
| Bearer tokens                                     | A session that avoids re-signing every request                                          | **the relying party itself** — it signs and verifies its own tokens                  |
| Principal chain replay (`GET /tip`, `GET /patch`) | The key set and lifecycle state to check against                                        | **nobody, for what is replayed** — every step is verifiable. **Unmet, for currency** |
| Genesis pinning (`docs/specs/server-identity.md`) | A durable account identifier that survives key rotation                                 | **the person, once**, at the moment of pinning                                       |
| Recovery at Level 3+                              | Continuity of the account across device loss                                            | **the recovery agent** — attestor; its out-of-band check cannot be re-run            |

For ordinary sign-in the trusted party is the person. That is the design working as
intended: the alternative is an identity provider, which is the thing this replaces.

## What is open

**What a currency attestation asserts.** Whether a signed statement about a principal's
state can say anything about _now_, as opposed to _as of some moment_, is an open protocol
question tracked as issue #139, with a demonstrated consequence in #152. This document
states the obligation and does not answer it. No signed present-tense timestamp is
proposed here, because a claim that fails monotonicity admits no offline, non-expiring,
present-tense certificate at all.

**Whether each recovery admission is a fresh trust root.** Admitting a recovery agent
imports that agent's own genesis into what the account's validity rests on. Whether every
out-of-band exercise counts as a new admission, or whether admitting the agent once
settles it, is not decided by the specification and is not decided here. It bears on how
many parties row 6 ultimately rests on. It is marked open rather than assumed either way.

**The identity-binding gap.** Row 2 of the claim table is undischarged system-wide and is
tracked as issue #154.

## What this document does not cover

This path is about one relying party with one view of a principal. Everything that
requires comparing **two or more views of the same principal** is out of scope here, and
deliberately so:

- Which participants can cause a record to be filed under an identifier, and whether each
  holds the derived genesis when it writes.
- The design of the party that assembles reports about one principal from more than one
  source — its inputs, its freshness obligation, and what it does with a disagreement.
- How such a party would be built: gossip, a polled registry, an operator-driven audit, or
  anything else.

[currency-unmet](#currency-unmet) reaches that boundary and stops at it, stating the
obligation and the party kind that discharges it. `SPEC.md` §2.2.16 already names the
participant that keeps another principal's state:

> A **witness** is a client that keeps a copy of an external principal's state and
> communicates state through gossip.

The gossip clause has to be answered rather than passed over: gossip is one of the two
instances [the trust model](../trust-model.md#party-kinds) gives for the party that cures a
monotonicity failure. What the model names, though, is a **collective** — a witness _quorum_
or a gossip _protocol_ — and a participant in a gossip protocol is not the protocol. A
single gossiping witness can receive information that leaves its view less stale, but it
cannot detect that its own view _is_ stale: detecting staleness means comparing two views,
and the comparison belongs to the protocol rather than to any client running it. So a
witness is a participant in a cure rather than an instance of one, and what closes the gap
is the party holding the comparison. Naming that requirement is this document's job.
Designing that party is not.
