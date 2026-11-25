# Sovereign sign-on: who a website trusts when a person signs in

When someone signs in to a website with Cyphr, the website trusts three things it
cannot check: that the key presented belongs to the person the account is for, that
the key set it is checking against is complete, and that the key set is current. The
first is unavoidable and is what "sovereign" costs. The second and third are
unavoidable when the website is separate from the record — which is the ordinary
deployment. A website that keeps the record itself avoids them.

This document is about **Path A**: the sign-on path in which the person's own signing key
is the only authenticator, with no password and no identity provider (`SPEC.md` §17). The
website, which the rest of the document calls the **relying party**, is the party relying on
that key.

This document describes what a relying party does, in two parts. The first part reads
the decision procedure off the relying party built into the Cyphr server, which is
co-located with the record it checks against. The second part establishes what changes
when the relying party is separated from that record, which is the ordinary deployment.
`cyphr_client::RelyingParty` (`rs/cyphr-client/src/relying_party.rs`) is that separated
relying party: it replays the principal's chain from peers it chose, pinned at the
principal's genesis key, and decides a sign-in only from the key set that replay produced.

**Audience.** Someone deciding how to integrate Cyphr sign-in, and anyone deciding what
to build next. It answers how the pieces fit together, not what must be true bit by bit;
the normative source is `SPEC.md`.

## Participants

Each is described by what it is trying to accomplish. The **owed as** column says which
party, in [the trust model's](../trust-model.md#terms-used-here) terms, the participant is:
a **watcher** is owed for a monotonicity failure and holds more than one view over time. A
participant trusted for nothing carries no entry — its claims are discharged by an
evaluator instead.

| participant              | what it is trying to accomplish                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | owed as                                                                                             |
| :----------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------- |
| **The person**           | Prove she controls her account without a password and without an identity provider standing between her and the site.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | none — possession is checked by an evaluator                                                        |
| **The relying party**    | Decide whether to serve this person as the holder of a particular account, and decide it again on every session.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | none — it is the party doing the trusting                                                           |
| **The record authority** | Serve a correct, replayable view of a principal's chain to anyone who asks.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | none — it is _not_ sufficient for the claims that need one; see [the claim table](#the-claim-table) |
| **The recovery agent**   | Restore a person's control of her account after she loses her keys, having verified out of band that she is who she says. Where permissions are delegated to it as an external account it can also initiate a freeze, and it signs the recovery transaction that links a new Principal Root (PR) to the original Principal Genesis (PG), the account's permanent identifier ([`SPEC.md` §3.7.1](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#371-principal-root-and-principal-genesis)).                                                                                                                                                                                                                           | none                                                                                                |
| **The watcher**          | Establish that the view of a principal one party holds is not a stale or partial one. **The specification names this participant but does not define its protocol.** `SPEC.md` §13 is headed _"State Synchronization and Gossip // TODO"_ and its §13.7 _"Gossip"_ is a stub with an empty Prover and Verifier. What ships is the implementation's own gossip, not a specified protocol: a server's `[gossip]` timer pulls every principal it holds from the peers its operator chose, `cyphr verify`, `cyphr watch` and `cyphr audit` compare a client's view with those peers' views, and `cyphr gossip export` and `import` carry a verified record between clients with no peer. None of it makes a view current; see [currency-unmet](#currency-unmet). | **watcher**                                                                                         |

Recovery agent and Recovery Authority: `SPEC.md` §14.2 names the external account that
holds delegated recovery permissions a **Recovery Authority** (_"**External Recovery**
Where some permissions are delegated to an external account, a **Recovery Authority**."_).
§14.6, the recovery flow, uses both names: the user contacts the _"recovery agent"_, the
agent verifies identity and signs the recovery transaction, and the new PR is _"manually
linked to the original PG by the Recovery Authority's recovery transaction."_ The
specification does not define them as separate roles, so this document treats them as one
and calls it the recovery agent. Whether they are one role is a question for nrd and the
specification's author, not settled here. Whether every admission of such an agent is a
fresh trust root is also open; see [what is open](#what-is-open).

**What the person is trusted for.** Her signature proves she holds the key, and a
relying party checks that without trusting anyone. A site that needs identifying details
takes them as a signed data action: the record then fixes that the principal asserted
them under its key, and whether they are true is the signer's word, as for any identity
claim. This is what "sovereign" means in practice: no third party is interposed.
`SPEC.md` §17.5 states the design intent:
`SPEC.md` §17.5 states the design intent:

> In Cyphr, the principal's cryptographic keys are the sole authentication factor,
> verifiable by any party without a central authority.

The rest of this document is about what "verifiable by any party" costs when the party is
not the one keeping the record.

## Part 1 — the relying party that exists

`rs/cyphr-server/src/auth/` is a working relying party, routed at
`rs/cyphr-server/src/lib.rs` as `POST /auth/challenge` and `POST /auth/login`. It
is described here to fix a concrete referent, so that Part 2 is a delta rather than an
invention.

**It is co-located with the record.** It answers _is this key active for this principal_
from its own storage, in its own words in `login` (`rs/cyphr-server/src/auth/login.rs`):

> Read the _claimed_ principal and gate on it: key active in it, and it is Active. The
> verified state at its tip, from the same engine entry the write path uses.

It never crosses a trust boundary to learn a key set, so it never faces the question the
rest of this document is about.

Only the behaviours a separated relying party must **inherit** or **break** are described.
Behaviours that are neither are named at the end of this part and left alone.

### What it checks, in order

**It binds the login to its own identity.** The login's `typ` carries an audience segment
naming the service the signer believes she is authenticating to, and the server checks it
against its own configured identity rather than against any transport detail
(`parse_login`, `rs/cyphr-server/src/auth/login.rs`). Without this, a malicious service can relay a login a person signed
for it to a victim service and collect her session there — the relay that WebAuthn closes
by binding the origin inside the signed client data (W3C Web Authentication, the
[`CollectedClientData` `origin`
member](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin)). A separated
relying party **inherits** this unchanged, and needs it more, because it is exactly the
party a relay targets.

**It requires the signer to name the principal she claims.** The key's thumbprint is not
used to look up an account, because one key may belong to several principals; the signer
names the principal and the server verifies the key is active in _that_ one
(`authorize_login`). A separated relying party **inherits** this, and it becomes harder:
it must map the person to a principal identifier without a local store to search.

**It verifies possession, activity, and lifecycle.** The signature must verify against the
named key; the key must be active in the claimed principal; the principal must be in an
Active lifecycle state (`authorize_login`). The signature check is free — anyone can run
it. The activity and lifecycle checks are not: they require the principal's current state,
and a separated relying party **breaks** here. This is the pivot of the whole document.

**It refuses a key its holder disowned out of band.** A key recorded in the global
death-set (the server's record of keys whose holders declared them dead out of band,
kept apart from any principal's chain) is refused at login even when the chain still shows it active
(the `is_dead` check in `login`), because the holder declared it compromised by a route the chain does
not carry. A separated relying party **breaks** here too, and worse: the death-set is
state it does not have at all.

**It bounds replay.** Either a single-use nonce or a ±60-second timestamp window,
selected by whether the payload carries a challenge (the replay branch of `login`). `SPEC.md` §17.3
gives both, as a two-row table reproduced here as it stands:

| Mechanism            | How it works                                          | Trade-off           |
| -------------------- | ----------------------------------------------------- | ------------------- |
| **Challenge nonce**  | Service issues unique 256-bit nonce per login attempt | Requires round-trip |
| **Timestamp window** | `now` must be within ±N seconds of server time        | Clock sync required |

A separated relying party **inherits** this unchanged: both mechanisms are local to the
exchange and need no record.

**It issues a session token bound to its kind.** On success the service signs a bearer
token with its own key, stamped with a fixed `typ` so that no other message the service
ever signs can be presented as a session (`BEARER_TOKEN_TYP` and `verify_token`, `token.rs`). `SPEC.md` §17.4:

> The service signs the token with its own key. The principal verifies the token came from
> the expected service.

A separated relying party **inherits** this, and the token's terms matter more there —
see below.

**The token's terms are the damage bound.** The default lifetime is fifteen minutes
(`DEFAULT_TTL_SECS`, `token.rs`) and there is no revocation list, but a session is also
bound to the key that opened it: co-located, the server ends it as soon as that key leaves
the chain (see "The exposure bound" under [the forcing case](#the-forcing-case)). Separated,
the record change may never be observed at all, so only the expiry still functions as a
bound. A separated relying party **breaks** the assumption this design rests on.

**It declines honestly when it cannot do the job.** A server with no signing identity
refuses both login and the challenge that precedes it, with the same error, rather than
issuing a nonce that can never be redeemed (`login_capability`). A separated relying party
**inherits** this as a pattern: a party that cannot establish a precondition should say so
rather than serve a session that silently means less than it appears to.

**The identifier survives key rotation.** A principal's genesis identifier does not change
when its keys do; rotation extends the chain and leaves the genesis untouched
(`docs/specs/server-identity.md`):

> **The PG is rotation-stable.** A server's Principal Genesis never changes across a key
> rotation -- rotation extends the chain with a `key/replace` commit and leaves the genesis
> untouched

The next item states the corollary: _"**The current key is NOT the identity -- the chain
is.**"_

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

Everything in this part follows from two calls (`login` in
`rs/cyphr-server/src/auth/login.rs`):

```rust
let principal = state
    .engine
    .at_tip(&parsed.pg)
    .await
    .map_err(map_load_error)?
    .ok_or_else(|| AppError::unauthorized("login: unknown principal"))?;
let parsed = authorize_login(parsed, &principal)?;
```

Those are local calls. Every check Part 1 describes that needs the principal's key set —
activity, lifecycle, and the checks layered on them — reaches it through them, into
storage the relying party owns. An ordinary deployment is a website that
is not the record authority, and it is defined by the fact that it **cannot make that
call**. It must obtain the same key set over a channel it does not control.

This is the one thing the co-located relying party does that a separated one cannot, and
every difference between the two is downstream of it. The separated case is
`cyphr_client::RelyingParty`, which the rest of this part describes, and
`rs/cyphr-client/examples/relying_party.rs` runs it against a server.

### How it obtains the key set

The mechanism is the one a client uses for a server. A client pins a server's genesis
identifier on first contact and thereafter verifies every later key by replaying the
server's own chain through the public surface, rather than trusting what the server asserts
about itself (`docs/specs/server-identity.md`):

> **Pin the PG on first contact.** … This is the only moment trust is extended on faith;
> every later interaction verifies against the pinned value instead of re-trusting the
> network.

The same shape applies to a person's principal, and `RelyingParty` does it: it is anchored
at the principal's genesis key or genesis commit id (never the PG alone, because one key
set under different openers derives one PG), and `refresh` replays the chain from peers it
chose to learn the current key set. No peer's statement about the current key is believed.
Every step of that replay is verifiable by the party doing it. **This is the part that works**, and it is what
`SPEC.md` §17.5's _"verifiable by any party without a central authority"_ delivers.

### What replay does not establish

Replay establishes that every commit the relying party _has_ is valid and follows from the
genesis it pinned. It does not establish that it has all of them.

This is not a hypothetical. A server in witness mode syncs another principal's state over
exactly such a channel, and a signed tip report authenticates what the authority holds, not
that it is current: nothing binds it to a request, so a genuine report can be replayed
while the authority advances ([known limits](../guides/known-limits.md), "Tip currency").
An on-path party can hold a response the authority genuinely signed and keep serving it.
No comparison of wire fields against each other or against local state can distinguish it
from a live response.

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
outage, but it establishes only that the view is no older than the window, not that it is
current.

The claim _"the record I hold for this principal is canonical"_ fails monotonicity: it can
be true when evaluated and false after the record grows, with nothing in the record
announcing the change. Such a claim admits no certificate that is at once offline, eternal
and about the present; it can have at most two, so a design gives one up. There are three
ways to do that, and they discharge different claims. A **watcher** — a party holding more
than one view over time — gives up _offline_ checking and keeps _now_, so it is the only
remedy that establishes currency, online. A claim restricted to "as of" a stated moment
gives up _now_ and discharges only the weaker, time-scoped claim. An accepted expiry gives
up _eternal_ and discharges only a bounded claim, "fresh within the window": past the
window the certificate says nothing about the present. That is why an expiry covers row 9
below but not a current key set for rows 4 and 5. None of the three is in place for the
key set. A witness is none of these: its word is a point observation of exactly the kind
that goes stale. This is stated as [a requirement](#currency-unmet) rather than designed
here; see [what this document does not cover](#what-this-document-does-not-cover).

## The claim table

Every claim crossing between participants on this path, in two groups: claims about the
**record** — what a relying party concludes about a principal — and claims about the
**exchange** — what it concludes about the request in front of it. **Det/Cert/Mono** are
the three conditions (determination, certifiability and monotonicity); a claim's
**owes** entry lists the parties owed for the conditions it fails (witness for
determination, voucher for certifiability, watcher for monotonicity), and "nothing" when
it fails none. A claim that holds on all three is enduring: it needs an evaluator and no
trusted party at all. Every row carries
a requirement or a note saying why it has none.

### Claims about the record

| #   | claim                                                            | Det | Cert |  Mono  | owes            | trusted party                                                                            | a bad one yields                                                  |
| :-- | :--------------------------------------------------------------- | :-: | :--: | :----: | :-------------- | :--------------------------------------------------------------------------------------- | :---------------------------------------------------------------- |
| 1   | This request was signed by key _K_                               |  —  |  —   |   —    | below the floor | none — evaluator: `coz::verify_json`, called in `authorize_login`                        | a forged sign-in is accepted                                      |
| 2   | This chain derives to identifier _P_                             | yes | yes  |  yes   | nothing         | none — evaluator required; **none exists**, see row note                                 | a record is served under an identifier it does not belong to      |
| 3   | _P_'s identifier is the same one as last session                 | yes | yes  |  yes   | nothing         | none — evaluator required; **none exists**, see row note                                 | the account silently becomes a different account after a rotation |
| 4   | _K_ is an active key of principal _P_                            | yes | yes  | **no** | a watcher       | **watcher** — none exists; no "as of" scoping; `RelyingParty` bounds the age of its view | a revoked or lost key still signs in                              |
| 5   | The record I hold for _P_ is canonical — _P_ has not equivocated | yes | yes  | **no** | a watcher       | **watcher** — none exists; no "as of" scoping; `RelyingParty` bounds the age of its view | a split or frozen view is served indefinitely                     |
| 6   | _P_ may perform operation _X_                                    |  —  |  —   |   —    | decision        | the relying party itself                                                                 | over-authorization                                                |

**Rows 2 and 3 owe nothing:** determined,
certifiable and monotone, discharged by running something rather than by trusting someone.
Row 1 of this table is not one — it sits `below the floor`, where "the message carries
everything the check needs" and there is no trust residue to type — but rows 1, 2 and 3
all name no party. Row 1
carries no requirement of its own, and deliberately: verifying a signature over the bytes
presented is the precondition every path shares, and what this document has to say about it
is that satisfying it is not enough — which is what the exchange rows say.

**Row 2 is undischarged, and that is a defect rather than a design choice.** The storage
engine holds both the derived genesis and the identifier a record is filed under at the
moment of the write, and does not compare them; its own documentation names the same gap on
the read path — "storage never binds a derived genesis to the identifier it is filed under"
(forge issue #154). A claim that owes nothing and is left unchecked is
[indefensible](../trust-model.md#labels-this-project-adds) — the check is free and nobody is running it.
Discharging it at every writer is a system-wide task beyond this path; the requirement here
is only that a relying party must not assume it.

**Row 3 has no evaluator, and the nearest candidate is about a different principal.**
`rotation_preserves_pg_and_swaps_active_key`
(`rs/cyphr-server/tests/server_principal.rs`) does assert that a genesis identifier
survives rotation, but it drives `ServerPrincipal::bootstrap` and `sp.rotate` — the
**server's** own chain. A person's principal rotates through the ordinary write path, and
the two golden fixtures that exercise `key/replace` both leave `pg` empty, which
`rs/cyphr/tests/golden_fixtures.rs` skips. Nothing checks that a person's identifier
survives her own rotation.

**Rows 4 and 5 are the same failure at two scopes.** Row 4 is about one principal's key
set going stale; row 5 is about the whole view being non-canonical. Both need a watcher to
be established as current. The two weaker remedies discharge only a scoped or bounded
claim, not a current key set, and none of the three is in place: no watcher
establishes currency, nothing a separated party is served is scoped "as of" a moment, and
the one remedy in place is the bound on the age of the view that `RelyingParty` applies
([separated-staleness-not-absence](#separated-staleness-not-absence) requires one).

**Row 6 has no requirement, and that is a scope decision rather than an oversight.** Its
label is [`decision`](../trust-model.md#labels-this-project-adds) — "the claim's truth is
fixed by a party's own choice rather than by any state of the world" — so the action it
calls for is that the relying party decides, and this document does not. Such a claim
reports no axis outcomes, which is why all three columns read `—`. It is not the source's
`elective`, a claim a verifier could check and declines to: nothing is declined here,
because there is no fact of the matter to check, and this document uses "forced" in that
word's paired sense under [the forcing case](#the-forcing-case).

### Claims about the exchange

Row 1 of the first table — _this request was signed by key K_ — is **true of a relayed
login and of a replayed one**. The attack succeeds with the row satisfied, so what those
attacks defeat is not a claim about the record at all. Four requirements trace here rather
than to rows 1 and 6.

| #   | claim                                        | Det | Cert |  Mono  | owes              | trusted party                                                                                                       | a bad one yields                                               |
| :-- | :------------------------------------------- | :-: | :--: | :----: | :---------------- | :------------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------------- |
| 7   | This assertion was made _to me_              | yes | yes  |  yes   | nothing           | none — evaluator: `login_rejects_mismatched_audience`, `rs/cyphr-server/tests/login.rs`                             | a login signed for one service is relayed to another           |
| 8   | This assertion is _fresh_ — challenge        | yes | yes  |  yes   | nothing           | none — evaluator: `login_rejects_replayed_challenge`, `rs/cyphr-server/tests/login.rs`                              | a captured login is replayed                                   |
| 9   | This assertion is _fresh_ — timestamp window | yes | yes  | **no** | an exit by expiry | none — an accepted expiry, plus clock agreement                                                                     | a captured login is replayed inside the window                 |
| 10  | This artifact _is a session token I issued_  | yes | yes  |  yes   | nothing           | none — evaluator: `bearer_refuses_server_signed_non_token`, `rs/cyphr-server/tests/route_protection.rs`             | another message the service signed is presented as a session   |
| 11  | A challenge I issue can be redeemed          | yes | yes  |  yes   | nothing           | none — evaluator: `keyless_login_and_challenge_share_the_same_rejection`, `rs/cyphr-server/tests/keyless_matrix.rs` | a person completes a challenge that can never become a session |

**Rows 8 and 9 are one claim under two mechanisms, and the two do not owe the same.** A single-use challenge checks state the relying party issued and holds, so
freshness is determined, certifiable and monotone. A timestamp window is [an exit by
expiry](../trust-model.md#terms-used-here) — a verdict that expires, giving up _eternal_ — resting additionally on clock agreement nothing in the record
establishes. One row cannot carry two entries without prose in a condition column. **No exchange
row names a trusted party**: rows 7, 8, 10 and 11 name evaluators, and row 9 is
discharged by an accepted bound rather than by a watcher — the one exchange claim a
relying party pays for instead of checking.

## The forcing case

_She loses her device._

**This section grounds the typing of rows 4 and 5** — it is where monotonicity is forced
rather than chosen. Levels are the key-management tiers of
`SPEC.md` §3: Level 1 is a single static key, and Level 3 introduces the commit tree and
the Principal Genesis; `SPEC.md` §14.2 says Level 1 supports no recovery (only sideband)
and Level 3+ supports it, including adding new keys. At Level 3+ a designated recovery
agent signs a `key/create` for her and the account survives, because _"the agent's
authority derives from the `recovery/create` delegation"_
(`docs/specs/recovery.md`). Her identifier survives; at Level 1 it would not, and
`SPEC.md` §14.1 says so — _"Note that sideband recovery results in a new Principal
identity."_ The account continues. Those mechanics are here only to make the participant
table's recovery row legible; they produce no requirements.

**Is the case forced?** Yes, for a separated relying party. Her
old key is now revoked and her new key is now active — in the record. The separated party
may hold neither fact. Until it learns them, it will refuse her real key and accept the
key on the device she lost.

**Does it block the decision?** Yes, and in the dangerous direction. The relying party is not merely under-informed; it is confidently wrong, and
its confidence is well-founded on everything it can see. Every signature verifies, every
commit chains, the view is internally consistent. There is no error to handle.

**What the party does when the answer is bad.** Co-located, the answer is already correct.
That a revoked key stops signing in is checkable, and is checked:
`revoked_key_refused_at_login_sibling_survives`
(`rs/cyphr-server/tests/naked_revoke.rs`) asserts the whole sequence — the key signs in
first, so the baseline is empirical rather than assumed; the revocation is accepted; the
key is then refused; and a sibling key of the same principal still signs in, so the
refusal is scoped to the key and not the account.

**The exposure bound is checked, and it is tighter than a token lifetime.** A login
token is signed with the thumbprint of the key that opened the session (the `ltmb`
claim, `token.rs`), and route protection (`middleware.rs`, `check_session_key`) reloads
the principal from the server's own storage on each request and refuses the session once
that key is no longer active: `KeyNotActive` if it was deleted, `Revoked` if it was
revoked on the chain or naked-revoked (the death-set login already consults;
`token_key_naked_revoked_session_refused` covers it). A token without the claim is
refused. So a session issued before a revocation
survives only until the revocation reaches the server's view, not for fifteen minutes
(`exp`, `token.rs`, remains a cap on top). `token_key_revoked_session_refused_at_push`
(`rs/cyphr-server/tests/route_protection.rs`) logs in with two keys, revokes one through
a real `key/revoke` commit, and asserts the revoked key's session is refused at `/push`
while `token_key_survivor_session_outlives_sibling_revoke` asserts the sibling's session
still works. What this establishes is relative to the server's current view of the
principal; it says nothing about a revocation the server has not yet seen.

Separated, session lifetime alone is no bound. The stale view never expires on its own,
the fifteen minutes restart on every fresh sign-in with the lost key, and the correct
behaviour — the one this document requires — is to bound the age of the view explicitly,
refuse to serve past that bound, and treat the refusal as an outage to be fixed rather
than a security event that has been handled. With a view-age bound _v_ and a session
lifetime _s_, a repudiated key retains access for at most _v_ + _s_ after the
repudiation; without _v_ there is no finite bound.

## Requirements

Each is traceable to a row of [the claim table](#the-claim-table). Requirements in the
first group are satisfied by the relying party built into the server. Each requirement
carries a fenced `claim` block read by docket, this repository's documentation claim gate
([`docs/AGENTS.md`](../AGENTS.md), section "Docket — the documentation claim gate"): `kind` is always
`requirement` here, `evaluator` is `test` when an automated test backs the requirement and
`none` when nothing does, and `because` lists the requirement ids it depends on.

The machine binding runs from the test to the requirement: an `@docket: <id> :: <command>`
marker comment at a test names the requirement id and the command that runs the test, and
a requirement's claim block never names a test. Prose may still cite tests that carry no
marker of their own, as several requirements below do. The requirements from
[separated-key-set-by-replay](#separated-key-set-by-replay) on
are satisfied by `cyphr_client::RelyingParty`, except
[currency-unmet](#currency-unmet), which nothing in the record can meet. Docket registers those
requirements with `evaluator: none` because no test carries an `@docket:` marker for them yet;
`rs/cyphr-client/tests/relying_party.rs` and `rs/cyphr-scenarios/tests/relying_party_signin.rs`
exercise them.

### [signon-audience-binding]

A relying party MUST verify that the audience named inside the signed login payload is its
own identity, and MUST NOT take the audience from any unsigned transport detail. Traces to
row 7. The MUST NOT clause is closed structurally rather than by a test, which is a
stronger closure than a test: `parse_login` derives the audience from the signed
payload's `typ` (`parse_request` in `rs/cyphr-client/src/login.rs`) and compares it to the
configured `server_audience` (`parse_login`), so no transport value reaches the comparison and there is no path a test
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
(`rs/cyphr-server/tests/login.rs`) and `login_rejects_deleted_principal` (same file),
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
acceptance window on the signed timestamp. Traces to rows 8 and 9 — one row per mechanism,
because the two do not owe the same. The marker registers the challenge arm; the
window arm is closed by `login_rejects_out_of_window_timestamp`
(`rs/cyphr-server/tests/login.rs`), which carries no marker of its own.

```claim
kind: requirement
evaluator: test
```

### [signon-token-kind-binding]

A session token MUST be bound to its kind inside the signature, so that no other message
the relying party signs can be presented as a session. Traces to row 10.

```claim
kind: requirement
evaluator: test
```

### [signon-honest-refusal]

A relying party that cannot complete sign-on MUST decline it, and MUST decline every step
leading to it with the same error, rather than completing early steps that cannot be
redeemed. Traces to row 11.

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
canonical"_ fails monotonicity, and there are three remedies. A **watcher** holding more
than one view over time gives up offline checking and keeps _now_, so it is the only
remedy that establishes currency, online. A claim restricted to "as of" a stated moment
gives up _now_ and discharges only the weaker, time-scoped claim. An accepted expiry gives
up _eternal_ and discharges only a bounded claim, "fresh within the window". None is in
place for the key set, and a witness is not one of them: its word is a point observation
of exactly the kind that goes stale. A relying party MUST state this obligation as unmet
rather than treat a successful replay as having met it. Traces to rows 4 and 5.

```claim
kind: requirement
evaluator: none
because: [separated-key-set-by-replay]
```

### [separated-staleness-not-absence]

A relying party MUST NOT treat "no update observed" as "no update exists". It MUST bound
the age of its view explicitly and refuse to serve past that bound. Bounding the age of
the view is the accepted-expiry remedy: it gives up an eternal certificate, so past the
bound the view says nothing about the present and the party refuses. That converts a
silent wrong answer into a refusal, which is an improvement. What it establishes is a
bounded claim — the view is no older than the bound, so a repudiation older than the
bound plus one session lifetime cannot still be honored — and not that the view is
current, so
[currency-unmet](#currency-unmet) stays unmet. Traces to row 5.

```claim
kind: requirement
evaluator: none
because: [currency-unmet]
```

### [separated-session-window]

A relying party MUST treat session lifetime, together with the age bound on its view
([separated-staleness-not-absence](#separated-staleness-not-absence)), as the only bounds
on how long a repudiated key retains access, and MUST set the session lifetime against
that exposure rather than against convenience. A system with no revocation list has no
other mechanism, and under [currency-unmet](#currency-unmet) a separated party may never
observe the repudiation at all, so the exposure is the view-age bound plus one session
lifetime. Traces to row 4.

```claim
kind: requirement
evaluator: none
because: [currency-unmet]
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
| The login flow, either option                     | Proof that the signer possesses a key, bound to an audience and defended against replay | **the person** — for possession, verifiably                                          |
| Bearer tokens                                     | A session that avoids re-signing every request                                          | **the relying party itself** — it signs and verifies its own tokens                  |
| Principal chain replay (`GET /tip`, `GET /patch`) | The key set and lifecycle state to check against                                        | **nobody, for what is replayed** — every step is verifiable. **Unmet, for currency** |
| Genesis pinning (`docs/specs/server-identity.md`) | A durable account identifier that survives key rotation                                 | **the person, once**, at the moment of pinning                                       |
| Recovery at Level 3+                              | Continuity of the account across device loss                                            | **the recovery agent**; its out-of-band check cannot be re-run                       |

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
settles it, is not decided by the specification and is not decided here. It is marked open rather than assumed either way.

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
  anything else. The implementation ships a gossip timer on the server and `cyphr verify`,
  `watch`, `audit` and `gossip` on the client; this document does not analyse them.

[currency-unmet](#currency-unmet) reaches that boundary and stops at it, stating the
obligation and the party kind that discharges it. `SPEC.md` §2.2.16 already names the
participant that keeps another principal's state:

> A **witness** is a client that keeps a copy of an external principal's state and
> communicates state through gossip.

The gossip clause has to be answered rather than passed over: a participant in a gossip
protocol is not the protocol. A single gossiping witness can receive information that
leaves its view less stale, but it cannot detect that its own view _is_ stale: detecting
staleness means comparing two views, and the comparison belongs to the watcher
([the trust model](../trust-model.md#names-that-collide)). So the specification's witness is a
participant in discharging what a monotonicity failure owes rather than the watcher, and
what closes the gap is the party holding the comparison. Naming that requirement is this document's job.
Designing that party is not.
