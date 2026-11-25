# SPEC: Consensus and Error Handling

<!--
  SPEC document produced by /spec Apply mode.
  Source: SPEC.md at be0663f (spec author's zami branch) §13, §15, §18, §19.
  Authority: that SPEC.md — this document does NOT replace it.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Cyphr consensus — fork detection, proof of error,
resync, witness behavior, state jumping, and the error taxonomy. The
consensus model is deliberately minimal, favoring simplicity and
independent verifiability over global coordination.

**Target System:** `SPEC.md` at commit `be0663f` on the spec author's
`zami` branch, the normative text:
[§13](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#13-state-synchronization-and-gossip--todo)
(State Synchronization and Gossip),
[§15](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#15-consensus)
(Consensus),
[§18](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#18-state-jumping)
(State Jumping) and
[§19](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#19-error-conditions)
(Error Conditions). Every `§` reference below is to that text.

**Authority model.** No server, witness or peer is an authority over a
principal's state. Each party makes signed claims only about itself, and
each verifier reaches its own verdict from the claims it chose to
collect. SPEC grounds this in §13.7 ("Principals are the authority over
their own state"; the section is marked TODO), §15.1 (independent
verifiability "without requiring global coordination") and §15.5
("witnesses independently track principal consensus states"). Every
constraint below is read under this model.

**Model Reference:**
[`principal-state-model.md`](../models/principal-state-model.md)

**Criticality Tier:** High — consensus failures can let a verifier
accept one branch of a fork as the principal's state, accept a rewritten
history, or deny service.

**Cross-references:**
[`transactions.md`](./transactions.md)
— commit chain that consensus protects.
[`principal-lifecycle.md`](./principal-lifecycle.md)
— lifecycle state transitions triggered by consensus violations.
[`equivocation-detection.md`](../architecture/equivocation-detection.md)
— how fork and equivocation evidence is detected and kept.

## Implementation Status

**`VERIFIED: agent-check` / `pass` in this document means "explicit in or
inferable from SPEC.md at `be0663f`," not "implemented in `rs/` or
`go/`."** What `rs/` does at this revision:

- **Partly implemented:** the consensus states. `cyphr::fork::Consensus`
  has only `Active` and `Error` (`rs/cyphr/src/fork.rs:12`), and the
  storage engine reads it from the held commits
  (`rs/cyphr-storage/src/engine/mod.rs:6275` (`assess`)). Pending, Resync, Offline,
  Ignore and Client Mismatch have no counterpart: `git grep` over `rs/`
  finds no `ConsensusState`.
- **Implemented:** retention of both branches of a fork. The engine keeps
  a verified rival as a retained branch (`retain_rival`,
  `rs/cyphr-storage/src/engine/mod.rs:4873`; `list_branches`, `:6222`),
  within caps, and `GET /branches` lists them.
- **Implemented:** proof-of-error retention and service. A held rival is
  the proof of error, and `GET /evidence` serves each principal fork
  (`rs/cyphr-server/src/routes.rs:705-721`). No `ProofOfError` type
  exists; the evidence is the retained commits.
- **Not implemented:** state jumping. `git grep` over `rs/` finds no
  `state_jump` or `jump_to_ps`.
- **Fork handling per server:** `cyphr-server` answers a commit whose
  `pre` its chain has moved past with `409` (see
  `s2_3_2_push_on_a_stale_pre_is_refused_and_the_chain_stays_put` in
  `rs/cyphr-server/tests/spec_conformance.rs`). A commit that verifies on
  a held predecessor is kept as a rival and the principal can enter
  Error; the `423` and `409` contract is in
  `docs/reference/http-api.md` ("`POST /push`").
- **Resync fetch:** `GET /patch?pg=…&from=…` serves the delta from a
  content-digest anchor (§13 Resync, step 2). A server in witness mode
  pulls that delta from one configured upstream and verifies each
  commit before persisting it (`rs/cyphr-server/src/sync.rs`).
- **Timestamps:** `cyphr::Principal` rejects a data action whose `now`
  is older than the latest it has seen (`TimestampPast`), and rejects a
  future-dated one (`TimestampFuture`) beyond the verifier clock plus a
  skew. The default skew is 360 s (SPEC §15.9); `set_max_clock_skew(0)`
  removes the tolerance and does not disable the check.
- **No third-party resolution:** no server route resolves a fork or
  picks a branch, and no server pushes a principal's commits to another
  server (`rs/cyphr-server/tests/no_registration.rs`).

## Constraints

### Type Declarations

```
TYPE ConsensusState = Active | Pending | Resync | Offline
                    | Error | Ignore | ClientMismatch

TYPE ProofOfError   = SignedMessage                   -- retained invalid message
TYPE ErrorCode      = INVALID_SIGNATURE | INVALID_CONSTRUCTION | UNKNOWN_KEY
                    | UNKNOWN_ALG | TRANSACTION_ORDER_UNKNOWN | COZ_REUSE
                    | TIMESTAMP_PAST | TIMESTAMP_FUTURE | TIMESTAMP_OUT_OF_RANGE
                    | MALFORMED_PAYLOAD | KEY_REVOKED | INVALID_PRIOR
                    | DUPLICATE_KEY | THRESHOLD_NOT_MET | MULTIHASH_MISMATCH
                    | STATE_MISMATCH | HASH_ALG_MISMATCH | ALG_INCOMPATIBLE
                    | CHAIN_BROKEN | INVALID_FORK | DUPLICATE
                    | JUMP_INVALID
                    | UNRECOVERABLE_PRINCIPAL | RECOVERY_NOT_DESIGNATED
                    | UNAUTHORIZED_ACTION
                    | MESSAGE_TOO_LARGE

TYPE TimestampTolerance = Integer                     -- default ±360s (§15.9)
```

The error codes are the union of the §15.6 list and the §19 tables.

### Invariants

#### Chain Integrity

**[single-chain]**: Cyphr assumes a single linear chain per principal. An
**invalid fork** occurs when two or more conflicting commits reference the
same `pre` (prior PR), violating this assumption (§15.7, §15.7.1; §11.5
lists "invalid fork" as "forbidden chain divergence"). This is distinct
from an **explicit fork** (`cyphr/principal/fork/create`), which is a
sanctioned, history-preserving protocol operation, not a violation — see
"Fork Detection and Resolution" below.
`VERIFIED: agent-check`

**[proof-of-error]**: Witnesses MAY retain invalid messages as proof of
error — a signed message demonstrating bad behavior (e.g., invalid
signature, conflicting commit). Proof of error MAY be shared via gossip,
presented during recovery or escalation, or retained until resync
resolves the error (§15.2).
`VERIFIED: agent-check`

#### Timestamp Verification

**[timestamp-tolerance]**: Witnesses reject messages whose `now` is
outside ±360 seconds (default) of the witness's time on receipt, and
reject future-dated messages (§15.9). The tolerance is a default, so it
is local witness policy, not a global protocol invariant: different
witnesses MAY use different tolerances. The protocol-level constraint
is [timestamp-monotonic]. Open for the spec author: §15.7.1 names the
timestamp tolerance as ±60 s ("within timestamp tolerance, ±60s") where
§15.9 gives ±360 s; SPEC does not say which governs.
`VERIFIED: agent-check`

**[timestamp-monotonic]**: Witnesses MUST track the latest known timestamp
per principal from the most recent valid message. Any `now` earlier than
the latest known timestamp MUST be rejected, which prevents history
rewriting (§15.9).
`VERIFIED: agent-check`

**[timestamp-global-range]**: Messages with `now` outside a global
tolerance (e.g., more than one year in the future) are rejected as
`TIMESTAMP_OUT_OF_RANGE` (§15.6 error list).
`VERIFIED: agent-check`

#### Consensus State Machine

**[witness-consensus-states]**: Each witness tracks its own consensus
state per principal: Active, Pending, Resync, Offline, Error, Ignore, and
Client Mismatch (§15.5). These states are orthogonal to the principal's
base lifecycle states. A witness's consensus state is its own verdict and
binds no other party.
`VERIFIED: agent-check`

**[consensus-state-transitions]**: §15.6 lists these transitions:

| From    | To             | Trigger                                               |
| :------ | :------------- | :---------------------------------------------------- |
| Active  | Pending        | Incomplete transaction received                       |
| Pending | Active         | Transaction completes or timeout                      |
| Active  | Error          | Fork detected, chain invalid, repeated resync failure |
| Error   | Active         | Fork resolved (branch selection or resync PoP)        |
| Active  | Resync         | Trust anchor is stale, delta needed                   |
| Resync  | Active         | Patch verified and applied                            |
| Resync  | Error          | Repeated resync failure (e.g., >3 attempts)           |
| Active  | Offline        | Communication failure                                 |
| Offline | Resync         | Reconnect with stale state                            |
| Any     | Ignore         | Principal dropped from gossip                         |
| Any     | ClientMismatch | Witness and client disagree on message validity       |

`VERIFIED: agent-check`

#### Error Handling

**[error-reject-atomic]**: Implementations MUST reject transactions with
any error condition. Implementations MUST NOT apply partial state
changes — transaction processing is atomic (§19.5).
`VERIFIED: agent-check`

**[error-codes-transaction]**: Implementations MUST detect these
transaction errors (§19, §19.1): `INVALID_SIGNATURE`, `UNKNOWN_KEY`,
`UNKNOWN_ALG`, `TIMESTAMP_PAST`, `TIMESTAMP_FUTURE`, `MALFORMED_PAYLOAD`,
`KEY_REVOKED`, `INVALID_PRIOR` (Level 2+), `TRANSACTION_ORDER_UNKNOWN`
(Level 3+), `COZ_REUSE` (Level 3+), `DUPLICATE_KEY` (Level 3+),
`THRESHOLD_NOT_MET` (Level 5+).
`VERIFIED: agent-check`

**[error-codes-state]**: Implementations MUST detect: `STATE_MISMATCH`
(computed PR ≠ claimed PR), `HASH_ALG_MISMATCH`, `ALG_INCOMPATIBLE`,
`CHAIN_BROKEN` (Level 2+) (§19.3).
`VERIFIED: agent-check`

**[error-codes-recovery]**: Implementations MUST detect:
`UNRECOVERABLE_PRINCIPAL` (no keys capable of transaction, no designated
recovery agents), `RECOVERY_NOT_DESIGNATED` (Level 3+) (§19.2).
`VERIFIED: agent-check`

### Transitions

#### Resync

**[resync-process]**: Resync follows four steps (§13, "Resync"): (1)
select a trust anchor, (2) fetch the patch via `/patch`, (3) verify the
patch (pre chaining, signing keys active with no revocation in path,
computed PR, timestamps, thresholds, no forks), (4) apply it and promote
the new PR to trust anchor. The witness verifies the patch itself; the
peer that served it is not trusted for its content.

- **PRE**: Witness trust anchor is behind current tip.
- **POST**: Trust anchor is advanced to current tip. Consensus state → Active.
  `VERIFIED: agent-check`

**[resync-backoff]**: Witnesses SHOULD use exponential backoff for
repeated resync attempts to prevent denial-of-service (§13, "Resync").
`VERIFIED: agent-check`

**[resync-pop]**: A principal MAY re-iterate an existing state as
authoritative without mutating PR/AR through a resync PoP, signing a
challenge such as `typ: "cyphr.me/cyphr/resync/create"` with an active
key (§13, "Resync PoP"). This proves current possession without advancing
the chain.

- **PRE**: Principal has an active key.
- **POST**: Witnesses that see it confirm the asserted tip. No state mutation.
  `VERIFIED: agent-check`

#### Fork Detection and Resolution

> **Fork taxonomy** (§11.5, §11.5.2): SPEC distinguishes three fork
> classes. An **explicit fork** (`cyphr/principal/fork/create`, bundled
> with `principal/create` and a new key) is a protocol-level,
> history-preserving operation equivalent to a genesis transaction — it
> is provided for by design and is not an error condition. An **implicit
> fork** (out-of-band AT-component transfer to a new principal) is
> prohibited by the protocol (§2.3.2). An **invalid fork** — two or more
> conflicting commits referencing the same `pre` — violates the
> append-only, single-tip assumption and is prohibited (§11.5). The
> constraints below concern only invalid forks.

**[fork-detection]**: Witnesses detect invalid forks via mismatched tips
in gossip, inconsistent `/patch` responses, and conflicting signed proofs
(§15.7.1). Detection is comparison: any verifier holding two conflicting
commits signed under the principal's keys with the same `pre` has
detected the fork, whichever peers it collected them from.
`VERIFIED: agent-check`

**[fork-response]**: On detecting an invalid fork, a witness holds both
branches, and the principal's consensus state is Error until the fork is
resolved (§15.8). §15.7.1 gives the response as "broadcast fork proof and
rejection of both branches until resolved". This document reads
"rejection" as neither branch being accepted as the principal's state,
not as either branch being discarded: §15.8 has witnesses hold both, and
§15.2 has a witness retain "both conflicting transactions as proof of
compromise and broadcast them to other witnesses or the principal for
resolution". So both branches and the fork proof propagate as evidence,
and no witness picks a branch. Per §15.5, Error means no new
transactions or actions are processed until resolved. §15.7 also lists
ignoring the message, escalation, and holding it as proof of error as
possible responses, without a verb that makes any of them required.
`VERIFIED: agent-check`

**[fork-resolution]**: An invalid fork is resolved when the principal
unambiguously selects one branch (§15.8), by either: (1) a new commit
whose `pre` references the tip of the chosen branch, which implicitly
abandons the other, or (2) a `resync/create` PoP re-asserting the current
tip. In this implementation a new commit resolves a fork only when it
leaves exactly one branch extended (`assessment`,
`rs/cyphr/src/fork.rs`): a fork whose branches both have a commit over
them stays in Error at any heights, and an abandoned branch that is
extended later re-opens a resolved fork. The PoP exit (2) is
implemented (`rs/cyphr/src/resync.rs`): a `resync/create` coz signed by
one key active at the asserted tip makes the walk follow the one child
holding it, whatever is extended elsewhere, so a later extension of the
abandoned branch does not re-open the fork; proofs into two children
leave the principal in Error for good. The abandoned branch's transactions become permanently invalid,
and keys added only in it are not part of KR. Witnesses retain the
abandoned branch only as proof of error. Resolution belongs to the
principal alone: witnesses observe the principal's choice and adopt it;
they do not adjudicate which branch is correct (§15.1: the principal is
"the primary custodian of its own security and state"). §15.7.1 also
names other ways a fork may end: "principal/merge, revocation, or
multi-sig confirmation in Level 5+"; §15.8 does not define them.

- **PRE**: Two conflicting branches exist; consensus state is Error.
- **POST**: One branch is canonical; abandoned branch retained as proof of
  error. Consensus state → Active.
  `VERIFIED: agent-check`

#### State Jumping

**[state-jump-mechanism]**: A state-jump transaction advances
a client's trust anchor from an old PR directly to a much later PR
without fetching every intermediate transaction (§18, §18.1).

- **PRE**: Signing key(s) MUST be present in KR at both the old trust
  anchor AND the current tip. `jump_to_ps` MUST match the
  service-reported or independently obtained current tip.
- **POST**: Client trust anchor updated to `jump_to_ps`. Future
  resolutions start from the new anchor.
  `VERIFIED: agent-check`

**[state-jump-revocation-check]**: State jumps MUST NOT bypass revocation
semantics. If a signing key was revoked between the anchor and tip, the
jump MUST fail with `JUMP_INVALID` (§18.3; §15.6 error list).
`VERIFIED: agent-check`

**[state-jump-optional]**: Clients MAY reject state jumps. The reference
client rejects state jumps by default (§18). A state jump delegates some
trust to third-party services, so accepting one is the verifier's own
choice.
`VERIFIED: agent-check`

**[state-jump-multi]**: Multiple jumps MAY be required to traverse from
anchor to tip when keys have been revoked in the intermediate range.
Each jump uses a key valid at both the jump source and the jump
destination (§18, §18.4).
`VERIFIED: agent-check`

### Forbidden States

**[no-branch-as-state]**: Before an invalid fork is resolved, no witness
or verifier accepts either branch as the principal's state: the
consensus state is Error (§15.7.1, §15.8). This governs acceptance, not
evidence — both branches and the fork proof are still kept and shared
(see [fork-evidence-propagates]).
`VERIFIED: agent-check`

**[no-third-party-resolution]**: No server, witness or verifier resolves
a principal's fork or selects a branch on its behalf. Only the
principal's own signed act ends the fork (§15.8).
`VERIFIED: agent-check`

**[no-backward-timestamp]**: A message with `now` earlier than the latest
known timestamp for that principal MUST NOT be accepted (per
[timestamp-monotonic]).
`VERIFIED: agent-check`

**[no-partial-apply]**: Implementations MUST NOT apply partial state
changes from a commit that contains any error (per
[error-reject-atomic]).
`VERIFIED: agent-check`

**[no-jump-bypassing-revocation]**: A state jump MUST NOT succeed if the
signing key was revoked at any point between the anchor and the tip (per
[state-jump-revocation-check]).
`VERIFIED: agent-check`

### Behavioral Properties

**[consensus-is-local]**: A consensus state is each verifier's own local
verdict, reached from the claims it chose to collect. No verifier's
verdict binds another, and none needs global coordination; consensus
emerges from what actually occurred and who published what when (§15.1,
§15.5).

- **Type**: Design Property
  `VERIFIED: agent-check`

**[fork-evidence-propagates]**: Both branches of an invalid fork, and the
fork proof, are evidence that witnesses keep and share by gossip, to
other witnesses and to the principal (§15.2, §15.7.1, §15.8). Evidence is
never withheld to protect a branch, and resolving the fork does not
delete it.

- **Type**: Design Property
  `VERIFIED: agent-check`

**[proof-of-error-durable]**: Witnesses retain proof of error for
resolution, escalation, or forensic analysis (§15.2: "retained until
resync error resolution").

- **Type**: Liveness
  `VERIFIED: agent-check`

**[resync-resolves-transient]**: Many transient errors resolve via
resync. Persistent failure escalates to errored state or ignore (§13,
"Resync"); §15.6 gives repeated resync failure (e.g., more than three
attempts) as the Resync → Error trigger.

- **Type**: Liveness
  `VERIFIED: agent-check`

## Formal Specification

<!-- Tier 2+ formalization is structured for but not populated in this pass. -->

## Verification

> See "Implementation Status" above: every `pass` below means consistency
> with SPEC.md at `be0663f`, not a working implementation.

| Constraint                     | Method      | Result | Detail                                        |
| :----------------------------- | :---------- | :----- | :-------------------------------------------- |
| [single-chain]                 | agent-check | pass   | §15.7, §15.7.1; term in §11.5                 |
| [proof-of-error]               | agent-check | pass   | Explicit in §15.2                             |
| [timestamp-tolerance]          | agent-check | pass   | Explicit in §15.9                             |
| [timestamp-monotonic]          | agent-check | pass   | Explicit in §15.9                             |
| [timestamp-global-range]       | agent-check | pass   | §15.6 error list                              |
| [witness-consensus-states]     | agent-check | pass   | Explicit in §15.5                             |
| [consensus-state-transitions]  | agent-check | pass   | Explicit in §15.6                             |
| [error-reject-atomic]          | agent-check | pass   | Explicit in §19.5                             |
| [error-codes-transaction]      | agent-check | pass   | Explicit in §19, §19.1                        |
| [error-codes-state]            | agent-check | pass   | Explicit in §19.3                             |
| [error-codes-recovery]         | agent-check | pass   | Explicit in §19.2                             |
| [resync-process]               | agent-check | pass   | Explicit in §13, "Resync"                     |
| [resync-backoff]               | agent-check | pass   | Explicit in §13, "Resync"                     |
| [resync-pop]                   | agent-check | pass   | Explicit in §13, "Resync PoP"                 |
| [fork-detection]               | agent-check | pass   | §15.7.1                                       |
| [fork-response]                | agent-check | pass   | §15.2, §15.5, §15.7, §15.7.1, §15.8           |
| [fork-resolution]              | agent-check | pass   | §15.8; §15.1                                  |
| [state-jump-mechanism]         | agent-check | pass   | Explicit in §18, §18.1                        |
| [state-jump-revocation-check]  | agent-check | pass   | Explicit in §18.3                             |
| [state-jump-optional]          | agent-check | pass   | Explicit in §18                               |
| [state-jump-multi]             | agent-check | pass   | Explicit in §18, §18.4                        |
| [no-branch-as-state]           | agent-check | pass   | §15.7.1, §15.8                                |
| [no-third-party-resolution]    | agent-check | pass   | §15.8 ("the principal unambiguously selects") |
| [no-backward-timestamp]        | agent-check | pass   | Follows from §15.9                            |
| [no-partial-apply]             | agent-check | pass   | Explicit in §19.5                             |
| [no-jump-bypassing-revocation] | agent-check | pass   | Explicit in §18.3                             |
| [consensus-is-local]           | agent-check | pass   | §15.1, §15.5                                  |
| [fork-evidence-propagates]     | agent-check | pass   | §15.2, §15.7.1, §15.8                         |
| [proof-of-error-durable]       | agent-check | pass   | §15.2                                         |
| [resync-resolves-transient]    | agent-check | pass   | §13, "Resync"; §15.6                          |

## Implications

### For Implementation (`/core`)

- **Witness state machine**: [consensus-state-transitions] is directly
  implementable. Each witness keeps its own state per principal.
- **Keep both branches**: a store that accepts only one chain per
  principal drops the second branch of a fork instead of keeping it as
  evidence. Meeting [fork-response] needs commits kept per `pre`.
- **Timestamp tracking per principal**: Implementations must maintain a
  monotonically increasing "latest known timestamp" per principal to
  enforce [timestamp-monotonic].
- **Fork detection**: comparing views collected from the peers a
  verifier chose — mismatched tips, or inconsistent patch responses.
- **State jumping is optional**: The reference client defaults to
  rejecting jumps. Implementations that support jumping must verify the
  signing key exists in KR at both anchor and tip.

### For Testing

- **Fork simulation**: Create two valid commits with the same `pre`,
  deliver them through different peers, and verify that a verifier
  holding both reaches Error, keeps both branches, and can pass the
  evidence on.
- **Fork resolution**: Resolve via new commit (extending exactly one
  branch) and via resync PoP — verify both paths
  return to Active and keep the abandoned branch as proof of error.
  Verify that a both-extended fork stays in Error whichever branch is
  taller, and that extending an abandoned branch re-opens a fork a commit
  settled but not one a PoP settled.
- **Timestamp edge cases**: Messages at exactly the ±360 s boundary.
  Messages before and after the latest known timestamp.
- **State jump**: Single jump (no revokes), multi-jump (revoke in path),
  invalid jump (revoked key).
- **Error taxonomy**: Test each error code from §19.1–§19.4 individually.
- **Atomicity**: Submit a commit where one transaction is valid but
  another is not — verify the entire commit is rejected.

### Deferred Specifications (Witness Node Level)

> **Design Pending**: Resolution guidelines for `CLIENT_MISMATCH`, data
> retention policies for proof of error, and configurable limits on
> "maximum jump distances" concern witness implementation logic. They
> are deferred until the witness interactions and sync protocols are
> specified.
