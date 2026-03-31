# SPEC: Consensus and Error Handling

<!--
  SPEC document produced by /spec Apply mode.
  Source: SPEC.md §17, §23, §24
  Authority: SPEC.md (Zamicol and nrdxp) — this document does NOT replace SPEC.md.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Cyphrpass consensus — fork detection, proof of error,
resync, witness behavior, state jumping, and the complete error taxonomy.
The consensus model is deliberately minimal, favoring simplicity and
independent verifiability over global coordination.

**Target System:** `SPEC.md` §17 (Consensus), §23 (State Jumping), §24 (Error
Conditions).

**Model Reference:**
[`principal-state-model.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/models/principal-state-model.md)

**Criticality Tier:** High — consensus failures can allow fork propagation,
history rewriting, or denial of service.

**Cross-references:**
[`transactions.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/specs/transactions.md)
— commit chain that consensus protects.
[`principal-lifecycle.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/specs/principal-lifecycle.md)
— lifecycle state transitions triggered by consensus violations.

## Constraints

### Type Declarations

```
TYPE ConsensusState = Active | Pending | Resync | Offline
                    | Error | Ignore | ClientMismatch

TYPE ProofOfError   = SignedMessage                   -- retained invalid message
TYPE ErrorCode      = INVALID_SIGNATURE | UNKNOWN_KEY | UNKNOWN_ALG
                    | TIMESTAMP_PAST | TIMESTAMP_FUTURE | TIMESTAMP_OUT_OF_RANGE
                    | MALFORMED_PAYLOAD | KEY_REVOKED | INVALID_PRIOR
                    | DUPLICATE_KEY | THRESHOLD_NOT_MET
                    | STATE_MISMATCH | HASH_ALG_MISMATCH | ALG_INCOMPATIBLE
                    | CHAIN_BROKEN | FORK | IMPLICIT_FORK | DUPLICATE
                    | JUMP_INVALID
                    | UNRECOVERABLE_PRINCIPAL | RECOVERY_NOT_DESIGNATED
                    | UNAUTHORIZED_ACTION
                    | MESSAGE_TOO_LARGE

TYPE TimestampTolerance = Integer                     -- default ±360s
```

### Invariants

#### Chain Integrity

**[single-chain]**: Cyphrpass assumes a single linear chain per principal. An
implicit fork occurs when two or more conflicting commits reference the same
`pre` (prior PR), violating this assumption.
`VERIFIED: agent-check`

**[proof-of-error]**: Witnesses MAY retain invalid messages as proof of error —
a signed message demonstrating bad behavior (e.g., invalid signature, conflicting
commit). Proof of error MAY be shared via gossip or retained for
recovery/escalation.
`VERIFIED: agent-check`

#### Timestamp Verification

**[timestamp-tolerance]**: Witnesses MUST reject messages where `now` is
outside ±360 seconds (default) of the witness's time. Future-dated messages
MUST be rejected. This tolerance is configurable per witness and represents
**local witness policy**, not a global protocol invariant — different witnesses
MAY use different tolerances. The protocol-enforced hard constraint is
[timestamp-monotonic].
`VERIFIED: agent-check`

**[timestamp-monotonic]**: Witnesses MUST track the latest known timestamp per
principal from the most recent valid message. Any `now` earlier than the latest
known timestamp MUST be rejected (prevents history rewriting).
`VERIFIED: agent-check`

**[timestamp-global-range]**: Messages with `now` outside a global tolerance
(e.g., > 1 year in the future) MUST be rejected as `TIMESTAMP_OUT_OF_RANGE`.
`VERIFIED: agent-check`

#### Consensus State Machine

**[witness-consensus-states]**: Witnesses MUST independently track principal
consensus states: Active, Pending, Resync, Offline, Error, Ignore, and
ClientMismatch. These states are orthogonal to the principal's base lifecycle
states.
`VERIFIED: agent-check`

**[consensus-state-transitions]**: The following state transitions MUST be
supported by witnesses:

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

**[error-reject-atomic]**: Implementations MUST reject transactions with any
error condition. Implementations MUST NOT apply partial state changes —
transaction processing is atomic.
`VERIFIED: agent-check`

**[error-codes-transaction]**: Implementations MUST detect at minimum these
transaction errors: `INVALID_SIGNATURE`, `UNKNOWN_KEY`, `UNKNOWN_ALG`,
`TIMESTAMP_PAST`, `TIMESTAMP_FUTURE`, `MALFORMED_PAYLOAD`, `KEY_REVOKED`,
`INVALID_PRIOR` (Level 2+), `DUPLICATE_KEY` (Level 3+), `THRESHOLD_NOT_MET`
(Level 5+).
`VERIFIED: agent-check`

**[error-codes-state]**: Implementations MUST detect: `STATE_MISMATCH` (computed
PR ≠ claimed PR), `HASH_ALG_MISMATCH`, `ALG_INCOMPATIBLE`, `CHAIN_BROKEN`
(Level 2+).
`VERIFIED: agent-check`

**[error-codes-recovery]**: Implementations MUST detect: `UNRECOVERABLE_PRINCIPAL`
(no active keys, no recovery agents), `RECOVERY_NOT_DESIGNATED` (Level 3+).
`VERIFIED: agent-check`

### Transitions

#### Resync

**[resync-process]**: Resync MUST follow: (1) select trust anchor, (2) fetch
patch via `/patch` endpoint, (3) verify patch (pre chaining, signing keys,
computed PR, timestamps, thresholds, no forks), (4) apply and promote new PR
to trust anchor.

- **PRE**: Witness trust anchor is behind current tip.
- **POST**: Trust anchor is advanced to current tip. Consensus state → Active.
  `VERIFIED: agent-check`

**[resync-backoff]**: Witnesses SHOULD use exponential backoff for repeated
resync attempts to prevent denial-of-service.
`VERIFIED: agent-check`

**[resync-pop]**: A principal MAY re-iterate an existing state as authoritative
without mutating PR/AR through a resync PoP (signing `resync/create`). This
proves current possession without advancing the chain.

- **PRE**: Principal has an active key.
- **POST**: Witnesses confirm the asserted tip. No state mutation.
  `VERIFIED: agent-check`

#### Fork Detection and Resolution

**[fork-detection]**: Witnesses MUST detect implicit forks via: mismatched tips
in gossip, inconsistent `/patch` responses, and conflicting signed proofs.
`VERIFIED: agent-check`

**[fork-response]**: On fork detection, witnesses MUST: broadcast fork proof,
reject both branches until resolved. Witnesses transition the principal's
consensus state to Error.
`VERIFIED: agent-check`

**[fork-resolution]**: An implicit fork is resolved when the principal
unambiguously selects one branch via either: (1) a new commit whose `pre`
references the tip of the chosen branch (implicitly abandons the other), or
(2) a `resync/create` PoP re-asserting the current tip. Abandoned branch
transactions become permanently invalid.

- **PRE**: Two conflicting branches exist; consensus state is Error.
- **POST**: One branch is canonical; abandoned branch retained as proof of
  error. Consensus state → Active.
  `VERIFIED: agent-check`

#### State Jumping

**[state-jump-mechanism]**: A state-jump transaction (Level 3+) advances a
client's trust anchor from an old PR directly to a much later PR without
fetching every intermediate transaction.

- **PRE**: Signing key(s) MUST be present in KR at both the old trust anchor
  AND the current tip. `jump_to_ps` MUST match the service-reported tip.
- **POST**: Client trust anchor updated to `jump_to_ps`. Future resolutions
  start from the new anchor.
  `VERIFIED: agent-check`

**[state-jump-revocation-check]**: State jumps MUST NOT bypass revocation
semantics. If a signing key was revoked between the anchor and tip, the jump
MUST fail with `JUMP_INVALID`.
`VERIFIED: agent-check`

**[state-jump-optional]**: Clients MAY reject state jumps. The reference client
rejects state jumps by default, preserving a conservative security baseline.
State jumping is an optimization that delegates some trust to third-party
services.
`VERIFIED: agent-check`

**[state-jump-multi]**: Multiple jumps MAY be required to traverse from anchor
to tip when keys have been revoked in the intermediate range. Each jump uses
a key valid at both the jump source and the jump destination.
`VERIFIED: agent-check`

### Forbidden States

**[no-fork-propagation]**: Witnesses MUST NOT propagate either branch of a
detected fork until the fork is resolved.
`VERIFIED: agent-check`

**[no-backward-timestamp]**: A message with `now` earlier than the latest known
timestamp for that principal MUST NOT be accepted (per [timestamp-monotonic]).
`VERIFIED: agent-check`

**[no-partial-apply]**: Implementations MUST NOT apply partial state changes
from a commit that contains any error (per [error-reject-atomic]).
`VERIFIED: agent-check`

**[no-jump-bypassing-revocation]**: A state jump MUST NOT succeed if the signing
key was revoked at any point between the anchor and the tip (per
[state-jump-revocation-check]).
`VERIFIED: agent-check`

### Behavioral Properties

**[consensus-independent]**: Each witness MUST independently compute consensus
state. No global coordination is required — consensus emerges from what
actually occurred and who published what when.

- **Type**: Design Property
  `VERIFIED: agent-check`

**[proof-of-error-durable]**: Proof of error SHOULD be retained durably by
witnesses for future resolution, escalation, or forensic analysis.

- **Type**: Liveness
  `VERIFIED: agent-check`

**[resync-resolves-transient]**: Many transient errors SHOULD resolve via
resync. Persistent failure (>3 attempts) escalates to Error state.

- **Type**: Liveness
  `VERIFIED: agent-check`

## Formal Specification

<!-- Tier 2+ formalization is structured for but not populated in this pass. -->

## Verification

| Constraint                     | Method      | Result | Detail                           |
| :----------------------------- | :---------- | :----- | :------------------------------- |
| [single-chain]                 | agent-check | pass   | Explicit in SPEC.md §17.4        |
| [proof-of-error]               | agent-check | pass   | Explicit in SPEC.md §17.1        |
| [timestamp-tolerance]          | agent-check | pass   | Explicit in SPEC.md §17.6        |
| [timestamp-monotonic]          | agent-check | pass   | Explicit in SPEC.md §17.6        |
| [timestamp-global-range]       | agent-check | pass   | Explicit in SPEC.md §17.3 errors |
| [witness-consensus-states]     | agent-check | pass   | Explicit in SPEC.md §17.3        |
| [consensus-state-transitions]  | agent-check | pass   | Explicit in SPEC.md §17.3.1      |
| [error-reject-atomic]          | agent-check | pass   | Explicit in SPEC.md §24.5        |
| [error-codes-transaction]      | agent-check | pass   | Explicit in SPEC.md §24.1        |
| [error-codes-state]            | agent-check | pass   | Explicit in SPEC.md §24.3        |
| [error-codes-recovery]         | agent-check | pass   | Explicit in SPEC.md §24.2        |
| [resync-process]               | agent-check | pass   | Explicit in SPEC.md §17.2        |
| [resync-backoff]               | agent-check | pass   | Explicit in SPEC.md §17.2        |
| [resync-pop]                   | agent-check | pass   | Explicit in SPEC.md §17.2.1      |
| [fork-detection]               | agent-check | pass   | Explicit in SPEC.md §17.5        |
| [fork-response]                | agent-check | pass   | Explicit in SPEC.md §17.5        |
| [fork-resolution]              | agent-check | pass   | Explicit in SPEC.md §17.5.1      |
| [state-jump-mechanism]         | agent-check | pass   | Explicit in SPEC.md §23.1        |
| [state-jump-revocation-check]  | agent-check | pass   | Explicit in SPEC.md §23.3        |
| [state-jump-optional]          | agent-check | pass   | Explicit in SPEC.md §23          |
| [state-jump-multi]             | agent-check | pass   | Explicit in SPEC.md §23.4        |
| [no-fork-propagation]          | agent-check | pass   | Follows from §17.5               |
| [no-backward-timestamp]        | agent-check | pass   | Follows from §17.6               |
| [no-partial-apply]             | agent-check | pass   | Explicit in §24.5                |
| [no-jump-bypassing-revocation] | agent-check | pass   | Explicit in §23.3                |
| [consensus-independent]        | agent-check | pass   | Explicit in §17 philosophy       |
| [proof-of-error-durable]       | agent-check | pass   | Explicit in §17.1                |
| [resync-resolves-transient]    | agent-check | pass   | Explicit in §17.2                |

## Implications

### For Implementation (`/core`)

- **Witness state machine**: [consensus-state-transitions] is directly
  implementable. Each witness maintains its own state per principal.
- **Timestamp tracking per principal**: Implementations must maintain a
  monotonically increasing "latest known timestamp" per principal to enforce
  [timestamp-monotonic].
- **Fork detection**: The most critical detection path — mismatched tips during
  gossip or inconsistent patch responses.
- **State jumping is optional**: Reference client defaults to rejecting jumps.
  Implementations that support jumping must verify the signing key exists in
  KR at both anchor and tip.

### For Testing

- **Fork simulation**: Create two valid commits with the same `pre` and verify
  fork detection and error state transition.
- **Fork resolution**: Resolve via new commit and via resync PoP — verify both
  paths return to Active.
- **Timestamp edge cases**: Messages at exactly ±360s boundary. Messages before
  and after latest known timestamp.
- **State jump**: Single jump (no revokes), multi-jump (revoke in path),
  invalid jump (revoked key).
- **Error taxonomy**: Test each error code from §24.1-24.4 individually.
- **Atomicity**: Submit a commit where one transaction is valid but another
  is not — verify the entire commit is rejected.

### Open Questions (for Zami / sketch)

1. **Client Mismatch resolution**: §17.3 defines CLIENT_MISMATCH but does not
   specify a resolution path. How does a witness transition out of this state?
2. **Proof of error retention**: How long should witnesses retain proof of error?
   The spec says "may retain" but doesn't specify retention requirements.
3. **State jump distance limits**: §23.3 mentions services MAY enforce
   "maximum jump distance" — is there a recommended default?
