# SPEC: Authentication and Mutual State Synchronization

<!--
  SPEC document produced by /spec Apply mode.
  Source: SPEC.md §12, §14, §16
  Authority: SPEC.md (Zamicol and nrdxp) — this document does NOT replace SPEC.md.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Cyphr authentication mechanisms — Proof of Possession
(PoP), bearer tokens, login flows, and Mutual State Synchronization (MSS). Also
covers embedding and conjunctive authorization for delegated identity.

**Target System:** `SPEC.md` §12 (Embedding), §14 (Authentication), §16 (MSS).

**Model Reference:**
[`principal-state-model.md`](../models/principal-state-model.md)

**Criticality Tier:** High — authentication errors compromise identity
verification and access control.

**Cross-references:**
[`transactions.md`](./transactions.md)
— authorization model.
[`principal-lifecycle.md`](./principal-lifecycle.md)
— lifecycle gate for authentication.
[`state-tree.md`](./state-tree.md)
— Merkle tree structure for embeddings.

## Constraints

### Invariants

#### Proof of Possession

**[pop-via-signature]**: Every valid signature by an authorized key MUST
constitute a Proof of Possession (PoP). No additional authentication factor
is required at the protocol level.
`VERIFIED: agent-check`

**[pop-types]**: The protocol recognizes four PoP types: Genesis PoP (first
signature), Transaction PoP (key mutation), Action PoP (data action), and Login
PoP (challenge-response or timestamp-based). Each is a valid signature under
the same verification rules.
`VERIFIED: agent-check`

#### Login Flow

**[login-challenge-response]**: In challenge-response login, the service MUST
generate a 256-bit cryptographic challenge (nonce). The principal signs the
challenge, and the service MUST verify: (1) signature is valid, (2) `tmb`
belongs to an active key in KR, (3) principal lifecycle state is Active, (4)
challenge matches the one issued.
`VERIFIED: agent-check`

**[login-timestamp-based]**: In timestamp-based login, the principal signs a
login request with current `now`. The service MUST verify: (1) signature is
valid, (2) `tmb` belongs to an active key in KR, (3) principal lifecycle is
Active, (4) `now` is within the acceptable window (e.g., ±60 seconds).
`VERIFIED: agent-check`

**[login-lifecycle-gate]**: During authentication, services MUST reject
principals whose lifecycle state is not Active. Frozen, Deleted, Errored, and
other non-Active states MUST NOT be accepted for login.
`VERIFIED: agent-check`

#### Replay Prevention

**[replay-prevention]**: Replay attacks MUST be prevented by at least one of:
(1) challenge nonce — service issues a unique nonce per attempt, or (2)
timestamp window — `now` within ±N seconds of server time. Implementations MUST
support at least one mechanism.
`VERIFIED: agent-check`

#### Bearer Tokens

**[bearer-token-service-signed]**: Bearer tokens MUST be signed Coz messages
from the service (not the principal). The service signs the token with its own
key, binding it to a specific principal PG and permission set.
`VERIFIED: agent-check`

**[bearer-token-fields]**: Bearer tokens SHOULD contain at minimum: principal
PG, authorized permissions, and expiry (`exp`). The `typ` is service-defined.
`VERIFIED: agent-check`

#### Embedding

**[embedding-weight-default]**: An embedded node MUST have a default weight of
one (1), regardless of how many children the embedded node contains. Weight
MAY be overridden by rules (RR) at Level 5+.
`VERIFIED: agent-check`

**[embedding-cyclic-stop]**: Embedding MUST stop recursion at the point of
cycle. When principal A embeds principal B and B embeds A, verifying A includes
B's members but MUST NOT recursively resolve B's embedding of A (preventing
infinite recursion).
`VERIFIED: agent-check`

**[embedding-conjunctive-auth]**: Authorization involving an embedded principal
MUST be conjunctive: (1) the transaction must be valid according to the
embedded principal's own rules (its KR/RR), AND (2) the act of using that
embedded principal must be authorized by the primary principal's rules. Both
conditions MUST hold.
`VERIFIED: agent-check`

**[embedding-tip-retrieval]**: For PG, PR, and AR references exclusively,
embedded nodes MUST trigger tip retrieval from the referenced principal at
verification time before any operation. Other node types MUST NOT trigger
retrieval. Opaque nodes MUST NOT trigger synchronization.
`VERIFIED: agent-check`

**[embedding-pinning]**: Pinned identifiers (prefixed `PIN:<alg>:<value>`)
MUST denote static states that prohibit updates. Pinned embeddings MUST NOT
trigger tip retrieval.
`VERIFIED: agent-check`

#### State Verification

**[verification-replay]**: To verify a principal's current state, a verifier
MUST: (1) identify the trust anchor (PG or known PR), (2) obtain ordered
transaction history from trust anchor to tip, (3) replay each transaction
verifying signature, key membership in KR, lifecycle gate, timestamp ordering,
and well-formedness, (4) compare final computed state against claimed state.
`VERIFIED: agent-check`

**[verification-timestamp-order]**: During chain replay, each transaction's
`now` MUST be after the previous transaction's `now`. Backward timestamps MUST
be rejected.
`VERIFIED: agent-check`

#### Checkpoints

**[checkpoint-self-contained]**: A checkpoint MUST be a self-contained snapshot
of the authentication-relevant state at a particular commit. Once verified, a
checkpoint allows verification from that point forward without replaying
earlier history.
`VERIFIED: agent-check`

**[checkpoint-genesis-foundational]**: Genesis is the foundational checkpoint.
Services SHOULD cache later checkpoints to reduce chain length for
verification.
`VERIFIED: agent-check`

**[checkpoint-declarative]**: A declarative transaction (`checkpoint/create`)
MUST enumerate the full principal tree (PT). Since declarative transactions
exhaustively declare state, they inherently serve as checkpoints.
`VERIFIED: agent-check`

#### MSS Properties

**[mss-bidirectional]**: Both users and services MUST be representable as
Cyphr principals, enabling bidirectional state tracking. Neither party
holds a privileged position.
`VERIFIED: agent-check`

**[mss-push-on-mutation]**: After a state mutation (key/create, key/revoke,
etc.), clients SHOULD push the mutation to all registered services. This
enables low-latency authentication by pre-syncing state.
`VERIFIED: agent-check`

### Forbidden States

**[no-login-non-active]**: A service MUST NOT authenticate a principal whose
lifecycle state is not Active (per [login-lifecycle-gate]).
`VERIFIED: agent-check`

**[no-unsigned-bearer]**: A bearer token that is not signed by the issuing
service's key MUST NOT be accepted.
`VERIFIED: agent-check`

### Behavioral Properties

**[aaa-over-bearer]**: Authenticated Atomic Action (AAA) SHOULD be preferred
over bearer tokens when possible. AAA provides per-action cryptographic
verification without session state. Bearer tokens remain useful for access
control and legacy system upgrades.

- **Type**: Liveness / Design Guidance
  `VERIFIED: agent-check`

**[sso-without-centralization]**: Cyphr provides SSO semantics without
centralized identity providers or password/email dependency. The principal's
keys are the sole authentication factor, verifiable by any party.

- **Type**: Design Property
  `VERIFIED: agent-check`

## Formal Specification

<!-- Tier 2+ formalization is structured for but not populated in this pass. -->

## Verification

| Constraint                        | Method      | Result | Detail                             |
| :-------------------------------- | :---------- | :----- | :--------------------------------- |
| [pop-via-signature]               | agent-check | pass   | Explicit in SPEC.md §14.1          |
| [pop-types]                       | agent-check | pass   | Explicit in SPEC.md §14.1          |
| [login-challenge-response]        | agent-check | pass   | Explicit in SPEC.md §14.2 Option A |
| [login-timestamp-based]           | agent-check | pass   | Explicit in SPEC.md §14.2 Option B |
| [login-lifecycle-gate]            | agent-check | pass   | Explicit in SPEC.md §14.2          |
| [replay-prevention]               | agent-check | pass   | Explicit in SPEC.md §14.3          |
| [bearer-token-service-signed]     | agent-check | pass   | Explicit in SPEC.md §14.4          |
| [bearer-token-fields]             | agent-check | pass   | Explicit in SPEC.md §14.4          |
| [embedding-weight-default]        | agent-check | pass   | Explicit in SPEC.md §12            |
| [embedding-cyclic-stop]           | agent-check | pass   | Explicit in SPEC.md §12            |
| [embedding-conjunctive-auth]      | agent-check | pass   | Explicit in SPEC.md §12.2          |
| [embedding-tip-retrieval]         | agent-check | pass   | Explicit in SPEC.md §12.1          |
| [embedding-pinning]               | agent-check | pass   | Explicit in SPEC.md §12.4          |
| [verification-replay]             | agent-check | pass   | Explicit in SPEC.md §16.2          |
| [verification-timestamp-order]    | agent-check | pass   | Explicit in SPEC.md §16.2          |
| [checkpoint-self-contained]       | agent-check | pass   | Explicit in SPEC.md §8.2           |
| [checkpoint-genesis-foundational] | agent-check | pass   | Explicit in SPEC.md §8.2           |
| [checkpoint-declarative]          | agent-check | pass   | Explicit in SPEC.md §8.3           |
| [mss-bidirectional]               | agent-check | pass   | Explicit in SPEC.md §16            |
| [mss-push-on-mutation]            | agent-check | pass   | Explicit in SPEC.md §16.3          |
| [no-login-non-active]             | agent-check | pass   | Follows from §14.2                 |
| [no-unsigned-bearer]              | agent-check | pass   | Follows from §14.4                 |
| [aaa-over-bearer]                 | agent-check | pass   | Explicit in SPEC.md §14            |
| [sso-without-centralization]      | agent-check | pass   | Explicit in SPEC.md §14.5          |

## Implications

### For Implementation (`/core`)

- **Conjunctive auth is complex**: Embedding verification requires recursing
  into the embedded principal's rules, then checking back against the host
  principal. This is the most complex authentication path.
- **Cycle detection**: Implementations MUST detect embedding cycles and stop
  recursion, or risk infinite loops.
- **Pinning**: Pinned embeddings are a performance optimization (skip tip
  retrieval) and a security feature (immutable delegation). Implementations
  must distinguish pinned from unpinned references.
- **MSS push**: Client push is SHOULD, not MUST — implementations must handle
  stale service state gracefully.

### For Testing

- **Challenge-response**: End-to-end login with nonce generation, signing, and
  verification.
- **Timestamp-based login**: Clock skew edge cases (exactly at boundary,
  slightly past boundary).
- **Embedding cycle**: A embeds B, B embeds A — verify recursion terminates.
- **Conjunctive auth**: Embedded principal authorizes action on host — verify
  both rule sets are checked.
- **Pinned vs unpinned**: Verify pinned embedding does not trigger tip
  retrieval.

### Deferred Specifications (Level 5+)

> **Design Pending**: The exact representation of Principal Embedding (pinned vs native structures) and the formalization of MSS registration models involve Level 5 capabilities. These rule-based configurations (such as embedding RR into KR vs PR) are currently deferred and will be formalized alongside the Level 5 Rule State specification rollout.
