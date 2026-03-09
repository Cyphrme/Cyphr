# SPEC: Transactions and Commit Semantics

<!--
  SPEC document produced by /spec Apply mode.
  Source: SPEC.md §2.3, §4, §5, §6, §7
  Authority: SPEC.md (Zamicol and nrdxp) — this document does NOT replace SPEC.md.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Cyphrpass transaction processing — the commit chain, genesis,
key lifecycle operations, data actions, and the `typ` action grammar that
governs intent declaration. This document covers what goes into a commit and
what happens when it is processed.

**Target System:** `SPEC.md` §2.3 (Core Protocol Constraints), §4 (Commit), §5
(Genesis), §6 (Key), §7 (`typ` Action Grammar).

**Model Reference:**
[`principal-state-model.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/models/principal-state-model.md)

**Criticality Tier:** High — transaction processing errors compromise identity
integrity and chain validity.

**Cross-references:**
[`state-tree.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/specs/state-tree.md)
— state computation rules that transactions produce.

## Constraints

### Type Declarations

```
TYPE Coz            = { pay: Payload, sig: B64ut }
TYPE Payload        = { alg: KeyAlg, tmb: B64ut, now: Timestamp, typ: TypString, ... }
TYPE Timestamp      = Integer                              -- Unix timestamp, 0 < t < 2^53 - 1
TYPE TypString      = "<authority>/<action>"
TYPE Authority      = String                               -- domain name or Principal Root
TYPE Action         = "<noun>[/<noun>...]/<verb>"
TYPE Verb           = "create" | "read" | "update" | "upsert" | "delete"
TYPE TransactionCoz = Coz & { pay: { pre: Digest } }      -- transaction cozies require `pre`
TYPE DataActionCoz  = Coz                                  -- no `pre` required
TYPE Commit         = List<TransactionCoz>                 -- ≥1 transaction cozies
TYPE GenesisCommit  = Commit & { keys: List<PublicKey> }   -- includes key material
TYPE CS             = Digest                               -- Commit State (PT minus CommitID)

-- Key lifecycle
TYPE KeyVerb        = "key/create" | "key/delete" | "key/replace" | "key/revoke"

-- Revocation (Coz-inherited)
TYPE Rvk            = Integer                              -- 0 < rvk < 2^53 - 1
```

### Invariants

#### Coz Required Fields

**[coz-required-fields]**: All Cyphrpass cozies MUST contain the fields `alg`,
`tmb`, `now`, and `typ` in `pay`. Cozies missing any of these fields MUST be
rejected. (Coz itself makes all fields optional; Cyphrpass constrains this.)
`VERIFIED: agent-check`

**[transaction-pre-required]**: Transaction cozies (those that mutate AT and
advance the commit chain) MUST additionally contain `pre` in `pay`, referencing
the targeted Principal Tree (PT), as denoted by PS, for mutation (SPEC.md §7.1).
Cozies without `pre` are not transactions (except naked revokes — see
[revoke-naked]).
`VERIFIED: agent-check — updated 2026-03-09 per A-2, A-4`

**[data-action-no-pre]**: Data action cozies MUST NOT contain `pre`. Data
actions are stateless signed messages that do not mutate AT and are not part
of the commit chain.
`VERIFIED: agent-check — updated 2026-03-09 per B-5 (AS→AT)`

#### Authorization

**[authorization-triple]**: A transaction MUST be authorized if and only if all
three conditions hold:

1. **Pre-mutation state**: The signing key (`tmb`) MUST be active in KS
   _before_ the transaction is applied. A key added or revoked within the same
   commit MUST NOT affect authorization of that commit's transactions.
2. **Lifecycle gate**: The principal's current lifecycle state MUST permit the
   operation (see `principal-lifecycle.md`).
3. **Capability gate**: The principal MUST have the state components required
   for the operation (e.g., DT must exist for data actions, RT for rule
   operations).
   `VERIFIED: agent-check — citation updated 2026-03-09 per A-1 (§2.3.3→§3)`

**[pre-mutation-key-rule]**: Authorization is evaluated against the key state
that existed _before_ any transactions in the current commit are applied. Keys
added during a commit MUST NOT authorize other transactions in that same commit.
Keys revoked or deleted during a commit MUST still authorize their own
containing transactions if they were active before the commit.
`VERIFIED: agent-check — citation updated 2026-03-09 per A-1 (§2.3.3→§3)`

#### Commit Chain

**[commit-append-only]**: Commits MUST be append-only. A commit, once published,
MUST NOT be removed from the chain. Implicit forks are prohibited by the
protocol.
`VERIFIED: agent-check`

**[commit-one-or-more]**: A commit MUST contain one or more transaction cozies.
Empty commits (zero transactions) are not valid.
`VERIFIED: agent-check`

**[commit-pre-chain]**: All transaction cozies in a commit MUST reference the
same `pre` value — the PS targeted for mutation. The `pre` field groups
transactions into a transaction bundle for a commit.
`VERIFIED: agent-check`

**[commit-id-computation]**: Commit ID MUST be computed as MR(czd₀, czd₁, ...)
of all transaction cozies in the commit. Cozies MUST be processed in **array
order** (the order they appear in `txs`), not lexical sort order. This is an
exception to `state-tree.md` [mr-sort-order].
`VERIFIED: agent-check — updated 2026-03-09 per array-order decision`

**[commit-finality]**: A commit is finalized by having `"commit":<CS>` appear in
the last coz of the commit (SPEC.md §4.2). CS is computed as all PT components
except CommitID: `CS = MR(AS, DS?, embedding?, ...)`. The `commit` field serves
as the forward-reference finality signal. See `state-tree.md` State Formulas.
`VERIFIED: agent-check — new 2026-03-09 per B-1, R-1`

**[commit-field-required]**: The last coz in a commit MUST contain the `commit`
field in `pay` with its value set to the computed CS. Cozies that are not the
last in a commit MAY omit the `commit` field. A commit without a `commit` field
in its final coz MUST be rejected as incomplete.
`VERIFIED: agent-check — new 2026-03-09 per S-1`

#### `typ` Grammar

**[typ-grammar]**: The `typ` field MUST follow the grammar:
`<authority>/<noun>[/<noun>...]/<verb>`. The authority is the first path unit.
The verb is the last path unit. Everything between is the noun (which MAY be
compound, e.g., `user/image`).
`VERIFIED: agent-check`

**[typ-verbs]**: Standard verbs MUST be one of: `create`, `read`, `update`,
`upsert`, `delete`. Protocol-level special verbs (`revoke`, `replace`, `merge`,
`ack-merge`) are additionally permitted for their defined transaction types.
`VERIFIED: agent-check`

**[idempotent-transactions]**: Transaction mutations MUST be idempotent.
Replaying an already-applied coz MUST be ignored and produce no state change.
`VERIFIED: agent-check`

**[create-uniqueness]**: All `create` operations MUST enforce uniqueness. If the
target item (key, rule, principal) already exists, the operation MUST return
error `DUPLICATE`.
`VERIFIED: agent-check`

**[transaction-id-required]**: Transaction cozies MUST contain `id` in `pay`,
identifying the target noun. For example, for `key/create`, `id` is the key's
`tmb`. (SPEC.md §7.1)
`VERIFIED: agent-check — new 2026-03-09 per S-3`

#### Wire Format

**[wire-format-plurals]**: JSON wire format MUST use plural field names. The
singular forms `tx`, `key`, and `coz` are prohibited. Valid fields: `txs`,
`keys`, `cozies`. (SPEC.md JSON Wire Format)
`VERIFIED: agent-check — new 2026-03-09 per S-2`

#### Timestamp

**[timestamp-range]**: The `now` field MUST be a positive integer less than
2^53 − 1 (9,007,199,254,740,991). Timestamps outside this range MUST be
rejected.
`VERIFIED: agent-check`

#### AT/DT Duality

**[at-append-only]**: Auth Tree (AT) history MUST be append-only (immutable).
Commits form a monotonic sequence and MUST NOT be modified or deleted after
publication.
`VERIFIED: agent-check`

**[dt-mutable]**: Data Tree (DT) MAY permit mutation (update, deletion) of its
contents. DT has no chain structure; verification is point-in-time snapshot
only, not replay-from-genesis.
`VERIFIED: agent-check`

### Transitions

#### Genesis

**[genesis-bootstrap]**: Genesis MUST follow the bootstrap model: the first
key exists without a transaction (Level 1+ identity: `tmb` == KS == AS == PS
via implicit promotion). Additional keys, rules, or other AT components
MUST be added via transactions that reference `pre` = the current PS. Genesis
is finalized by a `principal/create` transaction.

- **PRE**: No principal exists for this key identity.
- **POST**: PR is established and immutable (Level 3+ only). Commit chain begins.
  `VERIFIED: agent-check`

**[genesis-pre-continuity]**: Every transaction in a genesis commit, including
the genesis transactions themselves, MUST include `pre` referencing the current
PS. For the first transaction (e.g., `key/create` adding a second key), `pre`
MUST reference the first key's `tmb` (which is PS via implicit promotion).

- **PRE**: First key's `tmb` is the current PS.
- **POST**: Each transaction targets the same PS, maintaining chain continuity.
  `VERIFIED: agent-check`

**[genesis-finality]**: Genesis MUST be finalized by a `principal/create`
transaction with `id` set to the computed Principal State (PS), which at genesis
is the Principal Root (PR).

- **PRE**: All genesis mutations (key additions, etc.) are included.
- **POST**: PR = the `id` field of `principal/create`. Principal is created.
  `VERIFIED: agent-check — updated 2026-03-09 per B-3 (AS→PS), SPEC §5.1`

#### Key Lifecycle

**[key-create]**: `key/create` (Level 3+) adds a new key to KT. The
transaction MUST include `id` = `tmb` of the new key and `pre` = targeted PS.
The signing key (`tmb`) MUST be active in KS at pre-mutation state.

- **PRE**: Key identified by `id` MUST NOT already exist in KT (per
  [create-uniqueness]).
- **POST**: New key is active in KT. KS is recomputed. AS evolves.
  `VERIFIED: agent-check`

**[key-delete]**: `key/delete` (Level 3+) removes a key from KT without
marking it as compromised. The transaction MUST include `id` = `tmb` of the
key being removed, and `pre` = targeted PS.

- **PRE**: Key identified by `id` MUST be active in KT.
- **POST**: Key is removed from KT. Past signatures from the key's active
  period(s) remain valid. Key MAY be re-added later via `key/create`.
  `VERIFIED: agent-check`

**[key-replace]**: `key/replace` (Level 2+) atomically removes the signing key
and adds a new key. The transaction MUST include `id` = `tmb` of the new key,
and `pre` = targeted PS. For Level 2, `pre` is the `tmb` of the previous key
(since AS == KS == `tmb`).

- **PRE**: Signing key (`tmb`) MUST be active in KT. Level 2 principal MUST
  have exactly one key.
- **POST**: Signing key is removed from KT. New key is added. Single-key
  invariant is maintained for Level 2.
  `VERIFIED: agent-check`

**[key-revoke]**: `key/revoke` (Level 1+) is a self-signed declaration that a
key is compromised. The `tmb` signing the revoke MUST be the key being revoked
(self-signed). The transaction MUST include `rvk` with an integer value > 0
(current Unix timestamp RECOMMENDED). `rvk` MUST be a positive integer < 2^53 − 1.

- **PRE**: The key identified by `tmb` exists (may or may not be in KT).
- **POST**: The key is marked as compromised. All future signatures from
  this key MUST be rejected.
  `VERIFIED: agent-check`

**[revoke-naked]**: A revoke MAY omit `pre` (naked revoke). A naked revoke
does NOT mutate PS. Third parties MAY sign naked revokes to declare a key
compromised without knowledge of the principal's state. A naked revoke, or a
revoke with `pre` but without a subsequent `delete`, puts the principal in an
error state (see `consensus.md`).
`VERIFIED: agent-check`

**[revoke-self-signed]**: Revoke MUST be self-signed — the key signing the
revoke coz MUST be the same key identified by `tmb`. Third-party revokes are
valid as declarations of compromise but are still self-signed (by the
compromised key, not by another key).
`VERIFIED: agent-check`

**[key-active-period]**: A key's active period is the time span during which it
is present in KT and authorized to sign actions. A key MAY have multiple
successive active periods if deleted and re-added. Actions signed outside an
active period MUST be ignored.
`VERIFIED: agent-check`

#### Data Actions

**[data-action-stateless]**: Data actions are stateless signed messages. They
MUST NOT mutate AT. They do not participate in the commit chain.

- **PRE**: Signing key MUST be active in KS.
- **POST**: Action is recorded in DT (if DT exists). No AT change.
  `VERIFIED: agent-check — updated 2026-03-09 per B-5 (AS→AT)`

**[ds-inclusion]**: To include DS into PS, a `ds/create` transaction MUST be
signed, updating the DS component in the principal state tree. Without this
explicit inclusion transaction, DS is absent from PS (excluded, not zero).

- **PRE**: DT exists (Level 4+). Signing key MUST be active.
- **POST**: DS = MR(DT) is included as a component of PS.
  `VERIFIED: agent-check`

#### Nonce Transactions

**[nonce-path]**: Nonce `typ` MUST specify the insertion path in the state tree.
The path grammar is: `cyphrpass/<tree-path>/nonce/<verb>`. Examples:

- `cyphrpass/nonce/create` — Principal root level
- `cyphrpass/AT/nonce/create` — Auth Tree root
- `cyphrpass/AT/KT/nonce/create` — Key Tree root
  `VERIFIED: agent-check`

### Forbidden States

**[no-orphan-pre]**: A transaction's `pre` MUST reference a valid, known PS.
Transactions referencing a `pre` that does not correspond to any known state
in the commit chain MUST be rejected.
`VERIFIED: agent-check`

**[no-unauthorized-transaction]**: A transaction signed by a key not active in
KS at the pre-mutation state MUST be rejected. There MUST NOT be a state where
a transaction is accepted from an unauthorized key.
`VERIFIED: agent-check`

**[no-self-revoke-recovery]**: At Level 1, a self-revoke results in permanent
lockout (DEAD state). There MUST NOT be a protocol-level recovery mechanism
for Level 1 self-revocation — recovery requires sideband intervention.
`VERIFIED: agent-check`

**[no-revoke-non-self]**: A revoke coz where `tmb` (the signing key) does not
match the key being revoked MUST be rejected. Revokes MUST be self-signed.
`VERIFIED: agent-check`

> [!NOTE]
> **PLACEHOLDER — Commit Finality (partially resolved)**: The commit finality
> mechanism is now resolved: inline `"commit":<CS>` in the last coz (see
> [commit-finality], [commit-field-required]). However, the exact behavior when
> `commit` appears in cozies other than the last one is not specified. Is it
> ignored? Rejected?

**[intra-commit-ordering]**: Transactions within a commit MUST be applied in
**array order** (the order they appear in the `txs` array). This ordering is
also used for Commit ID computation (per [commit-id-computation]). Application
order determines the final state when operations on the same target are present.
`VERIFIED: agent-check — new 2026-03-09 per array-order decision`

### Behavioral Properties

**[commit-deterministic]**: Given identical transaction cozies in a commit, the
resulting PS MUST be identical regardless of implementation. This follows from
deterministic state computation (per `state-tree.md` [deterministic-state])
applied to transaction outputs.

- **Type**: Safety
  `VERIFIED: agent-check`

**[genesis-irreversible]**: Once a principal reaches genesis (PR is established),
the PR MUST NOT change. Genesis is a one-way transition from "no principal" to
"principal with permanent PR."

- **Type**: Safety
  `VERIFIED: agent-check`

**[revoke-propagation]**: A valid revoke, once observed, MUST be honored by all
conforming implementations. A revoked key MUST NOT be accepted for new
signatures by any witness or service, regardless of whether the revoke
included `pre`.

- **Type**: Safety
  `VERIFIED: agent-check`

## Formal Specification

<!-- Tier 2+ formalization is structured for but not populated in this pass. -->

## Verification

| Constraint                    | Method      | Result | Detail                                              |
| :---------------------------- | :---------- | :----- | :-------------------------------------------------- |
| [coz-required-fields]         | agent-check | pass   | Explicit in SPEC.md §2.3.1                          |
| [transaction-pre-required]    | agent-check | pass   | SPEC.md §7.1 (updated 2026-03-09)                   |
| [data-action-no-pre]          | agent-check | pass   | SPEC.md §4.4 (updated 2026-03-09)                   |
| [authorization-triple]        | agent-check | pass   | SPEC.md §3 (relocated from §2.3.3)                  |
| [pre-mutation-key-rule]       | agent-check | pass   | SPEC.md §3 item 1 (relocated from §2.3.3)           |
| [commit-append-only]          | agent-check | pass   | Explicit in SPEC.md §2.3.2                          |
| [commit-one-or-more]          | agent-check | pass   | Inferred from §4 ("one or more transaction cozies") |
| [commit-pre-chain]            | agent-check | pass   | Explicit in SPEC.md §4.1.1                          |
| [commit-id-computation]       | agent-check | pass   | SPEC.md §9; array order per decision           |
| [commit-finality]             | agent-check | pass   | SPEC.md §4.2 (new 2026-03-09)                  |
| [commit-field-required]       | agent-check | pass   | SPEC.md §4.2 (new 2026-03-09)                  |
| [typ-grammar]                 | agent-check | pass   | Explicit in SPEC.md §7                              |
| [typ-verbs]                   | agent-check | pass   | Explicit in SPEC.md §7, §7.2                        |
| [idempotent-transactions]     | agent-check | pass   | Explicit in SPEC.md §7.5                            |
| [create-uniqueness]           | agent-check | pass   | Explicit in SPEC.md §7.6                            |
| [transaction-id-required]     | agent-check | pass   | SPEC.md §7.1 (new 2026-03-09)                  |
| [timestamp-range]             | agent-check | pass   | Explicit in SPEC.md §6.4 (inherited from Coz)       |
| [at-append-only]              | agent-check | pass   | Explicit in SPEC.md §2.3.4 table                    |
| [dt-mutable]                  | agent-check | pass   | Explicit in SPEC.md §2.3.4 table                    |
| [genesis-bootstrap]           | agent-check | pass   | Explicit in SPEC.md §5.1                            |
| [genesis-pre-continuity]      | agent-check | pass   | Explicit in SPEC.md §5.1                            |
| [genesis-finality]            | agent-check | pass   | SPEC.md §5.1 (id=PS, updated 2026-03-09)       |
| [key-create]                  | agent-check | pass   | Explicit in SPEC.md §6.1                            |
| [key-delete]                  | agent-check | pass   | Explicit in SPEC.md §6.2                            |
| [key-replace]                 | agent-check | pass   | Explicit in SPEC.md §6.3                            |
| [key-revoke]                  | agent-check | pass   | Explicit in SPEC.md §6.4                            |
| [revoke-naked]                | agent-check | pass   | Explicit in SPEC.md §6.4                            |
| [revoke-self-signed]          | agent-check | pass   | Explicit in SPEC.md §6.4                            |
| [key-active-period]           | agent-check | pass   | Explicit in SPEC.md §6.2                            |
| [data-action-stateless]       | agent-check | pass   | SPEC.md §4.4 (AS→AT, updated 2026-03-09)       |
| [ds-inclusion]                | agent-check | pass   | Explicit in SPEC.md §4.5.1                          |
| [nonce-path]                  | agent-check | pass   | Explicit in SPEC.md §4.7                            |
| [no-orphan-pre]               | agent-check | pass   | Inferred from §4 chain semantics                    |
| [no-unauthorized-transaction] | agent-check | pass   | Follows from §3                                     |
| [no-self-revoke-recovery]     | agent-check | pass   | Explicit in SPEC.md §3.1                            |
| [no-revoke-non-self]          | agent-check | pass   | Explicit in SPEC.md §6.4                            |
| [commit-deterministic]        | agent-check | pass   | Follows from state-tree.md [deterministic-state]    |
| [genesis-irreversible]        | agent-check | pass   | Follows from state-tree.md [pr-immutable]           |
| [revoke-propagation]          | agent-check | pass   | Inferred from §6.4 revoke semantics                 |
| [wire-format-plurals]         | agent-check | pass   | SPEC.md JSON Wire Format (new 2026-03-09)      |
| [intra-commit-ordering]       | agent-check | pass   | Array-order decision (new 2026-03-09)          |

## Implications

### For Implementation (`/core`)

- **Authorization snapshot**: The [pre-mutation-key-rule] is the most critical
  implementation detail — authorization is evaluated against the state _before_
  the commit is applied, not during. Implementations must snapshot KS before
  processing any transaction in a commit.
- **Revoke without `pre`**: Naked revokes are valid Coz messages that don't
  mutate PS but must be stored and propagated. Implementations must handle
  revokes arriving out-of-band (not in the commit chain).
- **Key re-addition**: [key-delete] explicitly permits re-adding a deleted key
  via `key/create`. Implementations must not treat "previously deleted" as a
  permanent state.
- **Idempotency**: [idempotent-transactions] means implementations must detect
  and silently ignore duplicate transaction cozies.

### For Testing

- **Genesis sequence tests**: Verify the bootstrap model — single key genesis,
  multi-key genesis, and the `pre` continuity invariant.
- **Authorization boundary tests**: Add a key in commit N, verify it cannot
  authorize transactions in commit N (only commit N+1).
- **Revoke edge cases**: Naked revoke, revoke-with-pre, revoke-then-delete,
  revoke-of-already-deleted key.
- **Idempotency tests**: Replay a valid transaction and verify no state change.
- **`typ` grammar validation**: Malformed `typ` strings, missing verbs, empty
  nouns.

### Open Questions (for Zami / sketch)

1. **Commit field in non-last coz**: §4.2 says `"commit":<CS>` appears in the
   "last coz". What happens if it appears in an earlier coz? Ignored? Rejected?
2. **Key material in transactions**: §6.1 shows `key` outside `pay` (unsigned).
   Is the public key material always required alongside `key/create`, or can
   it be transmitted via sideband?
3. **Naked revoke and error state**: §6.4 says a naked revoke puts the principal
   in an error state. Is this the same concept as the `Errored` lifecycle state
   in §11, or something different?
