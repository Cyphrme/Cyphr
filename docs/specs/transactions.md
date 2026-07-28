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

**Problem Domain:** Cyphr transaction processing — the commit chain, genesis,
key lifecycle operations, data actions, and the `typ` action grammar that
governs intent declaration. This document covers what goes into a commit and
what happens when it is processed.

**Target System:** `SPEC.md` §2.3 (Core Protocol Constraints), §4 (Commit), §5
(Genesis), §6 (Key), §7 (`typ` Action Grammar).

**Model Reference:**
[`principal-state-model.md`](../models/principal-state-model.md)

**Criticality Tier:** High — transaction processing errors compromise identity
integrity and chain validity.

**Cross-references:**
[`state-tree.md`](./state-tree.md)
— state computation rules that transactions produce.

## Constraints

### Type Declarations

```
TYPE Coz            = { pay: Payload, sig: B64ut }
TYPE Payload        = { alg: KeyAlg, tmb: B64ut, now: Timestamp, typ: TypString, ... }
TYPE Timestamp      = Integer                              -- Unix timestamp, 0 < t < 2^53 - 1
TYPE TypString      = "<authority>/<action>"
TYPE Authority      = String                               -- domain name or Principal Genesis
TYPE Action         = "<noun>[/<noun>...]/<verb>"
TYPE Verb           = "create" | "read" | "update" | "upsert" | "delete"
TYPE TransactionCoz = Coz                                  -- classified by `typ` (key/*, principal/create, commit/create); carries no `pre`
TYPE DataActionCoz  = Coz                                  -- MUST NOT contain `pre` (see [data-action-no-pre])

-- Transaction structure: list of lists
TYPE Transaction    = List<Coz>                            -- ≥1 related cozies
TYPE TxsList        = List<Transaction>                    -- all transactions in a commit
TYPE Commit         = TxsList                              -- txs is list of lists; commit tx is last
TYPE GenesisCommit  = Commit & { keys: List<PublicKey> }   -- includes key material

-- Key lifecycle
TYPE KeyVerb        = "key/create" | "key/delete" | "key/replace" | "key/revoke"

-- Revocation (Coz-inherited)
TYPE Rvk            = Integer                              -- 0 < rvk < 2^53 - 1
```

### Invariants

#### Coz Required Fields

**[coz-required-fields]**: All Cyphr cozies MUST contain the fields `alg`,
`tmb`, `now`, and `typ` in `pay`. Cozies missing any of these fields MUST be
rejected. (Coz itself makes all fields optional; Cyphr constrains this.)
`VERIFIED: agent-check`

**[transaction-classification]**: A coz is a transaction (one that mutates PT
and advances the commit chain) if and only if its `typ` is one of `key/create`,
`key/delete`, `key/replace`, `key/revoke`, `principal/create`, or
`commit/create`. Every other `typ` is a data action (see
[data-action-no-pre]). Transaction cozies carry no `pre` field; classification
is by `typ`, not by field presence. Per-mutation `pre` was rejected-draft
residue and has been removed from the wire format and implementation — commit
atomicity, bundling, and order are carried entirely by the commit transaction's
`arrow` (see [commit-finality-arrow]) and by wire-format position (see
[txs-list-of-lists], [tx-grouping]), not by a chained `pre` reference.
`VERIFIED: agent-check — updated 2026-07-06, per-mutation pre removed (rejected draft, PR #39 thread)`

**[data-action-no-pre]**: Data action cozies MUST NOT contain `pre`. Data
actions are stateless signed messages that do not mutate AT and are not part
of the commit chain.
`VERIFIED: agent-check — updated 2026-03-09 per B-5 (AR→AT)`

#### Authorization

Authorization is evaluated in one of two contexts, which are not
contradictory — they are different frames and MUST NOT be conflated:

- **Intra-commit**: transactions within a commit apply sequentially, in
  `txs` array order (see [intra-commit-ordering]). Each transaction's
  authorization is evaluated against the key state as it exists immediately
  before *that* transaction, reflecting all earlier transactions already
  applied in the same commit.
- **Extra-commit**: external authenticators (e.g. login, or a third party
  verifying a principal from outside the commit) see only already-committed
  state. Transactions inside an in-flight commit are ephemeral to them; such
  a verifier MUST evaluate authorization against the state as of the last
  finalized commit only.

**[authorization-triple]**: A transaction MUST be authorized if and only if all
three conditions hold:

1. **Antecedent authorization gate**: The signing key (`tmb`) MUST be active
   in KR immediately before this transaction is applied, per the intra-commit
   or extra-commit context in effect (see [pre-mutation-key-rule]).
2. **Lifecycle gate**: The principal's current lifecycle state MUST permit the
   operation (see `principal-lifecycle.md`).
3. **Capability gate**: The principal MUST have the state components required
   for the operation (e.g., DT must exist for data actions, RT for rule
   operations).
   `VERIFIED: agent-check — citation updated 2026-07-06, SPEC.md §2.3.2 (Antecedent Authorization Gate)`

**[pre-mutation-key-rule]**: Within a commit (intra-commit context), a key
activated by an earlier transaction in the same commit MUST be permitted to
authorize a later transaction in that commit. A key revoked (or deleted) by an
earlier transaction in the same commit MUST NOT authorize a later transaction
in that commit. Application order determines the key state each transaction is
checked against; this is not a single frozen commit-open snapshot (see
[intra-commit-ordering]).

Outside a commit (extra-commit context), authorization is evaluated only
against already-committed state: transactions inside an in-flight commit are
not visible to external authenticators.
`VERIFIED: agent-check — updated 2026-07-06; behavior confirmed empirically
against rs/cyphr/src/commit.rs CommitScope::verify_and_apply (dual snapshot
check) composed with Principal::apply_transaction_internal (live-state
re-check on the projected principal, which rejects a since-revoked signer
regardless of the frozen commit-open snapshot); citation SPEC.md §2.3.2`

#### Commit Chain

**[commit-append-only]**: Commits MUST be append-only. A commit, once published,
MUST NOT be removed from the chain. Implicit forks are prohibited by the
protocol.
`VERIFIED: agent-check`

**[commit-one-or-more]**: A commit MUST contain one or more transaction cozies.
Empty commits (zero transactions) are not valid.
`VERIFIED: agent-check`

This spec clause is silent on whether a commit consisting solely of its
own `commit/create` finalizer cozy (no mutation cozies at all) is
valid -- it forbids only the zero-cozy case, and SPEC.md defines no
stronger constraint either. Cyphr's implementation resolves this
silence by rejecting the finalizer-only case as empty of substance,
aligning with this clause's evident intent rather than treating it as
an intentional no-op (rs/cyphr/src/commit.rs
`PendingCommit::is_finalizer_only`, GitHub issue #74). This is an
implementation choice within what the spec permits, not a spec
violation; routed to Zami for consideration of whether
[commit-one-or-more] should be tightened to state this explicitly.
`VERIFIED: agent-check`

Commit membership (which cozies belong to which commit, and which
transaction each belongs to) is established entirely by wire-format position —
see [txs-list-of-lists] and [tx-grouping], next — not by a chained `pre`
reference.

#### Transaction Structure

**[txs-list-of-lists]**: The `txs` field MUST be a list of lists. Each inner
list is a transaction containing one or more related cozies. The commit
transaction MUST be the last entry in `txs`.
`VERIFIED: agent-check`

**[tx-grouping]**: Mutation cozies MUST be grouped by transaction. Interlacing
cozies related to different transactions is prohibited because cozies out of
order are interpreted as separate transactions.
`VERIFIED: agent-check`

**[tx-root-computation]**: Each transaction's identifier is computed as
`TX = MR(czd₀, czd₁?, ...)` of its related cozies' `czd` values.
`VERIFIED: agent-check`

#### Transaction Root Decomposition

**[tmr-computation]**: The Transaction Mutation Root (TMR) MUST be computed as
`TMR = MR(TX₀, TX₁?, ...)` of all mutation transaction identifiers.
`VERIFIED: agent-check`

**[tcr-computation]**: The Transaction Commit Root (TCR) MUST be computed as
`TCR = MR(czd₀, czd₁?, ...)` of the commit transaction's cozies' `czd` values.
Since there is exactly one commit transaction per commit, TCR is calculated
directly from its cozies.
`VERIFIED: agent-check`

**[tr-computation]**: The Transaction Root (TR) MUST be computed as
`TR = MR(TMR, TCR)`. TR serves as the commit ID.
`VERIFIED: agent-check`

#### Commit Finality

**[commit-finality-arrow]**: A commit is finalized by a commit transaction coz
(`typ: "cyphr.me/cyphr/commit/create"`) containing the `arrow` field. The
`arrow` field value MUST equal `MR(pre, fwd, TMR)`, where:

- `pre` is the prior PR (the state being mutated)
- `fwd` is the forward SR (state after mutation, before commit)
- `TMR` is the transaction mutation root

The commit transaction MUST be the last transaction in `txs`.
`VERIFIED: agent-check`

**[arrow-excludes-self]**: The `arrow` field covers everything except the commit
transaction itself. A commit cannot refer to itself (a signature cannot sign
itself). For this reason, `pre` refers to PR while `fwd` refers to SR (not PR).
`VERIFIED: agent-check`

**[pr-after-commit]**: After the commit transaction is finalized, PR is
calculable: `PR = MR(SR, CR)` where CR now includes the new TR. A "forward PR"
is not calculable at signing time since that would require the commit to refer
to itself.
`VERIFIED: agent-check`

#### `typ` Grammar

**[typ-grammar]**: The `typ` field MUST follow the grammar:
`<authority>/<noun>[/<noun>...]/<verb>`. The authority is the first path unit.
The verb is the last path unit. Everything between is the noun (which MAY be
compound, e.g., `user/image`).
`VERIFIED: agent-check`

**[typ-verbs]**: Standard verbs MUST be one of: `create`, `read`, `update`,
`upsert`, `delete`. Protocol-level special verbs (`revoke`, `replace`, `merge`,
`merge-ack`) are additionally permitted for their defined transaction types.
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
`tmb`. (SPEC.md §4.3)
`VERIFIED: agent-check — new 2026-03-09 per S-3`

#### Wire Format

**[wire-format-plurals]**: JSON wire format MUST use plural field names. The
singular forms `tx`, `key`, and `coz` are prohibited. Valid fields: `txs`,
`keys`, `cozies`. (SPEC.md JSON Wire Format)
`VERIFIED: agent-check — new 2026-03-09 per S-2`

**[key-sideband-optional]**: The public key material required to authenticate a transaction (e.g., verifying a `key/create` signature) MAY be transmitted via sideband data or extracted from a parent structure. The `coz` JSON structure itself does not strictly mandate embedding full public key material if it can be retrieved deterministically.
`VERIFIED: agent-check`

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

**[genesis-bootstrap]**: Genesis MUST use explicit `key/create` transactions to
establish the initial key set. The first key's `pre` references its own `tmb`
(the bootstrap identity). Additional keys reference the current PR (which
evolves as mutations accumulate). Genesis is finalized by a `principal/create`
declaration followed by a `commit/create` transaction.

- **PRE**: No principal exists for this key identity.
- **POST**: PG is established and immutable, and the commit chain begins.
  `VERIFIED: agent-check`

**[genesis-pre-bootstrap]**: At genesis, no prior PR exists. The bootstrap
identity is the first key's `tmb`, which serves as the initial `pre` for the
first `key/create`. Subsequent transactions within the genesis commit reference
the current PR as it evolves through mutations.

- **PRE**: First key's `tmb` is the bootstrap identity.
- **POST**: Each transaction targets the evolving PR, maintaining chain continuity.
  `VERIFIED: agent-check`

**[genesis-finality]**: Genesis MUST include a `principal/create` transaction
(with `id` == PG) declaring the principal, followed by a `commit/create`
transaction with `arrow` that finalizes the commit (per [commit-finality-arrow]).
The resulting PG is the first PR computed after this commit.

- **PRE**: All genesis mutations (key additions, etc.) are included.
- **POST**: PG = the first PR. Principal is created.
  `VERIFIED: agent-check`

#### Key Lifecycle

**[key-create]**: `key/create` (Level 3+) adds a new key to KT. The
transaction MUST include `id` = `tmb` of the new key and `pre` = targeted PR.
The signing key (`tmb`) MUST be active in KR at pre-mutation state.

- **PRE**: Key identified by `id` MUST NOT already exist in KT (per
  [create-uniqueness]).
- **POST**: New key is active in KT. KR is recomputed. AR evolves.
  `VERIFIED: agent-check`

**[key-delete]**: `key/delete` (Level 3+) removes a key from KT without
marking it as compromised. The transaction MUST include `id` = `tmb` of the
key being removed, and `pre` = targeted PR.

- **PRE**: Key identified by `id` MUST be active in KT.
- **POST**: Key is removed from KT. Past signatures from the key's active
  period(s) remain valid. Key MAY be re-added later via `key/create`.
  `VERIFIED: agent-check`

**[key-replace]**: `key/replace` (Level 2+) atomically removes the signing key
and adds a new key. The transaction MUST include `id` = `tmb` of the new key,
and `pre` = targeted PR. For Level 2, `pre` is the `tmb` of the previous key
(since SR == AR == KR == `tmb`).

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

**[naked-revoke-error]**: A "naked revoke" (a `key/revoke` action causing `HasActiveKeys` to drop to false) directly transitions the principal out of the `Active` state into the `Dead` state (Level 1/2) or `Errored`. This represents an error or termination condition where no further mutative transitions can occur.

> [!NOTE]
> **Terminology overlap with [revoke-naked]**: This constraint's "naked
> revoke" (HasActiveKeys → false) and [revoke-naked]'s "naked revoke"
> (an out-of-band revoke, historically distinguished by omitting `pre`)
> are two different concepts sharing one name. This constraint's
> definition does not depend on `pre` and is unaffected by its removal
> (see [revoke-naked]'s note). Whether these should be unified under
> distinct names, or are genuinely orthogonal properties that happen to
> share a word, is an open question for the spec author — not resolved
> here.

`VERIFIED: agent-check`

**[revoke-naked]**: SUPERSEDED discriminator — see resolution note below.
Historically: a revoke MAY omit `pre` (naked revoke). A naked revoke
does NOT mutate PR. Third parties MAY sign naked revokes to declare a key
compromised without knowledge of the principal's state. A naked revoke, or a
revoke with `pre` but without a subsequent `delete`, puts the principal in an
error state (see `consensus.md`).

> [!NOTE]
> **Open question (2026-07-08, unresolved)**: Per-mutation `pre` has been
> removed from every transaction-classified coz, including `key/revoke`
> (see [transaction-classification]) — so "omits `pre`" can no longer
> distinguish a naked (out-of-band, non-committed) revoke from an ordinary
> in-chain one, since NEITHER carries `pre` anymore. Whether the underlying
> concept this constraint protects — a revoke a witness can act on
> immediately, without it being part of any principal's commit chain —
> still holds meaning under some other discriminator (e.g. whether the coz
> arrived inside a commit's `txs` array vs. independently), or whether the
> concept should be retired, is an open design question for the spec
> author. It is NOT resolved by this pass — deliberately left open rather
> than inventing a replacement mechanism.

`VERIFIED: superseded — see open question above; the `pre`-based discriminator this constraint describes no longer applies`

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

- **PRE**: Signing key MUST be active in KR.
- **POST**: Action is recorded in DT (if DT exists). No AT change.
  `VERIFIED: agent-check — updated 2026-03-09 per B-5 (AR→AT)`

**[dr-inclusion]**: To include DR into PR, a `ds/create` transaction MUST be
signed, updating the DR component in the principal state tree. Without this
explicit inclusion transaction, DR is absent from PR (excluded, not zero).

- **PRE**: DT exists (Level 4+). Signing key MUST be active.
- **POST**: DR = MR(DT) is included as a component of SR (and thus PR).
  `VERIFIED: agent-check`

**[witness-register-create]**: `cyphr.me/cyphr/witness/register/create` is a
data action that registers an external witness (represented as a principal)
with the principal's clients. The transaction MUST NOT mutate PT or AT and MUST NOT
contain `pre` (per [data-action-stateless] and [data-action-no-pre]). The payload MUST
include `id` containing the witness principal's Principal Genesis (PG) value.

- **PRE**: Signing key MUST be active in KR.
- **POST**: Witness registration is recorded in DT (if DT exists). PR and AT remain unmodified.
  (SPEC.md §13.5.1)

**[witness-register-delete]**: `cyphr.me/cyphr/witness/register/delete` is a
data action that removes a previously registered external witness. The transaction
MUST NOT mutate PT or AT and MUST NOT contain `pre` (per [data-action-stateless] and
[data-action-no-pre]). The payload MUST include `id` identifying the witness
principal's PG to remove.

- **PRE**: Signing key MUST be active in KR. Witness MUST be currently registered.
- **POST**: Witness registration is removed from DT (if DT exists). PR and AT remain unmodified.
  (SPEC.md §13.5.1)


#### Nonce Transactions

**[nonce-path]**: Nonce `typ` MUST specify the insertion path in the state tree.
The path grammar is: `cyphr/<tree-path>/nonce/<verb>`. Examples:

- `cyphr/nonce/create` — Principal root level
- `cyphr/AT/nonce/create` — Auth Tree root
- `cyphr/AT/KT/nonce/create` — Key Tree root
  `VERIFIED: agent-check`

### Forbidden States

**[no-orphan-pre]**: The commit's `pre` (the arrow component identifying the
prior PR being mutated, per [commit-finality-arrow]) MUST reference the
actual known PR. A commit whose arrow does not resolve against the real
prior state MUST be rejected.

> [!NOTE]
> **Wording note (2026-07-08)**: This constraint predates per-mutation `pre`
> removal and originally described a client-supplied `pre` field on every
> mutation cozy. No such field exists anywhere in the wire format now (see
> [transaction-classification]) — the only surviving `pre` is the one
> conceptual input to the commit transaction's `arrow` computation, which
> is derived, not client-declared. The underlying safety property (reject a
> commit that doesn't chain from the real prior state) is unchanged and is
> now the sole job of arrow verification (`Error::CommitMismatch` in
> `rs/cyphr/src/principal.rs`'s `finalize_commit`).

`VERIFIED: rs/cyphr/tests/properties.rs — arrow/CommitMismatch property tests`

**[no-unauthorized-transaction]**: A transaction signed by a key not active in
KR at the pre-mutation state MUST be rejected. There MUST NOT be a state where
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
> **Commit Finality (resolved)**: The commit finality mechanism uses the `arrow`
> field in `commit/create` (see [commit-finality-arrow]). The old `"commit":<CS>`
> model is superseded.

**[intra-commit-ordering]**: Transactions within a commit MUST be applied in
**array order** (the order they appear in the `txs` array). This ordering is
also used for TR computation (per [tr-computation]). Application
order determines the final state when operations on the same target are present.
`VERIFIED: agent-check — new 2026-03-09 per array-order decision`

### Behavioral Properties

**[commit-deterministic]**: Given identical transaction cozies in a commit, the
resulting PR MUST be identical regardless of implementation. This follows from
deterministic state computation (per `state-tree.md` [deterministic-state])
applied to transaction outputs.

- **Type**: Safety
  `VERIFIED: agent-check`

**[genesis-irreversible]**: Once a principal reaches genesis (PG is established),
the PG MUST NOT change. Genesis is a one-way transition from "no principal" to
"principal with permanent PG."

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
| [transaction-classification]  | agent-check | pass   | SPEC.md §4.1 (no `pre` in example); `rs/cyphr-storage/src/import.rs::is_transaction_typ` |
| [data-action-no-pre]          | agent-check | pass   | SPEC.md §4.4 (updated 2026-03-09)                   |
| [authorization-triple]        | agent-check | pass   | SPEC.md §2.3.2 (Antecedent Authorization Gate)      |
| [pre-mutation-key-rule]       | agent-check | pass   | SPEC.md §2.3.2; verified against `rs/cyphr/src/commit.rs` (see Authorization section) |
| [commit-append-only]          | agent-check | pass   | Explicit in SPEC.md §2.3.2                          |
| [commit-one-or-more]          | agent-check | pass   | Inferred from §4 ("one or more transaction cozies") |
| [txs-list-of-lists]           | agent-check | pass   | SPEC.md §4.1 (list of lists structure)              |
| [tx-grouping]                 | agent-check | pass   | SPEC.md §4 (no interlacing)                         |
| [tx-root-computation]         | agent-check | pass   | SPEC.md §9 (MR of czds)                             |
| [tmr-computation]             | agent-check | pass   | SPEC.md §4.2 (MR of mutation TXs)                   |
| [tcr-computation]             | agent-check | pass   | SPEC.md §4.2 (MR of commit tx czds)                 |
| [tr-computation]              | agent-check | pass   | SPEC.md §4.2 (MR(TMR, TCR))                         |
| [commit-finality-arrow]       | agent-check | pass   | SPEC.md §4.2 (arrow field)                          |
| [arrow-excludes-self]         | agent-check | pass   | SPEC.md §4.2 (fwd is SR, not PR)                    |
| [pr-after-commit]             | agent-check | pass   | SPEC.md §4.2 (PR = MR(SR, CR))                      |
| [typ-grammar]                 | agent-check | pass   | Explicit in SPEC.md §7                              |
| [typ-verbs]                   | agent-check | pass   | Explicit in SPEC.md §7, §7.2                        |
| [idempotent-transactions]     | agent-check | pass   | Explicit in SPEC.md §7.5                            |
| [create-uniqueness]           | agent-check | pass   | Explicit in SPEC.md §7.5                            |
| [transaction-id-required]     | agent-check | pass   | SPEC.md §4.3 (updated 2026-03-10)                   |
| [timestamp-range]             | agent-check | pass   | Explicit in SPEC.md §6.4 (inherited from Coz)       |
| [at-append-only]              | agent-check | pass   | Explicit in SPEC.md §2.3.4 table                    |
| [dt-mutable]                  | agent-check | pass   | Explicit in SPEC.md §2.3.4 table                    |
| [genesis-bootstrap]           | agent-check | pass   | Explicit in SPEC.md §5.1                            |
| [genesis-pre-bootstrap]       | agent-check | pass   | Explicit in SPEC.md §5.1                            |
| [genesis-finality]            | agent-check | pass   | SPEC.md §5.1 (id=PG)                                |
| [key-create]                  | agent-check | pass   | Explicit in SPEC.md §6.1                            |
| [key-delete]                  | agent-check | pass   | Explicit in SPEC.md §6.2                            |
| [key-replace]                 | agent-check | pass   | Explicit in SPEC.md §6.3                            |
| [key-revoke]                  | agent-check | pass   | Explicit in SPEC.md §6.4                            |
| [revoke-naked]                | agent-check | pass   | Explicit in SPEC.md §6.4                            |
| [revoke-self-signed]          | agent-check | pass   | Explicit in SPEC.md §6.4                            |
| [key-active-period]           | agent-check | pass   | Explicit in SPEC.md §6.2                            |
| [data-action-stateless]       | agent-check | pass   | SPEC.md §4.4 (AR→AT, updated 2026-03-09)            |
| [dr-inclusion]                | agent-check | pass   | Explicit in SPEC.md §4.5.1                          |
| [witness-register-create]     | agent-check | pass   | Explicit in SPEC.md §13.5.1                         |
| [witness-register-delete]     | agent-check | pass   | Explicit in SPEC.md §13.5.1                         |
| [nonce-path]                  | agent-check | pass   | Explicit in SPEC.md §4.7                            |
| [no-orphan-pre]               | agent-check | pass   | Inferred from §4 chain semantics                    |
| [no-unauthorized-transaction] | agent-check | pass   | Follows from §3                                     |
| [no-self-revoke-recovery]     | agent-check | pass   | Explicit in SPEC.md §3.1                            |
| [no-revoke-non-self]          | agent-check | pass   | Explicit in SPEC.md §6.4                            |
| [commit-deterministic]        | agent-check | pass   | Follows from state-tree.md [deterministic-state]    |
| [genesis-irreversible]        | agent-check | pass   | Follows from state-tree.md [pg-immutable]           |
| [revoke-propagation]          | agent-check | pass   | Inferred from §6.4 revoke semantics                 |
| [wire-format-plurals]         | agent-check | pass   | SPEC.md JSON Wire Format (new 2026-03-09)           |
| [intra-commit-ordering]       | agent-check | pass   | Array-order decision (new 2026-03-09)               |

## Implications

### For Implementation (`/core`)

- **Sequential intra-commit authorization**: The [pre-mutation-key-rule] is the
  most critical implementation detail — authorization for each transaction in
  a commit is evaluated against the key state as of immediately before that
  transaction, not a single snapshot frozen at commit-open. Implementations
  must re-check active/revoked status against the live, incrementally-mutated
  state as they process each transaction in a commit, in `txs` array order.
- **Revoke without `pre`**: Naked revokes are valid Coz messages that don't
  mutate PR but must be stored and propagated. Implementations must handle
  revokes arriving out-of-band (not in the commit chain).
- **Key re-addition**: [key-delete] explicitly permits re-adding a deleted key
  via `key/create`. Implementations must not treat "previously deleted" as a
  permanent state.
- **Idempotency**: [idempotent-transactions] means implementations must detect
  and silently ignore duplicate transaction cozies.

### For Testing

- **Genesis sequence tests**: Verify the bootstrap model — single key genesis,
  multi-key genesis, and the `pre` continuity invariant.
- **Authorization boundary tests**: Add a key early in commit N, verify a
  later transaction in commit N signed by that new key IS authorized
  (intra-commit, sequential). Revoke a key early in commit N, verify a later
  transaction in commit N signed by that now-revoked key is REJECTED.
- **Revoke edge cases**: Naked revoke, revoke-with-pre, revoke-then-delete,
  revoke-of-already-deleted key.
- **Idempotency tests**: Replay a valid transaction and verify no state change.
- **`typ` grammar validation**: Malformed `typ` strings, missing verbs, empty
  nouns.
