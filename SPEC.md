# Cyphrpass Protocol Specification

**Version**: Draft v0.1  
**Status**: Work in Progress  
**Built on**: [Coz v1.0](https://github.com/Cyphrme/Coz)

---

## 1. Introduction

Cyphrpass is a self-sovereign, decentralized identity and authentication
protocol built on cryptographic Merkle trees. It enables:

- Password-free and email-free authentication via public key cryptography
- Multi-device key management with revocation.
- Authenticated Atomic Actions (AAA) — individually signed, independently
  verifiable user actions.
- Cryptographic primitive agnosticism via the Coz JSON specification.

Cyphrpass provides the authentication layer for the Internet. 


| Feature             |  Traditional SSO/Passwords    |         Cyphrpass                                      |
| ---                 |     ---                       |                                                    --- |
| **Identity Factor** | Email, Password, or Provider  | Cryptographic Public Keys                              |
| **Verification**    | Centralized Database          | Independent (Merkle Tree & Coz Spec)                   |
| **State Tracking**  | Service-only (Centralized)    | Bidirectional (Mutual State Sync)                      |
| **Action Auth**     | Bearer Tokens (Session-based) | Authenticated Atomic Actions (AAA)                     |
| **Trust Model**     | Trusted Service               | Explicit Cryptographic Verification (Self-Sovereign)   |
| **User Recovery**   | Admin-reset or Email          | Cryptographic Key Revocation/Rotation, Social Recovery |

---

## 2. Terminology

### 2.1 Core Concepts

Binary encoded values in this document are in `b64ut`: "Base64 URI canonical
truncated" (URL alphabet, errors on non-canonical encodings, no padding).

| Term                  | Abbrev | Definition                                             |
| --------------------- | ------ | ------------------------------------------------------ |
| **Principal**         | —      | An identity in Cyphrpass. Replaces "account".          |
| **Principal Root**    | PR     | The initial, permanent digest identifying a principal. |
| **Principal State**   | PS     | Specific top-level digest: `MR(AS, DS)` or promoted.   |
| **Tip**               | Tip    | The latest PS using a digest identifier.               |
| **Auth State**        | AS     | Authentication state: `MR(KS, TS, RS)` or promoted.    |
| **Data State**        | DS     | State of user data/actions (Level 4+).                 |
| **Key State**         | KS     | Digest of active key thumbprints (`tmb`s).             |
| **Transaction State** | TS     | Digest of transaction `czd`s (key mutations).          |
| **Rule State**        | RS     | State of rules (Level 5: weighted keys, timelocks).    |
| **Action**            | Act    | A signed coz. Denoted by `typ`. Foundation of AAA.     |
| **trust anchor**      |        | Last known trusted state for a principal               |

"Action" is the hypernym of authentication transaction (transaction in this
document) and data action, which mutate data state.

Cyphrpass has siz operational levels.  See section "Levels" for more.

| Level | Description       | State Components             |
| ----- | ----------------- | ---------------------------- |
| **1** | Single static key | KS = AS = PS = PR            |
| **2** | Key replacement   | KS (single key, replaceable) |
| **3** | Multi-key/Commit  | KS (n keys) + TS             |
| **4** | Arbitrary data    | AS + TS + DS → PS            |
| **5** | Rules             | AS (with RS) + DS            |
| **6** | Programmable      | VM execution                 |


### State Tree
The **state tree** is a hierarchical structure of cryptographic Merkle roots
that represents the complete state of a Principal (identity).

```text
Principal State (PS)
│
├── Auth State (AS) ──────────── [Security & Identity]
│   │
│   ├── Key State (KS) ───────── [Public Keys]
│   │
│   ├── Transaction State (TS) ─ [State Mutations]
│   │
│   ├── Rule State (RS) ──────── [Permissions & Thresholds]
│   │
│   └── Nonce ────────────────── [Optional Nonce]
│
└── Data State (DS) ──────────── [User Data Actions]
```


The **Auth State (AS) chain** is the core of Cyphrpass. Each auth transaction
forms a node referencing the prior AS.


```text

        PR/PS (Genesis)            PS (State 2)                PS (State 3)
   +-------------------+      +-------------------+      +-------------------+
   |                   |      |                   |      |                   |
   |   [AS]     [DS]   | ===> |    [AS]    [DS]   | ===> |    [AS]    [DS]   | ===> (Future)
   |    ^              |      |    |  ^           |      |    |  ^           |
   +----|--------------+      +----V--|-----------+      +----V--|-----------+ 
        |                          |  |                       |  |
        + <--------(pre)-----------+  +---------(pre)---------+  +---(pre)-------------
```


### 2.2 Implicit Promotion

When a component of the state tree contains only **one node**, that node's
value is **promoted** to the parent level without additional hashing.

**Examples:**

- Single key: `tmb` is promoted to KS, then AS, then PS, which equals PR on genesis.
- No DS present: AS is promoted to PS
- Only KS present (no TS/RS): KS is promoted to AS

This rule simplifies single-key principals by eliminating the need for explicit
genesis transactions. Promotion is recursive; items deep in the tree can be
promoted to the root level.  Implicit promotion applies to all entropic values:
digests and sufficient strength nonces. 

### 2.4 Authenticated Atomic Action (AAA)

Authenticated Atomic Actions are when a principal performs individually
verifiable operations using Cyphrpass which supersedes trust traditionally
delegated to centralized session state or bearer tokens.

An AAA is simply a signed coz whose `typ` corresponds to a meaningful
application-level action (comment, post, vote, save, like, etc.) and whose
signature is produced by one or more keys currently authorized in the
principal's Key State (KS).

Instead of authenticating to a centralized login service which provides a bearer
token for user action, users may sign individual actions directly. Each atomic
action may be trustlessly authenticated by anyone, irrespective of centralized
services. For example, instead of logging in to make a comment, a user signs a
comment directly which is then verifiable by anyone. In this model, centralized
services that maintain user identity are irrelevant and should be actively
deprecated.

Historically, nearly all services depended upon bearer tokens where trusting
centralized services is required. Third parties, such as users, have no way to
verify actions without trusting the integrity of the centralized service despite
countless examples of that trust being abused. AAA defends the user against
such abuse.

### 2.5 Nonces

One or more cryptographic nonces may be included at any level of the state tree:

- **Encapsulation**: Hides structure when desired
- **Reuse**: Allows one identity to be used by many accounts
- **Privacy**: Prevents correlation across services
- **Obfuscation**: Nonces are indistinguishable from key thumbprints and
  other digest values, so observers cannot determine the true count

Design Notes:

- Nonces may be implicitly promoted in the Merkle tree just like any other
  digest or entropic value.
- Multiple nonces are permitted.
- At signing, the key structure may be revealed.
- Nonces, like all other node values, are associated with a hashing algorithm.

The general principle of obfuscated structures becoming transparent is
**reveal**. Keys are revealed at signing; nonces and other data structures may
also need to be revealed during transactions, actions, or signing operations.

**Interaction with implicit promotion**: Because nonces are cryptographically
indistinguishable from key thumbprints (both are digests of the same size), they
follow the same promotion rules. A principal with 1 key + 1 nonce has
`KS = MR(sort(tmb, nonce))`, not implicit promotion. The presence of any
additional component—whether key or nonce—blocks promotion.


#### Identifier
All identifiers are Merkel roots (PS, KS, TS, AS, RS, DS).  If order is not
otherwise given, lexical order is used. 

All identifiers are digest values or cryptographically random in the case of a
nonce. These values are opaque bytes, meaning a sequence of bytes that should be
treated as a whole unit, without any attempt by the consuming software to
interpret their internal structure or meaning.

Cyphrpass identifiers are CID's, content identifiers.

#### Digest
Good practice for digest identifiers is prepending with Coz algorithm
identifier, e.g. `SHA256:<B64-value>`.  Without an algorithm identifier, the
system is as strong as the weakest supported hashing algorithm. 


#### Commit
A commit is bundle of finalized transactions that results in a new TS and thus a
new PS.  Commits are chained together using references to prior commits through
`pre`.  The last coz message in the transaction bundle finalizes the commit by
the inclusion of `"commit":true`.

### Embedded Principal and Embedded Nodes.
Cyphrpass is a recursive tree structure.  An **embedded principal** is a full
Cyphrpass identity embedded into another principal and an opaque node, which may
be a AS, KS, nonce, or other node value, is an **embedded node**.  See section
on embedding. 

### Witnesses and Oracle
A **witness** is a client that keeps a copy of a principal's state. Clients may
transmit their state through a gossip protocol. 

An **oracle** is a witness with some degree of trust delegated to that client.
For example, if a client does not want to verify all transaction in a jump, that
client may delegate some processing to an oracle, where it is trusted that the
transactions in the jump were appropriately processed. 


### 2.3 Unrecoverable Principal

A principal with no active keys and no viable recovery path within the protocol.
Authentication, mutations, and recovery transactions are impossible without
out-of-band intervention. See Section Recovery.


---

## 3. Feature Levels

| Level | Description       | State Components             |
| ----- | ----------------- | ---------------------------- |
| **1** | Single static key | KS = AS = PS = PR            |
| **2** | Key replacement   | KS (single key, replaceable) |
| **3** | Multi-key/Commit  | KS (n keys) + TS             |
| **4** | Arbitrary data    | AS + TS + DS → PS            |
| **5** | Rules             | AS (with RS) + DS            |
| **6** | Programmable      | VM execution                 |

### 3.1 Level 1: Static Key

- Single key, never changes
- `PR = PS = AS = KS = tmb`
- No transactions, no TS
- Use case: IoT devices, hardware tokens
- **Self-revoke**: A Level 1 key can self-revoke, but this results in permanent lockout (no recovery without sideband intervention)

### 3.2 Level 2: Key Replacement

- Single active key at any time
- `key/replace` transaction swaps current key for new key
- TS is implicit at Level 2 (not stored in protocol)
- Use case: Devices that can rotate keys but only store one

### 3.3 Level 3: Multi-Key (Commit)

- Multiple concurrent keys with equal authority
- Any key can `key/create`, `key/delete`, or `key/revoke` any other key
- Standard for multi-device users
- Recommended minimum for services

### 3.4 Level 4: Arbitrary Data

- Introduces Data State (DS) for user actions
- Actions (comments, posts, etc.) recorded in DS
- `PS = MR(AS, DS)`
- Enables Authenticated Atomic Actions (AAA)

### 3.5 Level 5: Rules (Weighted Permissions)

- Introduces Rule State (RS) for access control
- Each key has a weight (default: 1)
- Transactions and actions have threshold requirements
- Enables: M-of-N signing, tiered permissions, timelocks
- RS is a digest component of AS (like KS and TS)
- Like all Cyphrpass values, it is sorted by digest value (bytes), not by label.

**Key concepts:**

- **Weight**: Numeric value assigned to each key
- **Threshold**: Minimum total weight required for an action
- **Timelock**: Delay before certain actions take effect

### 3.6 Level 6: Programmable VM

- Introduces programmable rule execution
- Rules are executable bytecode stored in RS
- Enables: Complex conditional logic, programmable policies
- VM execution produces a deterministic state transition
- Use case: Smart contracts, complex organizational policies

## 4. Data Structures

### 4.1 Key

Example private Coz key with standard fields:

```json5
{
  tag: "User Key 0", // optional human label, non-programatic.
  tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Key's thumbprint
  alg: "ES256", // Key algorithm.
  now: 1623132000, // creation timestamp
  pub: "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g", // Public component
  prv: "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA", // Private component, never transmitted
}
```

`tmb` is the digest of the canonical public key representation using the hash
algorithm associated with `alg`.

Example public key:

```json
{
  "tag": "User Key 0",
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
  "alg": "ES256",
  "now": 1623132000,
  "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"
}
```

### 4.2 Commit
A **commit** is an atomic unit, denoted by principal state (PS), at a particular
point.  The principal fully controls the grouping, ordering, and intent of the
commit.

A commit consists of an ordered collection of one or more transactions bundled
together by the principal in a single submission, rule state, auth state, nonce,
and recursively other principal states.

A commit also allows atomicity by services.  Many mutations may occur per commit,
as dictated by the principal.

For Cyphrpass, unlike other systems, there are no minting fees or gas, and no
need for a global ledger.


## 5. Genesis (Account Creation)

### 5.1 Initial Transactions

A principal is created (genesis) in one of two ways:

**Implicit Genesis (Single Key)**

- Principal exists the moment the key exists. No transaction required.
- `pr` == `tmb` of the single key (via implicit promotion).
- Multikey is not supported.

```
PR == PS == AS == KS == `tmb`
```

**Explicit Genesis (Single-Key)**

- Requires a signed genesis transaction (for transaction, see section "Transaction".)
- Key signs a `key/create` transaction to add itself as the principal. In this
  special case, `id` == `tmb`
- `pre = MR(tmb₀, nonce?)`
- For genesis, `pre` is the value of the first key bundle, which in the case of
  a single key is just the value of that one key. (For level 3+)

**`typ`**: `<authority>/key/create`

- `id`: `<genesis key tmb>` 
- `pre`: `<previous>`
- `key`: `<key public material>`

```json5
{
  pay: {
    alg: "ES256",
    now: 1628181264,
    tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // genesis key tmb
    typ: "cyphr.me/cyphrpass/key/create",
    id: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // genesis key tmb
    pre: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // "pre" is the `tmb`, promoted to AS, then PR, since there is no nonce or other value.  
    commit:true
  },
  sig: "<b64ut>", // TODO valid sig
  key: {
    // key public material
    alg: "ES256",
    now: 1623132000,
    pub: "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
    tag: "User Key 0",
    tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
  },
}
```

**Explicit Genesis (Multi-Key)**

- Key signs a `key/create` transaction
- `pre = MR(tmb₀, tmb₁, ..., nonce?)`
- Without rules, each key has equal weight, so any initial key can sign.
- Keys are added to the PR, calculated beforehand.

**`typ`: `<authority>/key/create`**

- `id`: `<genesis key tmb>`
- `pre`: `<previous>`
- `keys`: `<key public material>`

```json5
{
  cozies: [
    {
      pay: {
        alg: "ES256",
        now: 1628181264,
        tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        typ: "cyphr.me/cyphrpass/key/create",
        id: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        pre: "<key bundle>", // TODO insert actual value for this transaction.
      },
      sig: "<b64ut>", // TODO actual sig
    },
    {
      pay: {
        alg: "ES256",
        now: 1628181264,
        tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        typ: "cyphr.me/cyphrpass/key/create",
        id: "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
        pre: "<key bundle>", // TODO insert actual value for this transaction.
        commit:true
      },
      sig: "<b64ut>", // TODO actual sig
    },
  ],
  keys: [
    // Public key material
    {
      tag: "User Key 0",
      alg: "ES256",
      now: 1623132000,
      pub: "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
      tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    },
    {
      tag: "User Key 1",
      alg: "ES256",
      now: 1768092490,
      pub: "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
      tmb: "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
    },
  ],
}
```

### Transaction
Transactions mutate the AS and form a chain via the `pre` field:

`typ` may be `<authority>/key/create` or similar key mutation type.

```json5
{
  pay: {
    alg: "ES256",
    now: 1628181264,
    tmb: "<signing key tmb>", // Existing key
    typ: "<authority>/key/create",
    pre: "<previous AS>",
    id: "<new keys tmb>",
    commit:true

  },
  key: {
    /* new key */
  },
  sig: "<b64ut>",
}
```

The `pre` field links to the previous AS, enabling chain traversal without
full history.

When verifying the transaction, Cyphrpass clients must be sure that the
transaction is valid based on key state, rule state, and prior transaction. See
section "Resolve" for more detail.


### 4.2.1 Transactions and Transaction Bundles

Transactions are signed Coz messages that mutate Auth State (AS).  A transaction
may be one coz, or multiple cozies, that results in a mutation.  The transaction
identifier is the Merkle root of the transactions (unless there's only one and
implicit promotion then applies.)

Many transactions may be included per commit.  All transactions for a commit are
grouped into a **transaction bundle**.  The transaction state is the identifier
for transaction bundle, representing all transaction for a commit. For example, a
transaction bundle may have one transaction for `key/update`, signed by two keys
and containing two cozies, and one for `key/create`, signed by one key and
consisting of one coz. 

#### Transaction Order
Transactions are processed linearly in order as given by the client through
`pre`. The first transaction refers to `ps`, the state of the principal at the
previous commit.  Subsequent transactions refer to the previous transaction in
`pre`, and the last transaction must include the value `commit:true` in
`pay`.

Transaction order allows action repetition. or example, two key updates on a
single key are permitted, and the transactions must be processed in order.
Transaction bundles allows atomicity where multiple mutations may be performed
in sequence to produce a desired result.

The Merkle Root of all transactions for a commit is the Transaction State, which
is then used to compute AS (along with KS, RS, nonce, and potentially PS
recursively)

Instead of each commit containing all transactions associated with the principal,
each commit refers to the prior `pre` and includes only transactions required to
generate the last commit. For the full list of transactions, all transactions
from all commit need to be parsed. 

### Transaction Identifier and Ordering
All coz messages in a single transaction are Merkle rooted together to create
the identifier for the transaction.  (On a single transaction, the czd is
implicitly promoted and becomes the identifier.) If a transaction requires
multiple cozies, all cozies refer to the same `pre` 

The first transaction refers to the previous commit via `pre`.  Subsequent
transactions refer to the identifier of the previous transaction in `pre`,
giving order to the transactions.

### Commit Finality
Commits must be explicitly finalized, where the last transaction includes a
`"commit":true` in `pay`.

Commits that are not yet finalized are in a **transitory state** and are termed
are **transitory commits**, where it should be assumed that the finalized state
is still being processes. Since messages may be coming from many different
clients, geographically separated, third party clients, witnesses, may have
timeouts on transitory states, dropping previously received transactions and
requiring a full replay before accepting mutations. 

Any transaction that refers to a transitory commit that is not finalized must be
rejected. 


Example Finalize:
```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    typ: "cyphr.me/cyphrpass/key/create",
    "pre": "<on gensis, MR of keys, PS of last commit, or czd of last tx in bundle>",
    "commit":true
  },
  "sig": "<b64ut>"
}
```

### Transaction Nonce
As explained in detail above, Cyphrpass uses nonces at every level.  A new PS
may be generated through TS by signing a transaction nonce.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "nonce",
    "nonce": "T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8",
    "commit":true
  },
  "sig": "" // TODO
}
```



#### 4.2.1 `key/create` — Add a Key (Level 3+)

Adds a new key to KS.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Signing `tmb`
    "typ": "cyphr.me/cyphrpass/key/create",
    "pre": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Previous AS
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M", // New key
    "commit":true
  },
  "key": {
    "alg": "ES256",
    "now": 1623132000,
    "tag": "User Key 1",
    "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
    "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
  },
  "sig": "<b64ut>", // TODO actual sig
}
```

**Required fields:**

- `tmb`: Thumbprint of the signing key (must be in current KS)
- `pre`: Previous Auth State (AS) digest
- `id`: `tmb` of the key being added
- `key`: Public key material (separate from `pay` for clarity)

#### 4.2.2 `key/delete` — Remove a Key (Level 3+)

Removes a key from KS without marking it as compromised. Unlike `key/revoke`,
`key/delete` does not invalidate the key itself, it only removes it from KS,
which is useful for graceful key retirement (e.g., decommissioning a device)
when the key was never compromised.

If a key is deleted, any action signed with that key _after_ it has been removed
from the principal is ignored. Only actions that were signed while the key was
still active in the Key State (KS) are respected. Past signatures from previous
active periods remain valid even after the key is no longer active, provided
they were created while the key was in KS.

There is no effective cryptographic difference between a key that was deleted
and one that was never added except that a deleted key may have a duration of
legitimate past signatures that remain valid, whereas a never-added key never
had any legitimate signatures for this principal.

Deleted keys can be re-added later (via `key/create`), and, if desired, deleted
again afterward. Implementations should store the public key of deleted keys
that signed at least one action so that the client can cryptographically verify
its own chain.

**Key Active Period**: The time span during which a key is present and active in
the Key State (KS), and therefore authorized to sign new actions, for the
principal. A key may have multiple successive active periods if it is deleted
and later re-added (each re-addition starts a new active period).

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/key/delete",
    "pre": "<previous AS>",
    "id": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "commit":true
  },
  "sig": "<b64ut>"
}
```

**Required fields:**

- `id`: `tmb` of the key being removed

#### 4.2.3 `key/replace` — Atomic Key Swap (Level 2+)
Removes the signing key and adds a new key atomically. Maintains single-key
invariant for Level 2 devices.

For level 2, `pre` is optional. For level 3+, `pre` is required.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // The existing key.
    "typ": "cyphr.me/cyphrpass/key/replace",
    "pre": "<previous AS>", // In the case of level 2, AS is the previous `tmb`
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M" // The second key's `tmb`
  },
  "key": {
    "alg": "ES256",
    "pub": "<new key pub>",
    "tmb": "<new key tmb>"
  },
  "sig": "<b64ut>"
}
```

**Semantics:** The signing key (`tmb`) is removed; the new key (`id`) is added.

#### 4.2.4 `key/revoke` — Revoke a Key (Self-Revoke, Level 1+)

Self-revoke is a special case of `key/revoke` where the signing key is the same
as the key being revoked. It is used to revoke a key that has been compromised.
Self-revoke is built into the Coz standard. Note that `pre` is not required, a
revoke is a special case mutating the user's AS without reference to prior
states.

`pre` is not required.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/key/revoke",
    "rvk": 1628181264
  },
  "sig": "<b64ut>"
}
```

**Required fields:**

- `rvk`: Revocation timestamp (Coz standard field)

**Semantics:**

- Signatures by the revoked key with `now >= rvk` are invalid
- Setting `rvk = now` removes a key without invalidating past signatures

#### 4.2.5 `key/other-revoke` — Revoke Another Key (Level 3+)

Revokes a different key from the signing key. Used in multi-key accounts.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/key/revoke",
    "pre": "<previous AS>",
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
    "rvk": 1628181264
  },
  "sig": "<b64ut>" // TODO
}
```

**Required fields:**

- `pre`: Previous Auth State digest
- `id`: `tmb` of the key being revoked (must differ from `tmb`)
- `rvk`: Revocation timestamp

**Transaction Type Summary:**

| Type                | Level | Adds Key | Removes Key | Notes                   |
| ------------------- | ----- | -------- | ----------- | ----------------------- |
| `key/revoke` (self) | 1+    | —        | ✓ (signer)  | Self-revoke, sets `rvk` |
| `key/replace`       | 2+    | ✓        | ✓ (signer)  | Atomic swap             |
| `key/create`        | 3+    | ✓        | —           | —                       |
| `key/delete`        | 3+    | —        | ✓           | No revocation timestamp |
| `key/revoke-other`  | 3+    | —        | ✓           | Revoke another key      |

### 4.3 Data Action

A data action is a signed Coz message representing a user action, recorded in DS:

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/comment/create",
    "msg": "Hello, world!"
  },
  "sig": "<b64ut>" // TODO
}
```

Data actions are ordered by `now` in the Merkle tree.





















### 9.2 Data Actions (Level 4)

Data Actions are **stateless** signed messages. They are simply signed by an
authorized key without chain structure:

- No `prior` field required
- DS is computed from action `czd`s, but actions themselves don't track order
- Ordering (if needed) is determined by `now` timestamps

This keeps actions lightweight for common use cases (comments, posts, etc.).

### 9.3 State Resolution

To resolve from a **target AS** to a **prior known AS**:

1. Obtain current AS (from principal or trusted service)
2. Request transaction chain from target back to prior known (`pre`)
3. Verify `pre` references form unbroken chain
4. Validate each signature against KS at that point

Trust is optional — full independent verification is always possible.

#### 9.3.1 Checkpoints

Each state digest (AS, PS) encapsulates the full state at that point. Verifiers
only need the current state plus the transaction chain back to a known-good
checkpoint. The genesis state is the foundational checkpoint; services may cache
intermediate checkpoints to reduce chain length for verification.




#### 9.4 Declarative Transaction

Detailed in this document so far is iterative state mutation.  Declarative structure:

```json5
{
  "Principal_Tag":"Example Account",
  "PR":   "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",   // PR (permanent genesis digest)
  "PS":   "dYkP9mL2vNx8rQjW7tYfK3cB5nJHs6vPqRtL8xZmA2k=",

  // Digest Meta
  "PRE":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Previous Commit
  "ASD":"", // Auth State Digest
  "KSD":"", // Key State Digest
  "TSD":"", // Transaction State Digest (the last transaction resulting in the current commit.)
  "RSD":"", // Rule State Digest
  "DSD":"", // Data State Digest

// The actual Principal Tree, at the point of this commit
"PT":{
  "AT":{   // Auth State
    "KT": {
      "keys": [{
        "tag": "User Key 0",
        "alg": "ES256",
        "now": 1623132000,
        "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
        "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
        },{
        "tag": "User Key 1",
        "alg": "ES256",
        "now": 1623132000,
        "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
        "prv": "dRlV0LjnJOVfK_hNl_6rjVKutZWTHNL-Vs4_dVZ0bls",
        "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
        }
      ],
    },
    "TT":{ // Transaction Tree
      "TXS":[{
      "pay": {
      "alg": "ES256",
      "now": 1623132000,
      "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
      "typ": "cyphr.me/cyphrpass/key/create",
      "pre": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
      "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
      "commit":true
      },
      "key": {
      "alg": "ES256",
      "now": 1623132000,
      "tag": "User Key 1",
      "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
      "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
      },
      "sig": "<b64ut>", // TODO actual sig
    }],
    },
    "RT":{}, // Rule Tree
    "DT":{}, // Data Tree
  },

  // Other account Meta
  "recoveryConfigured": false,
  "hasDataActions": false,
  "hasRules": false

"past_TXS":[
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // genesis key tmb
    typ: "cyphr.me/cyphrpass/key/create",
    id: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // genesis key tmb
    pre: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // "pre" is the `tmb`, promoted to AS, then PR, since there is no nonce or other value.  
    commit:true
  },
  sig: "<b64ut>", // TODO valid sig
]

"revoked":[]


}
```













### 9.4 Level 5 Preview: Weighted Permissions

At Level 5, the Rule State (RS) introduces **weighted keys**:

- Each key has a weight/score.
- Actions require meeting a threshold weight
- Enables tiered permissions (e.g., admin keys vs. limited keys)

Without being defined, each key weight, action threshold, and transaction
threshold is implicitly 1.

For example, for 2 out of three for a `cyphrpass/key/create`, two cozies need to
be signed by independent keys of weight 1 for the transaction to be valid.

First, define the rule:

```json5
{
  "cyphrpass/key/create": 2,
  "cyphrpass/key/upsert": 2,
}
```

Then to add a new key, the following two key cozies must be signed for a valid
total transaction:

```json5
{
  cozies: [
    {
      pay: {
        alg: "ES256",
        now: 1628181264,
        tmb: "<signing key tmb>", // First Existing key
        typ: "<authority>/cyphrpass/key/create",
        pre: "<previous AS>",
        id: "<new keys tmb>",
      },
      sig: "<b64ut>",
    },
    {
      pay: {
        alg: "ES256",
        now: 1628181264,
        tmb: "<signing key tmb>", // Second Existing key
        typ: "<authority>/cyphrpass/key/create",
        pre: "<previous AS>",
        id: "<new keys tmb>",
      },
      sig: "<b64ut>",
    },
  ],
  key: {
    /* new key */
  },
}
```
































---

## 6. Authentication

Cyphrpass replaces password-based authentication with cryptographic Proof of
Possession (PoP).

Cyphrpass recommends AAA (Authenticated Atomic Action) over bearer tokens when
possible, but bearer tokens remain useful for access control and for upgrading
legacy password systems to Cyphrpass.

### 6.1 Proof of Possession (PoP)

Every valid signature by an authorized key constitutes a Proof of Possession:

- **Genesis PoP**: First signature by a key proves possession.
- **Transaction PoP**: Signing a key mutation proves authorization.
- **Action PoP**: Signing an action proves the principal performed it.
- **Login PoP**: Signing a challenge proves identity to a service.

### 6.2 Login Flow

To authenticate to a service:

**Option A: Challenge-Response**

1. Service generates a 256-bit cryptographic challenge (nonce)
2. Principal signs the challenge with an authorized key
3. Service verifies:
   - Signature is valid
   - `tmb` belongs to an active key in principal's KS
   - Challenge matches the one issued (prevents replay)
4. Service issues bearer token

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg,
    "typ": "cyphr.me/cyphrpass/auth/login",
    "challenge": "T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8" // 256 bit nonce from service.
  },
  "sig": "<b64ut>"
}
```

**Option B: Timestamp-Based**

1. Principal signs a login request with current `now` timestamp
2. Service verifies:
   - Signature is valid
   - `tmb` belongs to an active key in principal's KS
   - `now` is within acceptable window (e.g., ±60 seconds of server time)
3. Service issues bearer token

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg,
    "typ": "<authority>/<service>/auth/login"
  },
  "sig": "<b64ut>"
}
```

### 6.3 Replay Prevention

Two mechanisms prevent signature replay:

| Mechanism            | How it works                                          | Trade-off           |
| -------------------- | ----------------------------------------------------- | ------------------- |
| **Challenge nonce**  | Service issues unique 256-bit nonce per login attempt | Requires round-trip |
| **Timestamp window** | `now` must be within ±N seconds of server time        | Clock sync required |

Challenge-response is useful for security contexts where time isn't trusted,
while timestamp-based authentication works for low-friction flows with
reasonably accurate time sources.

### 6.4 Bearer Tokens

After successful PoP, the service issues a bearer token:

- Token is a signed Coz message from the service
- `typ` is service-defined (e.g., `<service>/auth/token`)
- Contains: principal PR, authorized permissions, expiry
- Used for subsequent requests (avoids re-signing each request)

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<service key tmb>",
    "typ": "<service>/auth/token",
    "pr": "<principal root>",
    "exp": 1628267664,
    "perms": ["read", "write"]
  },
  "sig": "<b64ut>"
}
```

**Note:** The service signs the token with its own key. The principal verifies the
token came from the expected service.

### 6.5 Single Sign-On (SSO)

Cyphrpass provides single sign-on semantics but differs from traditional SSO
systems that depend on passwords and email. Traditional SSO creates
centralization around identity providers. In Cyphrpass, the principal's
cryptographic keys are the sole authentication factor, verifiable by any party
without a central authority.

## 7. Storage Models

### 7.1 Client/Principal Storage

Cyphrpass distinguishes between several storage contexts. Clients are
categorized as **thin**, **fat**, or **full**, based on storage capacity:

**Thin clients** rely on services for state resolution and only the private key
is essential. **Fat clients** store exhaustive auth history. **Full clients**
store exhaustive auth history and action data for offline verification and
maximum sovereignty.

Storing PR, public keys, and Tip is good practice to store locally,
but could be retrieved from a service.

**Thin Client** (browser, IoT):

| Data         | Required | Notes                |
| ------------ | -------- | -------------------- |
| Private keys | ✓        | Never transmitted    |
| Transactions | Optional | Full audit trail     |
| Actions      | Optional | Application-specific |

**Fat Client** (desktop app, trusted device):

| Data         | Required | Notes                |
| ------------ | -------- | -------------------- |
| Private keys | ✓        | Never transmitted    |
| Transactions | ✓        | Full audit trail     |
| Actions      | Optional | Application-specific |

**Full Client** (desktop app, trusted device):

| Data         | Required | Notes                |
| ------------ | -------- | -------------------- |
| Private keys | ✓        | Never transmitted    |
| Transactions | ✓        | Full audit trail     |
| Actions      | ✓        | Application-specific |

### 7.2 Third-Party Service Storage

Services that interact with principals store:

| Data                | Purpose                |
| ------------------- | ---------------------- |
| PR                  | Principal identity     |
| Current PS (Tip)    | State verification     |
| Active public keys  | Signature verification |
| Transaction history | Full audit trail       |
| Actions (DS)        | Application data       |

**Service operations:**

- **Pruning**: Services may discard irrelevant user data (old actions, etc.)
- **Key recovery**: Services may assist in recovery flows (see Disaster Recovery section)
- **State resolution**: Services can provide transaction history for principals to verify

**Trust model:** Services are optional — principals can self-host or use multiple services. Full verification is always possible with transaction history.

### 7.3 Storage API (Non-Normative)

> Note: This section is informative only. Implementations may use any storage
> mechanism appropriate to their deployment context.

#### 7.3.1 Export Format

The recommended export format is newline-delimited JSON (JSONL) containing all
signed transactions and actions:

```jsonl
{"typ":"cyphr.me/cyphrpass/key/create","pay":{...},"sig":"...","key":{...}}
{"typ":"cyphr.me/cyphrpass/key/create","pay":{...},"sig":"...","key":{...}}
{"typ":"cyphr.me/comment/create","pay":{...},"sig":"..."}
```

**Properties:**

- **Immutable history**: Past entries are never modified
- **Self-verifying**: Each line is a complete, signed Coz message
- **Order derivable**: Canonical order determined by `pre` field chaining

Entries with `typ` prefix `<authority>/cyphrpass/*` are authentication
transactions; all others are data actions.

#### 7.3.2 Storage Capabilities

Storage backends provide:

- **Append**: Store signed entries for a principal
- **Retrieve**: Fetch entries (all or filtered by time range)
- **Existence check**: Determine if a principal exists

Semantic operations (verification, state computation, key validity) are handled
by the Cyphrpass protocol layer, not storage.

#### 7.3.3 Checkpoints

**Checkpoints** are self-contained snapshots of the authentication-relevant
state at a particular point in the chain, allowing verification from the
checkpoint forward without needing to fetch or replay earlier parts of the
history. Checkpoints do not rely on prior history to reconstruct AS (KS, TS, or
RS) as all required material is included directly. Checkpoints are implicit: any
signed transaction can serve as a checkpoint provided it contains all concrete
components necessary to recompute the AS at that point.

For a Cyphrpass client, the last known trusted state for a particular principal
is the **trust anchor**, ASₐ. The ordered sequence of transactions linking two
known Auth States ASₐ → ASₓ is called the `tx_path`. The transactions that must
actually be fetched and verified to move from ASₐ to ASₓ form the `tx_patch`
(Δ).

When `tx_patch` becomes very long (hundreds or thousands of transactions),
verification cost can become prohibitive, especially for thin clients, new
devices, or after long periods of being unsynced. Checkpoints are a useful
optimization for implementations that expect long-lived principals with high
transaction volume (e.g., automated key rotation, frequent rule changes). They
are also a useful debugging tool.

## See also State Jumping

## 8. State Calculation

### 8.1 Canonical Digest Algorithm

All state digests follow the same algorithm:

1. **Collect** component digests (including nonce if present).
2. **Sort** lexicographically (byte comparison).
3. **Merkle Root** 

```
digest = MR(d₀, d₁, ...)
```

**Implicit Promotion**: If only one digest component exists, it is promoted without hashing.

### 8.2 Key State (KS)

```
if n == 1:
    KS = tmb₀                              # implicit promotion
else:
    KS = MR(tmb₀, tmb₁, nonce?, PS?, ...)
```

### 8.3 Transaction State (TS)

TS is the digest of all transaction `czd`s:

```
if no transactions:
    TS = nil
elif 1 transaction:
    TS = czd₀                              # implicit promotion
else:
    TS = MR(czd₀, czd₁, nonce?, ...)
```

**Note**: TS is inherently **append-only**. Unlike DS, which services may prune
at their discretion, removing transactions from TS would break chain integrity
verification. For high-volume principals, use checkpoints or state jumping
(§16) rather than pruning.

### 8.4 Data State (DS) — Level 4+

DS is the digest of all action `czd`s:

```
if no actions:
    DS = nil
elif 1 action && no nonce:
    DS = czd₀                              # implicit promotion
else:
    DS = MR(czd₀, czd₁, ..., nonce?)
```

### 8.5 Auth State (AS)

AS combines authentication-related states:

```
if TS == nil && RS == nil && no nonce:
    AS = KS                                # implicit promotion
else:
    AS = MR(KS, TS?, RS?,  nonce?)   # nil components excluded from sort
```

### 8.6 Principal State (PS)

```
if DS == nil && no nonce:
    PS = AS                                # implicit promotion
else:
    PS = MR(AS, DS?, recursion? nonce?)
```

### 8.7 Principal Root (PR)

The PR is the **first** PS ever computed for the principal. It is **permanent** and never changes.

**Genesis cases:**

- **Single key, no transactions, no nonce**: `PR = tmb` (fully promoted)
- **Multiple keys**: `PR = MR(tmb₀, tmb₁, nonce?, ...)`
- **With DS at genesis**: `PR = MR(AS₀, DS₀, nonce?)`

When a principal upgrades (e.g., adds a second key), the **PR stays the same**, only PS evolves.

---




---

## 10. Verification by a Third Party (Level 3)

To verify a principal's current state:

1. **Obtain PR or PS** — the claimed root or transitive state (PS)
2. **Obtain transaction history** — ordered list of transactions from genesis or prior PS trust anchor.
3. **Replay transactions**:
   - Start with genesis KS (initial keys)
   - For each transaction, verify:
     - Signature is valid
     - `tmb` belongs to a key in current KS
     - `now` is after previous transaction (if time ordering required)
     - Transaction is well-formed for its `typ`
   - Apply mutation to derive new KS
4. **Compare** — final computed KS/AS/PS should match claimed current state

### 10.1 Mutual State Synchronization (MSS)

Cyphrpass enables symmetric, bidirectional state awareness between principals
and services, eliminating the one-sided dependency inherent in traditional
password-based or federated authentication models. Outside of a specific
authority, Cyphrpass's distributed model does not distinguish between users and
services—both are represented by a Cyphrpass principal. Services themselves may
be represented as Cyphrpass principals, allowing users to track services outside
the certificate authority (CA) system and without depending on email.

In legacy systems, only the service tracks user authentication state (first
established by passwords and then tracked by sessions), while users have no
independent view of the service's view of their account. Recovery is manual,
service-specific, and often funneled through email, creating a central point of
failure and control. Programmatic key rotation or bulk recovery is typically
impossible without service cooperation.

MSS makes authentication quicker by allowing clients to push state to services
before authentication. When a client mutates their own state, they may push the
mutations to all registered third parties.

Cyphrpass inverts and symmetrizes this relationship through Mutual State
Synchronization (MSS):

- Services should be represented as Cyphrpass principals themselves.
- Principals (users) and services maintain independent, cryptographically
  verifiable views of each other's state.
- Cyphrpass clients push state mutations (new transactions that advance PS) to
  registered services immediately after local application.
- Services accept and verify these pushes against the principal's current
  chain, reducing round-trips during authentication.

MSS directly addresses concerns about stale distributed state, helping clients
to keep in sync. This practice is similar to double entry accounting, where
instead of one entry in a ledger being depended upon as a single source of
truth, two entries are best practice.

#### Core Properties of MSS

| Property                     | Description                                                             | Benefit vs. Legacy Systems                                  |
| ---------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------- |
| **Bidirectional tracking**   | Both user and service hold and verify the other's transaction chain/PS. | No single source of truth; reduces trust in service logs.   |
| **Push-based updates**       | Client proactively pushes mutations.                                    | Faster auth (pre-synced state); no polling required.        |
| **Independent verification** | Each party resolves the other's state from trust anchor.                | Censorship-resistant; survives service outage.              |
| **Service as principal**     | Service exposes its own state via API or public chain.                  | Bypasses CA/email dependency for service identity.          |
| **Double-entry analogy**     | Not a single ledger, parties may track each other's state               | Stronger auditability and Fraud/spoofing/evasion detection. |

#### MSS API Operations (Non-Normative)

Typically, Cyphrpass's `typ` system builds a ready to use API. However, there
are a few endpoints not enumerated by `typ`, such as synchronization. Services
should expose an interface for MSS (like HTTP API). Services may of course
limit depth and have other rate limits. A gossip communication layer may be used
to keep clients in sync. See also section `API`.

**tip**

- `GET /tip?pr=<principal-root>`
  Returns the service's view of the tip (or latest known AS/PS digest) for the principal.

**patch** - Returns the service's view for the principal.

- `GET /patch?pr=<principal-root>&from=<ps>&to=<target-ps>` - Full form
- `GET /patch?from=<ps>` - From PS to current
- `GET /patch?pr=<principal-root>` from PR to current
- `GET /patch?pr=<principal-root>from=<ps>` from PS, for particular PR, to current
- `GET /patch?from=<ps>&to=<target-ps-or-empty>` - Range

`to` is optional and on omission is `tip`.
`pr` is optional since it should be included in patch. May be explicit for debugging.
`from` is optional if pr is given.

- `POST /push`
  Accepts one or more signed transactions (`tx_patch`). Service verifies chain validity and applies update.

**Synchronization check:**

- If service-reported tip equals the client's local PS, state is synced.
- On mismatch, client pushes delta or service requests missing patch.

// TODO suggest a way to do local client registration.

#### Recommended Usage Patterns

- **Proactive push on mutation** — After transaction (`key/create`, `key/revoke`,
  etc.), client pushes to all registered services (stored locally through
  previous registration).
- **On-demand sync** — Before high-value actions, client queries service tip and
  reconciles if needed.
- **Service identity anchoring** — Users track service PR/PS directly (instead
  of DNS + CA certs), enabling trust outside email/CAs.
- **Recovery acceleration** — Pre-synced state allows new devices to bootstrap
  faster via push to known services.

#### Why MSS Matters

MSS addresses centralization risks in legacy SSO (passwords + email as de facto
recovery root) and bearer-token models (service as sole state oracle). By making
state mutual, verifiable, and push-capable, Cyphrpass enables:

- Lower-latency authentication flows.
- Independence from email/CA choke points.
- Auditable recovery without manual per-service intervention.
- Programmable, symmetric trust between users and services.

Although Cyphrpass provides single-sign-on semantics, it differs from historic
systems by eliminating passwords, email dependency, and unidirectional state
tracking.

---

### 10.2 MSS Registration Example

Example ledger displaying remote state synchronization. Local Principal `X` is
at tip `State3`.

| Principal | Trust Anchor | Synced? |
| --------- | ------------ | ------- |
| A         | State0       | N       |
| B         | State2       | N       |
| C         | State3       | Y       |

After successful syncing:

| Principal | Trust Anchor | Synced? |
| --------- | ------------ | ------- |
| A         | State3       | Y       |
| B         | State3       | Y       |
| C         | State3       | Y       |

---


## Embedding 
Embedding is the mechanism by which Cyphrpass achieves hierarchy, delegation,
and selective opacity.

All embedding is by digest reference.  Also, embedding is how opacity is
implemented through using nonces.

Recursive loops are generally discouraged.

### Embedded Principal
Cyphrpass permits a recursive tree structure.  An **embedded principal** is a
full Cyphrpass identity embedded into another principal.  An embedded principal
appears in the Merkle tree of another principal as the digest of its current
Principal State (PS) or Auth State (AS).  Full subtrees are not inlined.

When PR, PS, or AS is used as an identifier, tip at verification time from that
Principal is retrieved first before any operation, such as authentication, is
performed.

External Recovery is accomplished through embedded principals, where some
permissions are delegated to an external account. (See section on recovery)

```text
Principal State (PS0)
│
├── Auth State (AS) ──────────── [Security & Identity]
│   │
│   ├── Key State (KS) ───────── [Public Keys]
│   │   |
│   |   ├── Embedded Principal (PS1)
```

The typical use for embedded principals is identity encapsulation, external
recovery authorities, social recovery, organizational delegation, and disaster
recovery.

### Embedded Node
An opaque node, or a partial identity, which may be a AS, KS, nonce, or other
node value, is an **embedded node**. 

An embedded node is an opaque digest value (nonce, AS, KS, or other node) or
partial identity (AS, KS) that appears in the tree.

```text
Principal State (PS0)
│
├── Auth State (AS) ──────────── [Security & Identity]
│   │
│   ├── Key State (KS0) ───────── [Public Keys]
│   │   |
│   |   ├── Embedded Key State (KS1)
```


### Conjunctive Authorization
To sign/act as the primary principal, the embedded principal must produce a
valid signature according to its own rules (its own AS).

Authorization involving an embedded principal is conjunctive:  
 - Transaction must be valid according to the secondary principal’s own rules
   (its KS/RS), and  
 - The act of using that embedded principal must be authorized by the primary
   principal’s rules.

When a Principal(B) or AS(B) is embedded into a KS(A), embedded principal is
treated as one logical key (with a default weight of 1), but the internal
authorization depends on Principal(B)


### Meaningful Embeddings and Embedding Promotion
All nodes may be embedded into other nodes, but that embedding may not always be
meaningful. For example, a Rule State embedded into a Key State carries no
meaning.  Clients should discourage such practice, but this may not be
enforceable due to opaqueness.

When a Key State(B) is embedded into another Key State(A), the keys from B are
be logically unioned to A. This is **embedded promotion**.  Embedded promotion
applies to KS and DS.


### Pinning
PR, PS, and AS denote fetching.  If a principal wants to denote a static state
that does not permit updating, a pin may be used.  

A pin prefixes the digest value: 

```
PIN:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg
```



## 11. Recovery

### 11.1 Unrecoverable, Dead, and Zombie Accounts

There are three concerning states:

1. Unrecoverable: Protocol-level inability to mutate AS. No new transactions
   are possible. (Level 1+)
2. Dead: No new transactions or actions (including data actions) are possible.
   Total immutability (Level 1+)
3. Zombie: No new transactions, but some data actions may still be possible.
   (Partial functionality remains) (Level 3+)

**Unrecoverable**: An **unrecoverable principal** is one where:

- No active keys remain (all revoked or otherwise inaccessible),
- No designated recovery agents or fallback mechanisms are present or able to
  act,
- The principal AS cannot be mutated. No new transactions are possible via the
  protocol (although some data actions may be possible),
- And recovery is impossible within the Cyphrpass protocol rules (i.e.,
  requires sideband intervention).

None of the self-recovery mechanisms listed can prevent or reverse an
unrecoverable principal state once it has occurred, they must be established
before key loss/revocation.

**Level 1 and Unrecoverable**
A Level 1 key can self-revoke, but this results in DEAD (permanent lockout).
Recovery requires sideband intervention defined by the implementor
or service (see Section 10.1).

Level 1 implementors have two options:

1. The proper option is sideband recovery. Devices and services should define
   sideband recovery method.
2. Ignore the revoke. This is bad practice, but some simple services may not
   define a sideband method.

Simple devices and services using Level 1 should define sideband recovery.
Although it's recommended against, services without a sideband method may want
to ignore revokes so that an unrecoverable state isn't possible.

**Sideband Recovery Examples**
An example of sideband recovery would be having physical access or SSH access to
the device with the unrecoverable principal, deleting the old key replacing it
with a new key, and updating the public key on services that communicate to that
device.

### Dead and Zombie

Unrecoverable principals may also be Dead or Zombie:

1. **Dead**: An unrecoverable principal is dead if no actions are possible (no
   transactions or data actions)
2. **Zombie**: An unrecoverable is a zombie if transactions are not possible but
   some data actions are still possible.

**Zombie example** (level 4) `key/create` requires 2 points, but there's only
one key with weight 1. `comment/create` requires default 1, so comments are
still possible but AS mutation is impossible.

**Dead example**: (level 1) The only key is revoked. The account is
unrecoverable and dead.

### 11.2 Recovery Mechanisms

When a principal loses access to all active keys, or the account is otherwise in
an **unrecoverable state** recovery mechanisms allow regaining control.

There are two main mechanisms:

- **Self Recovery**, various methods of backup. For user self management.
- **External Recovery** Where some permissions are delegated to an external
  account, a **Recovery Authority**. This may be social recovery or third-party service.

Level 1 doesn't support recovery. Any recovery is accomplished through sideband.
Level 2 supports recovery but only atomic swaps. The recovery key can replace the existing key.
Level 3+ supports recovery and can add new keys.

### 11.3 Self-Recovery Mechanisms

| Mechanism         | Description                            | Trust Model  |
| ----------------- | -------------------------------------- | ------------ |
| **Backup Key**    | Backup key stored in a secure location | User custody |
| **Paper wallet**  | Backup key printed/stored offline      | User custody |
| **Hardware key**  | Hardware key device (U2F-Zero, solo1)  | User custody |
| **Airgapped key** | Cold storage, never online             | User custody |

### 11.4 Implicit Fallback (Single-Key Accounts)

For implicit (single-key) accounts, a `fallback` field may be included at key creation:

```json
{
  "alg": "ES256",
  "pub": "<b64ut>",
  "tmb": "<b64ut>",
  "fallback": "<backup key tmb>"
}
```

**Fallback types by level:**

| Level | Fallback Value | Description                                                |
| ----- | -------------- | ---------------------------------------------------------- |
| 1     | —              | No recovery support (static key)                           |
| 2     | `tmb`          | Backup key thumbprint                                      |
| 3+    | `PS`           | External Principal recovery agent (with rules or defaults) |

**Notes:**

- The `fallback` field is not included in `tmb`'s calculation (allows changing
  fallback without changing identity)
- Assumes a trusted initial setup
- **Level 2 Restriction**: Level 2 accounts only support **atomic swap**
  (`key/replace`). The fallback functionality must adhere to this, replacing the
  lost key rather than complying with `key/create` like Level 3+.

#### 11.4.1 Recovery Validity // TODO needs some work

Recovery agents can only act when the account is in an **unrecoverable state**:

- All regular keys have been revoked or are inaccessible.
- Insufficient keys remain to meet threshold for mutations (Level 5+).
- Signatures from recovery agents are invalid while account is recoverable.
- This prevents recovery from being used as a backdoor.
- The rule for `key/create` is of a higher weight than keys on the account.

### 11.5 Recovery Transactions

#### 11.5.1 `cyphrpass/recovery/create` — Register Fallback

Registers a recovery agent (backup key, service, or social contacts).

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/cyphrpass/recovery/create",
    "pre": "<previous AS>",
    "recovery": {
      "agent": "<recovery agent PR or tmb>",
      "threshold": 1
    }
  },
  "sig": "<b64ut>"
}
```

**Fields (within `recovery` object):**

- `agent`: PR of service, tmb of backup key, or array of contact PRs
- `threshold`: For social recovery, M-of-N threshold (default: 1)

#### 11.5.2 `recovery/delete` — Remove Fallback

Removes a previously designated recovery agent.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/recovery/delete",
    "pre": "<previous AS>",
    "recovery": {
      "agent": "<recovery agent PR or tmb>"
    }
  },
  "sig": "<b64ut>"
}
```

### 11.6 Recovery Flow

When a principal is locked out:

0. **User generates a new account with a fresh PS**
1. **User contacts recovery agent** (out-of-band)
2. **Agent verifies identity** (method varies by agent type)
3. **Agent signs a Recovery Initialization transaction** for the new user key:

   This initializes a new Principal State (PS) that is manually linked to the previous state by the Recovery Authority. The new PS is not cryptographically linked to the previous state, but it is manually linked to the original PR by the Recovery Authority's recovery transaction.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<recovery agent tmb>",
    "typ": "<authority>/key/create",
    "pre": "<previous AS>",
    "id": "<new user key tmb>"
  },
  "key": {
    /* new user key */
  },
  "sig": "<b64ut>"
}
```

Because the agent was designated via `cyphrpass/recovery/create`, their `key/create` is valid even though no regular user key signed it.

### 11.7 External Recovery

External recovery delegates recovery authority to an external principal. The recovery agent verifies identity out-of-band and signs a recovery transaction on behalf of the locked-out user.

| Mechanism               | Description             | Trust Model       |
| ----------------------- | ----------------------- | ----------------- |
| **Social recovery**     | M-of-N trusted contacts | Distributed trust |
| **Third-party service** | Verification service    | Service trust     |

### 11.8 Social Recovery

For social recovery, multiple contacts sign:

- Each contact signs the same `key/create` transaction
- When `threshold` signatures are collected, the transaction is valid
- Contacts are identified by their PR

**Example:** 3-of-5 social recovery requires 3 contacts to sign the `key/create`.

### 11.9 Account Freeze

A **freeze** is a global protocol state where valid transactions are temporarily rejected to prevent unauthorized changes during a potential compromise. A freeze halts all key mutations (`key/*`) and may restrict other actions depending on service policy.

Freezes are **global** — they apply to the principal across all services that observe the freeze state.

#### 11.9.1 Self-Freeze

A user may initiate a freeze if they suspect their keys are compromised but do not yet want to revoke them (e.g., lost device).

- **Mechanism**: User signs a `cyphrpass/freeze/create` transaction with an active key.
- **Effect**: Stops all mutations until unfrozen.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/cyphrpass/freeze/create",
    "pre": "<previous AS>"
  },
  "sig": "<b64ut>"
}
```

A designated **Recovery Authority** may initiate a freeze based on heuristics
(irregular activity) or out-of-band communication (user phone call).

- **Mechanism**: Recovery agent signs `cyphrpass/freeze/create`.
- **Effect**: Same as self-freeze.
- **Trust**: The principal explicitly delegates this power to the authority via
  `cyphrpass/recovery/create`.

#### 11.9.3 Thaw (Unfreeze)

To unfreeze an account, a `cyphrpass/freeze/delete` is signed:

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/cyphrpass/freeze/delete",
    "pre": "<previous AS>"
  },
  "sig": "<b64ut>"
}
```

**Rules:**

- Self-freeze can be thawed by active keys.
- External freeze requires the Recovery Authority to thaw (or the principal after a timeout, if configured)

### 11.10 Security Considerations

- **Timelocks (Level 5+):** Recovery can have a mandatory waiting period.
- **Revocation:** Backup keys can be revoked if compromised.
- **Multiple agents:** A principal may designate multiple fallback mechanisms, including M-of-N threshold requirements
- **Freeze abuse:** External freeze authority requires explicit delegation and trust

### 11.11 Retrospection

**TODO:** Define retrospection semantics — how past signatures are validated
after key removal/revocation needs further specification. Stub:

Retrospection is undoing actions to a timestamp. This is a complex issue for
services.

As a best practice Level 3 plus should define more than one key being required
for retrospection, since if only one key set, a single

retrospection attack: Backdating actions to "undo" actions since a time period.

Instead of removing a record, the record can be marked as "rescinded"

## 12. Close, Merge, Fork

### 12.1 Closing an Account (Principal Delete, Level 3+)

Closing an account is performed via a `principal/delete` transaction. Closed
accounts are permanently closed and cannot be recovered. No transactions or
actions are possible on a closed account. However, the protocol does not prevent
a user from creating a new principal reusing the same keys, unless those keys
were revoked.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "<target signing key tmb>",
    "typ": "cyphr.me/cyphrpass/principal/delete",
    "pre": "<current AS>"
  },
  "sig": "<b64ut>"
}
```

### 12.2 Account Merging (Principal Merge, Level 3+)

Merging allows one principal (the **source**) to adopt the state of another
principal (the **target**), consolidating identities while preserving the
targets's original **Principal Root** (PR).

There are two ways to merge:

1. Implicit merge: The source account deletes all keys and adds the PS of the
   target. The target accepts by adding the PS of the source.
2. Explicit merge: The source signs a `principal/merge` transaction with the PS
   of the target. The target account must accept the merge by signing a
   `principal/ack-merge` transaction with the PS of the source. (Optionally, the
   source can still delete all keys and/or sign a `principal/delete`.)

It is important that in both cases the target accepts the merge. Without
acknowledgement external accounts could attack an account by merging in their
state (merge attack).

Further, to ensure that no future transactions are possible on the source
account, the source may sign a `principal/delete` transaction.

**`principal/merge` — Merge into Target Principal (Level 3+)**

Explicit merging is performed via a special transaction type:

- References the source's current AS via `pre`
- Declares the target's PS as the next state via a new field `merge_to_ps`
- Includes proof that the signer is authorized on the **source** (not the target)
- Note that if the target account wants to reuse keys from the source account, it
  must explicitly add keys from the source account (if the keys are not already
  present).

Example source principal merge transaction:

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "<source signing key tmb>",
    "typ": "cyphr.me/cyphrpass/principal/merge",
    "pre": "<source current AS>",
    "merge_to_ps": "<target Principal State>"
  },
  "sig": "<b64ut>"
}
```

And the acknowledgement by the target principal:

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "<target signing key tmb>",
    "typ": "cyphr.me/cyphrpass/principal/ack-merge",
    "pre": "<target current AS>",
    "merge_from_ps": "<source Principal State>"
  },
  "sig": "<b64ut>"
}
```

### 12.3 Account Forking (Principal Fork, Level 3+)

Forking allows one principal (the **source**) to create a new principal (the
**target**), effectively splitting identities while preserving the source's
original **Principal Root** (PR).

Typically, this is straightforward. Any set of keys that has not been revoked
may be used to create a new PR.

However, the fork may want to preserve prior identity and history. Since PR
must resolve to one and only one principal account, PR itself cannot be used as
the identity for multiple accounts.


---

## 13. Timestamp Verification

When a key is compromised, attackers can sign messages with arbitrary `now` values. Timestamp verification prevents retroactive and future-dated attacks.

### 13.1 PS Timestamp Binding

The **latest known timestamp** for a principal is:

- The `now` field of the most recent transaction (if any)
- Otherwise, the key creation `now` (implicit accounts)

**Rule:** Services should reject actions where:

- `now` < latest known PS timestamp (too far in the past)
- `now` > server time + tolerance (too far in the future)

### 13.2 Tolerance Window

Services accept `now` values within an acceptable variance:

| Type             | Tolerance       | Rationale                                        |
| ---------------- | --------------- | ------------------------------------------------ |
| **Transactions** | ±60 seconds     | Strict — key mutations are security-critical     |
| **Actions**      | Service-defined | Looser — user data may legitimately be backdated |

**Implementation:** Compare `now` to server time at receipt. Reject if outside tolerance.

### 13.3 Revocation Timestamp Semantics

When a key is revoked with `rvk` = T:

- Signatures with `now` >= T are **invalid** (key was compromised)
- Signatures with `now` < T are **valid** (signed before compromise)
- Attackers cannot forge pre-revocation signatures if services enforce PS timestamp binding

### 13.4 Oracle Tiers

| Tier        | Method                               | Trust Level | Use Case                |
| ----------- | ------------------------------------ | ----------- | ----------------------- |
| **None**    | Trust `now` field                    | Lowest      | Simple apps, low-value  |
| **Service** | Service logs first-seen time         | Medium      | Most applications       |
| **Trusted** | Hash into blockchain (Bitcoin, etc.) | Highest     | Legal, financial, audit |

**No Oracle (Default):**

- Accept `now` field as claimed
- Simple but vulnerable to retroactive signing

**Service Oracle:**

- Service records `received_at` timestamp when signature arrives
- Stored alongside action for dispute resolution
- Not cryptographically provable, but practical

**Trusted Oracle:**

- Signature (or `czd`) is hashed into a blockchain transaction
- Commit timestamp proves signature existed before that time
- Irrefutable, but adds latency and cost

---


## 14. Multihash Identifiers
In Cyphrpass, cryptographic algorithms are pluggable: no single cryptographic
primitive is exclusively authoritative or tightly coupled to the architecture.
This enables flexibility in algorithm choice, security upgrades, and rapid
removal of broken algorithms. Instead of identifiers being tightly coupled to a
single digest, identifiers are coupled to an abstraction named a **multihash
identifier**—a set of equivalent digests, one per supported hash algorithm at
commit time.

No single algorithm is canonical. All variants in a multihash identifier are
considered equivalent by Cyphrpass; security judgments are out-of-scope.

A multihash identifier is calculated for all state (KS, AS, PS, and Merkle tree
nodes) on a per commit basis. States are singular, having a singular underlying
structure, but may be referenced via multiple hashing algorithms. 

For a particular commit, for each algorithm supported by any key, nonce, or
embedded node in KS, a digest value is calculated. When only one algorithm is
used, the multihash has only one variant. When multiple algorithms are used, the
multihash has many variants, many digest identifiers. For example, if the set of
keys supports SHA-256 and SHA-384, then both a SHA-256 and a SHA-384 digest is
calculated. If the keys support only SHA-256, then only a SHA-256 digest is
calculated.

A nonce (or multiple nonces) can be used to inject a specific digest
algorithm variant into the multihash identifier, even when no key supports that
algorithm natively.

In summary:
- PR, PS, AS, KS and nodes in the Merkle Trees are singular underlying states.
- Each can be referenced by multiple variants, one per hash algorithm.
- Cyphrpass makes no relative security judgements.  All variants are considered
  equivalent references.
- Digests are computed for hashing algorithms associated with all currently active keys.
- When an primitive algorithm is removed, its algorithm's hash is no
  longer computed.  When a primitive algorithm is added, its algorithm's
  variant begins being computed.

### 14.1 Algorithm Mapping
Each key algorithm implies a hash algorithm, as defined by Coz.

| Key Algorithm | Hash Algorithm | Digest Size | Strength Category  |
| ------------- | -------------- | ----------- | ------------------ |
| ES256         | SHA-256        | 32 bytes    | 256-bit            |
| ES384         | SHA-384        | 48 bytes    | 384-bit            |
| ES512         | SHA-512        | 64 bytes    | 512-bit            |
| Ed25519       | SHA-512        | 64 bytes    | 512-bit            |

### 14.2 Conversion
To support upgrades and embedded principals/nodes, values from one digest
algorithm may be **converted** as input to another.

For example, in a Merkle tree with a SHA-384 node (A) and SHA-256 node (B), a
SHA-384 root is: MR_SHA384(A, B)—B's value is fed directly into SHA-384.


```text
                SHA-384 Root
               ┌─────────────┐
               │  MR_SHA384  │
               └──────┬──────┘
                      │
              SHA-384( A || B )
                      |
          ┌───────────┼───────────┐
          │                       │
          │           Fed directly into SHA-384
          │                       │
   ┌─────────────┐         ┌─────────────┐
   │   Node A    │         │   Node B    │
   │  (SHA-384)  │         │  (SHA-256)  │
   └─────────────┘         └─────────────┘
```

### 14.3 Security Considerations
Conversion is not ideal, but is unavoidable for pluggability and
recursion/embedding. Implementors must be aware that inner nodes may have
different security levels than the lookup node; the overall tree is bounded by
the weakest link.

Algorithm diversity aids durability but risks misuse. For uniform security, use
keys from one strength category. If an algorithm is weakened, Coz will mark it
deprecated; principals should discontinue via key removal.


### 14.4 Rank
When multiple algorithms are supported, there may be a tie at the time of
conversion.  Cyphrpass provides a default rank.  Rank is a tiebreaker only and
not a security indicator. Misuse can have security implications.

Perhaps in the future, principals may set a
rank order via `cyphrpass/alg/rank/create` transaction (stored in AS), but for
now this is out-of-scope.


#### 14.5 Algorithm Incompatibility
A service and a client are deemed **incompatible** if the service cannot support
the specific algorithm (alg) used in a client's message.

However, due to Cyphrpass’s use of encapsulation, implicit promotion, and other
features, a service does not always require full algorithm support. For example,
if a service can process the top-level digests, it may remain compatible even if
it cannot verify the underlying primitives of nested components.

Compatibility is strictly required only for operations where the service must
 verify or interpret the cryptographic material. If such an operation is
attempted using an unsupported algorithm, the services are incompatible.
---



### 15 `typ` Action Grammar

Cyphrpass follows a grammar system developed by Cyphr.me. The `typ` grammar
consists of these core components: `auth`, `act`, `noun`, and `verb`.

```
<typ> = <authority>/<action>
<action> = <noun>[/<noun>...]/<verb>
<verb>   = create | read | update | upsert | delete
```

- **authority** (auth): The first unit — typically a domain name or a Principal
  Root.
- **action** (act): Everything after the authority.
- **noun**: One or more path units between authority and verb, representing the
  resource or subject of the action. Multiple units form a **compound noun**
  (e.g., `user/image`).
- **verb**: The final unit, the operation to perform.

Cyphrpass recommends that the authority be either a domain or a Principal Root.
When a domain is used as authority, that domain should ideally provide (or be
associated with) a Cyphrpass identity.

Example: `"cyphr.me/user/image/create"`

- Authority: `cyphr.me`
- Action: `user/image/create`
- Noun: `user/image` (compound noun)
- Verb: `create`


**Other Examples:**

- `cyphr.me/key/upsert`
- `cyphr.me/key/revoke`
- `cyphr.me/comment/create`
- `cyphr.me/principal/merge`


#### Special verbs
In addition to the standard CRUD-like verbs (`create`, `read`, `update`,
`upsert`, `delete`), Cyphrpass defines these special verbs for protocol-level
operations:

- `key/revoke`
- `key/replace`
- `principal/merge`
- `principal/ack-merge`
- `nonce`

**Terminology note:** "Action" is used in three distinct contexts by Cyphrpass.
Context disambiguates:

1. **User Action** — A signed Coz.  The hypernym of transactions and data action
   is "action".  The action type is denoted by `typ`.
2. **Data Action** — A signed user message, ideally recorded in Data State
   (Level 4+).
3. **Type Action** — The path after the authority in a `typ` field. `typ` itself
   denotes the action of the message.  This is why a "user action" is just
   simply an action.


## 16 Cyphrpass Type System and Ownership

Cyphrpass's `typ` as an alternative to HTTP semantics. 

Cyphrpass's `typ` naming convention is not just a naming convention, it's a
deliberate design choice that shifts how we think about invoking actions,
addressing resources, and expressing intent in a cryptographically native,
decentralized way which is realized in Authenticated Atomic Action.

### `typ` as a Unified Intent + Resource + Verb Descriptor

In 1968 there was the "Mother of all demos", demonstrating the GUI, mouse, and other computer
basics.  In 1988 was HTTP, which with other components was the creation of the
Web. 

Unlike most Internet systems, Cyphrpass is designed to work in parallel to HTTP,
not on top of it. Where HTTP has Method (GET/POST/PUT/DELETE/PATCH...),
Path (/users/123/profile/photo), Headers (Accept, Content-Type, Authorization...)
Cyphrpass collapses almost all of that expressive into one field: `typ`.

For example, `cyphr.me/cyphrpass/key/create`

This is close to a RESTful path plus method, but:
- It's self-describing and self-authenticating.
- No separate "method" field needed. The verb is included.
- No separate path vs. body distinction for intent. Everything meaningful is
  inside the pay payload.
- Authority prefix acts like a namespace / origin (replacing domain + scheme in
  a decentralized setting).
 - Cryptographic digests, especially in combination with public key
cryptography, naturally provides addressing.  

Cyphrpass Advantages Over HTTP (in Cyphrpass's World)
- No trusted third-party sessions (like cookies/tokens). Every request carries
  its own PoP.
- Replay resistance built-in via `now` (timestamp window).
- Intermediaries can cryptographically audit actions without trusting the
  service.
- Decentralized addressing. The Principal root is outside DNS/CA entirely.
- Append-only mutable state via transactions. Instead of PUT/PATCH fighting over
  eventual consistency, Cyphrpass provides a verifiable chain of mutations.

Actions are first-class and atomic. AAA means the "API call" is individually
verifiable forever, not just during a session.


#### Authority and `typ`
The authority defines the acceptance rules allowable for various types. These
rules may be enforced by a consensus mechanism like a blockchain, a VM, a
centralized service, or other processes. Although Cyphrpass itself agnosticly
does not set permissions outside of the core authentication rules, Cyphrpass
acknowledges that rules must be implemented by an authority.  (In the case of
this document, `Cyphr.me` is typically that authority)

### Noun Properties

The `typ` denotes a noun, which may have properties as set by an authority.
Properties
 - Creatable
 - Ownable
 - Updatable
 - Transferable

Create: Nouns that are able to be created, like `comment/create`
Owned: Things that are owned can only be mutated by owner. `comment`
Updatable: Nouns that are able to be mutated after the fact. `comment`
Transferable: Things that are able to be transferred.

In Cyphrpass, transferable is cryptographically implementable via key change,
but recording such changes in a ledger potentially results in human unreadable
transactions. Also, authorities may prohibit key updates to keys outside of the
principal, making transfer impossible. 

Transfer ambiguity: For example, a comment could be updated to be signed by a
new key, but that would be ambiguous: was is a transfer or just as a result of a
key update?  For that reason, updates with new keys outside of principal should
fail and transfer explicitly used for transfer. 


### Where Cyphrpass Diverges from Being a Full HTTP Replacement

Cyphrpass's `typ` + Coz model isn't a wire replacement for HTTP. Instead it offers an **alternative interaction model**:

| Aspect                  | HTTP                                       | Cyphrpass `typ` + Coz Model                              |
|-------------------------|--------------------------------------------|----------------------------------------------------------|
| Addressing              | URL + method                               | `typ` string (authority + noun/verb)                     |
| Authentication          | Headers / tokens / cookies                 | Embedded PoP (signature over the whole intent)           |
| State management        | Server-side sessions                       | Client + service mutual sync of auth chain               |
| Mutability model        | CRUD on resources                          | Append-only transactions + signed actions                |
| Verifiability           | Mostly server-trusted                      | Anyone can verify any action historically                |
| Transport               | Usually TLS + HTTP                         | Can be sent any way (TLS, HTTP, IPFS, email, gossip...)  |
| Response model          | Status + body                              | Tip, another signed Coz                                  |




### 16 Self-Sovereign Philosophy

#### Self-Ownership Philosophy in a Cryptographic System

There are three main categories of ownership:

1. Possess the private keys (Private Key Possession)
2. Possess the data (Data Possession)
3. Right to mutate state: `create`, `delete`, `update` (Right)

These three can be summarized as three points: **Keys, Data, Right**

#### 16.2.1 Cyphrpass Goal

The protocol seeks to maximize user ownership across all three dimensions:

Keys → Self-custody, multi-device, revocation, recovery paths.
Data → Portable exports, optional self-hosting, minimal service lock-in (via MSS).
Rights → AAA replaces bearer tokens; verifiable authorship/actions without centralized session state.

**Private Key Possession** is important in cryptography. Cryptographic systems
are implemented using key possession. (Not your keys, not your crypto.)

**Data Possession** - For non-encrypted data: Possession generally equates to
ownership, as anyone with access can read/copy/use it.
For encrypted data: Ownership is tied to possession of decryption keys (which
may overlap with Private Key Possession). Encrypted data hosted by third parties
(e.g., for availability/security) does not imply loss of ownership if keys
remain user-controlled.

**Right** is relevant for authorship (comments, user history) and where
ownership is tracked on a ledger (e.g., bitcoin). Right is proven in a
cryptographic system using private keys and PoP.

Cyphrpass seeks to help users own their keys, data, and rights.

### 16.5 Natural Ownership

The originating Principal is the **natural owner** of its actions. For example,
the principal that creates a comment `comment/create` is the natural owner of
that comment, and has exclusive rights for future mutations: `comment/update`,
`comment/delete`, and `comment/upsert`. Systems implementing AAA must give
special attention to items with natural ownership properties.

#### 16.5.1 Ownership Right Semantics

Perhaps:
ownership is proven by the latest valid transfer chain. Ownership = latest valid transfer chain

`typ`s:

```
cyphr.me/ownership/claim/create
cyphr.me/ownership/transfer
ownership/ack-transfer
```


TODO multiownership

Perhaps an item itself can be represented as a Principal. Abstract things themselves have a chain.

"smart contracts" are supported by level 5+
Verifiable without full blockchain, Off-chain data friendly
No native "minting fee" or gas
No miner, validator race, or fee market
Revocable/revocable keys
Soulbound-like — Set transferable=false
























---

## 16. State Jumping

For high-volume principals (e.g., those with tens of thousands of transactions)
or thin clients with limited bandwidth/storage, full chain replay from a distant
trust anchor to the current tip can become prohibitively expensive in time, data
transfer, or computation.

State jumping provides an optimization allowing a client to advance directly
from a known trust anchor (e.g., an old AS or PS at "block" N) to a much later
state (e.g., current tip at "block" M >> N), without fetching or verifying every
intermediate transaction.

Multiple jumps may be required to traverse from the trust anchor to the target
PS, for example in circumstances where keys have been revoked. In anticipation
of a state jump, clients may pre-sign jumps.

Clients may also reject state jumps as state jumps are an optimization that
delegates some trust to third party services. By default, the Cyphrpass
reference client rejects state jumps, preserving a conservative security
baseline.

### 16.1 Core Mechanism

A principal with access to one or more still-active keys from the trust anchor
can sign a special **state-jump transaction** that:

- References the old trust anchor via `pre`,
- Declares the new target PS in a new field (e.g., `jump_to_ps`),
- Is signed by one or more keys authorized at the anchor (and still valid at the
  tip).

Verification rules for the jump transaction:

- The signing key(s) must be present in KS at the anchor.
- The claimed `jump_to_ps` must match the service-reported or
  independently-obtained current tip.
- No intermediate revocations or key mutations are permitted that would
  invalidate the signing key(s) — this is enforced by requiring the jump
  transaction to be accepted only if KS at tip still includes the signing
  `tmb`(s).
- Services MAY require additional proofs (e.g., Merkle inclusion of unchanged KS
  components) or restrict jumps to trusted checkpoints.

**Typical Processing Flow**

1. Client queries service for current tip (via MSS `/tip` endpoint, §10.1).
   Client notes that chain is larger than optimization threshold (> 1,000) and
   triggers state jump process.
2. Client verifies tip KS includes the signing key (fetch minimal tx_patch if
   needed).
3. Client signs and pushes the jump transaction to services.
4. Services validate: signature, `pre` matches known history, `jump_to_ps` =
   current tip, no invalidating mutations.
5. If valid, client updates local trust anchor to `jump_to_ps`; future
   resolutions start from there.

**Swim Lane Chart**

```
 Local Principal Client                Remote Principal
  |                                            |
  |---1. Query current tip (MSS /tip)--------->|
  |<-- Return current PS (tip @100,000)--------|
  |                                            |
  | (Detect long chain → trigger jump)         |
  |                                            |
  | Verify signing key still in KS @ tip       |
  | (minimal tx_patch fetch if needed)         |
  |                                            |
  | Sign jump tx: pre=AS@2, jump_to_ps=tip     |
  |                                            |
  |---3. Push signed jump transaction--------->|
  |                                            |
  |                  Remote validates:         |
  |                  • Signature               |
  |                  • pre matches history     |
  |                  • jump_to_ps == current   |
  |                  • No revokes on key path  |
  |                                            |
  |<-- Accept (or reject if invalid)-----------|
  |                                            |
  | Update local trust anchor to new PS        |
  | Future resolutions start from here         |
  |                                            |
```

### 16.2 Example State Jump Transaction

```json5
{
  pay: {
    alg: "ES256",
    now: 1628181264,
    tmb: "<active key tmb from anchor>",
    typ: "cyphr.me/cyphrpass/principal/state_jump/create",
    pre: "<old trust anchor AS>", // e.g., PS at previous trust anchor
    jump_to_ps: "<current tip PS>", // e.g., PS at transaction 100,000
  },
  sig: "<b64ut>",
}
```

### 16.3 Security Considerations

- Jumping must not bypass revocation semantics: if a key was revoked between
  anchor and tip, the jump fails.
- Clients should verify the jump against multiple services or via full chain
  replay periodically to detect malicious jumps.
- Services may enforce maximum jump distance or require multi-signature for
  large jumps to mitigate abuse.

State jumping preserves Cyphrpass's core properties (verifiable history, no
trusted central oracle) while enabling scalable operation for long-lived
principals.

### 16.4 State Jump Examples

**Example 1: Single large jump (no revokes)**

Trust anchor is at block 2, but tip is at block 100,000. As long as keys have
not been revoked from block 2, and the principal still has those keys, they can
sign a transaction going from 2 → 100,000 which avoids having to download each
intermediary checkpoint. (Sometimes called "state warping".)

**Example 2: Multi-jump required (revokes in the middle)**

Trust anchor is at block 2, but tip is at block 100,000. All keys active at
block 2 were revoked sometime between block 2 and block 50,000.

To reach the tip:

- First jump: from block 2 → block 45,000 (using a key still active at 45,000
  but revoked later)
- Second jump: from block 45,000 → block 100,000 (using a key that became active
  after the revoke window and is still valid at the tip)

The client must discover or know an intermediate safe anchor where a valid
signing key exists. Services can help by returning recent checkpoints or
suggesting viable jump points when the direct jump fails due to revocation.

### 16.5 Other High Volume Strategies

In addition to state jumping, other future related designs include zero-knowledge
proofs and trusted third parties. (Ethereum uses Infura; similar infrastructure
may be useful for some client situations, although Cyphrpass is designed for
decentralization.)

See also §7.3.3 Checkpoints.

## 17. Error Conditions

This section defines error conditions that implementations MUST detect. Error
_responses_ (HTTP codes, messages, retry behavior) are implementation-defined.

### 17.1 Transaction Errors

| Error               | Condition                                        | Level |
| ------------------- | ------------------------------------------------ | ----- |
| `INVALID_SIGNATURE` | Signature does not verify against claimed key    | All   |
| `UNKNOWN_KEY`       | Referenced key (`tmb` or `id`) not in current KS | All   |
| `UNKNOWN_ALG`       | Client doesn't know or support the algorithm     | All   |
| `TIMESTAMP_PAST`    | `now` < latest known PS timestamp                | All   |
| `TIMESTAMP_FUTURE`  | `now` > server time + tolerance                  | All   |
| `MALFORMED_PAYLOAD` | Missing required fields for transaction type     | All   |
| `KEY_REVOKED`       | Signing key has `rvk` ≤ `now`                    | All   |
| `INVALID_PRIOR`     | `pre` does not match current AS                  | 2+    |
| `DUPLICATE_KEY`     | `key/create` for key already in KS               | 3+    |
| `THRESHOLD_NOT_MET` | Signing keys do not meet required weight         | 5+    |

### 17.2 Recovery Errors

| Error                     | Condition                                                        | Level |
| ------------------------- | ---------------------------------------------------------------- | ----- |
| `UNRECOVERABLE_PRINCIPAL` | No keys capable of transaction AND no designated recovery agents | All   |
| `RECOVERY_NOT_DESIGNATED` | Agent not registered via `cyphrpass/recovery/create`             | 3+    |

### 17.3 State Errors

| Error                 | Condition                                               | Level |
| --------------------- | ------------------------------------------------------- | ----- |
| `STATE_MISMATCH`      | Computed PS does not match claimed PS                   | All   |
| `HASH_ALG_MISMATCH`   | Multihash variant computed with wrong algorithm         | All   |
| `CHAIN_BROKEN`        | `pre` references do not form valid chain to known state | 2+    |


### 17.4 Action Errors (Level 4+)

| Error                 | Condition                               | Level |
| --------------------- | --------------------------------------- | ----- |
| `UNAUTHORIZED_ACTION` | Action `typ` not permitted for this key | 5+    |

### 17.5 Error Handling Guidance

**Implementations MUST:**

- Reject transactions with any error condition
- Not apply partial state changes (atomic)

**Implementations SHOULD:**

- Return meaningful error identifiers to clients
- Distinguish between client errors (fixable) and server errors (retry)
- Log errors for debugging (optional but recommended)

**Implementations MAY:**

- Define additional application-specific error conditions
- Implement rate limiting for repeated errors

---

## 18. Test Vectors

These golden test vectors enable implementation verification. All values use B64ut encoding.

- `tmb` = SHA-256(canonical(`{"alg":"ES256","pub":"..."}`))
- ES256 uses P-256 curve, SHA-256 for `tmb`

### 18.1 Golden Key "User Key 0" (ES256)

```json
{
  "tag": "User Key 0",
  "alg": "ES256",
  "now": 1623132000,
  "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
}
```

#### 18.1.1 Golden Key: "User Key 1" (ES256)

```json5
{
  tag: "User Key 1",
  alg: "ES256",
  now: 1623132000,
  pub: "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
  prv: "dRlV0LjnJOVfK_hNl_6rjVKutZWTHNL-Vs4_dVZ0bls",
  tmb: "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
}
```

#### 18.1.2 Golden Key: Cyphrpass Server Key A (ES256)

```json5
{
  alg: "ES256",
  now: 1623132000,
  tag: "Cyphrpass Server Key A",
  tmb: "T0jUB_Bk4pzgvnNWMGfmV0pK4Gu63g_M08pu8HIUGkA",
  pub: "yfZ-PY4QdhWKJ0o41yc8-X9qnahpfKoTN6sr0zd68lMFNbAzOwj9LSVdRngno4Bs_CNyDJCQJ6uqq9Q65cjn-A",
  prv: "WG-hEn8De4fJJ3FxWAsOAADDp89XigiRajUCI9MFWSo",
}
```

### 18.2 Golden Message

The canonical Coz test message with verified signature:

```json
{
  "pay": {
    "msg": "Coz is a cryptographic JSON messaging specification.",
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/msg/create"
  },
  "sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"
}
```

**Computed digests:**
`cad` = SHA-256(canonical(`pay`)), `czd` = SHA-256(`[cad, sig]`)

- `cad`: `XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU`
- `czd`: `xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo`

### 18.3 Golden Nonce

"T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8"

### 18.4 State and Cryptographic Digest (Level 1 and 2)

For a single-key account with the golden key:

```
KS = tmb (implicit promotion)
AS = KS (no TS, no RS)
PS = AS (no DS)
PR = PS = "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
```

### 18.5 Transaction State (Level 3+)

Given a `key/create` transaction with `czd = "<transaction czd>"`:

```
TS = czd (single transaction, implicit promotion)
AS = MR(KS, TS)  # KS and TS are digests; sort by byte value, not label
PS = AS (no DS)
```

### 18.6 Implementation Notes

Follow the Coz spec.

- All signatures must be verified using the key's `alg`
- ECDSA signatures must be low-S normalized (non-malleable)
- `tmb`'s use the hash algorithm associated with `alg`
- State digests use the hash algorithm of the signing key

### 18.7 Integration Test Requirements

Language-agnostic test vectors are provided in `/test_vectors/`. Integration
tests consuming these vectors SHOULD:

1. **Validate fixture `pre` values**: Before applying a transaction, verify that
   the fixture's `pre` field matches the implementation's computed Auth State.
   If they differ, the test SHOULD fail immediately, indicating a fixture data
   error rather than an implementation bug.

2. **Use fixture values directly**: Tests should use the `pre`, `czd`, and other
   fields from fixtures directly, not compute substitutes. This validates both
   implementation correctness and fixture accuracy.

3. **Test all error conditions**: Error test fixtures intentionally include
   invalid data (wrong `pre`, unknown keys, etc.). Implementations MUST NOT skip
   these tests due to complexity.

4. **Deterministic sorting**: All state computations involving multiple
   components (KS with multiple keys, AS with KS+TS, etc.) MUST use
   lexicographic byte-order sorting of the raw digest bytes before concatenation
   and hashing.

**Rationale**: Multiple implementations (Go, Rust) consuming the same fixtures
ensures protocol specification correctness. Fixture validation catches spec
drift early.



## Suggested API
See also section "MSS".

Good practice for digest identifiers is prepending with Coz algorithm
identifier, e.g. `SHA256:<B64-value>`.

Since cryptographic digests are suitable, all `GETS` may simply be looked up by digest.
- `GET /<diget-value>`

- Alternatively, `e` for everything is suggest:

- `GET /e/<diget-value>`

**tip** - Gets the latest state for the principal

- `GET /tip?pr=<principal-root>`
  Returns the service's view of the tip (or latest known AS/PS digest) for the principal.

**patch** - Returns the service's view for the principal.

- `GET /patch?pr=<principal-root>&from=<ps>&to=<target-ps>` - Full form
- `GET /patch?from=<ps>` - From PS to current
- `GET /patch?pr=<principal-root>` from PR to current
- `GET /patch?pr=<principal-root>from=<ps>` from PS, for particular PR, to current
- `GET /patch?from=<ps>&to=<target-ps-or-empty>` - Range

`to` is optional and on omission is `tip`.
`pr` is optional since it should be included in patch. May be explicit for debugging.
`from` is optional if pr is given.

- `POST /push`
  Accepts one or more signed transactions (`tx_patch`). Service verifies chain validity and applies update.





---

## Cyphrpass Applications

- Cryptographically verifiable web archive
- Unstoppable, internet-wide user comments

## Appendix A: Coz Field Reference

| Field | Description                       |
| ----- | --------------------------------- |
| `alg` | Algorithm identifier              |
| `now` | UTC Unix timestamp                |
| `tmb` | Key thumbprint                    |
| `pub` | Public component                  |
| `prv` | Private component                 |
| `sig` | Signature                         |
| `rvk` | Revocation timestamp              |
| `typ` | Action type URI                   |
| `msg` | Human readable message            |
| `dig` | External content digest           |
| `cad` | Canonical hash of payload         |
| `czd` | Coz digest (hash of `[cad, sig]`) |



## Appendix B: See also

Ethereum wants to implement multihash:
https://ethresear.ch/t/multihashing-in-ethereum-2-0/4745

Merkle-tree-based verifiable logs

Keybase
Protocol Labs



