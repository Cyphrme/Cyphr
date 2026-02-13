# Cyphrpass

Protocol Specification

**Version**: Draft v0.1  
**Status**: Work in Progress  
**Authors**: Zamicol and nrdxp

Built on [Coz v1.0](https://github.com/Cyphrme/Coz)

QUICK AI Guidance:
DO NOT USE EM DASH OR DASH. Use period, comma, semi-colon, and other sentence construction appropriately.
DO NOT USE uppercase MAY, SHOULD, or MUST.  This isn't an IETF RFC.

---

## 1. Introduction

Cyphrpass is a self-sovereign, decentralized identity and authentication
protocol built on cryptographic Merkle trees. It enables:

- Password-free and email-free authentication via public key cryptography.
- Multi-device key management with revocation.
- Authenticated Atomic Actions (AAA) — individually signed, independently
  verifiable user actions.
- Cryptographic primitive agnosticism via the Coz JSON specification.
- Data Provenance.

Cyphrpass provides the authentication layer for the Internet.

| Feature             | Traditional Passwords/SSO     | Cyphrpass                                              |
| ------------------- | ----------------------------- | ------------------------------------------------------ |
| **Identity Factor** | Email, Password, or Provider  | Cryptographic Public Keys                              |
| **Verification**    | Centralized Database          | Independent (Merkle Tree & Coz Spec)                   |
| **State Tracking**  | Service-only (Centralized)    | Bidirectional (Mutual State Sync)                      |
| **Action Auth**     | Bearer Tokens (Session-based) | Authenticated Atomic Actions (AAA)                     |
| **Trust Model**     | Trusted Service               | Explicit Cryptographic Verification (Self-Sovereign)   |
| **User Recovery**   | Admin-reset or Email          | Cryptographic Key Revocation/Rotation, Social Recovery |

---

## 2. Core Concepts

### State Tree

The **state tree** is a hierarchical structure of cryptographic Merkle roots
that represents the complete state of a Principal (identity).

```text
Principal State (PS)
│
├── Commit State (CS) ─────────────── [Finalized Commit]
│   │
│   ├── Auth State (AS) ───────────── [Authentication]
│   │   │
│   │   ├── Key State (KS) ────────── [Public Keys]
│   │   │
│   │   └── Rule State (RS) ───────── [Permissions & Thresholds]
│   │
│   └── Commit ────────────────────── [Auth State Mutation]
│
└── Data State (DS) ───────────────── [User Data / Application State]
```

The **Commit chain** is the core of Cyphrpass. Each commit forms a node
referencing the prior commit.

```text

     PR/PS (Genesis)             PS (State 2)               PS (State 3)
   +-------------------+      +------------------+      +------------------+
   |                   |      |                  |      |                  |
   |   [CS]     [DS]   | ===> |   [CS]    [DS]   | ===> |   [CS]    [DS]   | ===> (Future)
   |      ^            |      |   |  ^           |      |   |  ^           |
   +------|------------+      +---V--|-----------+      +---V--|-----------+
          |                       |  |                      |  |
          + <------(pre)----------+  +------(pre)-----------+  +------(pre)------------

```

### 2.1 Terminology

Binary encoded values in this document are in `b64ut`: "Base64 URI canonical
truncated" (URL alphabet, errors on non-canonical encodings, no padding).

| Term                | Abv | Definition                                            |
| ------------------- | --- | ----------------------------------------------------- |
| **Principal**       | —   | An identity in Cyphrpass. Replaces "account"          |
| **Principal Root**  | PR  | The initial, permanent digest identifying a principal |
| **Principal State** | PS  | Specific top-level digest: `MR(CS, DS)` or promoted   |
| **Commit State**    | CS  | MR(AS, commit ID)                                     |
| **Auth State**      | AS  | MR(KS, RS) (Authentication state)                     |
| **Key State**       | KS  | Merkle root of active key thumbprints (`tmb`s)        |
| **Rule State**      | RS  | Merkle root of rules (Level 5)                        |
| **Data State**      | DS  | Merkle root of user data actions (Level 4+)           |
| **Tip**             | —   | The latest PS (digest identifier)                     |
| **Commit ID**       | —   | Merkle root of `czd` of all cozies in a commit        |
| **Action**          | —   | A signed coz, denoted by `typ`. Foundation of AAA     |
| **trust anchor**    | —   | Last known valid state for a principal                |

PR, PS, CS, AS, KS, RS, and DS are all Merkle root digest values.

Each digest corresponds to a tree datastructure: Principal Tree (PT), Commit
Tree (CT), Auth Tree (AT), Key Tree (KT), Rule Tree (RT), Data Tree (DT). (PT,
CT, AT, KT, RT, DT).  In addition to principal state, clients may track
principal non-mutating state (example, for proof of possession PoP). 

An action the `typ` of a signed coz. "Action" is the hypernym of commit
transaction coz and data action. A key and a rule is not an action, but the
cozies used to generate keys, rules, and data actions are actions.

Cyphrpass has six operational levels. See section "Levels" for more.

| Level | Description       | State Components             |
| ----- | ----------------- | ---------------------------- |
| **1** | Single static key | KS = AS = PS = PR            |
| **2** | Key replacement   | KS (single key, replaceable) |
| **3** | Multi-key/Commit  | KS (n keys) + CS             |
| **4** | Arbitrary data    | CS + DS → PS                 |
| **5** | Rules             | AS with RS                   |
| **6** | Programmable      | VM execution                 |

### 2.2 Implicit Promotion

When a component of the state tree contains only **one node**, that node's
value is **promoted** to the parent level without additional hashing.

**Examples:**

- Single key: `tmb` is promoted to KS, then AS, then PS, which equals PR on genesis.
- No DS present: AS is promoted to PS
- Only KS present (no RS): KS is promoted to AS

This rule simplifies single-key principals by eliminating the need for explicit
genesis transactions. Promotion is recursive; items deep in the tree can be
promoted to the root level. Implicit promotion applies to all entropic values:
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

A **nonce** is a high-entropy cryptographic random value used to add entropy and
ensure uniqueness in Cyphrpass. Unlike systems that rely on incrementing
counters to enforce “used only once” behavior, Cyphrpass is distributed and
cannot guarantee sequential uniqueness across principals. Instead, a
sufficiently large random value provides probabilistic uniqueness that is
guaranteed in practice.

Unless explicitly labeled, Cyphrpass is unable to distinguish a nonce for any
other node value.

One or more cryptographic nonces may be included at any level of the state tree:

- **Encapsulation**: Hides structure when desired
- **Reuse**: Allows one identity to be used by many accounts
- **Privacy**: Prevents correlation across services
- **Obfuscation**: Nonces are indistinguishable from key thumbprints and
  other digest values, so observers cannot determine the true count

Design Notes:

- Nonces, like all other node values, are associated with a hashing algorithm or
  a multihash. For example, `SHA256:<nonce_value>`. This keeps nonces opaque as
  needed and denotes a particular bit strength.
- Nonce values should be cryptographic randomly generated values must match the
  target strength of the associated hashing alg.
- Nonces may be implicitly promoted in the Merkle tree just like any other
  digest or entropic value.
- At any tree level, multiple nonces are permitted.
- For any opaque value, at signing, specific structure may need to be revealed,
  for example like keys
- Like other digest values, when calculating a new hashing algorithm value, new
  values are calculated from a prior value. (See section on digest conversion.)

As an aside, cryptographic signatures and other identifiers may act as an
entropy source, but that's outside of the scope of this document.

#### Digest

A digest is the binary output of a cryptographic hashing algorithm.

Good practice for digest identifiers is prepending with Coz algorithm
identifier, e.g. `SHA256:<B64-value>`. Without an algorithm identifier, the
system is as strong as the weakest supported hashing algorithm. When in a coz,
the digest's algorithm is assumed to aligned with alg in pay unless otherwise
noted.

However, systems like Cyphr.me have measures in place to protect against
collisions, so generally digest labels are not used in practice.

#### Identifier

All identifiers are encoded as b64ut. For MRs, if order is not otherwise given,
lexical byte order is used. Values are opaque bytes, meaning a sequence of bytes
that should be treated as a whole unit, without any attempt by the consuming
software to interpret their internal structure or meaning. Cyphrpass identifiers
are CID's, cryptographic Content IDentifiers. The identifier provides addressing
and cryptographically protects the integrity of the reference.

#### Commit

A commit is a finalized bundle of cozies that results in a new CS and thus a new
PS. Commits are chained together using references to prior commits through
`pre`.

#### Embedded Principal and Embedded Nodes.

Cyphrpass is a recursive tree structure. An **embedded principal** is a full
Cyphrpass identity embedded into another principal and an opaque node, which may
be a AS, KS, nonce, or other node value, is an **embedded node**. See section
on embedding.

#### Witnesses and Oracle

A **witness** is a client that keeps a copy of a principal's state. Clients may
transmit their state through a gossip protocol.

An **oracle** is a witness with some degree of trust delegated to that client.
For example, if a client does not want to verify all commits in a jump, that
client may delegate some processing to an oracle, where it is trusted that the
commits in the jump were appropriately processed.

#### Unrecoverable Principal

A principal with no active keys and no viable recovery path within the protocol.
Authentication, mutations, and recovery are impossible without out-of-band
intervention. See Section Recovery.

#### Reveal

The general principle of obfuscated structures becoming transparent is reveal.
Public keys must be revealed for verification; nonces and other data structures
may also need to be revealed during commits or other signing operations.

#### Coz Required fields:

- `alg`: Following Coz semantics, this the algorithm of the signing key, which
  also is paired to a hashing algorithm.
- `tmb`: Thumbprint of the signing key (must be in current KS)
- `now`: The timestamp of the current time. (Clients may reject messages with
  timestamps out of sync.)
- `typ`: Denotes the intent of the coz.

And for transaction cozies:

- `pre`: The identifier for the targeted commit to mutate.

---

## 3. Feature Levels

| Level | Description       | State Components             |
| ----- | ----------------- | ---------------------------- |
| **1** | Single static key | KS = AS = PS = PR            |
| **2** | Key replacement   | KS (single key, replaceable) |
| **3** | Multi-key/Commit  | KS (n keys) + CS             |
| **4** | Arbitrary data    | CS + DS → PS                 |
| **5** | Rules             | AS (with RS) + DS            |
| **6** | Programmable      | VM execution                 |

### 3.1 Level 1: Static Key

- Single key, never changes
- `PR = PS = AS = KS = tmb`
- No commit, no CS
- Use case: IoT devices, hardware tokens
- **Self-revoke**: A Level 1 key can self-revoke, but this results in permanent lockout (no recovery without sideband intervention)

### 3.2 Level 2: Key Replacement

- Single active key at any time
- `key/replace` swaps current key for new key
- CS is implicit at Level 2 (not stored in protocol)
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
- RS is a digest component of AS (like KS)
- Like all Cyphrpass values, it is sorted by digest value (bytes), not by label.

Level 5 Key concepts:

- **Weight**: Numeric value assigned to each key
- **Threshold**: Minimum total weight required for an action
- **Timelock**: Delay before certain actions take effect

### 3.6 Level 6: Programmable VM

- Introduces programmable rule execution
- Rules are executable bytecode stored in RS
- Enables: Complex conditional logic, programmable policies
- VM execution produces a deterministic state transition
- Use case: Smart contracts, complex organizational policies

---

## 4 Commit

A **commit** is a finalized atomic bundle containing one or more transaction
cozies. Many mutations may occur per commit, as dictated by the principal.
Unlike other systems, there are no minting fees, gas, or need for a global
ledger.

A commit contains cozies that mutate AS and forms a chain via the `pre` field.

- `pre`: The Commit State (CS) targeted for mutation.

# 4.1.0 Transaction Coz

Transactions are signed Coz messages that mutate Auth State (AS). A transaction
may be one or multiple cozies that results in a mutation. A transaction coz
contains `typ` which defines the purpose of the intent and `pre` containing the
identifier for the current commit.

For example, `typ` may be `<authority>/key/create` or similar key mutation type.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>", // Existing key
    "typ": "<authority>/key/create",
    "pre": "<current CS>",
    "id": "<new key's tmb>",
  },
  "sig": "<b64ut>",
}
```

When verifying, Cyphrpass clients must verify the transaction based on auth
state (key state, rule state). In addition to these required fields, various
`typ`s may require their own additional fields.

Following Coz semantics, all digest references in `pay`, such as `id`, must
align with `alg` unless explicitly labeled. For example, the `id` of the new key
must be `SHA256`, aligning with alg `ES256` unless explicitly labeled.

### 4.1.1 Transactions and Transaction Bundles

The transaction identifier is the Merkle root of `czd` for transaction cozies.

Many transactions may be included per commit. `pre` groups transactions and is
the identifier for transaction bundle, representing all transaction for a
commit. For example, a transaction bundle may have one transaction for
`key/update`, signed by two keys and containing two cozies, and one for
`key/create`, signed by one key and consisting of one coz.

### 4.2 DS inclusion (Stub)
DS may or may not be included in a transaction.  To explicitly include DS:

```json
{
  "pay": {
    alg: "ES256",
    now: 1736893000,
    tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    typ: "cyphr.me/cyphrpass/data/create",
    pre: "<prior CS>",
    new_ds: "<computed new DS MR>",
    commit: true
  },
  sig: "<b64ut>"
}
```

---

## 5. Genesis (Principal Creation)

### 5.1 Initial Commit

A principal is created (genesis) by its **genesis key**. Levels 1 and 2 have an
implicit genesis and levels 3+ have an explicit genesis.

**Implicit Genesis (Levels 1 and 2)**

- Multikey is not supported.
- The Principal exist with a single key. No commit required.
- `pr` == `tmb` of the single key (via implicit promotion, PR == PS == CS == AS == KS == `tmb`).

**Genesis AS implicit promotion To CS** On genesis only, since there is no commit, the prior
AS is the genesis key, which is then promoted to CS. `pre` must be the value of this key.

**Commit Genesis (Levels 3+)**
A commit genesis explicitly creates a stateful principal with a commit. Commit
genesis uses a bootstrap model, gracefully upgrading from level 1/2 to level 3:

1. First key is level 1+ and exists without a transaction. CS == AS == KS == `tmb`
   of the first key initially.
2. Additional keys, rules, or any other AS component (if any) require
   transactions with `pre` referencing the current CS. For example, for a second
   key, `key/create` contains `pre` referring to the first key's `tmb`.
3. `principal/create` finalizes the genesis commit. This establishes PR and
   marks the principal as created.

This design ensures every transaction (including genesis transactions) requires
`pre`, maintaining chain continuity from the moment the first key
exists.

**`typ`**: `<authority>/key/create`
- `id`: Thumbprint of key being added

**`typ`**: `<authority>/principal/create`
- `id`: Final Auth State (the PR to anchor)


### 5.1.2 Single Key Genesis
Outside of the cozies is `key`, which is the public key material. Note that it
is unsigned since it is outside of a coz, but the `tmb` is signed within the
coz.

```json5
{
  tx: [ // Always a list, even with one.
    {
      pay: {
        alg: "ES256",
        now: 1736893000,
        tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        typ: "cyphr.me/cyphrpass/principal/create",
        id: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // The bootstrap genesis key.
        pre:"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // Genesis Key
      },
      sig: "<source sig>",
    },
  ],
  key: { // key public material
    alg: "ES256",
    now: 1623132000,
    pub: "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
    tag: "User Key 0",
    tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
  },
}
```

### 5.1.2 Multi Key Genesis

Commit Genesis (Multi-Key, Multi-Transaction)

- Key signs a `key/create` transaction.
- That key then constructs the rest of the AS by adding other AS components. In
  this case, just adding another key.
- For all cases, `CS = MR(RS, KS(tmb₀, tmb₁, ..., nonce?))` CS is omitted since there are no prior transactions.
- The principal is created by `principal/create`.
- `pre` is omitted since there isn't a prior principal state until after the
  genesis `principal/create`.

```json5
{
  cozies: [
    {
      pay: {
        alg: "ES256",
        now: 1628181264,
        tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // The genesis key
        typ: "cyphr.me/cyphrpass/key/create",
        id: "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M", // The second key.
        pre:"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // Genesis Key
      },
      sig: "<b64ut>", // TODO actual sig
    },
    {
      pay: {
        alg: "ES256",
        now: 1736893000,
        tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        typ: "cyphr.me/cyphrpass/principal/create",
        id: "", // TODO calc CS (equal to AS) which is tmb MR
        pre:"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // Genesis Key
      },
      sig: "<source sig>",
    },
  ],
  keys: [ // Public keys material
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

### 5.2 Transaction Verbs Required Fields

Required fields for `create`, `delete`, `update`, `replace` auth transactions:

- `id`: The identifier for the noun. For example, for `key/create`, `id` is the key.
  `tmb` The identifier for the key.
- `pre`: The prior state of the auth, AS.

---

### 6 Key

Example private Coz key with standard fields:

```json5
{
  tag: "User Key 0", // Optional human label, non-programmatic.
  tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Key's thumbprint
  alg: "ES256", // Key algorithm.
  now: 1623132000, // Creation timestamp
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

#### 6.1 `key/create` — Add a Key (Level 3+)

Adds a new key to KS for an existing principal.

Note that `key` is included in the JSON payload, but not the signed payload, as
reference for client. The key may be transmitted through sideband or known
previously. This construction is good practice.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Signing `tmb`
    "typ": "cyphr.me/cyphrpass/key/create",
    "pre": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Targeted CS.  At genesis, CS == AS == KS == first key's tmb.
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M", // New key
    "commit": true
  },
  "key": {
    "alg": "ES256",
    "now": 1623132000,
    "tag": "User Key 1",
    "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
    "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M"
  },
  "sig": "<b64ut>" // TODO actual sig
}
```

#### 6.2 `key/delete` — Remove a Key (Level 3+)

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

- `id`: `tmb` of the key being removed

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/key/delete",
    "pre": "<targeted CS>",
    "id": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "commit": true
  },
  "sig": "<b64ut>"
}
```

#### 6.3 `key/replace` — Atomic Key Swap (Level 2+)

Removes the signing key and adds a new key atomically. Maintains single-key
invariant for Level 2 devices.

For level 2, `pre` is the `tmb` of the previous key. (CS == AS == KS == tmb)
For level 3+, `pre` is required.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // The existing key.
    "typ": "cyphr.me/cyphrpass/key/replace",
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M", // The second key's `tmb`
    "pre": "<targeted CS>" // In the case of level 2, CS is the previous `tmb`
  },
  "key": {
    "alg": "ES256",
    "pub": "<new key pub>",
    "tmb": "<new key tmb>"
  },
  "sig": "<b64ut>"
}
```

#### 6.4 `key/revoke` — Revoke a Key (Level 1+)

A revoke is a self-signed declaration that a key is compromised and should never
be trusted again. The key signing the revoke message must be the key itself.
Revoke is built into the Coz standard:

> A revoke is a self-signed declaration that a key is compromised. A Coz key may
> revoke itself by signing a coz containing the field `rvk` with an integer value
> greater than `0`. The integer value `1` is suitable to denote revocation and
> the current Unix timestamp is the suggested value.
>
> `rvk` and `now` must be a positive integer less than 2^53 – 1
> (9,007,199,254,740,991), which is the integer precision limit specified by
> IEEE754 minus one. Revoke checks must error if `rvk` is not an integer or
> larger than 2^53 - 1.

Example Naked Revoke:

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/key/revoke",
    "rvk": 1623132000,
    "msg": "Private key was uploaded to Github repo: cyphrme/cyphrpass"
  },
  "sig": "<b64ut>"
}
```

Note that `pre` is not required for a revoke. This is termed a **naked revoke**.
Third parties may sign the revoke, declaring the key compromised, without any
other knowledge of the principal state, and Cyphrpass must appropriately
interpret this event.

A revoke without a `pre`, or a revoke with a `pre` but without a subsequent
`delete`, puts the principal in an error state. See section Consensus for error
recovery, but in sort, when a principal receives a naked revoke, it should sign
a revoke including `pre` and a subsequent `key/delete` to remove the key from
the account for error recovery.

A revoke without a `pre` does not mutate PS. If a principal itself wants to
initiate a key revoke, it should sign a revoke with `pre` and a subsequent
`delete`, removing the key from the account.

A client may include `msg` detailing why the key was revoked. See also section
"Recovery" for principal lockout.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/key/revoke",
    "pre": "<targeted CS>",
    "rvk": 1623132000,
    "msg": "Private key was uploaded to Github repo: cyphrme/cyphrpass"
  },
  "sig": "<b64ut>"
}
```

#### 6.5 Key Transactions Summary

| Type          | Level | Adds Key | Removes Key | Notes                           |
| ------------- | ----- | -------- | ----------- | ------------------------------- |
| `key/revoke`  | 1+    | —        | ✓ (signer)  | Sets `rvk`, must be self-signed |
| `key/replace` | 2+    | ✓        | ✓ (signer)  | Atomic swap                     |
| `key/create`  | 3+    | ✓        | —           | —                               |
| `key/delete`  | 3+    | —        | ✓           | No revocation timestamp         |

### 6.6.0 Transaction Nonce

As explained in detail above, Cyphrpass uses nonces at every level. A new PS
may be generated through CS by signing a transaction nonce.

To delete a nonce, a `nonce/delete` is signed.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphrpass/nonce/create",
    "nonce": "T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8",
    "commit": true
  },
  "sig": "" // TODO
}
```

#### 6.6.1 Nonce path

Nonces may be inserted anywhere in the state tree. `typ` species the path. A
`nonce/delete`, where `id` == nonce removes the nonce.

`cyphrpass/nonce/create` // Principal (Root)
`cyphrpass/AS/nonce/create` // Auth State
`cyphrpass/AS/KS/nonce/create` // Key State

#### 6.6.2 Nonce as Opaque Value

Since nonces may be indistinguishable from other digest values, the may be
inserted into the state tree through normal creates.

`cyphrpass/key/create`
`cyphrpass/rule/create`

The client should keep the nonce value for reveal.

### 6.7 Data Action

Data Actions are stateless signed messages. They are simply signed by an
authorized key without chain structure:

- No prior field required (no `pre`)
- DS is computed from action `czd`s.
- Ordered by `now` and if needed lexical as tie-breaker.

This keeps actions lightweight for common use cases (comments, posts, etc.).

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

Data actions are ordered by `now`, and secondly by lexographical order, in the
Merkle tree.

---

## 7 Declarative Datastructure

Detailed in this document so far is iterative state mutation. Cyphrpass also
supports declarative mutation.

Transactional and declarative are isomorphic. The following is a client JSON
dump, which includes meta values and values that would be secrete to the client.

```json5
{
  "Principal_Tag":"Example Account",
  "PR":   "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",   // PR (permanent genesis digest)
  "PS":   "dYkP9mL2vNx8rQjW7tYfK3cB5nJHs6vPqRtL8xZmA2k=",

  // Digest Meta
  "PRE":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Targeted Commit
  "AS":"", // Auth State
  "KS":"", // Key State
  "CS":"", // Commit State  (the last transaction resulting in the current commit.)
  "RS":"", // Rule State
  "DS":"", // Data State

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
    "CT":[ // Commit tree
      {
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
        "now": 1623132000,
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // genesis key tmb
        "typ": "cyphr.me/cyphrpass/key/create",
        "id": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // genesis key tmb
        "pre": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // "pre" is the `tmb`, promoted to AS, then PR, since there is no nonce or other value.
        "commit":true
      },
      "sig": "<b64ut>" // TODO valid sig
    }
  ]

  "revoked_keys":[],
  "last_signed_now":000001 // Provides the ability to prevent signing too many auth mutations within a certain timeframe.
}
```

### 7.1 Declarative Transaction
Instead of imperatively creating principal state, state may be exhaustively
declared. Declarative data structures are are in JSON.

Since declarative transaction enumerate the full principal state, they
inherently act as checkpoints (see section Checkpoint). As always, the
declarative structure is compactified according to Coz.

Note that all client secretes are stripped before signing. (The Go/Rust
implementation accomplishes this by using types that preclude secretes.)

`cyphrpass/principal/checkpoint/create`

The declarative principal:

```json
{
"PT":{ // The actual Principal Tree, at the point of this commit
  "AT":{   // Auth Tree
    "KT": {
      "keys": [{
        "tag": "User Key 0",
        "alg": "ES256",
        "now": 1623132000,
        "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
        },{
        "tag": "User Key 1",
        "alg": "ES256",
        "now": 1623132000,
        "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
        "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
        }
      ],
    },
  }
}
```

Embedded into a coz transaction:

```JSON
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/checkpoint/create",
    "pre": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",  // Links to prior PS/AS for chain integrity
    "id": "<b64UT>",  // The computed AS of the declared state
    "PT": {...},
    "commit": true
  },
  "sig": "<b64ut>"
}
```


### 8 Level 5 Preview: Weighted Permissions

At Level 5, the Rule State (RS) introduces **weighted keys** and **timelocks**:

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
        now: 1623132000,
        tmb: "<signing key tmb>", // First Existing key
        typ: "<authority>/cyphrpass/key/create",
        pre: "<targeted CS>",
        id: "<new keys tmb>",
      },
      sig: "<b64ut>",
    },
    {
      pay: {
        alg: "ES256",
        now: 1623132000,
        tmb: "<signing key tmb>", // Second Existing key
        typ: "<authority>/cyphrpass/key/create",
        pre: "<targeted CS>",
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

## 9 Principal Root (PR)

The PR is the **first** PS ever computed for the principal. It is **permanent** and never changes.

**Genesis cases:**

- **Single key, no transactions, no nonce**: `PR = tmb` (fully promoted)
- **Multiple keys**: `PR = MR(tmb₀, tmb₁, nonce?, ...)`
- **With DS at genesis**: `PR = MR(AS₀, DS₀, nonce?)`

When a principal upgrades (e.g., adds a second key), the **PR stays the same**, only PS evolves.

### 9.1 Node Canonical Digest Algorithm

All state digests follow the same algorithm:

1. **Collect** component digests (including nonce if present).
2. **Sort** lexicographically (byte comparison).
3. **Merkle Root** Take the Merkle root of a binary node Merkle tree.

```
digest = MR(d₀, d₁, ...)
```

**Implicit Promotion**: If only one digest component exists, it is promoted without hashing.

### 9.2 Key State (KS)

```
if n == 1:
    KS = tmb₀                              # implicit promotion
else:
    KS = MR(tmb₀, tmb₁, nonce?, PS?, ...)
```

### 9.3 Principal State (PS)

```
if DS == nil :
    PS = CS                                # implicit promotion
else:
    PS = MR(CS, DS?, recursion? nonce?)
```

### 9.4 Auth State (AS)

AS combines authentication-related states:

```
if RS == nil:
    AS = KS                         # implicit promotion
else:
    AS = MR(KS, RS?,  nonce?)      # nil components excluded from sort
```

### 9.5 Commit State (CS)

Commit is the digest of all transaction `czd`s, and CS is the MR(AS, commit ID)

```
if no transactions:
    Commit = nil
elif 1 transaction:
    Commit = czd₀                              # implicit promotion
else:
    Commit ID = MR(czd₀, czd₁, nonce?, ...)
```

CS is inherently append-only. Unlike DS, which services may prune at
their discretion, removing transactions from CS would break chain integrity
verification. For high-volume principals, use checkpoints or state jumping (§16)
rather than pruning.

### 9.6 Data State (DS) — Level 4+

DS is the digest of all action `czd`s:

```
if no actions:
    DS = nil
elif 1 action && no nonce:
    DS = czd₀                              # implicit promotion
else:
    DS = MR(czd₀, czd₁, ..., nonce?)
```

### 10 Principal States

A Principal may be in different states, Active, Errored, Deleted, Frozen, and
Unrecoverable.

- **Active** - Principal state is normal.
- **Errored** - Principal state is errored. (Caused by an exception like signing
  an implicit fork.) See section Consensus.
- **Deleted**: The principal signed `principal/delete`. No new transactions or
  actions (including data actions) are possible, total immutability (Level 3+)
- **Frozen**: Principal has been frozen `freeze/create` and has not yet been
  unfrozen `freeze/delete`
- **Unrecoverable**: Principal cannot mutate AS, but may be able to perform DS
  actions. (Level 4+) An recoverable account is either dead or zombie based on
  the ability of doing DS actions, but that may not be known.
- **Dead** - An principal is dead if no transactions or actions possible (no
  transactions or data actions). This may be caused by signing a
  `principal/delete` or revoking/deleting all keys. Dead is a hypernym of
  deleted, nuked, and sometimes unrecoverable. A dead account may or may not
  have been deleted. Example: The only key is revoked. The account is
  unrecoverable and dead.
- **Zombie**: (Level 4+) An unrecoverable principal is a zombie if no new
  transactions are possible but some data actions are still possible. (Partial
  functionality remains) Example: `key/create` requires 2 points, but there's
  only one key with weight 1. `comment/create` requires default 1, so comments
  are still possible but AS mutation is impossible.
- **Nuked**: (Level 3+) All keys revoked (`revoke`), all keys deleted
  (`key/delete`), and the principal deleted (`principal/delete`). Nuked may be
  the hypernym of deleted, unrecoverable, and dead.

### 10.1 All Principals States

- Active
- Errored
- Deleted
- Frozen
- Unrecoverable
- Dead
- Zombie
- Nuked

---

### 11 Checkpoints

**Checkpoints** are self-contained snapshots of the authentication-relevant
state at a particular point in the chain, allowing verification from the
checkpoint forward without needing to fetch or replay earlier parts of the
history. Checkpoints do not rely on prior history to reconstruct AS (KS, CS, or
RS) as all required material is included directly. Checkpoints are implicit: any
signed transaction can serve as a checkpoint provided it contains all concrete
components necessary to recompute the AS at that point.

Each state digest (PS, AS) encapsulates the full state tree (PT, AT) at that
point. Verifiers only need the current state plus the transaction chain back to
a known good state, the trust anchor. Since chains may get long, clients may
issue checkpoint which contain the whole state without the need of transitive
transaction. Clients may update their trust anchor to a checkpoint for faster
client synchronization. (See section Declarative Transaction)

The genesis state is the foundational checkpoint; services may cache
intermediate checkpoints to reduce chain length for verification.

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
See also State Jumping


---

## 12 Embedding

An embedding is a digest reference. Embedding is the mechanism by which
Cyphrpass achieves hierarchy, delegation, and selective opacity (using nonces).

Recursive loops are generally discouraged. Embedding is transitive.

### 12.1 Embedded Principal

Cyphrpass permits a recursive tree structure. An **embedded principal** is a
full Cyphrpass identity embedded into another principal. An embedded principal
appears in the Merkle tree of another principal as the digest of its current
Principal State (PS) or Auth State (AS). Full subtrees are not inlined.

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

### 12.2.0 Embedded Node

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

### 12.2.1 Conjunctive Authorization

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

### 12.2.2 Meaningful Embeddings and Embedding Promotion

All nodes may be embedded into other nodes, but that embedding may not always be
meaningful. For example, a Rule State embedded into a Key State carries no
meaning. Clients should discourage such practice, but this may not be
enforceable due to opaqueness.

When a Key State(B) is embedded into another Key State(A), the keys from B are
be logically unioned to A. This is **embedded promotion**. Embedded promotion
applies to KS and DS.

### 12.3 Pinning

Pinned identifiers (prefixed with `PIN`, `PIN:<alg>:<value:`) denote static
states that prohibit updates, ensuring immutability for lookups. PR, PS, and AS
denote fetching. If a principal wants to denote a static state that does not
permit updating, a pin may be used.

A pin prefixes the digest value:

```
PIN:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg
```

---

### 13 `typ` Action Grammar

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


### Idempotency
All `create` operations in Cyphrpass are idempotent. If the target item (e.g.,
key, rule, principal) already exists, the operation fails. This applies
universally, not just to keys. `DUPLICATE`

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
    "now": 1623132000,
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
    "now": 1623132000,
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
    "now": 1623132000,
    "tmb": "<service key tmb>",
    "typ": "<service>/auth/token",
    "pr": "<principal root>",
    "exp": 1623132000,
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

---

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

Service operations:

- **Pruning**: Services may discard irrelevant user data (old actions, etc.)
- **Key recovery**: Services may assist in recovery flows (see Disaster Recovery
  section)
- **State resolution**: Services can provide transaction history for principals
  to verify

**Trust model:** Services are optional — principals can self-host or use
multiple services. Full verification is always possible with transaction
history.

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

---

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


## 10.2 Verification by a Third Party

To verify a principal's current state:

1. **Obtain PR or PS** — the claimed root (PR) or transitive state (PS).
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

Third parties that also forward principal state are witnesses.


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

## Witness Registration
A principal may have many clients.  The principal signs a message to inform
clients of the registration of external witnesses, which themselves are
represented as principals.  This message is not included in AS, and is instead
included in DS as a data action, so that PS may remain unmodified. 

`cyphr.me/cyphrpass/witness/register/create`: Value of the Principal's PR.

This message is transported to the external witness for registration.

The witness is removed with a `delete`. 

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


### State Resolution

To resolve from a **target AS** to a **prior known AS**:

1. Obtain current AS (from principal or trusted service)
2. Request transaction chain from target back to prior known (`pre`)
3. Verify `pre` references form unbroken chain
4. Validate each signature against KS at that point

Trust is optional — full independent verification is always possible.

## Witness Timestamps
Clients should record their own "first_seen" if the oracle has a date after
receipt.  If external witness timestamps are out of expected range, clients
should also record external witness timestamps.  This allows MSS to detect
conflict, dishonest behavior, and bugs.

---

## Consensus
### Consensus Philosophy

Cyphrpass is a self-sovereign protocol in which the principal is the primary
custodian of its own security and state. Consensus rules are deliberately
minimal. They detect and respond only to clear, cryptographically undeniable
violations such as invalid signatures, contradictions, and conflicting commits
that signal compromise, bugs, or attacks.

Consensus rules prioritize simplicity, determinism, and independent
verifiability by any witness, without requiring global coordination or a
blockchain-like mechanism. Security is largely delegated to the principal
itself, with witnesses (clients, services, oracles) enforcing basic invariants
to prevent propagation of invalid state. The design assumes principals generally
act honestly because repeatedly dishonest clients are dropped from gossip and
that principals control their keys.

Consensus is intentionally "shades of grey" rather than strict black-and-white.
The design accommodates diverse implementations (including smart-contract
clients on external hosted blockchains) and accepts that incompatibility between clients can be
an intentional choice. This consensus model also permits logical deduction.
Retained errors and timestamps serve as transparent signals of client honesty.
It represents a fundamentally different philosophy: consensus emerges from what
actually occurred and who published what when, not strictly from coordinated
rule enforcement or majority vote, and opens the door for intelligent agents to
detect violations through reasoning instead of strict rule matching.

Although outside of the scope of this document, consensus rules attempt to
accommodate a wide set of circumstances and implementation, and should assume
minimal control of implementation.  Consensus rules accommodate as best as
possible such situations, but acknowledge that various circumstances may result
in client incompatibility, which may be an intentional decision by principals.

For conflict resolution beyond consensus rules, see section "Recovery".

### Proof of Error

All messages in Cyphrpass are signed by the principal, making errors auditable
and attributable. Witnesses may retain invalid messages as **proof of error**, a
signed message demonstrating bad behavior (e.g., an invalid signature or
conflicting commit). This proof can be shared via gossip, **proactive error
sharing**, presented during recovery/escalation, or retained until resync error
resolution. For example, during an implicit fork, a witness may retain both
conflicting transactions as proof of compromise and broadcast them to other
witnesses or the principal for resolution.  Proof of error is a hypernym of
"fraud proof" and "fault proof". Proof of error is powerful: security may be
improved from game theory or novel mechanisms.  Exhaustive detailing is outside
the scope of this document, but the authors acknowledge its potential in
security distributed systems.

### Resync

**Resync** lets a witness advance from a known good trust anchor to the current
tip by fetching and verifying the delta (tx_patch) and may be triggered manually
or automatically.  

1. **Select Trust Anchor**  Select trust anchor (trusted PS, AS, or PR).
2. **Fetch Delta (Patch)** Request minimal patch with GET
   /patch?from=<anchor-PS>&to=<tip-or-empty> or GET
   /patch?pr=<PR>&from=<anchor-PS>.
3. **Verify Patch**  Independently verify the patch for valid pre chaining,
   signing keys that were active with no revocation in path, computed
   intermediate and final PS that match claims, correct timestamps, thresholds
   (Level 5+), and no forks.
4. **Apply and Progress Trust Anchor**  On success, apply patch, update local
   state, and promote new PS to trust anchor.

Witnesses should use an exponential backoff cooldown for repeated resync
attempts to prevent denial-of-service. Clients should gossip tip to other
clients to ensure a uniformed presentation of the principal, especially after
long offline periods.

Many transient errors resolve via resync. Persistent failure escalates to
errored state or ignore.

#### Resync PoP

A principal may re-iterate an existing state as authoritative without mutating
PS/AS/CS through a resync POP.
- **PoP Confirmation**: To accelerate resync or confirm intent, the principal
  may perform a Proof of Possession (PoP) by signing a challenge message (e.g.,
  `typ: "cyphr.me/cyphrpass/resync/create"`) with an active key. This helps
  distinguish transient errors from genuine issues.

Resync PoP is also useful for expired timestamps.  When a client has been
offline, but the principal issue a transaction a while ago, a Resync PoP may
confirm current possession without mutating PS.  Clients should also gossip
these timestamps to other clients that were online to verify integrity.

Local clients track their own last operation timestamp (written to disk) to
detect offline periods and decide when a Resync PoP is needed.  Local clients
should also add their own timestamps to the receipt of principal messages.

### Principal Consensus States

In addition to principal base states (see "Principal States" for base states
like Active, Errored, etc.) witnesses independently track principal consensus
states. Witnesses may escalate ignored/resync errors to error state after
repeated failures (e.g., >3 attempts).

- **Active**: Client is Normal
- **Pending**: Message requires more context before principal mutation
   (incomplete transaction) may or may not be gossiped. 
- **Resync**: Attempt automatic recovery before escalating. 
- **Offline**: Failed to communicate with principal.  Client should timestamp "Offline Since".
- **Error**: Mark the principal as errored for severe violations
  or if resync repeatedly fails. No new transactions or actions are processed
  until resolved (e.g., via recovery or resync). 
- **Ignore**: Silently discard messages without state change.
- **Client Mismatch**:
When a witness sees an error but the principal’s client insists the message is
valid, mark principal as CLIENT_MISMATCH. This usually indicates a bug, version
skew, or intentional divergence. Witnesses may reject interaction until
resolved.

For individual messages:
- **Forward**: Gossip to local clients.
- **Hold Local**: Message is incorrect, is held locally, and not forwarded in the gossip.
- **Error**: Message is incorrect.
- **Proof of Error**: 

Errors:
- `INVALID_SIGNATURE`: Transaction signature fails verification.
- `INVALID_CONSTRUCTION`: Malformed coz or transaction (e.g., missing fields).
- `KEY_REVOKED`: Signing key has `rvk` set.
- `MULTIHASH_MISMATCH`: Computed digests do not match claimed values.
- `CHAIN_BROKEN`: Cannot calculate tip from prior trust anchor.
- `FORK`: An implicit fork.  Resolved by resync or see section Recovery.
- `INVALID_PRIOR`: `pre` chain invalid or incomplete.
- `UNKNOWN_KEY`: `tmb` not in KS.
- `UNKNOWN_ALG`: Unsupported algorithm.
- `MESSAGE_TOO_LARGE`: Payload exceeds limits.
- `TIMESTAMP_PAST`: `now` < latest known timestamp.
- `TIMESTAMP_FUTURE`: `now` > witness time + tolerance.
- `TIMESTAMP_OUT_OF_RANGE`: `now` outside global tolerance (e.g., > 1 year in
  future).
- `THRESHOLD_NOT_MET` (Level 5+) 
- `MALFORMED_PAYLOAD`
- `JUMP_INVALID`: State jump fails (e.g., revoked key in path).
- `IMPLICIT_FORK`: Conflicting commits (see below).
- `DUPLICATE`: `*/create` for existing items. Cyphrpass `create` is idempotent.
- `STATE_MISMATCH`: Computed PS/AS differs from claimed.


### Consensus and Witnesses

Cyphrpass assumes a single linear chain per principal. An implicit fork occurs
when two or more conflicting commits reference the same pre (prior AS),
violating this assumption.

- Ignoring the message
- Escalation (e.g., freeze the principal temporarily until resolved) or
- Holding the message as Proof of Error.

Rejection is auditable: Witnesses log the reason (e.g., INVALID_SIGNATURE) and
may broadcast it via gossip for other witnesses to confirm.

### Implicit Forks, Fork Detection, and Duplicitous Behavior
An implicit fork occurs when two or more commits reference the same pre,
violating the single-chain rule. Quick succession (e.g., within timestamp
tolerance, ±60s) is strong evidence of compromise (e.g., two devices signing
conflicting mutations simultaneously).  Witnesses should keep such transaction
as proof of error. 

Witnesses detect forks via mismatched tips in gossip, inconsistent /patch
responses, and conflicting signed proofs.

Response includes broadcast fork proof and rejection of both branches until
resolved (for example principal/merge, revocation, or multi-sig confirmation in
Level 5+).

Fork Resolution: TODO finish
- Sign a resync PoP
- Select by building on the correct chain.

## Timestamp Verification

Compromised keys can produce backdated or future-dated messages. Mitigation
includes comparing now to witness time on receipt and rejecting outside ±360 s
default tolerance, tracking latest known timestamp per principal from the most
recent valid message, rejecting any now earlier than latest known timestamp to
prevent history rewriting, and rejecting future-dated messages.

Clients maintain their own persistent last-seen timestamp to detect offline
periods and trigger Resync PoP when rejoining. Time servers can be compromised.
Cyphrpass remains durable by relying on relative ordering and possession proofs
rather than absolute trusted time.

---

## 11. Recovery

## Resync and Recovering from Trust Anchor (Last Known Good State)

When a third party is out of sync or divergent from the principal state, the
third party may recover from the the trust anchor, resync.  See section Consensus Resync.

An unrecoverable principal is where:

- No useful active keys remain (all revoked or otherwise inaccessible),
- No designated recovery agents or fallback mechanisms are present or able to
  act,
- The principal AS cannot be mutated. No new transactions are possible via the
  protocol (although some data actions may be possible),
- And recovery is impossible within the Cyphrpass protocol rules (i.e.,
  requires sideband intervention).

For unrecoverable principals, none of the self-recovery mechanisms listed can prevent or reverse an
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

**Sideband Recovery Examples** An example of sideband recovery would be having
physical access or SSH access to the device with the unrecoverable principal,
deleting the old key replacing it with a new key, and updating the public key on
services that communicate to that device.

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
| Level | Fallback Value | Description |
| ----- | -------------- | ---------------------------------------------------------- |
| 1 | — | No recovery support (static key) |
| 2 | `tmb` | Backup key thumbprint |
| 3+ | `PS` | External Principal recovery agent (with rules or defaults) |

**Notes:**

- The `fallback` field is not included in `tmb`'s calculation (allows changing
  fallback without changing identity)
- Assumes a trusted initial setup
- **Level 2 Restriction**: Level 2 accounts only support **atomic swap**
  (`key/replace`). The fallback functionality must adhere to this, replacing the
  lost key rather than complying with `key/create` like Level 3+.

#### 11.4.1 Recovery Validity 

Ideally, recovery agents only act when the account is in an unrecoverable state,
however, the unrecoverable state may not be definitively known or verifiable by
the protocol, such as in the case with lost keys.

Principals should create recovery circumstances carefully. The protocol does not
enumerate these conditions here; they are defined by principal rules at the time
of the attempted recovery.

### 11.5 Recovery Transactions

#### 11.5.1 `cyphrpass/recovery/create` — Register Fallback

Registers a recovery agent (backup key, service, or social contacts).

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/cyphrpass/recovery/create",
    "pre": "<targeted CS>",
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
    "now": 1623132000,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/recovery/delete",
    "pre": "<targeted CS>",
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

This initializes a new Principal State (PS) that is manually linked to the
previous state by the Recovery Authority. The new PS is not cryptographically
linked to the previous state, but it is manually linked to the original PR by
the Recovery Authority's recovery transaction.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<recovery agent tmb>",
    "typ": "<authority>/key/create",
    "pre": "<targeted CS>",
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

A **freeze** is a global protocol state where valid transactions are temporarily
rejected to prevent unauthorized changes during a potential compromise. A freeze
halts all key mutations (`key/*`) and may restrict other actions depending on
service policy.

Freezes are **global** — they apply to the principal across all services that
observe the freeze state.

#### 11.9.1 Self-Freeze

A user may initiate a freeze if they suspect their keys are compromised but do not yet want to revoke them (e.g., lost device).

- **Mechanism**: User signs a `cyphrpass/freeze/create` transaction with an active key.
- **Effect**: Stops all mutations until unfrozen.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/cyphrpass/freeze/create",
    "pre": "<targeted CS>"
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

#### 11.9.3 Unfreeze (Thaw)

To unfreeze an account, a `cyphrpass/freeze/delete` is signed:

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/cyphrpass/freeze/delete",
    "pre": "<targeted CS>"
  },
  "sig": "<b64ut>"
}
```

**Rules:**

- Self-freeze can be unfrozen by active keys.
- External freeze requires the Recovery Authority to thaw (or the principal after a timeout, if configured)

### 11.10 Security Considerations

- **Timelocks (Level 5+):** Recovery can have a mandatory waiting period.
- **Revocation:** Backup keys can be revoked if compromised.
- **Multiple agents:** A principal may designate multiple fallback mechanisms, including M-of-N threshold requirements
- **Freeze abuse:** External freeze authority requires explicit delegation and trust

### 11.11 Append Only Verifiable Logs

Cyphrpass's commit chain forms a verifiable, append-only log of state mutations.
Each commit references the prior via pre and is anchored in the Merkle root
(MR), enabling efficient verification of history without full chain replay. This
supports tamper-evident auditing and is useful for compliance requirements, such
as regulatory record-keeping or forensic analysis.


### 11.12 Retroactivity (Reversion, Retrospection)

Retroactivity is undoing actions to a given timestamp. This is a complex issue
for services.  

Unlike Git, and outside of consensus, Cyphrpass does not use reversion, that is
undoing past actions.  Instead, clients should mutate their state using the
appropriate verbs, `create` and `delete`, as needed for a targeted state. 

For example, even though a `key/revoke` can be postdated to the time of an
attack, Cyphrpass should interpret transaction based on current `now` and not
`rvk`.

If an attacker gains access to keys and is able to sign actions unauthorized by
the agent represented by the Principal, when the Principal regains control, they
may want to undo these actions.  Instead of retrospectively marking revokes,
Principals must explicitly mutate their state forward.  

**Retrospection Attack**: An attacker uses retroactivity to undo legitimate
Principal actions.

As a matter of bookkeeping, a client may mark past actions as disowned,
expressing the intent of the Principal to mark that action as unintentional.
However disowning does not mutate AS.


## 12. Close, Merge, Fork

### 12.1 Closing an Account (Principal Delete, Level 3+)

Closing an account is performed via a `principal/delete` transaction. Closed
accounts are permanently closed and cannot be recovered. No transactions or
actions are possible on a closed account. However, the protocol does not prevent
a user from creating a new principal reusing the existing keys, unless those
keys were revoked.

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

To ensure that no aspect of a deleted principal may be reused, an account may be
"nuked", all keys revoked, then deleted, and then the principal deleted. This
ensures that no new principal may be created reusing existing principal keys.

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

### 12.3 Principal Forking (Account Fork, Level 3+)

Forking allows one principal (the **source**) to create a new principal (the
**target**), effectively splitting identities while preserving the source's
original PR a new PR for the target. A fork is created by signing
`cyphrpass/principal/fork/create` and adding at least one key. This transaction
bundle is equivalent to a genesis transaction.

Why does forking exist if a new PR can be generated at any time? The fork may
want to preserve prior identity and history. Since PR must resolve to one and
only one principal account, PR itself cannot be used as the identity for
multiple accounts. A fork allows the new principal to maintain history while
creating a new identity.

Sharing Keys: Nothing in Cyphrpass stops various principals from sharing keys.
Any set of keys that has not been revoked may be used to create a new PR, this
includes reusing keys from the source principal. The fork may declare new keys
or reuse existing keys.

For "bad faith" forking, see section "Consensus".

```json
{
  "cozies": [
    {
      "pay": {
        "alg": "ES256",
        "now": 1736893000,
        "tmb": "<signing tmb>",
        "typ": "cyphr.me/cyphrpass/principal/fork/create",
        "pre": "<common AS>",
        "fork_pr": "<fresh PR digest, which in this case is just KS>"
      },
      "sig": "<b64ut>"
    },
    {
      "pay": {
        "alg": "ES256",
        "now": 1623132000,
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        "typ": "cyphr.me/cyphrpass/key/create",
        "id": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        "pre": "<key bundle>"
      },
      "sig": "<b64ut>"
    },
    {
      "pay": {
        "alg": "ES256",
        "now": 1623132000,
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        "typ": "cyphr.me/cyphrpass/key/create",
        "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
        "pre": "<key bundle>",
        "commit": true
      },
      "sig": "<b64ut>"
    }
  ],
  "keys": [
    {
      "tag": "User Key 0",
      "alg": "ES256",
      "now": 1623132000,
      "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
      "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
    },
    {
      "tag": "User Key 1",
      "alg": "ES256",
      "now": 1768092490,
      "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
      "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M"
    }
  ]
}
```

---

## 14. Multihash Identifiers

In Cyphrpass, cryptographic algorithms are pluggable: no single cryptographic
primitive is exclusively authoritative or tightly coupled to the architecture.
This enables flexibility in algorithm choice, security upgrades, and rapid
removal of broken algorithms.

Instead of identifiers being tightly coupled to a single digest, identifiers are
coupled to an abstraction named a **multihash identifier**, a set of equivalent
digests, one per supported hash algorithm at commit time.

No single algorithm is canonical. All variants in a multihash identifier are
considered equivalent by Cyphrpass; security judgments are out-of-scope.

A multihash identifier is calculated for all state (e.g. PR/PS, KS, CS, and
Merkle tree nodes) on a per commit basis. States are singular, having a singular
underlying structure, but may be referenced via multiple hashing algorithms.

For a particular commit, for each algorithm supported by any key, nonce, or
embedded node in KS, a digest value is calculated. When only one algorithm is
used, the multihash has only one variant. When multiple algorithms are used, the
multihash has many variants, many digest identifiers. For example, if the set of
keys supports SHA-256 and SHA-384, then both a SHA-256 and a SHA-384 digest is
calculated. If the keys support only SHA-256, then only a SHA-256 digest is
calculated.

A nonce (or multiple nonces) can be used to inject a specific digest algorithm
variant into the multihash identifier, even when no key supports that algorithm
natively. This is because a nonce itself is associated with a hashing algorithm
or multihash identifier.

In summary:

- PR, PS, AS, KS and nodes in the Merkle Trees are singular underlying states.
- Each can be referenced by multiple variants, one per hash algorithm.
- Cyphrpass makes no relative security judgements. All variants are considered
  equivalent references.
- Digests are computed for hashing algorithms associated with all currently active keys.
- When an primitive algorithm is removed, its algorithm's hash is no
  longer computed. When a primitive algorithm is added, its algorithm's
  variant begins being computed.

### 14.1 Algorithm Mapping

Each key algorithm implies a hash algorithm, as defined by Coz.

| Key Algorithm | Hash Algorithm | Digest Size | Strength Category |
| ------------- | -------------- | ----------- | ----------------- |
| ES256         | SHA-256        | 32 bytes    | 256-bit           |
| ES384         | SHA-384        | 48 bytes    | 384-bit           |
| ES512         | SHA-512        | 64 bytes    | 512-bit           |
| Ed25519       | SHA-512        | 64 bytes    | 512-bit           |

### 14.2 Conversion

To support upgrades and embedded principals/nodes, values from one digest
algorithm may be **converted** as input to another. Conversion happens at the
node level and the parent node isn't required to know of the child node's
conversion.

For example, in a Merkle tree with a SHA-384 node (A) and SHA-256 node (B), a
SHA-384 root is: MR_SHA384(SHA384(A), B)—B's value is fed into the hashing
algorithm first before being inputted into the MR.

As a consequence of this design, for each algorithm, every node may have an
identifier for that hashing algorithm.

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
          │               SHA-384(Node B)
          │                       │
   ┌─────────────┐         ┌─────────────┐
   │   Node A    │         │   Node B    │
   │  (SHA-384)  │         │  (SHA-256)  │
   └─────────────┘         └─────────────┘
```

### 14.3 Conversion Security Considerations

Conversion is not ideal, but is unavoidable for pluggability and
recursion/embedding. Implementors must be aware that inner nodes may have
different security levels than the lookup node; the overall tree is bounded by
the weakest link.

Algorithm diversity aids durability but risks misuse. For uniform security, use
keys from one strength category. If an algorithm is weakened, Coz will mark it
deprecated; principals should discontinue via key removal.

### 14. Multi Hash Merkle Root (MHMR) Algorithm

The **Multi Hash Merkle Root (MHMR)** algorithm is used to compute every digest
in the Cyphrpass state tree (PR/PS, CS, AS, KS, RS, DS, and all internal Merkle
tree nodes) when multiple hash algorithms may be in use.

MHMR is computed with respect to a **target hash algorithm** H. The target H is
determined per commit as follows:

- H is one of the hash algorithms associated with any currently active key in KS
- When multiple hash algorithms are supported, implementations must compute an
  MHMR variant for each supported H.
- A multihash identifier for a node/state therefore consists of one digest per
  supported H at the time of the commit.
- All MHMR variants are considered equivalent references to the same logical
  state.

#### MHMR Computation

Given an ordered list of child digests (each child is a binary digest value
computed under some hash algorithm):

1. **Sort** the child digests in **lexical byte order** (treating them as opaque
   byte sequences, independent of their original hash algorithm).
2. **Single child (implicit promotion)**:  
   If there is exactly one child digest, the MHMR_H for any target H is simply
   the bytes of that child digest (no hashing occurs). Promotion is recursive.
3. **Binary Hashing of Children**:
   Concatenate the sorted child digest bytes in order.  
   Compute MHMR_H = H( concatenated bytes ).

#### Examples

| Case                         | Children                                 | Target H | MHMR_H Computation                        | Result             |
| ---------------------------- | ---------------------------------------- | -------- | ----------------------------------------- | ------------------ |
| Single child (promotion)     | B (32-byte SHA-256)                      | SHA-384  | — (implicit promotion)                    | B bytes (32 bytes) |
| Two children, different algs | A (48-byte SHA-384), B (32-byte SHA-256) | SHA-384  | sort(A,B) → assume A < B → SHA-384(A ∥ B) | 48-byte digest     |
| Two children, same alg       | C, D (both SHA-256)                      | SHA-256  | sort(C,D) → SHA-256(C ∥ D)                | 32-byte digest     |
| Three children               | A (SHA-384), B (SHA-256), E (SHA-512)    | SHA-512  | sort(A,B,E) → SHA-512(sorted concat)      | 64-byte digest     |

#### Important Properties

- **No re-hashing of children**: Inner digests are fed directly into the parent
  hash function as raw bytes (unless being converted, where the node is hashed first).
- **Byte-order determinism**: Lexical byte sorting ensures consistent ordering
  regardless of how children were labeled or enumerated.
- **Security bounded by weakest link**: The strength of any MHMR_hash variant is
  limited by the weakest hash algorithm appearing anywhere in the subtree below
  it.
- **Nonce injection**: A nonce carrying a desired hash algorithm can be inserted
  as a child to force computation of that algorithm variant even if no active
  key natively supports it.



#### Rationale

The MHMR design achieves three simultaneous goals:

1. Cryptographic pluggability without algorithm lock-in
2. Support for embedded principals and recursive structures
3. Backward- and forward-compatibility during algorithm transitions

Implementations must compute MHMR variants for every hash algorithm currently
supported by active keys (and any nonce-injected algorithms) at each commit.
When an algorithm is deprecated or removed from support, its MHMR variant is no
longer generated for new commits.

All references to state (PR/PS, CS, AS, KS, RS, DS, etc.) in protocol messages, storage,
gossip, and verification use one of these multihash variants. Equivalence across
variants is assumed by the protocol; no relative strength ordering is enforced
at the protocol level (see §14.4 Rank for tie-breaking considerations).

### 14.4 Rank

When multiple algorithms are supported, there may be a tie at the time of
conversion. Cyphrpass provides a default rank. Rank is a tiebreaker only and
not a security indicator. Misuse can have security implications.

Perhaps in the future, principals may set a rank order via
`cyphrpass/alg/rank/create` transaction (stored in AS as a rule), but for now
this is out-of-scope.

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

## 16 Cyphrpass Type System and Ownership

Cyphrpass's `typ` as an alternative to HTTP semantics.

Cyphrpass's `typ` naming convention is not just a naming convention, it's a
deliberate design choice that shifts how we think about invoking actions,
addressing resources, and expressing intent in a cryptographically native,
decentralized way which is realized in Authenticated Atomic Action.

### `typ` as a Unified Intent + Resource + Verb Descriptor

In 1968 there was the "Mother of all demos", demonstrating the GUI, mouse, and other computer
basics. In 1988 was HTTP, which with other components was the creation of the
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
acknowledges that rules must be implemented by an authority. (In the case of
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
key update? For that reason, updates with new keys outside of principal should
fail and transfer explicitly used for transfer.

### Where Cyphrpass Diverges from Being a Full HTTP Replacement

Cyphrpass's `typ` + Coz model isn't a wire replacement for HTTP. Instead it offers an **alternative interaction model**:

| Aspect           | HTTP                       | Cyphrpass `typ` + Coz Model                             |
| ---------------- | -------------------------- | ------------------------------------------------------- |
| Addressing       | URL + method               | `typ` string (authority + noun/verb)                    |
| Authentication   | Headers / tokens / cookies | Embedded PoP (signature over the whole intent)          |
| State management | Server-side sessions       | Client + service mutual sync of auth chain              |
| Mutability model | CRUD on resources          | Append-only transactions + signed actions               |
| Verifiability    | Mostly server-trusted      | Anyone can verify any action historically               |
| Transport        | Usually TLS + HTTP         | Can be sent any way (TLS, HTTP, IPFS, email, gossip...) |
| Response model   | Status + body              | Tip, another signed Coz                                 |

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
- Services may require additional proofs (e.g., Merkle inclusion of unchanged KS
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
    now: 1623132000,
    tmb: "<active key tmb from anchor>",
    typ: "cyphr.me/cyphrpass/principal/state_jump/create",
    pre: "<old trust anchor CS>", // e.g., CS at previous trust anchor
    jump_to_ps: "<current tip CS>", // e.g., CS at transaction 100,000
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

This section defines error conditions that implementations must detect. Error
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
| `UNRECOVERABLE_PRINCIPAL` | No keys capable of transaction and no designated recovery agents | All   |
| `RECOVERY_NOT_DESIGNATED` | Agent not registered via `cyphrpass/recovery/create`             | 3+    |

### 17.3 State Errors

| Error               | Condition                                               | Level |
| ------------------- | ------------------------------------------------------- | ----- |
| `STATE_MISMATCH`    | Computed PS does not match claimed PS                   | All   |
| `HASH_ALG_MISMATCH` | Multihash variant computed with wrong algorithm         | All   |
| `ALG_INCOMPATIBLE`  | Referred `alg` is not supported                         | All   |
| `CHAIN_BROKEN`      | `pre` references do not form valid chain to known state | 2+    |

### 17.4 Action Errors (Level 4+)

| Error                 | Condition                               | Level |
| --------------------- | --------------------------------------- | ----- |
| `UNAUTHORIZED_ACTION` | Action `typ` not permitted              | 5+    |

### 17.5 Error Handling Guidance

**Implementations must:**

- Reject transactions with any error condition
- Not apply partial state changes (atomic)

**Implementations should:**

- Return meaningful error identifiers to clients
- Log errors for debugging (optional but recommended)

**Implementations may:**

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

Computed digests, where `cad` = SHA-256(canonical(`pay`)), `czd` = SHA-256(`[cad, sig]`)

- `cad`: `XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU`
- `czd`: `xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo`

### 18.3 Golden Nonce

"T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8"

### 18.4 State and Cryptographic Digest (Level 1 and 2)

For a single-key account with the golden key:

```
KS = tmb (implicit promotion)
AS = KS (no CS, no RS)
PS = AS (no DS)
PR = PS = "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
```

### 18.6 Implementation Notes

Follow the Coz spec.

- All signatures must be verified using the key's `alg`
- ECDSA signatures must be low-S normalized (non-malleable)
- `tmb`'s use the hash algorithm associated with `alg`
- State digests use the hash algorithm of the signing key

### 18.7 Integration Test Requirements

Language-agnostic test vectors are provided in `/test_vectors/`. Integration
tests consuming these vectors should:

1. **Validate fixture `pre` values**: Before applying a transaction, verify that
   the fixture's `pre` field matches the implementation's computed Auth State.
   If they differ, the test should fail immediately, indicating a fixture data
   error rather than an implementation bug.

2. **Use fixture values directly**: Tests should use the `pre`, `czd`, and other
   fields from fixtures directly, not compute substitutes. This validates both
   implementation correctness and fixture accuracy.

3. **Test all error conditions**: Error test fixtures intentionally include
   invalid data (wrong `pre`, unknown keys, etc.). Implementations must not skip
   these tests due to complexity.

4. **Deterministic sorting**: All state computations involving multiple
   components (KS with multiple keys, etc.) must use lexicographic byte-order
   sorting of the raw digest bytes before concatenation and hashing.

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
- "Bittorrent for social media".

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

Algorithm governance is delegated to Coz. Weak algorithm sunsetting is handled
by Coz and is inherited by Cyphrpass. Implementations should warn and
appropriately remove support for deprecated algorithms.

## Appendix B: See also

Ethereum wants to implement multihash:
https://ethresear.ch/t/multihashing-in-ethereum-2-0/4745

Merkle-tree-based verifiable logs

Keybase
Protocol Labs

## Appendix C: Prior Art

- Coz
- Bitcoin
- Ethereum
- PGP
- SSH
- SSL
- SSHSIG and signify (OpenBSD)
- Secure Quick Reliable Login (SQRL) (https://www.grc.com/sqrl/sqrl.htm)
