# Cyphrpass

Protocol Specification

**Version**: Draft v0.1  - Work in Progress  
**Authors**: Zamicol and nrdxp

Built on [Coz v1.0](https://github.com/Cyphrme/Coz)


---


## 1. Introduction

Cyphrpass is a self-sovereign, decentralized identity and authentication
protocol. Cyphrpass provides an authentication layer for the Internet. Briefly,
it enables:

- Password-free and email-free authentication via public key cryptography.
- Authenticated Atomic Actions (AAA): individually signed, independently
  verifiable user actions.
- Cryptographic primitive agnosticism (via Coz, multihash, and MultiHash Merkle Root MHMR).
- Multi-device key management with revocation.
- Data Provenance.

| Feature             | Cyphrpass                                   | Legacy Passwords/SSO          |
| ------------------- | ------------------------------------------- | ----------------------------- |
| **Identity**        | Cryptographic Public Keys and Merkle Root   | Email, Password, or Provider  |
| **State Tracking**  | Bidirectional - Mutual State Sync (MSS)     | Service-only (Centralized)    |
| **Authentication**  | Authenticated Atomic Actions (AAA)          | Bearer Tokens (Session-based) |
| **Trust**           | Cryptographic Verification (Self-Sovereign) | Trusted Service               |
| **Verification**    | Independent (Signatures and Merkle Trees)   | Centralized Database          |
| **Recovery**        | Key Revocation/Rotation, Social Recovery    | Admin-reset or Email          |


---


## 2. Core Concepts

### 2.1 Levels and State Tree

The **principal tree** includes user authentication and data nodes.

```text
Principal Tree (PT)
│
├── Auth Tree (AT) ───────────── [Authentication]
│   │
│   ├── Key Tree (KT) ────────── [Public Keys]
│   │
│   └── Rule Tree (RT) ───────── [Permissions & Thresholds]
| 
└── Data Tree (DT) ───────────── [User Data / Application State]
```

The **principal state** is a hierarchical structure of cryptographic Merkle
roots representing the complete state of a Principal (identity) at a
particular commit.  CS is calculated as all PS components except for the commit
id.

```text
Principal State (PS)
│
├── Auth State (AS) ───────────── [Authentication]
│   │
│   ├── Key State (KS) ────────── [Public Keys]
│   │
│   └── Rule State (RS) ───────── [Permissions & Thresholds]
|
├── Data State (DS) ───────────── [Data Actions]
│
└── Commit ID ─────────────────── [Auth State Mutation]
```

The **commit chain** tracks principal state over time.  Each commit mutates PS
and includes a reference to the prior principal state.

```text
   Genesis, State 0              State 1                   State 2
  +----------------+        +----------------+        +----------------+
  |                | Commit |                | Commit |                |
  |     [PR]       | =====> | PS(Commit, CS) | =====> | PS(Commit, CS) | ==> (Future)
  |                |        |      |         |        |      |         |
  +----------------+        +------V---------+        +------V---------+
          ^                        |    ^                    |    ^
          + <------(pre)-----------+    +-------(pre)--------+    +-------(pre)-----------
```

### 2.2 Terminology
#### 2.2.1 Core Terminology

| Term                | Abv | Definition                                       |
| ------------------- | --- | ------------------------------------------------ |
| **Principal**       | -   | An identity in Cyphrpass, replaces "account"     |
| **Principal Root**  | PR  | The initial, permanent principal identifier      |
| **Principal State** | PS  | Top-level digest. `MR(AS, DS, Commit, ...)`      |
| **Auth State**      | AS  | Authentication state `MR(KS, RS, ...)`           |
| **Key State**       | KS  | Merkle root of active key `tmb`s                 |
| **Rule State**      | RS  | Merkle root of rules (Level 5)                   |
| **Data State**      | DS  | Merkle root of user data actions (Level 4+)      |
| **Tip**             | -   | The latest PS (digest identifier)                |
| **Commit ID**       | -   | Merkle root of `czd` of all cozies in a commit   |
| **Commit State**    | CS  | Merkle root PS components except commit          |
| **Action**          | -   | A signed coz, denoted by `typ`. Foundation of AAA|
| **trust anchor**    | -   | Last known valid state for a principal           |

PR, PS, AS, KS, RS, and DS are all Merkle root (MR) digest values.  Each
digest identifier corresponds to a tree datastructure: Principal Tree (PT), Auth
Tree (AT), Key Tree (KT), Rule Tree (RT), Data Tree (DT). (PT, AT, KT, RT, DT). 

An action is denoted by the `typ` of a signed coz. "Action" is the hypernym of
commit transaction coz and data action. Concrete types like keys, rules, user
comments, and binary files are not actions, but the cozies used to authorize
keys, rules, and data actions are actions.


#### 2.2.2 Digest

A digest is the binary output of a cryptographic hashing algorithm.

Inside a coz, all identifiers (digests) must aligned with algorithm
(`alg`) in `pay` unless otherwise explicitly labeled. When referred to alone
outside a coz, good practice for digest identifiers is prepending with the Coz
algorithm identifier, e.g. `SHA256:<b64ut_value>`.  Without explicit algorithm
labeling, the whole system is as strong as the weakest supported hashing
algorithm.  Systems may leverage previously identified digests from being
misinterpreted or reused, meaning explicit algorithm prefixes may not always be
strictly required in practice.

Digest binary values are encoded as **b64ut** ("Base64 URI canonical Truncated",
RFC 4648 base64 URL alphabet and encoding method, errors on non-canonical
encodings, and no padding).

#### 2.2.3 Identifier

All identifiers are cryptographic digest Content IDentifiers (CID's) encoded as
b64ut and provide addressing and integrity of the reference. For MRs, if order
is not otherwise given, lexical byte order is used. Values are opaque bytes,
meaning a sequence of bytes are treated as a whole unit without internal
structural or meaning.

#### 2.2.4 Commit

A commit is a finalized bundle of cozies resulting in a new PS. A commit consist
of one to many transactions, denoted by `typ`, and transactions themselves
consist of one to many cozies.  Commits are chained using references to
prior commits through `pre` and refer to the forward state through `commit`.

#### 2.2.5 Implicit Promotion

A value is **implicitly promoted** to the parent without additional hashing if a
state tree component has only one node. Promotion is recursive; items deep
in a tree can be promoted to the root level. For example:

- Single key: `tmb` is promoted to KS, then AS, then PS, which equals PR on
  genesis.
- No DS present: AS is promoted to PS
- Only KS present (no RS): KS is promoted to AS

#### 2.2.6 Authenticated Atomic Action (AAA)

Authenticated Atomic Action (AAA) is an individual self-verifiable operation.
AAA supersedes trust traditionally delegated to centralized services.

Applied, AAA is simply a signed coz whose `typ` corresponds to a meaningful
application-level action (comment, post, vote, save, like, etc.) and whose
signature is produced by a key currently authorized in the principal's Key State
(KS).

Historically, services depended upon  centralized bearer tokens. Third parties,
such as other users, have no way to verify user actions without trusting the
integrity of the centralized service.  There are countless examples of that
trust being abused.

AAA precludes such abuse and promotes a new design pattern for authentication.
Instead of authenticating to a centralized login service which provides a bearer
token for user action, users may sign individual actions directly. Each atomic
action may be trustlessly authenticated by anyone, irrespective of centralized
services. For example, instead of logging in to make a comment, a user signs a
comment directly which is then verifiable by anyone. In this model, centralized
services that maintain user identity are irrelevant and should be actively
deprecated.

#### 2.2.7 Embedded Principal and Embedded Nodes

An **embedded node** is an external tree reference.   Its value may be a `tmb`,
KS, AS, PS, nonce, or other node value. An **embedded principal** is a full
Cyphrpass identity embedded into another principal. See section Embedding.  

#### 2.2.8 Nonce

In Cyphrpass a **nonce** is a high-entropy value used to add entropy, obscure
content, and/or ensure uniqueness. Unless explicitly labeled, Cyphrpass is
unable to distinguish a nonce from any other node type such as an embedding. One
or more cryptographic nonces may be included at any level of the state tree.

#### 2.2.9 Reveal

**Reveal** is the process by which obfuscated structures, i.e. opaque nodes, are
made transparent. Public keys must be revealed for verification; embeddings,
nonces, and other data structures may also need revealing during commits or
other signing operations.

#### 2.2.10 Witnesses and Oracle

A **witness** is a client that keeps a copy of an external principal's state and
communicates state through gossip.

An **oracle** is a witness with some degree of delegated trust by external
clients. For example, a client may delegate some processing to an oracle for
state jumping, where the oracle is trusted that the commits in the jump were
appropriately processed.

#### 2.2.11 Unrecoverable Principal

A principal with no keys capable of mutating principal state and no viable
recovery path within the protocol.  Transactions and recovery are impossible.
See section Recovery.

### 2.3 Core Protocol Constraints
#### 2.3.1 Coz Required Fields
Cyphrpass requires specific fields for Coz messages.  All cozies must have the
fields: 

- `alg`: Following Coz semantics, `alg` is the algorithm of the signing key and
  a paired hashing algorithm, and also denotes algorithm for other values
  contained in `pay` unless explicitly denoted otherwise.
- `tmb`: Thumbprint of the signing key.
- `now`: The timestamp of the current time.
- `typ`: Denotes the intent of the coz.

Additionally for transaction cozies:

- `pre`: The identifier for the targeted commit to mutate (the "prior commit").

#### 2.3.2 Protocol Guarantees

1. **Commits are append-only**: Commits are never removed from the chain and
   implicit forks are prohibited by the protocol. See section Implicit Forks.
2. **Principal Root (PR) is immutable**: No operation can change a PR.

### 2.3.3 Authorization
Principal levels describe increasing complexity of a principal's state
composition and are not an authorization input. Authorization is determined by
which state components exist and what rules govern them.

A transaction is authorized if and only if all three conditions hold:

1. **Pre-mutation state**: The signing key must be active in the state before
   the transaction is applied. A key added or revoked within the same commit
   does not affect authorization of that commit's transactions.
2. **Lifecycle gate**: The principal's current lifecycle state must permit the
   operation. For example, a Frozen principal rejects all mutations; a Deleted
   principal rejects everything. (See Principal Lifecycle States.)
3. **Capability gate**: The principal must have the state components required
   for the operation. Principal genesis is required for commits. Data actions
   require DT to exist. Rule operations require RT to exist. At Level 5+, Rule
   Tree (RT) may define additional constraints; weight thresholds, timelocks, or
   other conditions that must be satisfied for the transaction to proceed.

#### 2.3.4 AT/DT Duality

Auth Tree (AT) and Data Tree (DT) have fundamentally different structural
properties.  AT has protocol defined rules while DT is a general-purpose data
action ledger. While not defined by this protocol, applications (authorities)
may impose additional structure on DT.

| Property      | Auth Tree (AT)                  | Data Tree (DT)             |
| :------------ | :------------------------------ | :------------------------- |
| Mutability    | Append-only (immutable history) | Mutable (deletable content)|
| Chain         | Linked via `pre`                | No chain                   |
| Verification  | Replay from genesis             | Point-in-time snapshot only|
| State type    | Monotonic sequence of commits   | Non-monotonic              |
| Semantics     | Full protocol semantics         | None (application-defined) |


---


## 3. Feature Levels

Cyphrpass has six operational levels.

| Level | Description       | Components                   |
| ----- | ----------------- | ---------------------------- |
| **1** | Single static key | Key (denoted by `tmb`)       |
| **2** | Key replacement   | Replaceable key              |
| **3** | Multi-key/Commit  | Key Tree  (KT)               |
| **4** | Arbitrary data    | Data Tree (DT)               |
| **5** | Rules             | Rule Tree (RT)               |
| **6** | Programmable      | VM execution                 |


### 3.1 Level 1: Static Key

- Single key, never changes
- No commit
- `tmb` == KS == AS == PS == PR
- Self-revoke results in permanent lockout (in lieu of sideband intervention)

### 3.2 Level 2: Key Replacement

- Single active key
- No commit
- `key/replace` swaps current key for new key
- Self-revoke results in permanent lockout (in lieu of sideband intervention)


### 3.3 Level 3: Commit (Multi-Key)

- Multiple concurrent keys with equal authority
- PS = MR(commit ID, AS, ...), CS = MR(AS, ...)
- Any key can `key/create`, `key/delete`, or `key/revoke` any other key
- Standard for multi-device users

### 3.4 Level 4: Arbitrary Data

- Introduces Data Tree (DT) for user actions
- Enables Authenticated Atomic Actions (AAA)
- Actions (comments, posts, etc.) recorded in DT

### 3.5 Level 5: Rules (Weighted Permissions)

- Introduces Rule Tree (RT) for access control with weights and timelocks.
- A **weight** is a numeric value assigned to keys and actions with
  minimum total weight (threshold) required for execution.
- Keys and actions have a default weight of 1.
- A **timelock** is a delay before certain actions take effect.
- Enables M-of-N signing, tiered permissions, custom timelocks
- RS is a component of AS.

### 3.6 Level 6: Programmable VM

- Introduces programmable rule execution
- Rules are executable bytecode stored in RT
- VM execution produces a deterministic state transition
- Enables complex conditional logic, programmable policies
- Use case: Smart contracts, complex organizational policies


---


## 4 Commit

A **commit** is a finalized atomic bundle containing one or more transaction
cozies. Many mutations may occur per commit, as dictated by the principal.
Unlike other systems, there are no minting fees, gas, or need for a global
ledger.

A commit contains cozies that mutate PT and forms a chain via the `pre` field.

- `pre`: The Principal State (PS) targeted for mutation.

### 4.1.0 Transaction Coz

Transactions are signed Coz messages (cozies) that mutate Principal Tree (PT). A
transaction may be one or multiple cozies that results in a mutation. For a
particular transaction, all related cozies contain an identical `typ` which
defines the intent.  All transaction cozies contained the field `pre`. When
verifying, clients verify the transaction based on auth state (AS). 

For example, `typ` may be `<authority>/key/create` or similar key mutation type.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>", // Existing key
    "typ": "<authority>/key/create",
    "id": "<new key's tmb>",
    "pre": "<target PS>",
    "commit":"<CS>"
  },
  "sig": "<b64ut>",
}
```

Following Coz semantics, all digest references in `pay`, such as `id`, must
align with `alg` unless explicitly labeled. For example, the `id` of the new key
must be `SHA256`, aligning with alg `ES256`, unless explicitly labeled.

### 4.1.1 Transactions and Transaction Bundles

Many transactions, consisting of one to many cozies, may be included in a single
commit. `pre` groups cozies and transactions into a transaction bundle for a
commit. Commit id is the Merkle root of all coz `czd`s for a commit. 

For example, a transaction bundle may have two transaction: one transaction for
`key/update`, signed by two keys and consisting two cozies, and one for
`key/create`, signed by one key and consisting of one coz.  The commit id is
`MR(coz₁, coz₂, coz₃)`.


### 4.2 Commit Finality
A commit has two references, 

- `pre` which refers to the prior principal state (PS), and 
- `commit` which refers to the forward targeted principal tree for the
principal, the **commit state** (CS). 

CS is calculated as all components of PT except the commit ID. PS is calculated
as all components of PT including the last commit, commit id.

A commit is finalized by having the targeted `"commit":<CS>` appear in the last
coz. For example, in a three coz commit, `"commit":<CS>` appears in the last
coz:

```json5
{"cozies":[
  {<coz 1>},
  {<coz 2>},
  {
    "pay": {
      "alg": "ES256",
      "now": 1736893000,
      "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
      "typ": "cyphr.me/cyphrpass/ds/create",
      "id": "<DS>",
      "pre": "<target PS>",
      "commit":"<CS>"
    },
    "sig": "<b64ut>"
  }
]}
```

To prevent client misbehavior, finality may be used as a proof of error (See
section Proof of Error).  The mutations defined by commit results in a new CS
which commit references.

### 4.3 Comparison to `git`
Cyphrpass's design is similar to git. 
  - `"commit":<CS>` is equivalent to the git tree root, which is referenced in
    the git commit.
  - `"pre":<PS>` is equivalent to parent in git.

Although currently outside of scope, as currently written, Cyphrpass is not
implemented as a Merkle DAG and instead leans on simple binary Merkle trees. In
the future Merkle DAGs may be implemented, where `pre` is a list of parents.

### 4.4 Data Action

Data Actions are stateless signed messages representing a user action and is
recorded in DT. Data actions are not transactions and do not mutate AT. Data
actions are simply messages signed by an authorized key without a chain
structure. Actions are lightweight for common use cases (comments, posts, etc.).

- No prior field required (no `pre`)
- DS is computed from action `czd`s.
- Ordered by `now` and if needed lexical as tie-breaker.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/comment/create",
    "msg": "Hello, world!"
  },
  "sig": "<b64ut>"
}
```

### 4.5.1 Data Tree (DT) Inclusion
DT is a binary Merkle Tree that stores user actions.  DT allows tree
reorganization, node deletion, and node omission; an intentionally broad design
allowing implementations to accommodate diverse applications.  Tree nodes may
represent various applications. Various data `typ`s may define their own
required fields as defined by an authority.

Like all nodes, DT/DS is first set to empty, and AS is implicitly promoted to
PS. To explicitly include a particular DS into PS, a DS transaction is signed,
which updates the value for DS in the Principal State Tree:

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/ds/create",
    "pre": "<target PS>",
    "id":  "<computed new DS = MR(DT)>"
  },
  "sig": "<b64ut>"
}
```

#### 4.5.2 DT Organization

As a Merkle Tree, DT provides broad flexibility. Nodes may represent Merkle
DAGs, Map/Trie-Based Structures (e.g., Sorted Merkle Maps, Merkle Patricia
Tries, Verkle Trees), Sparse Merkle Trees, History/Versioned Merkle Trees, or
hybrid/pluggable approaches. Clients may implement DT in append-only mode,
maintain subtrees per application or per account, and handle deletion via
tombstones or direct removal. DT organization for specific applications is
beyond the scope of this document. Principal may construct DT as an append only,
verifiable data structure.

### 4.6 Nonce, Embedding, and Opaque Node Transaction

Cyphrpass permits nonces, embeddings, or otherwise opaque nodes anywhere in the
Principal Tree. Embeddings are indistinguishable from other digest values unless
revealed by the client. A new PS may be generated by signing a transaction
nonce.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphrpass/nonce/create",
    "nonce": "T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8"
  },
  "sig": "<b64ut>" 
}
```

To delete a embedding or nonce, a `nonce/delete` is signed.

#### 4.7 Nonce path

Nonces, or otherwise opaque nodes, may be inserted anywhere in the state tree.
`typ` species the path for insertion.  A `nonce/delete`, where `id` == nonce
removes the nonce.

`cyphrpass/nonce/create`    // Principal Root
`cyphrpass/AT/nonce/create` // Nonce is inserted at the root of AT.
`cyphrpass/AT/KT/nonce/create` // Nonce is inserted at the root of KT.


---


## 5. Genesis (Principal Creation)

### 5.1 Initial Commit

A principal is created (genesis) by its **genesis key**. 

Levels 1 and 2 have an implicit genesis while Levels 3+ have an explicit commit
genesis.  PR only exists after the genesis commit, meaning that levels 1 and 2
do not have a PR.

**Levels 1 and 2: Genesis Key**

- Multikey is not supported. The principal exist with a single key. 
- No commit or PR exists.
- `PS` == `tmb` of the single key (via implicit promotion, `tmb` == KS == AS == PS).

**Commit Genesis (Levels 3+)**
A commit genesis explicitly creates a stateful principal. Commit genesis uses a
bootstrap model, gracefully upgrading from levels 1 and 2 to level 3.  Every
transaction, including genesis transactions, requires `pre`, maintaining chain
continuity from the genesis key.

1. First key is level 1+ and exists without a transaction. `tmb` == KS == AS == PS
2. Additional keys, rules, or any other AS component requires
   transactions with `pre` referencing the current PS. For example, if the first
   commit adds a second key, `key/create` contains `pre` referring to the first
   key's `tmb`.
3. `principal/create` finalizes the genesis commit. This establishes PR and
   marks the principal as created.

**`typ`**: `<authority>/key/create`
- `id`: Thumbprint of key being added

**`typ`**: `<authority>/principal/create`
- `id`: Final Principal State (PS) which for genesis is the Principal Root (PR)

### 5.1.2 Single Key Genesis
Note that outside of the cozies is `key`, which is the unsigned public key
material, but `tmb` is signed within the coz.

```json5
{
  "txs": [ 
    {
      "pay": {
        "alg": "ES256",
        "now": 1736893000,
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        "typ": "cyphr.me/cyphrpass/principal/create",
        "id": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",   // Adding itself
        "pre":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",   // Prior state is the genesis key
        "commit":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // CS = MR(tmb₁)
      },
      "sig": "<b64ut>",
    },
  ],
  "keys": [{ // key public material
    "tag": "User Key 0",
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "alg": "ES256",
    "now": 1623132000,
    "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  }],
}
```

### 5.1.2 Multi-Key, Multi-Transaction Genesis Example

- A genesis key constructs AT by adding itself and other components.
- At genesis there are no prior commits, so AS is promoted to PS via implicit
  promotion. AS = MR(KS) when only keys are present, or MR(KS, RS) if rules
  exist. For example, with two keys: AS = MR(tmb₀, tmb₁).
- Finally, the principal is created by `principal/create`.

```json5
{
  "cozies": [
    { // Second Key
      "pay": {
        "alg": "ES256",
        "now": 1628181264,
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // The genesis key
        "typ": "cyphr.me/cyphrpass/key/create",
        "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M", // The second key
        "pre":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // Genesis Key
      },
      "sig": "<b64ut>", 
    },
    {
      "pay": {
        "alg": "ES256",
        "now": 1736893000,
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        "typ": "cyphr.me/cyphrpass/principal/create",
        "id": "<b64ut>", 
        "pre":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Genesis Key
        "commit":"<CS>" // In this case, MR(tmb₁, tmb₂)
      },
      "sig": "<b64ut>",
    },
  ],
  "keys": [ // Public keys material
    {
      "tag": "User Key 0",
      "alg": "ES256",
      "now": 1623132000,
      "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
      "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    },
    {
      "tag": "User Key 1",
      "alg": "ES256",
      "now": 1768092490,
      "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
      "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
    },
  ],
}
```


---


## 6 Key

Example private Coz key with standard fields:

```json5
{
  "tag": "User Key 0", // Optional human label, non-programmatic.
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Key's thumbprint
  "alg": "ES256", // Key algorithm.
  "now": 1623132000, // Creation timestamp
  "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g", // Public component
  "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA", // Private component, never transmitted
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

#### 6.1 `key/create` - Add a Key (Level 3+)

Adds a new key to KS for an existing principal.

Note that `key` is included in the JSON payload, but not the signed payload, as
reference for client. The key may be transmitted through sideband or known
previously. This construction is good practice.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Signing `tmb`
    "typ": "cyphr.me/cyphrpass/key/create",
    "pre": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Targeted PS.  At genesis, PS == AS == KS == first key's tmb.
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M" // New key
  },
  "key": {
    "alg": "ES256",
    "now": 1623132000,
    "tag": "User Key 1",
    "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
    "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M"
  },
  "sig": "<b64ut>"
}
```

#### 6.2 `key/delete` - Remove a Key (Level 3+)

Removes a key from KT without marking it as compromised. Unlike `key/revoke`,
`key/delete` does not invalidate the key itself, it only removes it from KT,
which is useful for graceful key retirement (e.g., decommissioning a device)
when the key was never compromised.

If a key is deleted, any action signed with that key after it has been removed
from the principal is ignored. Only actions that were signed while the key was
still active in KT are interpreted. Past signatures from previous active periods
remain valid even after the key is no longer active, provided they were created
while the key was in KS.

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

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/key/delete",
    "pre": "<targeted PS>",
    "id": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
  },
  "sig": "<b64ut>"
}
```

#### 6.3 `key/replace` - Atomic Key Swap (Level 2+)

Removes the signing key and adds a new key atomically. Maintains single-key
invariant for Level 2 devices.

 - `pre` is required.
 - For level 2, `pre` is the `tmb` of the previous key. (AS == KS == tmb)


```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // The existing key.
    "typ": "cyphr.me/cyphrpass/key/replace",
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M", // The second key's `tmb`
    "pre": "<targeted PS>" // In the case of level 2, PS is the previous `tmb`
  },
  "key": {
    "alg": "ES256",
    "pub": "<new key pub>",
    "tmb": "<new key tmb>"
  },
  "sig": "<b64ut>"
}
```

#### 6.4 `key/revoke` - Revoke a Key (Level 1+)

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

```json5
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

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/key/revoke",
    "pre": "<targeted PS>",
    "rvk": 1623132000,
    "msg": "Private key was uploaded to Github repo: cyphrme/cyphrpass"
  },
  "sig": "<b64ut>"
}
```

#### 6.5 Key Transactions Summary

| Type          | Level | Adds Key | Removes Key | Notes                           |
| ------------- | ----- | -------- | ----------- | ------------------------------- |
| `key/revoke`  | 1+    | -        | ✓ (signer)  | Sets `rvk`, must be self-signed |
| `key/replace` | 2+    | ✓        | ✓ (signer)  | Atomic swap                     |
| `key/create`  | 3+    | ✓        | -           | -                               |
| `key/delete`  | 3+    | -        | ✓           | No revocation timestamp         |


---


### 7 `typ` Action Grammar

Cyphrpass follows a `typ` grammar system consisting of these core components:
`auth` (authority), `act` (action), `noun`, and `verb`.

```
<typ> = <auth>/<action>
<act> = <noun>[/<noun>...]/<verb>
<verb>   = create | read | update | upsert | delete
```

- **auth** (authority): The first unit.  Typically a domain name or a Principal
  Root.
- **act** (action): Everything after the authority.
- **noun**: One or more path units between authority and verb, representing the
  resource or subject of the action. Multiple units form a **compound noun**
  (e.g., `user/image`).
- **verb**: The final unit, the operation to perform.

Cyphrpass recommends that the authority be either a domain or a PR/PS. When a
domain is used as authority, that domain should provide a Cyphrpass identity.

Example: `"cyphr.me/user/image/create"`

- Auth: `cyphr.me`
- Act: `user/image/create`
- Noun: `user/image` (compound noun)
- Verb: `create`

**Other Examples:**

- `cyphr.me/cyphrpass/key/upsert`
- `cyphr.me/cyphrpass/key/revoke`
- `cyphr.me/cyphrpass/principal/merge`
- `cyphr.me/comment/create`

### 7.1 Required Fields for Transactions

In addition to Cyphrpass required fields, transactions have the following
required fields.

- `pre`: The prior Principal State (PS) to mutate. At genesis, PS equals AS via
  implicit promotion. (`commit` refers to the CS after the mutation)
- `id`: The identifier for the noun. For example, for `key/create`, `id` is the
  key. `tmb` The identifier for the key.

#### 7.2 Special verbs

In addition to the standard CRUD-like verbs (`create`, `read`, `update`,
`upsert`, `delete`), Cyphrpass defines these special verbs for protocol-level
operations:

- `key/revoke`                       (Terminal, inherited from Coz)
- `cyphrpass/key/replace`            (Atomicity)
- `cyphrpass/principal/merge`        (Merge is one way)
- `cyphrpass/principal/ack-merge`    (Merge is one way)

#### 7.3 Authority and `typ`

The authority defines the acceptance rules allowable for various types. These
rules may be enforced by a consensus mechanism like a blockchain, a VM, a
centralized service, or other processes. Although Cyphrpass itself agnosticly
does not set permissions outside of the core authentication rules, Cyphrpass
acknowledges that rules must be implemented by an authority (For example:
`cyphr.me`).

### 7.4 Authority and Noun Properties

In addition to the properties set by Cyphrpass, nouns may have properties as set
by an authority:

- Creatable    - Items that are able to be created, like `comment/create`
- Ownable      - Items that reserve some rights, such as mutation, only to owner. `comment`
- Updatable    - Items that are able to be mutated after the fact. `comment`
- Transferable - Items that are able to be transferred.

### 7.5 Idempotency
Cyphrpass transaction mutations are idempotent. Replaying an already applied coz
is ignored and produces no state change.

### 7.6 Uniqueness Enforcement
All `create` operations in Cyphrpass enforce uniqueness. If the target item
(e.g., key, rule, principal) already exists, the operation returns error
`DUPLICATE`.


---


## 8 Declarative Datastructure

Detailed in this document so far is iterative state mutation. Cyphrpass also
supports declarative mutation.

Transactional and declarative are isomorphic. The following is a client JSON
dump, which includes meta values and values that would be secrete to the client.

```json5
{
  "Principal_Tag":"Example Account",
  "PR":   "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",   // PR (permanent genesis digest)
  "PS":   "dYkP9mL2vNx8rQjW7tYfK3cB5nJHs6vPqRtL8xZmA2k=", // Current Principal State

  // Digest Meta
  "PRE":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Prior Principal State
  "AS":"", // Auth State
  "KS":"", // Key State
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
    "CT":[ // Commit tree of the last commit
      {
      "pay": {
      "alg": "ES256",
      "now": 1623132000,
      "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
      "typ": "cyphr.me/cyphrpass/key/create",
      "pre": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
      "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
      "commit": "<CS>"
      }],
    "RT":{}, // Rule Tree (empty)
    "DT":{}, // Data Tree (empty)
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
        "pre": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // "pre" is PS. In this case PS == AS since there is no nonce or other value.
      },
      "sig": "<b64ut>"
    }
  ]

  "revoked_keys":[],
  "last_signed_now":000001 // Provides the ability to prevent signing too many auth mutations within a certain timeframe.
}
```

### 8.1 Declarative Transaction
Instead of imperatively mutating or creating principal state, state may be
exhaustively declared in JSON. All client secretes are stripped before signing.
(The Go/Rust implementation accomplishes this by using types that preclude
secretes.)

Since declarative transaction enumerate the full principal state, they
inherently act as checkpoints (see section Checkpoint). As always, the
declarative structure is compactified according to Coz.

`cyphrpass/principal/checkpoint/create`

Example declarative principal.  Note that RS (RT) is omitted on empty:

```json5
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
    "pre": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Links to prior PS for chain integrity
    "id": "<b64UT>", // The computed AS of the declared state
    "PT": {...}
  },
  "sig": "<b64ut>"
}
```

### JSON Wire Format

For various components, JSON components are labeled. If a plural is possibly
valid, the plural is always used. This makes sure that there's one and only one
way to represent a payload. 

Valid JSON components:

**Singular**:
 - `pay` // `coz`
 - `sig` // `coz`

**Plurals**:
 - `txs`
 - `keys`
 - `cozies`

**Prohibited**:
 - `key` // Use keys
 - `tx`  // Use txs
 - `coz` // Use cozies


### 8.2 Checkpoints

**Checkpoints** are self-contained snapshots of the authentication-relevant
state at a particular point in the chain, allowing verification from the
checkpoint forward without needing to fetch or replay earlier parts of the
history. Checkpoints do not rely on prior history to reconstruct AS (KS or
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


## 9 State calculation
### 9.1 Node Canonical Digest Algorithm

All state digests follow the same algorithm:

1. **Collect** component digests (including embedding/nonce if present).
2. **Sort** lexicographically (byte comparison) unless otherwise defined.
3. **Implicitly Promote** without hashing if only one digest component exists.
4. **Merkle Root** Calculate the Merkle root of a binary Merkle tree.

```
State Digest = MR(d₀, d₁, ...)
```

### 9.2 Principal Root (PR) and Principal State (PS)

The PR is the first PS computed for the principal. PR is permanent and never
changes.  When a principal mutates (e.g., adds a second key), the PR stays the
same, only PS evolves.

```
    PS = MR(AS, Commit?, DS?, embedding?, ...)
```

### 9.3 Key State (KS)

```
  KS = MR(tmb₀, tmb₁?, embedding?, ...)
```

### 9.4 Auth State (AS)

AS combines authentication-related states:

```
  AS = MR(KS, RS?,  embedding?)      # nil components excluded from sort
```

### Commit ID

Commit ID is the Merkle root of all transaction `czd`s in the commit:

```
    commit_id = MR(czd₀, czd₁?, embedding?, ...)
```

### 9.6 Data State (DS) (Level 4+)

DS is the digest of all data action `czd`s.  By default, DS is sorted by `now`
and secondarily `czd`. DS may be an append only Merkle tree data structure.

```
DS = MR(czd₀, czd₁, ..., nonce?)
```

## 10 Rule State (RS) (Level 5 Preview)

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
        pre: "<targeted PS>",
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
        pre: "<targeted PS>",
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


## 11 Principal Lifecycle States

A principal's lifecycle is determined by the following conditions, each derived
from state.

### 11.1 Lifecycle Conditions

| Condition        | Definition                                                    |
| :--------------- | :------------------------------------------------------------ |
| `Errored`        | Fork detected or chain invalid (see Consensus)                |
| `Deleted`        | `principal/delete` transaction signed                         |
| `Frozen`         | `freeze/create` active and `freeze/delete` not signed         |
| `CanMutateAS`    | Has keys meeting required thresholds to mutate Auth State     |
| `HasActiveKeys`  | At least one active (non-revoked, non-deleted) key exists     |
| `CanDataAction`  | Can sign data actions (Level 4+, active key exists)           |

`Errored` is an orthogonal flag and indicates that something went wrong (fork
detected, chain invalid) but does not change which base state the principal
occupies. Any base state can be errored or non-errored.

#### 11.2 Base States

These conditions combine into 6 base states. `Deleted` and `Frozen` are
mutually exclusive. A principal cannot be frozen and deleted at the same time.

| State        | Conditions                                    |
| :----------- | :-------------------------------------------- |
| **Active**   | ¬Deleted, ¬Frozen, CanMutateAS, HasActiveKeys |
| **Frozen**   | Frozen, ¬Deleted, CanMutateAS, HasActiveKeys  |
| **Deleted**  | Deleted, ¬Frozen                              |
| **Zombie**   | ¬CanMutateAS, CanDataAction, ¬Deleted         |
| **Dead**     | ¬HasActiveKeys, ¬CanDataAction                |
| **Nuked**    | Deleted, all keys revoked or deleted          |

- **Active**: Normal operating state.
- **Frozen**: Principal has been frozen via `freeze/create` and has not yet been
  unfrozen via `freeze/delete`. No mutations until unfrozen.
- **Deleted**: The principal signed `principal/delete`. No new transactions or
  actions (including data actions) are possible.
- **Zombie**: (Level 4+) AS mutation is impossible (`¬CanMutateAS`), but data
  actions are still possible. Example: `key/create` requires 2 weight points,
  but only one key exists with weight 1. `comment/create` requires default 1,
  so comments are still possible but AS mutation is impossible.
- **Dead**: No transactions or actions possible at all. No active keys remain.
  Dead is a consequence of any condition that leaves the principal with no keys
  and no data action capability.
- **Nuked**: (Level 3+) A dead account with all keys revoked, all keys deleted,
  and the principal deleted (`principal/delete`). The most terminal state.

### 11.3 Unrecoverable

**Unrecoverable** is a partial classification: the principal cannot mutate AS
(`¬CanMutateAS`) and is not deleted, but whether data actions remain possible
has not yet been determined. Once `CanDataAction` is evaluated, an
unrecoverable principal resolves to either **Zombie** (data actions still
possible) or **Dead** (nothing possible).

**Note:** `CanMutateAS` is not monotonic in key count at Level 5+. A principal
with active keys may still have `¬CanMutateAS` if no key combination meets the
threshold for AS mutation.


---


## 12 Embedding

An embedding is a digest reference to an external node, such as a principal (PS),
key, or key tree. Embedding is the mechanism by which Cyphrpass achieves
hierarchy, delegation, and selective opacity (using nonces and digests).

The default weight of an embedded node is one, regardless of how man children
that node contains. Like all nodes, an embedded node may be assigned a different
weight by a rule (RS). For example, a principal embedded into KS by default has
a weight of one regardless of how nodes are weighed for the embedded principal.

On cyclic imports, embedding stops recursion at the point of cycle, preventing
infinite recursion. For example, when principal A embeds principal B, and B
embeds A, verifying A includes B's members but does not recursively resolve B's
embedding of A.


### Nonce Design

Nonces are used in Cyphrpass for a few purposes:

- **Obfuscation**: Nonces are indistinguishable from key thumbprints and
  other digest values, so observers cannot determine the true count
- **Privacy**: Prevents correlation across services
- **Reuse**: Allows reuse with a distinct identifier

Design notes:
- Nonces, like all other node values, are associated with a hashing algorithm or
  a multihash. For example, `SHA256:<nonce_value>`. This enables nonces to be
  opaque as needed while denoting a particular bit strength.
- The nonce's bit length must match the declared algorithm's output size (e.g.,
  a nonce declared as SHA-256 must be 256 bits). Bit-checking is the only
  strength check possible for nonce values.
- Nonce values should be cryptographic randomly generated values must match the
  target strength of the associated hashing alg.
- Nonces may be implicitly promoted in the Merkle tree just like any other
  digest or entropic value.
- At any tree level, multiple nonces are permitted.
- For any opaque value, specific structure may need to be revealed for specific
- operations.  For example, an opaque public key cannot be used until it is revealed.
- Like other digest values, when calculating a new hashing algorithm value, new
  values are calculated from a prior value. (See section Conversion.)

Unlike systems that rely on incrementing counters to enforce “used only once”
behavior, Cyphrpass is distributed and cannot guarantee sequential uniqueness
across principals. Instead, a sufficiently large random value provides
probabilistic uniqueness that is guaranteed in practice. As an aside,
cryptographic signatures and other identifiers may act as an entropy source, but
that's outside of the scope of this document.

### 12.1 Embedded Principal

Authorization is transitively conferred through embedding. An **embedded
principal** is a full Cyphrpass identity embedded into another principal. An
embedded principal has the default weight of a single node and appears in the
Merkle tree of another principal as the digest of the external Principal State
(PS).

For PR, PS, and AS exclusively, tip at verification time from the referenced
Principal is retrieved before any operation.  For all other node types no
retrieval is performed.  However, any node of these types must be revealed
first; opaque nodes do not trigger state synchronization.

The typical use for embedded principals is identity encapsulation, external
recovery authorities, social recovery, organizational delegation, and disaster
recovery. (See section Recovery.)

An example of embedding an external principal into key state:

```text
Principal Tree (PT0)
│
├── Auth Tree (AT0)
│   │
│   ├── Key Tree (KT0)
│   │   │
│   │   └── Embedded Principal (PS1)
```

An example of embedding multiple external principal's  KS's into KS:

```text
Principal Tree (PT0)
│
├── Auth Tree (AT0)
│   │
│   ├── Key Tree (KT0) // Principal 0's tree
│   │   
│   ├── Key State (KS1) from principal 1
│   │   
│   ├── Key State (KS2) from principal 2
```

Embedded nodes use the b64ut digest as the key in tree structure.  

For example: // TODO review
```json5
{"PT":{ // The actual Principal Tree, at the point of this commit
  "AT":{   // Auth Tree
    "KT": { // Key tree
      "keys": [
        {...} // Principal's value
        ],
      "SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":"", // External Embedding
}}}}
```

Example Principal's own labeled the same way (Thought Experiment: Principal embedded like anything else)
```json5
{"PT":{ // The actual Principal Tree, at the point of this commit
  "AT":{   // Auth Tree
    "KT": { // Key tree
      "SHA256:CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M":{"keys":[...]},// Keys labeled
      "SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":[...],// How do I know that this is a list of keys?
      "SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":"" // Opaque External Embedding
}}}}
```



Thought Experiment: No `keys` label.  KT is an array of either keys or embeddings.
```json5
{"PT":{ // The actual Principal Tree, at the point of this commit
    "AT":{   // Auth Tree
      "KT": [ // Key tree
          {...}, // Principal's key 1
          {...}, // Principal's key 2
          {"SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":""} // External Embedding
]}}}
```

Thought Experiment: Labeled Objects. No `keys` label, digest labels for all nodes.
```json5
{"PT":{
    "AT":{
      "KT": {
        "SHA256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg":{
          "tag": "User Key 0",
          "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
          "alg": "ES256",
          "now": 1623132000,
          "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
          "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA"
        },
        "SHA256:CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M":{
          "tag": "User Key 1",
          "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
          "alg": "ES256",
          "now": 1623132000,
          "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
          "prv": "dRlV0LjnJOVfK_hNl_6rjVKutZWTHNL-Vs4_dVZ0bls"
        },
        "SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":"" // Opaque External Embedding
}}}}
```





### Option 1 Tree types:
PT: Object
AT: Object
CT: Object
DS: Object (Label should be digest of node)
KT: Array
RT: Array
Commit: digest

Labels:
- keys
- rules
- txs

### Option 2 Tree types:
PT: Object
AT: Object
CT: Object
DS: Object (Label should be digest of node)
KT: Object
RT: Object
Commit: digest

Labels:
 - None.


### 12. Opacity

Example external opaque embedding:
```json
"SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":"", // Opaque External Embedding.  Unknown type.
```

Example external non-opaque embedding:
```json
"SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":{"keys":[...]}, // Non-opaque External Embedding.
```

### 12.2 Conjunctive Authorization

To sign/act as a primary principal, an embedded principal must produce a valid
signature according to its own rules (its own AS). Authorization involving an
embedded principal is conjunctive:

- Transaction must be valid according to the embedded principal’s own rules (its
  KS/RS), and
- The act of using that embedded principal must be authorized by the primary
  principal’s rules.

Example: when a Principal(B) or AS(B) is embedded into a KS(A), embedded
principal is treated as one logical key (with a default weight of 1), but the
internal authorization depends on Principal(B)

### 12.3 Meaningful Embeddings

All nodes may be embedded into other nodes, but embeddings may not always be
meaningful. For example, a Rule State (RS) embedded into a Key State carries no
meaning. Clients should discourage such practice, but this may not be
enforceable due to opaqueness.

### 12.4 Pinning

For PR, PS, and AS exclusively, embedded references trigger tip retrieval on
authentication, but synchronization isn't always desired. Pinned identifiers
denote static states that prohibit updates, ensuring immutable authorization
rules.

A pin prefixes the digest value (`PIN:<alg>:<value:`):

```
PIN:ES256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg
```

---


## 14. Authentication

Cyphrpass replaces password-based authentication with cryptographic Proof of
Possession (PoP).

Cyphrpass recommends AAA (Authenticated Atomic Action) over bearer tokens when
possible, but bearer tokens remain useful for access control and for upgrading
legacy password systems to Cyphrpass.

### 14.1 Proof of Possession (PoP)

Every valid signature by an authorized key constitutes a Proof of Possession:

- **Genesis PoP**: First signature by a key proves possession.
- **Transaction PoP**: Signing a key mutation proves authorization.
- **Action PoP**: Signing an action proves the principal performed it.
- **Login PoP**: Signing a challenge proves identity to a service.

### 14.2 Login Flow

To authenticate to a service:

**Option A: Challenge-Response**

1. Service generates a 256-bit cryptographic challenge (nonce)
2. Principal signs the challenge with an authorized key
3. Service verifies:
   - Signature is valid
   - `tmb` belongs to an active key in principal's KS
   - Principal lifecycle state is Active (reject Frozen, Deleted, Errored,
     etc.)
   - Challenge matches the one issued (prevents replay)
4. Service issues bearer token

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
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
   - Principal lifecycle state is Active (reject Frozen, Deleted, Errored,
     etc.)
   - `now` is within acceptable window (e.g., ±60 seconds of server time)
3. Service issues bearer token

```json5
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

### 14.3 Replay Prevention

Two mechanisms prevent signature replay:

| Mechanism            | How it works                                          | Trade-off           |
| -------------------- | ----------------------------------------------------- | ------------------- |
| **Challenge nonce**  | Service issues unique 256-bit nonce per login attempt | Requires round-trip |
| **Timestamp window** | `now` must be within ±N seconds of server time        | Clock sync required |

Challenge-response is useful for security contexts where time isn't trusted,
while timestamp-based authentication works for low-friction flows with
reasonably accurate time sources.

### 14.4 Bearer Tokens

After successful PoP, the service issues a bearer token:

- Token is a signed Coz message from the service
- `typ` is service-defined (e.g., `<service>/auth/token`)
- Contains: principal PR, authorized permissions, expiry
- Used for subsequent requests (avoids re-signing each request)

```json5
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

### 14.5 Single Sign-On (SSO)

Cyphrpass provides single sign-on semantics but differs from traditional SSO
systems that depend on passwords and email. Traditional SSO creates
centralization around identity providers. In Cyphrpass, the principal's
cryptographic keys are the sole authentication factor, verifiable by any party
without a central authority.


---


## 15. Storage Models

### 15.1 Client/Principal Storage

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

### 15.2 Third-Party Service Storage

Services that interact with principals store:

| Data                | Purpose                |
| ------------------- | ---------------------- |
| PR                  | Principal identity     |
| Current PS (Tip)    | State verification     |
| Active public keys  | Signature verification |
| Transaction history | Full audit trail       |
| Actions (DS)        | Application data       |

Service operations:

- **Pruning**: Services may discard irrelevant user data (old actions, etc.).
- **Key recovery**: Services may assist in recovery (see "Disaster Recovery").
- **State resolution**: Services can provide transaction history for principals
  to verify.

**Trust model:** Services are optional. Principals can self-host or use multiple
services. Full verification is always possible with transaction history.

### 15.3 Storage API (Non-Normative)

This section is informative only. Implementations may use any storage mechanism
appropriate to their deployment context.

#### 15.3.1 Transaction and Action Export Format

The recommended export format is newline-delimited JSON (JSONL).  Transactions
are saved to one file `transactions.jsonl` and data actions to
`data_actions.jsonl`. Entries with `typ` prefix `<authority>/cyphrpass/*` are
authentication transactions; all others are data actions.

```jsonl
{"typ":"cyphr.me/cyphrpass/key/create","pay":{...},"sig":"...","key":{...}}
{"typ":"cyphr.me/cyphrpass/key/create","pay":{...},"sig":"...","key":{...}}
```

```jsonl
{"typ":"cyphr.me/comment/create","pay":{...},"sig":"..."}
```

Past entries are not modified (unless implicit fork or data action removal) and
each line is a complete, signed Coz message. 


### Blob Format

Blobs are stored by digest value:




#### 15.3.2 Storage Capabilities

Storage backends provide:

- **Append**: Store signed entries for a principal
- **Retrieve**: Fetch entries (all or filtered by time range)
- **Existence check**: Determine if a principal exists

Semantic operations (verification, state computation, key validity) are handled
by the Cyphrpass protocol layer, not storage.

### 15.4 Append Only Verifiable Logs

Cyphrpass's commit chain forms a verifiable, append-only log of state mutations.
Each commit references the prior via pre and is anchored in the Merkle root
(MR), enabling efficient verification of history without full chain replay. This
supports tamper-evident auditing and is useful for compliance requirements, such
as regulatory record-keeping or forensic analysis.  This may be implemented as a
truly append only data structure or as a mutatable data structure, where events
like forks, requiring chain selection, may be deleted (mutatable) or marked as
discarded (immutable implementation).


---


## 16 Mutual State Synchronization (MSS)

Cyphrpass enables symmetric, bidirectional state awareness that eliminates the
one-sided dependency inherent in traditional password-based or federated
authentication models. Cyphrpass's distributed model does not distinguish
between users and services; both are represented by a Cyphrpass principal,
allowing users to track services without depending on legacy systems such as
certificate authorities (CA) or email.

In legacy models, only the service tracks user authentication state (first
established by passwords and then tracked by sessions), while users have no
independent view of the service's view of their account. Recovery is manual,
service-specific, and often funneled through email, creating a central point of
failure and control. Programmatic key rotation or bulk recovery is typically
impossible without service cooperation.

Cyphrpass inverts and symmetrizes these concerns through Mutual State
Synchronization (MSS):

- Services and users are represented as Cyphrpass principals and maintain
  independent, cryptographically verifiable views of each other's state.
- Cyphrpass clients push state mutations to registered services after local
  application.
- During authentication, services verify these pushes against the principal's
  current chain, reducing round-trips.

MSS directly addresses concerns about stale distributed state. This practice is
similar to double entry accounting, where instead of one entry in a ledger being
depended upon as a single source of truth, two entries are cross-checked.

Although Cyphrpass provides single-sign-on semantics, it differs from historic
systems by eliminating passwords, email dependency, and unidirectional state
tracking. MSS addresses centralization risks in legacy SSO (passwords + email as
de facto recovery root) and bearer-token models (service as sole state oracle).
By making state mutual, verifiable, and push-capable, Cyphrpass enables:

- Low-latency authentication flows.
- Independence from email/CA choke points.
- Recovery without manual per-service intervention.
- Programmable, symmetric trust between users and services.

#### 16.1 Core Properties of MSS

| Property                     | Description                                                 | Benefit vs. Legacy Systems                                  |
| ---------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------- |
| **Bidirectional tracking**   | Both user and service verify the other's authentication.    | No single source of truth; reduces trust in service logs.   |
| **Push/Pull-based updates**  | Client proactively pushes mutations, pull as needed.        | Faster auth (pre-synced state); no polling required.        |
| **Independent verification** | Each party resolves the other's state from trust anchor.    | Censorship-resistant; survives service outage.              |
| **Service as principal**     | Service exposes its own state via API or public chain.      | Bypasses CA/email dependency for service identity.          |
| **Double-entry analogy**     | Not a single ledger, parties may track each other's state   | Stronger auditability and fraud/spoofing/evasion detection. |

### 16.2 State Resolution and Verification by a Third Party 

To verify a principal's current state:

1. **Identify Trust Anchor**: the claimed root (PR) or transitive state (PS).
2. **Obtain transaction history**: ordered list of transactions from trust
   anchor to tip.
3. **Replay transactions**:
   - Start with trust anchor
   - For each transaction, verify:
     - Signature is valid
     - `tmb` belongs to a key in current KS
     - Principal lifecycle state permits the operation
     - `now` is after previous transaction
     - Transaction is well-formed for its `typ`
   - Apply mutation to derive new AS
4. **Compare**: final computed KS/AS/PS should match claimed current state

### 16.3 Recommended Usage

MSS makes authentication quicker by allowing clients to push state to services
before authentication. When a client mutates their own state, they may push the
mutations to all registered third parties.

- **Proactive push on mutation**: After transaction (`key/create`, `key/revoke`,
  etc.), client pushes to all registered services (stored locally through
  previous registration).
- **On-demand sync**: Before high-value actions, client queries service tip and
  reconciles if needed.


### 16.4 MSS API Operations (Non-Normative)

Cyphrpass's `typ` system builds a ready to use API. However, there are a few
endpoints not enumerated by `typ`, such as synchronization. Services should
expose an interface for MSS (like HTTP API). Services may of course limit depth
and have other rate limits. A gossip communication layer may be used to keep
clients in sync. See also section `API`.

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

### 16.5.1 Witness Registration
A principal may have many clients.  The principal signs a message to inform
clients of the registration of external witnesses, which themselves are
represented as principals.  This message is not included in AS, and is instead
may be included in DS as a data action, so that PS may remain unmodified. 

`cyphr.me/cyphrpass/witness/register/create`: Value of the Principal's PR.

This message is transported to the external witness for registration. The
witness is removed with a `delete`.

### 16.5.2 MSS Registration Example

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

### 16.6 Witness Timestamps
Clients should record their own "first_seen" if the oracle has a date after
receipt.  If external witness timestamps are out of expected range, clients
should also record external witness timestamps.  This allows MSS to detect
conflict, dishonest behavior, and bugs.

### 16.7 Gossip
Unlike existing gossip protocols, like Cassandra, where there is no authority on
a particular piece of data, Principals are the authority over their own state.

Clients may periodically query or exchange state details with other clients for
specific principals. This helps detect divergences, ensure consistency, and
propagate changes. For example, a client might check the tip against multiple
sources to verify integrity before accepting updates.  Clients may check
registration through `GET /tip?pr=<principal-root>`, which should return empty
if the principal isn't registered.

Clients may have an principal identity separate from the principal itself in
that a principal's primary client may be registered as a witness itself.

---


## 17 Consensus
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
clients on external hosted blockchains) and accepts that incompatibility between
clients can be an intentional choice. This consensus model also permits logical
deduction. Retained errors and timestamps serve as transparent signals of client
honesty. It represents a fundamentally different philosophy: consensus emerges
from what actually occurred and who published what when, not strictly from
coordinated rule enforcement or majority vote, and opens the door for
intelligent agents to detect violations through reasoning instead of strict rule
matching.

Although outside of the scope of this document, consensus rules attempt to
accommodate a wide set of circumstances and implementation, and should assume
minimal control of implementation.  Consensus rules accommodate as best as
possible such situations, but acknowledge that various circumstances may result
in client incompatibility, which may be an intentional decision by principals.

For conflict resolution beyond consensus rules, see section "Recovery".

### 17.1 Proof of Error

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

### 17.2 Resync

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

#### 17.2.1 Resync PoP

A principal may re-iterate an existing state as authoritative without mutating
PS/AS through a resync POP.
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

For record keeping, a resysnc PoP may be included by a principal into DT, but it
must not be used for after-the-fact authentication.

### 17.3 Principal Consensus States

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

#### 17.3.1 Consensus State Transitions

| From    | To              | Trigger                                                          |
| :------ | :-------------- | :--------------------------------------------------------------- |
| Active  | Pending         | Incomplete transaction received (e.g., missing bundle component) |
| Pending | Active          | Transaction completes or witness timeout expires                 |
| Active  | Error           | Fork detected, chain invalid, or repeated resync failure         |
| Error   | Active          | Fork resolved (branch selection or resync PoP)                   |
| Active  | Resync          | Trust anchor is stale, delta needed                              |
| Resync  | Active          | Patch verified and applied                                       |
| Resync  | Error           | Repeated resync failure (e.g., >3 attempts)                      |
| Active  | Offline         | Communication failure with principal                             |
| Offline | Resync          | Reconnect; stale state needs verification                        |
| Any     | Ignore          | Principal dropped from gossip                                    |
| Any     | Client Mismatch | Witness and client disagree on message validity                  |

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
- `DUPLICATE`: `*/create` for existing items. Cyphrpass `create` rejects duplicates.
- `STATE_MISMATCH`: Computed PS/AS differs from claimed.


### 17.4 Consensus and Witnesses

Cyphrpass assumes a single linear chain per principal. An implicit fork occurs
when two or more conflicting commits reference the same pre (prior AS),
violating this assumption.

- Ignoring the message
- Escalation (e.g., freeze the principal temporarily until resolved) or
- Holding the message as Proof of Error.

Rejection is auditable: Witnesses log the reason (e.g., INVALID_SIGNATURE) and
may broadcast it via gossip for other witnesses to confirm.

### 17.5 Implicit Forks, Fork Detection, and Duplicitous Behavior
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

#### 17.5.1 Fork Resolution

An implicit fork is resolved when the principal unambiguously selects one
branch. Until resolved, witnesses hold both branches and the principal's
consensus state is Error.

 - **1. New commit** - The principal signs a new commit whose `pre` references
the tip of the chosen branch. This implicitly abandons the other branch.
Witnesses that see this commit treat the selected branch as canonical and
discard the abandoned branch (retaining it only as proof of error).
 - **2. PoP assertion** - The principal signs a `resync/create` message
re-asserting the current tip without mutating PS/AS. Witnesses that held both
branches resolve to the asserted tip. This is appropriate when the principal
wants to confirm which branch is authoritative without advancing the chain.

In both cases, the abandoned branch's transactions become permanently invalid.
Keys that were only added in the abandoned branch are not part of KS. Witnesses
transition the principal's consensus state from Error back to Active upon
observing a valid resolution.

### 17.6 Timestamp Verification

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


## 18. Recovery

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

### 18.2 Recovery Mechanisms

When a principal loses access to all active keys, or the account is otherwise in
an **unrecoverable state** recovery mechanisms allow regaining control.

There are two main mechanisms:

- **Self Recovery**, various methods of backup. For user self management.
- **External Recovery** Where some permissions are delegated to an external
  account, a **Recovery Authority**. This may be social recovery or third-party service.

Level 1 doesn't support recovery. Any recovery is accomplished through sideband.
Level 2 supports recovery but only atomic swaps. The recovery key can replace the existing key.
Level 3+ supports recovery and can add new keys.

### 18.3 Self-Recovery Mechanisms

| Mechanism         | Description                            | Trust Model  |
| ----------------- | -------------------------------------- | ------------ |
| **Backup Key**    | Backup key stored in a secure location | User custody |
| **Paper wallet**  | Backup key printed/stored offline      | User custody |
| **Hardware key**  | Hardware key device (U2F-Zero, solo1)  | User custody |
| **Airgapped key** | Cold storage, never online             | User custody |

### 18.4 Implicit Fallback (Single-Key Accounts)

For implicit (single-key) accounts, a `fallback` field may be included at key creation:

```json5
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

#### 18.4.1 Recovery Validity 

Ideally, recovery agents only act when the account is in an unrecoverable state,
however, the unrecoverable state may not be definitively known or verifiable by
the protocol, such as in the case with lost keys.

Principals should create recovery circumstances carefully. The protocol does not
enumerate these conditions here; they are defined by principal rules at the time
of the attempted recovery.

### 18.5 Recovery Transactions

#### 18.5.1 `cyphrpass/recovery/create` — Register Fallback

Registers a recovery agent (backup key, service, or social contacts).

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/cyphrpass/recovery/create",
    "pre": "<targeted PS>",
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

#### 18.5.2 `recovery/delete` — Remove Fallback

Removes a previously designated recovery agent.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/recovery/delete",
    "pre": "<targeted PS>",
    "recovery": {
      "agent": "<recovery agent PR or tmb>"
    }
  },
  "sig": "<b64ut>"
}
```

### 18.6 Recovery Flow

When a principal is locked out:

0. **User generates a new account with a fresh PS**
1. **User contacts recovery agent** (out-of-band)
2. **Agent verifies identity** (method varies by agent type)
3. **Agent signs a Recovery Initialization transaction** for the new user key:

This initializes a new Principal State (PS) that is manually linked to the
previous state by the Recovery Authority. The new PS is not cryptographically
linked to the previous state, but it is manually linked to the original PR by
the Recovery Authority's recovery transaction.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<recovery agent tmb>",
    "typ": "<authority>/key/create",
    "pre": "<targeted PS>",
    "id": "<new user key tmb>"
  },
  "key": {
    /* new user key */
  },
  "sig": "<b64ut>"
}
```

Because the agent was designated via `cyphrpass/recovery/create`, their `key/create` is valid even though no regular user key signed it.

### 18.7 External Recovery
External recovery is accomplished through embedded principals, where some
permissions are delegated to an external account. 

External recovery delegates recovery authority to an external principal. The
recovery agent verifies identity out-of-band and signs a recovery transaction on
behalf of the locked-out user.

| Mechanism               | Description             | Trust Model       |
| ----------------------- | ----------------------- | ----------------- |
| **Social recovery**     | M-of-N trusted contacts | Distributed trust |
| **Third-party service** | Verification service    | Service trust     |

### 18.8 Social Recovery

For social recovery, multiple contacts sign:

- Each contact signs the same `key/create` transaction
- When `threshold` signatures are collected, the transaction is valid
- Contacts are identified by their PR

**Example:** 3-of-5 social recovery requires 3 contacts to sign the `key/create`.

### 18.9 Account Freeze

A **freeze** is a global protocol state where valid transactions are temporarily
rejected to prevent unauthorized changes during a potential compromise. A freeze
halts all key mutations (`key/*`) and may restrict other actions depending on
service policy.

Freezes are **global** — they apply to the principal across all services that
observe the freeze state.

#### 18.9.1 Self-Freeze

A user may initiate a freeze if they suspect their keys are compromised but do not yet want to revoke them (e.g., lost device).

- **Mechanism**: User signs a `cyphrpass/freeze/create` transaction with an active key.
- **Effect**: Stops all mutations until unfrozen.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/cyphrpass/freeze/create",
    "pre": "<targeted PS>"
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

#### 18.9.3 Unfreeze (Thaw)

To unfreeze an account, a `cyphrpass/freeze/delete` is signed:

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/cyphrpass/freeze/delete",
    "pre": "<targeted PS>"
  },
  "sig": "<b64ut>"
}
```

**Rules:**

- Self-freeze can be unfrozen by active keys.
- External freeze requires the Recovery Authority to thaw (or the principal after a timeout, if configured)

### 18.10 Security Considerations

- **Timelocks (Level 5+):** Recovery can have a mandatory waiting period.
- **Revocation:** Backup keys can be revoked if compromised.
- **Multiple agents:** A principal may designate multiple fallback mechanisms, including M-of-N threshold requirements
- **Freeze abuse:** External freeze authority requires explicit delegation and trust

### 18.12 Retroactivity (Reversion, Retrospection)

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


---


## 19. Close, Merge, Fork

### 19.1 Closing an Account (Principal Delete, Level 3+)

Closing an account is performed via a `principal/delete` transaction. Closed
accounts are permanently closed and cannot be recovered. No transactions or
actions are possible on a closed account. However, the protocol does not prevent
a user from creating a new principal reusing the existing keys, unless those
keys were revoked.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "<target signing key tmb>",
    "typ": "cyphr.me/cyphrpass/principal/delete",
    "pre": "<target PS>"
  },
  "sig": "<b64ut>"
}
```

To ensure that no aspect of a deleted principal may be reused, an account may be
"nuked", all keys revoked, then deleted, and then the principal deleted. This
ensures that no new principal may be created reusing existing principal keys.

### 19.2 Account Merging (Principal Merge, Level 3+)

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

- References the source's current PS via `pre`
- Declares the target's PS as the next state via a new field `merge_to_ps`
- Includes proof that the signer is authorized on the **source** (not the target)
- Note that if the target account wants to reuse keys from the source account, it
  must explicitly add keys from the source account (if the keys are not already
  present).

Example source principal merge transaction:

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "<source signing key tmb>",
    "typ": "cyphr.me/cyphrpass/principal/merge",
    "pre": "<target PS>",
    "merge_to_ps": "<target Principal State>"
  },
  "sig": "<b64ut>"
}
```

And the acknowledgement by the target principal:

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "<target signing key tmb>",
    "typ": "cyphr.me/cyphrpass/principal/ack-merge",
    "pre": "<target PS>",
    "merge_from_ps": "<source Principal State>"
  },
  "sig": "<b64ut>"
}
```

### 19.3 Principal Forking (Account Fork, Level 3+)

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

Sharing Keys: Nothing in Cyphrpass stops various principals from sharing keys,
as long as genesis does not result in the same PR. Any set of keys that has not
been revoked may be used to create a new PR, this includes reusing keys from the
source principal. The fork may declare new keys or reuse existing keys.

For "bad faith" forking, see section "Consensus".


A principal fork commit, consisting of three transactions:

```json5
{
  "cozies": [
    {
      "pay": {
        "alg": "ES256",
        "now": 1736893000,
        "tmb": "<signing tmb>",
        "typ": "cyphr.me/cyphrpass/principal/fork/create",
        "pre": "<target PS>",
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
        "pre": "<target PS>"
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
        "pre": "<target PS>"
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


## 20. Multihash Identifiers

In Cyphrpass, cryptographic algorithms are pluggable: no single cryptographic
primitive is exclusively authoritative or tightly coupled to the architecture.
This enables flexibility in algorithm choice, security upgrades, and rapid
removal of broken algorithms.

Instead of identifiers being tightly coupled to a single digest, identifiers are
coupled to an abstraction named a **multihash identifier**, a set of equivalent
digests, one per supported hash algorithm at commit time.

No single algorithm is canonical. All variants in a multihash identifier are
considered equivalent by Cyphrpass; security judgments are out-of-scope.

A multihash identifier is calculated for all state (e.g. PR/PS, AS, KS, and
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

### 20.1 Algorithm Mapping

Each key algorithm implies a hash algorithm, as defined by Coz.

| Key Algorithm | Hash Algorithm | Digest Size | Strength Category |
| ------------- | -------------- | ----------- | ----------------- |
| ES256         | SHA-256        | 32 bytes    | 256-bit           |
| ES384         | SHA-384        | 48 bytes    | 384-bit           |
| ES512         | SHA-512        | 64 bytes    | 512-bit           |
| Ed25519       | SHA-512        | 64 bytes    | 512-bit           |

### 20.2 Conversion

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

#### 12.2.1 Conversion Example
For a SHA384 tree, but a node is SHA256 only (for example, for an ES256 key, an
opaque embedding, or any node with a different hashing algorithm), the node is
converted into a SHA384 node.

The ES256 Key node:
```json
"SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":{<key data>}
```

The ES256 key node is converted to SHA384:
```json
"SHA384:NLDDkOyBHNVG4H6yHwSf8AwvI82B-tRhleeuBhYR4LCdvP9Is2-HjXMbllTv0NJk":""
```

### 20.3 Conversion Security Considerations

Conversion is not ideal, but is unavoidable for pluggability, recursion, and
embedding. Implementors must be aware that inner nodes may have different
security levels than parent nodes. Algorithm diversity aids durability but
risks misuse. For a particular node, security is bounded by the weakest link.
For uniform security, keys from one strength category may be used.

### 20.4 Multi Hash Merkle Root (MHMR) Algorithm

The **Multi Hash Merkle Root (MHMR)** algorithm is used to compute every digest
in the Cyphrpass state tree (PR/PS, AS, KS, RS, DS, and all internal Merkle
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

#### 20.5 MHMR Computation

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

#### 20.5.1 MHMR Examples

| Case                         | Children                                 | Target H | MHMR_H Computation                        | Result             |
| ---------------------------- | ---------------------------------------- | -------- | ----------------------------------------- | ------------------ |
| Single child (promotion)     | B (32-byte SHA-256)                      | SHA-384  | — (implicit promotion)                    | B bytes (32 bytes) |
| Two children, different algs | A (48-byte SHA-384), B (32-byte SHA-256) | SHA-384  | sort(A,B) → assume A < B → SHA-384(A ∥ B) | 48-byte digest     |
| Two children, same alg       | C, D (both SHA-256)                      | SHA-256  | sort(C,D) → SHA-256(C ∥ D)                | 32-byte digest     |
| Three children               | A (SHA-384), B (SHA-256), E (SHA-512)    | SHA-512  | sort(A,B,E) → SHA-512(sorted concat)      | 64-byte digest     |

**Important Properties**
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

#### 20.6 MHMR Rationale

The MHMR design achieves three simultaneous goals:

1. Cryptographic pluggability without algorithm lock-in
2. Support for embedded principals and recursive structures
3. Backward- and forward-compatibility during algorithm transitions

Implementations must compute MHMR variants for every hash algorithm currently
supported by active keys (and any nonce-injected algorithms) at each commit.
When an algorithm is deprecated or removed from support, its MHMR variant is no
longer generated for new commits.

All references to state (PR/PS, AS, KS, RS, DS, etc.) in protocol messages, storage,
gossip, and verification use one of these multihash variants. Equivalence across
variants is assumed by the protocol; no relative strength ordering is enforced
at the protocol level (see §14.4 Rank for tie-breaking considerations).

### 20.7 Multihash Algorithm Rank

When multiple algorithms are supported, there may be a tie at the time of
conversion. Cyphrpass provides a default rank. Rank is a tiebreaker only and
not a security indicator. Misuse can have security implications.

Perhaps in the future, principals may set a rank order via
`cyphrpass/alg/rank/create` transaction (stored in AS as a rule), but for now
this is out-of-scope.

#### 20.8 Algorithm Incompatibility

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







## Exposition
### 7.4 HTTP and `typ`:  Unified Intent + Resource + Verb Descriptor
Cyphrpass's `typ` is an alternative to HTTP semantics. `typ` is not just a
naming convention, it's a deliberate design choice that rethinks invoking
actions, addressing resources, and expressing intent in a cryptographically
native, decentralized way.  Its full power is realized in Authenticated Atomic
Action (AAA).

Unlike most Internet systems, Cyphrpass is designed to work in parallel to HTTP,
not necessarily on top of it. Where HTTP has Method
(GET/POST/PUT/DELETE/PATCH...), Path (/users/123/profile/photo), Headers
(Accept, Content-Type, Authorization...) Cyphrpass collapses almost all of that
expressive into one field: `typ`.

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

Advantages Over HTTP:

- No trusted third-party sessions (like cookies/tokens). Every request carries
  its own PoP.
- Replay resistance built-in via `now` (timestamp window).
- Intermediaries can cryptographically audit actions without trusting the
  service.
- Decentralized addressing. The Principal root my be outside DNS/CA entirely.
- Append-only mutable state via transactions. Instead of PUT/PATCH fighting over
  eventual consistency, Cyphrpass provides a verifiable chain of mutations.

Actions are first-class and atomic. AAA means the "API call" is individually
verifiable forever, not just during a session.


### 21.3 Where Cyphrpass Diverges from Being a Full HTTP Replacement

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







---


## 21 Cyphrpass Type System and Ownership
TODO move to ownership


# Ownership change

In Cyphrpass, transferable is cryptographically implementable via key change,
but recording such changes in a ledger potentially results in human unreadable
transactions. Also, authorities may prohibit key updates to keys outside of the
principal, making transfer impossible.

Transfer ambiguity: For example, a comment could be updated to be signed by a
new key, but that would be ambiguous: was is a transfer or just as a result of a
key update? For that reason, updates with new keys outside of principal should
fail and transfer explicitly used for transfer.


### 22 Self-Sovereign Philosophy

#### Self-Ownership Philosophy in a Cryptographic System

There are three main categories of ownership:

1. Possess the private keys (Private Key Possession)
2. Possess the data (Data Possession)
3. Right to mutate state: `create`, `delete`, `update` (Right)

These three can be summarized as three points: **Keys, Data, Right**

#### 22.1 Cyphrpass Goal

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

### 22.2 Natural Ownership

The originating Principal is the **natural owner** of its actions. For example,
the principal that creates a comment `comment/create` is the natural owner of
that comment, and has exclusive rights for future mutations: `comment/update`,
`comment/delete`, and `comment/upsert`. Systems implementing AAA must give
special attention to items with natural ownership properties.

#### 22.2.1 Ownership Right Semantics

TODO Perhaps:
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


## 23. State Jumping

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

### 23.1 Core Mechanism

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
  |                                            |
  |<-- Accept (or reject if invalid)-----------|
  |                                            |
  | Update local trust anchor to new PS        |
  | Future resolutions start from here         |
  |                                            |
```

### 23.2 Example State Jump Transaction

```json5
{
  pay: {
    alg: "ES256",
    now: 1623132000,
    tmb: "<active key tmb from anchor>",
    typ: "cyphr.me/cyphrpass/principal/state_jump/create",
    pre: "<old trust anchor PS>",
    jump_to_ps: "<tip PS>",
  },
  sig: "<b64ut>",
}
```

### 23.3 Security Considerations

- Jumping must not bypass revocation semantics: if a key was revoked between
  anchor and tip, the jump fails.
- Clients should verify the jump against multiple services or via full chain
  replay periodically to detect malicious jumps.
- Services may enforce maximum jump distance or require multi-signature for
  large jumps to mitigate abuse.

State jumping preserves Cyphrpass's core properties (verifiable history, no
trusted central oracle) while enabling scalable operation for long-lived
principals.

### 23.4 State Jump Examples

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

### 23.5 Other High Volume Strategies

In addition to state jumping, other future related designs include zero-knowledge
proofs and trusted third parties. (Ethereum uses Infura; similar infrastructure
may be useful for some client situations, although Cyphrpass is designed for
decentralization.)

See also §7.3.3 Checkpoints.

---


## 24. Error Conditions

This section defines error conditions that implementations must detect. Error
_responses_ (HTTP codes, messages, retry behavior) are implementation-defined.

### 24.1 Transaction Errors

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

### 24.2 Recovery Errors

| Error                     | Condition                                                        | Level |
| ------------------------- | ---------------------------------------------------------------- | ----- |
| `UNRECOVERABLE_PRINCIPAL` | No keys capable of transaction and no designated recovery agents | All   |
| `RECOVERY_NOT_DESIGNATED` | Agent not registered via `cyphrpass/recovery/create`             | 3+    |

### 24.3 State Errors

| Error               | Condition                                               | Level |
| ------------------- | ------------------------------------------------------- | ----- |
| `STATE_MISMATCH`    | Computed PS does not match claimed PS                   | All   |
| `HASH_ALG_MISMATCH` | Multihash variant computed with wrong algorithm         | All   |
| `ALG_INCOMPATIBLE`  | Referred `alg` is not supported                         | All   |
| `CHAIN_BROKEN`      | `pre` references do not form valid chain to known state | 2+    |

### 24.4 Action Errors (Level 4+)

| Error                 | Condition                               | Level |
| --------------------- | --------------------------------------- | ----- |
| `UNAUTHORIZED_ACTION` | Action `typ` not permitted              | 5+    |

### 24.5 Error Handling Guidance

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

## 25. Test Vectors
Language-agnostic test vectors are provided in `/tests`. 

### 25.1 Golden Key "User Key 0" (ES256)

```json5
{
  "tag": "User Key 0",
  "alg": "ES256",
  "now": 1623132000,
  "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
}
```

#### 25.1.1 Golden Key: "User Key 1" (ES256)

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

#### 25.1.2 Golden Key: Cyphrpass Server Key A (ES256)

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

### 25.2 Golden Message

The canonical Coz test message with verified signature:

```json5
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

Computed digests, where 
- `cad` = SHA-256(canonical(`pay`)) 
- `czd` = SHA-256(`[cad, sig]`)

- `cad`: `XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU`
- `czd`: `xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo`

### 25.3 Golden Nonce

"T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8"


## 26 Suggested API

See also section "MSS" for `tip`, `patch`, and `push` endpoint definitions.

Good practice for digest identifiers is prepending with Coz algorithm
identifier, e.g. `SHA256:<B64-value>`.

Since cryptographic digests are suitable, all `GETS` may simply be looked up by digest.

- `GET /<diget-value>`

- Alternatively, `e` for everything is suggest:

- `GET /e/<diget-value>`


---


## Appendix

### Cyphrpass Applications

- Cryptographically verifiable, internet-wide, web archive service.
- Unstoppable, internet-wide user comments
- "Bittorrent for social media".
- Enforce/audit life insurance.
- Enforce/audit contracts.

### Appendix 1: Coz Field Reference

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

Other key Coz requirements:
- All signatures must be verified using the key's `alg`
- ECDSA signatures must be low-S normalized (non-malleable)
- `tmb`'s use the hash algorithm associated with `alg`
- State digests use the hash algorithm of the signing key

Algorithm governance is delegated to Coz. Weak algorithm sunsetting is handled
by Coz and is inherited by Cyphrpass. If an algorithm is weakened, Coz will mark
it deprecated; principals should discontinue via key removal. Implementations
should warn and appropriately and remove support for deprecated algorithms. 

### Appendix 2: Prior Art

- Coz
- Bitcoin
- Ethereum
- PGP
- SSH
- SSL/TLS
- SSHSIG and signify (OpenBSD)
- Secure Quick Reliable Login (SQRL) (https://www.grc.com/sqrl/sqrl.htm)

### Appendix 3: See also

- Ethereum multihash: https://ethresear.ch/t/multihashing-in-ethereum-2-0/4745
- Merkle-tree-based verifiable logs (A merkle tree where new nodes are added to only one side.)
- Keybase
- Protocol Labs (Multiformats) 

----------------------------
----------------------------
----------------------------
----------------------------
----------------------------
----------------------------

## QUICK AI Guidance:
 - DO NOT USE EM DASH OR DASH. Use period, comma, semi-colon, and other sentence
   construction appropriately.
 - DO NOT USE uppercase MAY, SHOULD, or MUST.  This isn't an IETF RFC.
 - JSON example should be in valid json, not json5 **EXCEPT** for the comments.
   Use `json5` on the markdown so that the comments are valid.

## TODO AI clean up items:  
- NO EM DASH in the file other than in title names.
- NO other AI-ism.  Yes we know that you're using this for fingerprinting.  STOP.
- Run Humanizer.
- Actually calculate b64ut values like `sig`, `pre`, and `id`

# TODO
- Ownership
- Define Opaque reveal authorization semantics better
- ZAMI finish Login





### Level 2.5: Multi-Key (Transitional Multi-Key, Pre-Commit)
Level 2 has multiple concurrent keys with equal authority, but without a full
commit chain or historical tracking. This is a transitional level bridging
single-key simplicity (Level 1) and full commit-based multi-key management
(Level 3). It enables basic multi-device support while avoiding the overhead of
chained commits.

Level 2 has a implicit global state that isn't referred to be transactions.

KS is the Merkle root (MR) of multiple `tmb`s;
promoted to AS and then PS (similar to Levels 1-2).
- **Limitations**: No history; revocations and other mutations are not tracked
  historically, and concurrent mutations may lead to races (resolved by services
  via timestamp or nonce). 

Multi-device setup, or simple services not requiring audit trails.

#### Key Properties
- All keys have equal authority (default weight of 1, no rules).
- Any active key can perform `key/create`, `key/replace`, or `key/revoke`
  operations, which result in a new KS (MR of the updated `tmb` set).
- No `pre` field required for transactions (unlike Level 3+), as there is no
  chain. Instead, transactions target the current KS directly.
- Implicit promotion: If only one key remains, reverts to Level 2 behavior.
- To enable: A Level 2 principal performs a `key/create` to add the first
  additional key, promoting to Level 2.5 automatically.

#### Adding a key

**Example Transaction: Adding a Key**
```json
{
  "pay": {
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",  // Existing key tmb
    "typ": "cyphr.me/cyphrpass/key/create",
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M"// New Key
  },
  "sig": "<b64ut>"
}
```
- The new KS is computed as MR of the sorted `ks` list.
- Services validate: Signature from current KS, nonce uniqueness, no duplicates.
- If accepted, the new KS becomes the implicit PS.

Use `key/revoke` with `rvk` timestamp on a specific `tmb`. The transaction
includes the full updated `ks` list excluding the revoked key.

#### Upgrade to Level 3
- Perform a commit genesis with `pre` referencing the current KS.
- This establishes the chain and enables historical tracking.

#### Security Considerations
- **Race Conditions**: Without a chain, concurrent additions from different
  devices may conflict. Services should enforce a short acceptance window based
  on `now` and reject duplicates via nonce.
- **No Audit Trail**: Lost history means revocations are not verifiable
  retroactively; rely on services for dispute resolution.
- **Downgrade Risk**: If all but one key is revoked, implicitly demotes to Level
  2.
- Implementations should encourage upgrading to Level 3 for any principal with
  more than 2-3 keys or frequent mutations.