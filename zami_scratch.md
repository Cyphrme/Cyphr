MR(coz₁, coz₂, coz₃)

A commit includes reference to the prior principal state
(PS) through the field `pre`. The data tree may be included into PS through a inclusion transaction (see
section Inclusion).







### 4.1.0 Transaction Coz

Transactions are signed Coz messages (cozies) that mutate Auth State (AS). A
transaction may be one or multiple cozies that results in a mutation. For a
particular transaction, all related cozies contain an identical `typ` which
defines the purpose of the intent and the targeted commit identifier `pre`.
When verifying, clients verify the transaction based on auth state.

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

Following Coz semantics, all digest references in `pay`, such as `id`, must
align with `alg` unless explicitly labeled. For example, the `id` of the new key
must be `SHA256`, aligning with alg `ES256` unless explicitly labeled.









│
├── Commit State (CS) ─────────── [Finalized Commit]
│   │
│   └──── MR(Commit, AS) ──────── [Auth State Mutation]




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



```text
Principal State (PS)
│
└─ Commit State (CS) ───────────────────── [Finalized Commit]
   │
   ├── Auth State (AS) ───────────── [Authentication]
   │   │
   │   ├── Key State (KS) ────────── [Public Keys]
   │   │
   │   └── Rule State (RS) ───────── [Permissions & Thresholds]
   │
   ├── Data State (DS) ───────────── [Authentication]
   │
   └── Commit ────────────────────── [Auth State Mutation]

```



Commits are inherently append-only. Unlike DS, which services may prune at their
discretion, removing transactions would break chain integrity verification. For
high-volume principals, use checkpoints or state jumping may be used.

AS is computed independently of commit; there is no circular dependency. A
commit produces a new AS if the commit mutates any AT component.




Don't care about CS
Implicit Root. (Everything in PS except Commit ID is included in Commit MR)
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





// TODO thinking about explicit DS encapsulation
// PROBLEM: there could be other embeddings in PS, this isn't fixing the issue
```text
Principal State (PS)
│
├── Commit State (CS)
|   |
|   ├── Auth State (AS) ───────────── [Authentication]
│   |   │
│   |   ├── Key State (KS) ────────── [Public Keys]
│   |   │
│   |   └── Rule State (RS) ───────── [Permissions & Thresholds]
|   |
|   └─── Data State (DS) ──────────── [Data Actions]
│
└── Commit ID ─────────────────── [Auth State Mutation]
```


BAD
```text
Principal State (PS)
│
├── Auth State (AS) ───────────── [Authentication]
|   │
│   ├── Key State (KS) ────────── [Public Keys]
│   │
│   ├── Rule State (RS) ───────── [Permissions & Thresholds]
|   |
|   └── Data State (DS) ───────── [Data Actions]
│
└── Commit ID ─────────────────── [Auth State Mutation]
```

TODO new problem:

```json
{
"commit":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // actual CS
}
```







TODO alternatively:
```json
{
  "pay": { // Separate commit data structure design
    "alg": "ES256",
    "now": 1736893000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/cyphrpass/commit/create",
    "pre": "<target PS>",
    "commit":"AS/CS"
  },
  "sig": "<b64ut>"
}

// Outer wrap
// List
```



A consequence of the bootstrapping model is that the first key's `tmb`
is the principal's PR.








## TODO Consider genesis key PR dilemma.
Problem: having first `tmb` == PR wasn't an original design goal.  It also
disallows single key reuse, but this isn't necessarily a bad thing.

This is how it would work:
For genesis, `pre` refers to genesis key. 

PR == null before genesis commit.  
On genesis commit: `id`: Final Auth State (the PR to anchor).
- Before level 3, PR is all nill. At genesis commit, create generates a
new PR, MR(AS) == PR.

This allows the principal to generate an atomic PR wile still accommodating the
bootstrap model. 

Only problem is that there isn't a universal identifier for all levels.

Solution: PR doesn't exist for levels 1 and 2, only PS.








### 4.1.0 Transaction Coz

A transaction consists of one or more signed cozies that results in a mutation
of the Principal Tree (PT). All transactions contained in a particular commit
contain an identical `pre`. All related cozies for a particular transaction
contain an identical `typ`, which defines intent.  Clients verify transactions
based on the principal's auth tree (AT).

For example, `typ` may be `<authority>/key/create` or similar key mutation type.

```json5
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Existing key
    "typ": "cyphr.me/key/create",
    "id": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M", // New key's tmb
    "pre": "<target PS>",
    "commit":"<CS>"
  },
  "sig": "<b64ut>",
}
```



A new PS may be generated by signing a transaction
nonce.


Checkpoints are implicit: any
signed transaction can serve as a checkpoint provided it contains all concrete
components necessary to recompute the AS at that point.   Verifiers only need the current state plus the transaction chain
back to a known good state, the trust anchor. 


, especially for thin clients, new
devices, or after long periods of being unsynced. Checkpoints are a useful
optimization for implementations that expect long-lived principals with high
transaction volume (e.g., automated key rotation, frequent rule changes). They
are also a useful debugging tool. Clients should update their trust anchor to such checkpoints for faster client
synchronization. 



#### 6.5 Key Transactions Summary

| Type          | Level | Adds Key | Removes Key | Notes                           |
| ------------- | ----- | -------- | ----------- | ------------------------------- |
| `key/revoke`  | 1+    | -        | ✓ (signer)  | Sets `rvk`, must be self-signed |
| `key/replace` | 2+    | ✓        | ✓ (signer)  | Atomic swap                     |
| `key/create`  | 3+    | ✓        | -           | -                               |
| `key/delete`  | 3+    | -        | ✓           | No revocation timestamp         |

 well as
ensuring that the targeted PT is calculated correctly, 

Merging is performed via a special transaction type, `principal/merge` 


Multihash identifiers are calculated for all state on a per commit basis.  For a
particular commit, for each algorithm referenced by the principal a digest value is calculated.
States are singular, having a singular underlying
structure, but may be referenced via multiple hashing algorithms. For a
particular commit, for each algorithm supported by any key, nonce, or embedding
in KT, a digest value is calculated. When only one algorithm is used by a
principal, the multihash has only one variant. When multiple algorithms are
used, the multihash has many variants. 
Instead of identifiers being tightly coupled to a single digest, identifiers are
coupled to a 


For example, if the set of keys supports SHA-256 and SHA-384, then both a
SHA-256 and a SHA-384 digest is calculated. If the keys support only SHA-256,
then only a SHA-256 digest is calculated.

A nonce (or multiple nonces) can be used to inject a specific digest algorithm
variant into the multihash identifier, even when no key supports that algorithm
natively. This is because a nonce itself is associated with a hashing algorithm
or multihash identifier.

(PR/PS, AS, KS, RS, DS, and all internal Merkle tree
nodes) when multiple hash algorithms are in use. 



  


The MHMR design achieves three simultaneous goals:

1. Cryptographic pluggability without algorithm lock-in
2. Support for embedded principals and recursive structures
3. Backward- and forward-compatibility during algorithm transitions

All references to state (PR/PS, AS, KS, RS, DS, etc.) in protocol messages, storage,
gossip, and verification use one of these multihash variants. 


  A multihash identifier for a node therefore consists of one digest per
  supported H at the time of the commit.
- All MHMR variants are considered equivalent references to the same logical
  state.
  Clients compute MHMR variants for every hash algorithm
currently supported by active algorithms at each commit.


combines two principal histories,



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


AAA has two distinguishing properties: A payload expressing an atomic intent and
public-key verification contained entirely within the message itself.


















```json5
{
  "txa": [{
      "pay": {
        "alg": "ES256",
        "now": 1623132000,
        "typ": "cyphr.me/cyphrpass/key/create",
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Signing `tmb`
        "id": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // The `tmb` of the new key.  In this case, itself.
      },
      "sig": "<b64ut>"
      },{
      "pay": {
        "alg": "ES256",
        "now": 1736893000,
        "typ": "cyphr.me/cyphrpass/principal/create",
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        "id":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // ID == PR
      },
      "sig": "<b64ut>",
      }],
  "txc":[{
    "pay":{
        "alg": "ES256",
        "now": 1736893000,
        "typ": "cyphr.me/cyphrpass/commit/create",
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        // Commit
        "pre":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",   // Prior state is the genesis key
        "commit":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // In this case, CS = MR(tmb₁)
      },
      "sig": "<b64ut>"
  }],
  "meta":{
    "forward_PT":"<b64ut>",
    "txa_mr":"<b64ut>",
    "txc_mr":"<b64ut>",
    "commit_id":"<b64ut>"
  },
  "keys": [{ // key public material
    "tag": "User Key 0",
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "alg": "ES256",
    "now": 1623132000,
    "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  }]
}
```


```json5
{
  "txs": [{
    "pay": {
      "alg": "ES256",
      "now": 1623132000,
      "typ": "cyphr.me/cyphrpass/key/create",
      "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Signing `tmb`
      "id": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // The `tmb` of the new key.  In this case, itself.
    },
    "sig": "<b64ut>"
    },{
    "pay": {
      "alg": "ES256",
      "now": 1736893000,
      "typ": "cyphr.me/cyphrpass/principal/create",
      "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
      "id":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // ID == PR
    },
    "sig": "<b64ut>",
    },{
    "pay":{
        "alg": "ES256",
        "now": 1736893000,
        "typ": "cyphr.me/cyphrpass/commit/create",
        "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        // Commit
        "pre":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",   // Prior state is the genesis key
        "commit":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg" // In this case, CS = MR(tmb₁)
      },
      "sig": "<b64ut>"
  }],
  "meta":{
    "forward_PT":"<b64ut>",
    "txa_mr":"<b64ut>",
    "txc_mr":"<b64ut>",
    "commit_id":"<b64ut>"
  },
  "keys": [{ // key public material
    "tag": "User Key 0",
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "alg": "ES256",
    "now": 1623132000,
    "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  }]
}
```


 forward state (`fwd`) through
`commit`.







### 18.1 Resync and Recovering from Trust Anchor (Last Known Good State) // TODO WTF

When a third party is out of sync or divergent from the principal state, the
third party may recover from the the trust anchor.

- No useful active keys remain (all revoked, inaccessible, or lack appropriate permissions to meaningfully mutate AT.)
- No designated recovery agents or fallback mechanisms are present or able to
  act
- The principal AS cannot be mutated. No new transactions are possible via the
  protocol (although some data actions may be possible)

For unrecoverable principals, none of the self-recovery mechanisms listed can prevent or reverse an
unrecoverable principal state once it has occurred, they must be established
before key loss/revocation.


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
| ----- | -------------- | --------------------------------------------------- |
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




.  Commits
contain one or more transactions, which themselves contain one or more cozies



- `pre`: the prior principal state (PS)
- `fwd`: the forward principal tree 
- `TS`: ordered MR(txs)


Both
are the Merkle root of all related `czd`s ordered by position as given by the
principal with . // TODO sorta wrong
TMR
contains mutation transactions and TCR contains commit transaction cozies.
Interlacing cozies
related to different transaction would be interpreted as separate transactions.
Mutation
transaction cozies are grouped by transaction. 






For mutation transactions, all related coz's `czd` are rooted, which is the
identifier for the transaction.  Then all mutation transaction identifiers are
rooted, which gives the transaction mutation root (TMR). 

For the commit transaction, since there is only ever one transaction per commit,
the transaction commit root (TCR) is calculated directly from coz's `czd`.

Then the TMR and TCR are rooted, which yields the transaction root, TR.










A commit consists of N mutation transactions and one final commit transaction.
The Transaction Root (TR) (Level 3+) is the MR(TMR, TCR). The identifier for
each transaction, `tx_id`, is the MR of its `czd`s. 

The transaction mutation root, TMR, is the MR of mutation transactions.
The transaction commit root, TCR, is the commit `czd` MR. Unlike TMR, there are
no intermediate TCR roots since there is only one commit transaction per commit.

The wire format for transactions, labeled by the field `txs`, is a list of
lists, where each list item is a transaction, and each transaction contains one
to many cozies.  [ tx₀, tx₁, ..., commit_tx ] where each tx is an array of cozies.




Transactions and cozies are ordered as specified by the
principal with the condition of the commit transaction appearing last.

```
  TX₀ = MR(czd₀, czd₁?, ...)
  TMR = MR(TX₀, TX₁?, ...)
  TCR = MR(czd₀, czd₁?, ...)
  TR  = MR(TMR, TCR)
```


Pre 
In addition to Cyphrpass required fields, transactions have the following
required fields.

- `pre`: The prior Principal Tree (PT), as denoted by PR, to mutate. At genesis,
  PR equals AR via implicit promotion. (`commit` refers to the CR after the
  commit's mutation.)

  - No prior field (no `pre`).

  Every
transaction, including genesis transactions, requires `pre`, maintaining chain
continuity from the genesis key.




## 3 State
### 3.0 Feature Levels
Cyphrpass has six operational levels. Each level increases complexity. Clients
may choose to remain compatible with a particular level.

| Level | Description       | Components                   |
| ----- | ----------------- | ---------------------------- |
| **1** | Single static key | Key (denoted by `tmb`)       |
| **2** | Key replacement   | Replaceable key              |
| **3** | Multi-key/Commit  | Key Tree  (KT)               |
| **4** | Arbitrary data    | Data Tree (DT)               |
| **5** | Rules             | Rule Tree (RT)               |
| **6** | Programmable      | VM execution                 |

Principal levels describe increasing complexity of a principal's state
composition and are not an authorization input. Authorization is determined by
which state components exist and what rules govern them. A transaction is
authorized if and only if all three conditions hold:

1. **Antecedent Authorization Gate**: Every authentication component required to
   apply a transaction (signing key, target key, rule, etc.) must already be
   active in the principal's current state before the transaction is applied.
2. **Lifecycle gate**: The principal's current lifecycle state must permit the
   operation. For example, a frozen principal rejects mutations; a deleted
   principal rejects everything. (See section Lifecycle.)
3. **Capability gate**: The principal must have the state components required
   for the operation. Principal genesis is required for commits. Data actions
   require DT to exist. Rule operations require RT to exist. For Level 5+, Rule
   Tree (RT) may define additional constraints; weight thresholds, timelocks, or
   other conditions that must be satisfied for the transaction to proceed.



   is one of the two normal components for PR, so that PR = MR(SR,
CR). 



and
so `id` cannot be known at the time of the commit, only after.

 `tmb` == KR == AR ==
   PR







   Calculation Overhead:
Number of MR root digests in a commit:
 - Pre (Past PR)
 - TMR
 - TXC
 - Forward PT
 - arrow

Not cacheable (always have to recalculate at the time of a commit):
 - TMR
 - TXC
 - Forward PT
 - arrow

Don't need 
 - Forward CR. 


 wants to reuse keys from the source account, it




### 12.4 Rank

Equivalence across multihash algorithm variants is assumed by the protocol and
no relative strength ordering is enforced at the protocol level. When multiple
algorithms are supported, there may be a tie at the time of conversion.
Cyphr provides a default rank. Rank is a tiebreaker only and not a security
indicator. Misuse may have security implications.

Perhaps in the future, principals may set a rank order via
`cyphr/alg/rank/create` transaction (stored as a rule), but for now
this is out-of-scope.




No `keys` label.  KT is an array of either keys or embeddings.
```json5
{"PT":{ // The actual Principal Tree, at the point of this commit
    "AT":{   // Auth Tree
      "KT": { // Key tree
          "...":{...}, // Principal's key 1
          "...":{...}, // Principal's key 2
          "SHA256:T0T1HFBxNFbhjLC10sJTuzrdSJz060qIme1DKytDML8":"" // External Embedding
}}}}
```

Thought Experiment: Labeled Objects. No `keys` label, digest labels for all nodes.

