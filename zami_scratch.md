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




