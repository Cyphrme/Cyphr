+++
title       = "Glossary"
description = "Protocol terminology and definitions"
weight      = 3
toc         = true
+++

Terms are drawn from [SPEC.md §2.2](specification.html#22-terminology).
Implementation-specific terms are noted as such.

## State Tree

**Principal Tree (PT)**
: The complete state of an identity, encompassing authentication, data, and
commit history.

**State Root (SR)**
: Principal non-commit state. `SR = MR(AR, DR, ...)`.

**Auth Root (AR)**
: Authentication state. `AR = MR(KR, RR, ...)`.

**Key Root (KR)**
: Merkle root of active public keys. `KR = MR(tmb₁, tmb₂, ...)`.

**Rule Root (RR)**
: Merkle root of rules. `RR = MR(rule₁, rule₂, ...)`.
Introduced at Level 5.

**Data Root (DR)**
: Merkle root of user data action digests. Introduced at Level 4.

**Commit Root (CR)**
: MALT root of transactions. `CR = MALTR(TR₀, TR₁?, ...)`.
Introduced at Level 3.

**Transaction Root (TR)**
: The Merkle root of all transactions within a single commit.
Introduced at Level 3.

The corresponding tree data structures are: Auth Tree (AT), Key Tree (KT),
Rule Tree (RT), Data Tree (DT), and Commit Tree (CT).

## Roots and Identity

**Principal Genesis (PG)**
: The initial, permanent principal identifier. The first PR.
Once set, PG never changes — it is the stable identity anchor.

**Principal Root (PR)**
: The current top-level identity digest. `PR = MR(SR, CR?, ...)`.
PR changes with every commit. At genesis, PR = PG.

**Tip**
: The latest PR — the most recent digest identifier for a principal.

**Trust Anchor**
: The last known valid state for a principal. Used by services to
establish a reference point for verification.

## Lifecycle

**Implicit Promotion**
: When a root has only one child digest, it promotes without hashing.
At Level 1: `tmb == KR == AR == SR == PR`.

**Explicit Genesis**
: Level 3+ genesis where multiple keys produce a real Merkle root
distinct from any single key. Requires the Commit Tree and PG.

**Nascent Principal** _(implementation)_
: A principal that has not yet committed `principal/create`. The Rust
implementation encodes this as a type-state.

**Established Principal** _(implementation)_
: A principal whose PG has been frozen by `principal/create`.

## Actions and Commits

**Action**
: A signed Coz message identified by `typ`. The hypernym of
"transaction" and "data action."

**Transaction**
: An action that mutates authentication state (key operations).

**Data Action**
: An action recorded in the Data Tree (Level 4+). Application-defined
(e.g., login, vote, comment).

**Commit**
: An atomic bundle of one or more transactions. All transactions in
a commit succeed or fail together. Each commit references the prior
PR via the `pre` field.

**Commit Scope** _(implementation)_
: The API mechanism for grouping transactions into an atomic commit. In
Rust, `begin_commit()` returns a `CommitScope` that holds `&mut Principal`.
In Go, `BeginCommit()` returns an `OpenCommit`.

**Authenticated Atomic Action (AAA)**
: Any user action individually signed and independently verifiable.
Enabled at Level 4.

## Transaction Types

| Typ                | Level | Purpose                                       |
| ------------------ | ----- | --------------------------------------------- |
| `principal/create` | 3+    | Freeze PG and establish the principal         |
| `key/create`       | 3+    | Add a public key to the Key Tree              |
| `key/delete`       | 3+    | Remove a key (requires another key as signer) |
| `key/replace`      | 2+    | Atomic swap of one key for another            |
| `key/revoke`       | 1+    | Self-revoke (signer removes itself)           |

## Cryptographic Primitives

**Coz**
: The cryptographic JSON messaging standard that Cyphr uses for all signed
payloads. Defines signature format, verification, and thumbprint
computation.

**MALT**
: Merkle Append-only Log Tree. The data structure underlying the
Commit Tree. Provides append-only, verifiable accumulation.

**MultiHash Merkle Root (MHMR)**
: Algorithm-tagged digest format. PG, PR, SR, AR, KR, RR, DR, and CR
are all MHMR values, enabling cryptographic algorithm agnosticism.

**Derivation Set**
: The set of algorithm-specific digest variants for a single logical
value. A PR might carry SHA-256 and SHA-384 variants simultaneously.

**Thumbprint (tmb)**
: The canonical identifier for a public key, computed per the Coz
thumbprint algorithm.

**b64ut**
: Base64 URI canonical Truncated. The encoding used for all digest
values (RFC 4648 base64url, no padding, rejects non-canonical input).

## Protocol Levels

| Level | Name               | Introduces                                      |
| ----- | ------------------ | ----------------------------------------------- |
| 1     | Static Key         | Single key; `tmb == KR == AR == SR == PR`       |
| 2     | Key Replacement    | `key/replace` for atomic key swap               |
| 3     | Multi-Key / Commit | CT, PG, multi-key KT, `key/create`/`key/delete` |
| 4     | Arbitrary Data     | DT, data actions, AAA                           |
| 5     | Rules              | RT/RR, weights, timelocks, m-of-n signing       |
| 6     | Programmable (VM)  | Executable bytecode rules, smart contracts      |

## Storage

**FileStore** _(implementation)_
: The default storage backend. Persists commits as JSONL files in a
directory, keyed by Principal Root.

**Keystore** _(implementation)_
: Local private key storage. The CLI uses `cyphr-keys.json` by default.
Keys are stored with their algorithm, thumbprint, and optional tag.

**JSONL Export** _(implementation)_
: Portable identity format. One JSON object per line, one line per commit.
Used by `cyphr export` and `cyphr import`.
