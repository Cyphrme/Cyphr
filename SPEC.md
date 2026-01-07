# Cyphrpass Protocol Specification

**Version**: Draft v0.1  
**Status**: Work in Progress  
**Built on**: [Coz v1.0](https://github.com/Cyphrme/Coz)

---

## 1. Introduction

Cyphrpass is a self-sovereign identity and authentication protocol built on cryptographic Merkle trees. It enables:

- Password-free authentication via public key cryptography
- Multi-device key management with revocation
- Authenticated Atomic Actions (AAA) — individually signed, independently verifiable user actions
- Cryptographic primitive agnosticism via the Coz specification

---

## 2. Terminology

### 2.1 Core Concepts

| Term                  | Abbrev | Definition                                             |
| --------------------- | ------ | ------------------------------------------------------ |
| **Principal**         | —      | An identity in Cyphrpass. Replaces "account".          |
| **Principal Root**    | PR     | The initial, permanent digest identifying a principal. |
| **Principal State**   | PS     | Current top-level digest: `H(AS, DS)` or promoted.     |
| **Auth State**        | AS     | Authentication state: `H(KS, TS, RS)` or promoted.     |
| **Data State**        | DS     | State of user data/actions (Level 4+).                 |
| **Key State**         | KS     | Digest of active key thumbprints (`tmb`s).             |
| **Transaction State** | TS     | Digest of transaction `czd`s (key mutations).          |
| **Rule State**        | RS     | State of rules (Level 5: weighted keys, timelocks).    |

### 2.2 Implicit Promotion

When a component of the state tree contains only **one node**, that node's digest is **promoted** to the parent level without additional hashing.

**Examples:**

- Single key: `tmb` is promoted to KS, then to AS, then to PS (which equals PR)
- No DS present: AS is promoted to PS
- Only KS present (no TS/RS): KS is promoted to AS

This rule provides natural semantics for simple single-key principals without requiring explicit genesis transactions.

### 2.3 Nonces

One or more cryptographic nonces may be included at any level of the state tree:

- **Privacy**: Prevents correlation across services
- **Key count obfuscation**: Nonces are indistinguishable from key thumbprints, so observers cannot determine the true key count
- **Encapsulation**: Hides structure when desired

**Design Note:** Multiple nonces are permitted. An attacker cannot assume "N-1 of these must be real keys" since any number could be nonces.

---

## 3. Feature Levels

| Level | Description       | State Components             |
| ----- | ----------------- | ---------------------------- |
| **1** | Single static key | KS = AS = PS = PR            |
| **2** | Key replacement   | KS (single key, replaceable) |
| **3** | Multi-key         | KS (n keys) + TS             |
| **4** | Arbitrary data    | AS + TS + DS → PS            |
| **5** | Rules             | AS (with RS) + DS            |
| **6** | Turing complete   | VM execution                 |

### 3.1 Level 1: Static Key

- Single key, never changes
- `PR = PS = AS = KS = tmb`
- No transactions, no TS
- Use case: IoT devices, hardware tokens

### 3.2 Level 2: Key Replacement

- Single active key at any time
- `key/replace` transaction swaps current key for new key
- TS is implicit at Level 2 (not stored in protocol)
- Use case: Devices that can rotate keys but only store one
  ZAMI: Need to talk in disaster recover in disaster recovery section about revoke.

### 3.3 Level 3: Multi-Key

- Multiple concurrent keys with equal authority
- Any key can `key/add`, `key/delete`, or `key/revoke` any other key
- Standard for multi-device users
- Recommended minimum for services

### 3.4 Level 4: Arbitrary Data

- Introduces Data State (DS) for user actions
- Actions (comments, posts, etc.) recorded in DS
- `PS = H(AS, DS)`
- Enables Authenticated Atomic Actions (AAA)

### 3.5 Genesis (Account Creation)

A principal is created (genesis) in one of two ways:

**Implicit Genesis (Single Key)**

- No transaction required
- `PR = tmb` of the single key (via implicit promotion)
- First signature by this key constitutes Proof of Possession (PoP)
- Principal exists the moment the key exists

```
PR = PS = AS = KS = tmb
```

**Explicit Genesis (Multi-Key)**

- Requires a signed genesis transaction
- One key signs a `key/add` transaction to register additional keys
- `PR = H(sort(tmb₀, tmb₁, ..., nonce?))`
- The genesis transaction constitutes PoP for the signing key

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<genesis key tmb>",
    "typ": "<authority>/key/add",
    "id": "<second key tmb>"
  },
  "key": {
    /* second key public material */
  },
  "sig": "<b64ut>"
}
```

**Design Note:** The first transaction establishing multiple keys is the genesis. There is no separate "create account" operation — identity emerges from the first key or transaction.

---

## 4. Data Structures

### 4.1 Key

A Coz key with standard fields:

```json
{
  "alg": "ES256",
  "pub": "<b64ut>",
  "prv": "<b64ut>", // private, never transmitted
  "tmb": "<b64ut>", // thumbprint
  "now": 1623132000, // creation timestamp
  "tag": "Device name" // optional human label
}
```

Example key:

```json
{
  "alg": "ES256",
  "now": 1623132000,
  "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
  "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  "tag": "Zami's Majuscule Key.",
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
}
```

The `tmb` (thumbprint) is the digest of the canonical public key representation, using the hash algorithm associated with `alg`.

### 4.2 Transactions

Transactions are signed Coz messages that mutate Auth State. Each transaction references the prior AS via the `pre` field.

#### 4.2.1 `key/add` — Add a Key (Level 3+)

Adds a new key to KS.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/key/add",
    "pre": "<previous AS>",
    "id": "<new key tmb>"
  },
  "key": {
    "alg": "ES256",
    "pub": "<new key pub>",
    "tmb": "<new key tmb>"
  },
  "sig": "<b64ut>"
}
```

**Required fields:**

- `tmb`: Thumbprint of the signing key (must be in current KS)
- `pre`: Previous Auth State digest
- `id`: Thumbprint of the key being added
- `key`: Public key material (separate from `pay` for clarity)

#### 4.2.2 `key/delete` — Remove a Key (Level 3+)

Removes a key from KS without marking it as compromised.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/key/delete",
    "pre": "<previous AS>",
    "id": "<key to delete tmb>"
  },
  "sig": "<b64ut>"
}
```

**Required fields:**

- `id`: Thumbprint of the key being removed

#### 4.2.3 `key/replace` — Atomic Key Swap (Level 2+)

Removes the signing key and adds a new key atomically. Maintains single-key invariant for Level 2 devices.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<old key tmb>",
    "typ": "<authority>/key/replace",
    "pre": "<previous AS>",
    "id": "<new key tmb>"
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

#### 4.2.4 `key/revoke` — Revoke a Key (Level 2+)

Removes a key and marks it as compromised with a revocation timestamp.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/key/revoke",
    "pre": "<previous AS>",
    "id": "<key to revoke tmb>",
    "rvk": 1628181264
  },
  "sig": "<b64ut>"
}
```

**Required fields:**

- `id`: Thumbprint of the key being revoked
- `rvk`: Revocation timestamp (Coz standard field)

**Semantics:**

- Signatures by the revoked key with `now >= rvk` are invalid
- Setting `rvk = now` removes a key without invalidating past signatures

**Transaction Type Summary:**

| Type          | Level | Adds Key | Removes Key | Notes                   |
| ------------- | ----- | -------- | ----------- | ----------------------- |
| `key/add`     | 3+    | ✓        | —           | —                       |
| `key/delete`  | 3+    | —        | ✓           | No revocation timestamp |
| `key/replace` | 2+    | ✓        | ✓ (signer)  | Atomic swap             |
| `key/revoke`  | 2+    | —        | ✓           | Sets `rvk` timestamp    |

### 4.3 Action (Level 4)

A signed Coz message representing a user action, recorded in DS:

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "<signing key tmb>",
    "typ": "cyphr.me/comment/create",
    "msg": "Hello, world!"
  },
  "sig": "<b64ut>"
}
```

---

## 5. Authentication

Cyphrpass replaces password-based authentication with cryptographic Proof of Possession (PoP).

### 5.1 Proof of Possession (PoP)

Every valid signature by an authorized key constitutes a Proof of Possession:

- **Genesis PoP**: First signature by a key proves possession (account creation)
- **Transaction PoP**: Signing a key mutation proves authorization
- **Action PoP**: Signing an action proves the principal performed it
- **Login PoP**: Signing a challenge proves identity to a service

### 5.2 Login Flow

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
    "tmb": "<signing key tmb>",
    "typ": "<service>/auth/login",
    "challenge": "<256-bit nonce from service>"
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
    "tmb": "<signing key tmb>",
    "typ": "<service>/auth/login"
  },
  "sig": "<b64ut>"
}
```

### 5.3 Replay Prevention

Two mechanisms prevent signature replay:

| Mechanism            | How it works                                          | Trade-off           |
| -------------------- | ----------------------------------------------------- | ------------------- |
| **Challenge nonce**  | Service issues unique 256-bit nonce per login attempt | Requires round-trip |
| **Timestamp window** | `now` must be within ±N seconds of server time        | Clock sync required |

**Recommendation:** Use challenge-response for high-security contexts. Timestamp-based is acceptable for low-friction flows with trusted time sources.

### 5.4 Bearer Tokens

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

**Note:** The service signs the token with its own key. The principal verifies the token came from the expected service.

### 5.5 Storage Models

Cyphrpass distinguishes between two storage contexts:

#### 5.5.1 Client/Principal Storage

Clients are categorized as **thin** or **fat** based on storage capacity:

**Thin Client** (browser, IoT):

| Data         | Required | Notes                             |
| ------------ | -------- | --------------------------------- |
| Private keys | ✓        | Never transmitted                 |
| PR           | Optional | Can derive from key if single-key |
| Public keys  | Optional | Retrieve from service             |
| Current PS   | Optional | Retrieve from service             |
| Transactions | Optional | Delegate to service               |

Thin clients rely on services for state resolution. Only the private key is essential.

**Fat Client** (desktop app, trusted device):

| Data         | Required | Notes                  |
| ------------ | -------- | ---------------------- |
| Private keys | ✓        | Never transmitted      |
| Public keys  | ✓        | With `tmb`, `alg`      |
| PR           | ✓        | Permanent identity     |
| Current PS   | ✓        | For state verification |
| Transactions | ✓        | Full audit trail       |
| Actions      | Optional | Application-specific   |

Fat clients store exhaustive history for offline verification and maximum sovereignty.

#### 5.5.2 Third-Party Service Storage

Services that interact with principals store:

| Data                | Purpose                |
| ------------------- | ---------------------- |
| PR                  | Principal identity     |
| Current PS          | State verification     |
| Active public keys  | Signature verification |
| Transaction history | Full audit trail       |
| Actions (DS)        | Application data       |

**Service operations:**

- **Pruning**: Services may discard irrelevant user data (old actions, etc.)
- **Key recovery**: Services may assist in recovery flows (see Disaster Recovery section)
- **State resolution**: Services can provide transaction history for principals to verify

**Trust model:** Services are optional — principals can self-host or use multiple services. Full verification is always possible with transaction history.

---

## 6. State Calculation

### 6.1 Canonical Digest Algorithm

All state digests follow the same algorithm:

1. **Collect** component digests (including nonce if present).
2. **Sort** lexicographically (byte comparison).
3. **Concatenate** sorted digests.
4. **Hash** using the algorithm associated with the signing key.

```
digest = H(sort(d₀, d₁, ...))
```

**Implicit Promotion**: If only one digest component exists, it is promoted without hashing.

### 6.2 Key State (KS)

```
if n == 1:
    KS = tmb₀                              # implicit promotion
else:
    KS = H(sort(tmb₀, tmb₁, nonce?, PS?, ...))
```

### 6.3 Transaction State (TS)

TS is the digest of all transaction `czd`s:

```
if no transactions:
    TS = nil
elif 1 transaction:
    TS = czd₀                              # implicit promotion
else:
    TS = H(sort(czd₀, czd₁, nonce?, ...))
```

### 6.4 Data State (DS) — Level 4+

DS is the digest of all action `czd`s:

```
if no actions:
    DS = nil
elif 1 action && no nonce:
    DS = czd₀                              # implicit promotion
else:
    DS = H(sort(czd₀, czd₁,  nonce?, ...))
```

### 6.5 Auth State (AS)

AS combines authentication-related states:

```
if TS == nil && RS == nil && no nonce:
    AS = KS                                # implicit promotion
else:
    AS = H(sort(KS, TS?, RS?,  nonce?) ||)   # nil components excluded from sort
```

### 6.6 Principal State (PS)

```
if DS == nil && no nonce:
    PS = AS                                # implicit promotion
else:
    PS = H(sort(AS, DS?) || nonce?)
```

### 6.7 Principal Root (PR)

The PR is the **first** PS ever computed for the principal. It is **permanent** and never changes.

**Genesis cases:**

- **Single key, no transactions, no nonce**: `PR = tmb` (fully promoted)
- **Multiple keys**: `PR = H(sort(tmb₀, tmb1,nonce?, ...))`
- **With DS at genesis**: `PR = H(sort(AS₀, DS₀, nonce?))`

When a principal upgrades (e.g., adds a second key), the **PR stays the same**, only PS evolves.

---

## 7. Node Structure

The **Auth State (AS) chain** is the core of Cyphrpass — it provides the authentication and permission layer for the Internet. Each auth transaction forms a node referencing the prior AS.

### 7.1 Transaction Node

Transactions mutate the AS and form a chain via the `pre` field:

typ` may be "<authority>/key/add" or "<authority>/key/upsert"

```json5
{
  pay: {
    alg: "ES256",
    now: 1628181264,
    tmb: "<signing key tmb>", // Existing key
    typ: "<authority>/key/add",
    pre: "<previous AS>",
    id: "<new keys tmb>",
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
transaction is valid base on key state, rule state, and prior transaction. See
section "Resolve" for more detail.

### 7.2 Actions (Level 4)

Actions are **stateless** signed messages. They are simply signed by an authorized key without chain structure:

- No `prior` field required
- DS is computed from action `czd`'s, but actions themselves don't track order
- Ordering (if needed) is determined by `now` timestamps

This keeps actions lightweight for common use cases (comments, posts, etc.).

### 7.3 State Resolution

To resolve from a **target AS** to a **prior known AS**:

1. Obtain current AS (from principal or trusted service)
2. Request transaction chain from target back to prior known
3. Verify `pre` references form unbroken chain
4. Validate each signature against KS at that point
5. Trust is optional — full independent verification is always possible

ZAMI brainstorm with AI on Checkpoints.

1. Not sure if this is possible or useful. All blocks may already be checkpoints.

### 7.3.1 Checkpoint State Resolution

With long chains, transitive transactions may represent a significant amount of data.  
To shorten require resolution, a checkpoint may be created.
If not wanting to include transitive transactions (Transitive closure)

### 7.4 Level 5 Preview: Weighted Permissions

At Level 5, the Rule State (RS) introduces **weighted keys**:

- Each key has a weight/score.
- Actions require meeting a threshold weight
- Enables tiered permissions (e.g., admin keys vs. limited keys)

Without being define, each key weight, action threshold, and transaction
threshold is implicitly 1.

For example, for 2 out of three for a "cyphrpass/key/create", two cozies need to
be signed by independent keys of weight 1 for the transaction to be valid.

First, define the rule:
// Good point why `upsert` might be bad for keys.

```json5
{
  "cyphrpass/key/add": 2,
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
        typ: "<authority>/cyphrpass/key/add",
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
        typ: "<authority>/cyphrpass/key/add",
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

## 8. Verification (Level 3)

To verify a principal's current state:

1. **Obtain PR or PS** — the claimed principal root or transitive state (PS)
2. **Obtain transaction history** — ordered list of transactions from genesis or prior PS
3. **Replay transactions**:
   - Start with genesis KS (initial keys)
   - For each transaction, verify:
     - Signature is valid
     - `tmb` belongs to a key in current KS
     - `now` is after previous transaction (if time ordering required)
     - Transaction is well-formed for its `typ`
   - Apply mutation to derive new KS
4. **Compare** — final computed KS/AS/PS should match claimed current state

---

## 9. Derivations

Cyphrpass supports multiple cryptographic algorithms. A **derivation** is the digest of a state using a specific hash algorithm.

For each key `alg`, the associated hash algorithm is used:

- ES256 → SHA-256
- ES384 → SHA-384
- ES512, Ed25519 → SHA-512

By default, derivations are computed for all algorithms referenced by active keys.

---

## 10. Transaction Type Grammar

```
<typ> = <authority>/<action>
<action> = <noun>[/<noun>...]/<verb>
<verb> = create | read | update | upsert | delete | revoke
```

TODO brainstorm with AI about "action" being overloaded. DS has actions, `typ` is an action, and `typ` semantics itself has an action.

Example type: "cyphr.me/ac/image/create"

The first unit is the authority. (auth)
Everything after authority is action (act)
The last unit is the verb. (verb)
The second unit is the root. (root)
Middle units are the noun (noun)
Trailing nouns are adjectives. (adj)
The last noun unit is the child. (child)

In cases where there is only one noun, that noun is the noun, root, and child. When a noun has two or more components (such as /ac/image), it is called a compound noun.

Example 1: "cyphr.me/ac/image/create"

Authority: cyphr.me
Action: ac/image/create
Root: ac
Noun: ac/image
Verb: create
Child: image

**Examples:**

- `cyphr.me/key/upsert`
- `cyphr.me/key/revoke`
- `cyphr.me/comment/create`

The authority may be a domain or a Principal Root.

---

## 11. Test Vectors

_TODO: Add golden test vectors for Go/Rust implementation verification._

---

## Appendix A: Coz Field Reference

| Field | Description                       |
| ----- | --------------------------------- |
| `alg` | Algorithm identifier              |
| `now` | UTC Unix timestamp                |
| `tmb` | Key thumbprint                    |
| `pub` | Public key                        |
| `prv` | Private key                       |
| `sig` | Signature                         |
| `rvk` | Revocation timestamp              |
| `typ` | Action type URI                   |
| `msg` | Message payload                   |
| `dig` | External content digest           |
| `cad` | Canonical hash of payload         |
| `czd` | Coz digest (hash of `[cad, sig]`) |
