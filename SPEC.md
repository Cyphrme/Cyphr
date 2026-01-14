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
- Cryptographic primitive agnosticism via the Coz JSON specification

Binary encoded values in this document are in `b64ut`: "Base64 URI canonical truncated" (URL alphabet, errors on non-canonical encodings, no padding).

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

This rule provides natural semantics for simple single-key principals without requiring explicit genesis transactions. Also note that promotion is recursive; items deep in the tree can be promoted to the root level.

### 2.3 Nonces

One or more cryptographic nonces may be included at any level of the state tree:

- **Encapsulation**: Hides structure when desired
- **Reuse Privacy**: Prevents correlation across services
- **Count Obfuscation**: Nonces are indistinguishable from key thumbprints and other digest values, so observers cannot determine the true count

Design Notes:

- Multiple nonces are permitted.
- At signing, the key structure may be revealed.

The general principle of obfuscated structures becoming transparent is **reveal**. Keys are revealed at signing, nonces and other datastructures may also be required to be revealed during transactions, actions, or operations requiring signing.

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
- **Self-revoke**: A Level 1 key can self-revoke, but this results in permanent lockout (no recovery without sideband intervention)

### 3.2 Level 2: Key Replacement

- Single active key at any time
- `key/replace` transaction swaps current key for new key
- TS is implicit at Level 2 (not stored in protocol)
- Use case: Devices that can rotate keys but only store one

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

### 3.5 Level 5: Rules (Weighted Permissions)

- Introduces Rule State (RS) for access control
- Each key has a weight (default: 1)
- Transactions and actions have threshold requirements
- Enables: M-of-N signing, tiered permissions, timelocks
- RS is a digest component of AS (like KS and TS); we sort by digest _value_ (bytes), not by label

**Key concepts:**

- **Weight**: Numeric value assigned to each key
- **Threshold**: Minimum total weight required for an action
- **Timelock**: Delay before certain actions take effect

### 3.6 Level 6: Turing Complete VM

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
  tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // thumbprint
  alg: "ES256", // Key algorithm.
  now: 1623132000, // creation timestamp
  pub: "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g", // Public component
  prv: "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA", // Private component, never transmitted
}
```

The `tmb` (thumbprint) is the digest of the canonical public key representation, using the hash algorithm associated with `alg`.

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

**Semantics:** Unlike `key/revoke`, `key/delete` does NOT invalidate the key itself — only removes it from KS. Use for graceful key retirement (e.g., decommissioning a device) when the key was never compromised.

**TODO:** Define retrospection semantics — how past signatures are validated after key removal/revocation needs further specification.

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

#### 4.2.4 `key/revoke` — Revoke a Key (Self-Revoke, Level 1+)

Self-revoke is a special case of `key/revoke` where the signing key is the same
as the key being revoked. It is used to revoke a key that has been compromised.
Self-revoke is built into the Coz standard.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/key/revoke",
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

- `pre`: Previous Auth State digest
- `id`: Thumbprint of the key being revoked (must differ from `tmb`)
- `rvk`: Revocation timestamp

**Transaction Type Summary:**

| Type                 | Level | Adds Key | Removes Key | Notes                   |
| -------------------- | ----- | -------- | ----------- | ----------------------- |
| `key/add`            | 3+    | ✓        | —           | —                       |
| `key/delete`         | 3+    | —        | ✓           | No revocation timestamp |
| `key/replace`        | 2+    | ✓        | ✓ (signer)  | Atomic swap             |
| `key/revoke` (self)  | 1+    | —        | ✓ (signer)  | Self-revoke, sets `rvk` |
| `key/revoke` (other) | 3+    | —        | ✓           | Revoke another key      |

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

### 5. Genesis (Account Creation) // AI TODO, iterated this up to 5, subsequent sections need

### 5.1 Initial Transactions

A principal is created (genesis) in one of two ways:

**Implicit Genesis (Single Key)**

- No transaction required
- `PR = tmb` of the single key (via implicit promotion)
- First signature by this key constitutes Proof of Possession (PoP)
- Principal exists the moment the key exists
- The first transaction signed with the key is the implicit genesis.
- There is no separate "create account" operation. Identity emerges from the first key and transaction.

```
PR = PS = AS = KS = `tmb`
```

**Explicit Genesis (Single-Key)**

- Requires a signed genesis transaction
- Key signs a `key/add` transaction to add itself as the principal.
- `PR = H(sort(tmb₀, nonce?))`
- The genesis transaction constitutes PoP for the signing key.
- Optionally, the principal root, `pr` may also be included.

**`typ`**: `<authority>/key/add`

- `id`: `<genesis key tmb>`
- `pr`: `<Principal Root value>`
- `key`: `<key public material>`

```json5
{
  pay: {
    alg: "ES256",
    now: 1628181264,
    tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // genesis key tmb
    typ: "cyphr.me/cyphrpass/key/add",
    id: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // genesis key tmb
    pr: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg", // Principal Root value, in this case the same value as `tmb` since there is no nonce or other value.
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

- Key signs a `key/add` transaction
- `PR = H(sort(tmb₀, tmb₁, ..., nonce?))`
- The genesis transaction constitutes PoP for the signing key
- Without rules, each key has equal weight, so any initial key can sign.
- Keys are added to the PR, calculated beforehand.

**`typ`: `<authority>/key/add`**

- `id`: `<genesis key tmb>`
- `pr`: `<Principal Root value>`
- `keys`: `<key public material>`

```json5
{
  cozies: [
    {
      pay: {
        alg: "ES256",
        now: 1628181264,
        tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        typ: "cyphr.me/cyphrpass/key/add",
        id: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        pr: "<Principal Root value", // TODO insert actual value for this transaction.
      },
      sig: "<b64ut>", // TODO actual sig
    },
    {
      pay: {
        alg: "ES256",
        now: 1628181264,
        tmb: "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
        typ: "cyphr.me/cyphrpass/key/add",
        id: "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
        pr: "<Principal Root value", // TODO insert actual value for this transaction.
      },
      sig: "<b64ut>", // TODO actual sig
    },
  ],
  keys: [
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

---

## 5. Authentication

Cyphrpass replaces password-based authentication with cryptographic Proof of
Possession (PoP).

Cyphrpass suggests AAA (Authenticated Atomic Action) over bearer tokens when
possible, but bearer tokens are still useful for access control and quickly
upgrading legacy password systems.

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

## 6. Storage Models

Cyphrpass distinguishes between two storage contexts:

### 6.1 Client/Principal Storage

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

### 6.2 Third-Party Service Storage

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

### 6.3 Storage API (Non-Normative)

> [!NOTE]
> This section is **informative only**. Implementations may use any storage
> mechanism appropriate to their deployment context.

#### 6.3.1 Export Format

The recommended export format is newline-delimited JSON (JSONL) containing all
signed transactions and actions:

```jsonl
{"typ":"cyphr.me/cyphrpass/key/add","pay":{...},"sig":"...","key":{...}}
{"typ":"cyphr.me/cyphrpass/key/add","pay":{...},"sig":"...","key":{...}}
{"typ":"cyphr.me/comment/create","pay":{...},"sig":"..."}
```

**Properties:**

- **Immutable history**: Past entries are never modified
- **Self-verifying**: Each line is a complete, signed Coz message
- **Order derivable**: Canonical order determined by `pre` field chaining

Entries with `typ` prefix `<authority>/cyphrpass/*` are authentication
transactions; all others are data actions.

#### 6.3.2 Storage Capabilities

Storage backends provide:

- **Append**: Store signed entries for a principal
- **Retrieve**: Fetch entries (all or filtered by time range)
- **Existence check**: Determine if a principal exists

Semantic operations (verification, state computation, key validity) are handled
by the Cyphrpass protocol layer, not storage.

#### 6.3.3 Checkpoints

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

---

## 7. State Calculation

### 7.1 Canonical Digest Algorithm

All state digests follow the same algorithm:

1. **Collect** component digests (including nonce if present).
2. **Sort** lexicographically (byte comparison).
3. **Concatenate** sorted digests.
4. **Hash** using the algorithm associated with the signing key.

```
digest = H(sort(d₀, d₁, ...))
```

**Implicit Promotion**: If only one digest component exists, it is promoted without hashing.

### 7.2 Key State (KS)

```
if n == 1:
    KS = tmb₀                              # implicit promotion
else:
    KS = H(sort(tmb₀, tmb₁, nonce?, PS?, ...))
```

### 7.3 Transaction State (TS)

TS is the digest of all transaction `czd`s:

```
if no transactions:
    TS = nil
elif 1 transaction:
    TS = czd₀                              # implicit promotion
else:
    TS = H(sort(czd₀, czd₁, nonce?, ...))
```

### 7.4 Data State (DS) — Level 4+

DS is the digest of all action `czd`s:

```
if no actions:
    DS = nil
elif 1 action && no nonce:
    DS = czd₀                              # implicit promotion
else:
    DS = H(sort(czd₀, czd₁,  nonce?, ...))
```

### 7.5 Auth State (AS)

AS combines authentication-related states:

```
if TS == nil && RS == nil && no nonce:
    AS = KS                                # implicit promotion
else:
    AS = H(sort(KS, TS?, RS?,  nonce?) ||)   # nil components excluded from sort
```

### 7.6 Principal State (PS)

```
if DS == nil && no nonce:
    PS = AS                                # implicit promotion
else:
    PS = H(sort(AS, DS?) || nonce?)
```

### 7.7 Principal Root (PR)

The PR is the **first** PS ever computed for the principal. It is **permanent** and never changes.

**Genesis cases:**

- **Single key, no transactions, no nonce**: `PR = tmb` (fully promoted)
- **Multiple keys**: `PR = H(sort(tmb₀, tmb1,nonce?, ...))`
- **With DS at genesis**: `PR = H(sort(AS₀, DS₀, nonce?))`

When a principal upgrades (e.g., adds a second key), the **PR stays the same**, only PS evolves.

---

## 8. Node Structure

The **Auth State (AS) chain** is the core of Cyphrpass — it provides the authentication and permission layer for the Internet. Each auth transaction forms a node referencing the prior AS.

```text
       PR/PS (Genesis)             PS (State 2)               PS (State 3)
     +-------------------+      +-------------------+      +-------------------+
     |                   |      |                   |      |                   |
     |   [AS]     [DS]   | ===> |   [AS]     [DS]   | ===> |   [AS]     [DS]   |
     |    ^              |      |    |              |      |    |              |
     +----|--------------+      +----V--------------+      +----V--------------+
          |                          |                          |
          + <---------(pre)----------+ <-----------(pre)--------+
```

### 8.1 Transaction Node

Transactions mutate the AS and form a chain via the `pre` field:

`typ` may be `<authority>/key/add` or similar key mutation type.

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
transaction is valid based on key state, rule state, and prior transaction. See
section "Resolve" for more detail.

### 8.2 Actions (Level 4)

Actions are **stateless** signed messages. They are simply signed by an authorized key without chain structure:

- No `prior` field required
- DS is computed from action `czd`s, but actions themselves don't track order
- Ordering (if needed) is determined by `now` timestamps

This keeps actions lightweight for common use cases (comments, posts, etc.).

### 8.3 State Resolution

To resolve from a **target AS** to a **prior known AS**:

1. Obtain current AS (from principal or trusted service)
2. Request transaction chain from target back to prior known (`pre`)
3. Verify `pre` references form unbroken chain
4. Validate each signature against KS at that point

Trust is optional — full independent verification is always possible.

### 8.3.1 Checkpoints

Each state digest (AS, PS) encapsulates the full state at that point. Verifiers only need the current state plus the transaction chain back to a known-good checkpoint. The genesis state is the ultimate checkpoint; services MAY cache intermediate checkpoints to reduce chain length for verification.

### 8.4 Level 5 Preview: Weighted Permissions

At Level 5, the Rule State (RS) introduces **weighted keys**:

- Each key has a weight/score.
- Actions require meeting a threshold weight
- Enables tiered permissions (e.g., admin keys vs. limited keys)

Without being define, each key weight, action threshold, and transaction
threshold is implicitly 1.

For example, for 2 out of three for a `cyphrpass/key/create`, two cozies need to
be signed by independent keys of weight 1 for the transaction to be valid.

First, define the rule:

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

## 9. Verification (Level 3)

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

## 10. Recovery

When a principal loses access to all active keys, or the account is otherwise in
an **unrecoverable state** recovery mechanisms allow regaining control.

There are two main mechanisms:

- **Self Recovery**, various methods of backup. For user self management.
- **External Recovery** Where some permissions are delegated to an external
  account, a **Recovery Authority**. This may be social recovery or third-party service.

Level 1 doesn't support recovery. Any recovery is accomplished through sideband.
Level 2 supports recovery but only atomic swaps. The recovery key can replace the exiting key.
Level 3+ supports recovery and can add new keys.

### 10.1 Self-Recovery Mechanisms

| Mechanism         | Description                            | Trust Model  |
| ----------------- | -------------------------------------- | ------------ |
| **Backup Key**    | Backup key stored in a secure location | User custody |
| **Paper wallet**  | Backup key printed/stored offline      | User custody |
| **Hardware key**  | Yubikey or similar device              | User custody |
| **Airgapped key** | Cold storage, never online             | User custody |

### 10.2 Implicit Fallback (Single-Key Accounts)

For implicit (single-key) accounts, a `fallback` field MAY be included at key creation:

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

- The `fallback` field is NOT included in thumbprint calculation (allows changing fallback without changing identity)
- Assumes a trusted initial setup
- **Level 2 Restriction**: Level 2 accounts only support **atomic swap** (`key/replace`). The fallback functionality must adhere to this, replacing the lost key rather than complying with `key/add` like Level 3+.

### 10.2.1 Recovery Validity

Recovery agents can ONLY act when the account is in an **unrecoverable state**:

- All regular keys have been revoked or are inaccessible
- Insufficient keys remain to meet threshold for mutations (Level 5+)
- Signatures from recovery agents are invalid while account is recoverable
- This prevents recovery from being used as a backdoor
- The rule for key/add is of a higher weight than keys on the account

### 10.3 Recovery Transactions

#### 10.3.1 `recovery/designate` — Register Fallback

Registers a recovery agent (backup key, service, or social contacts).

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/recovery/designate",
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

#### 10.3.2 `recovery/delete` — Remove Fallback

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

### 10.4 Recovery Flow

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
    "typ": "<authority>/key/add",
    "pre": "<previous AS>",
    "id": "<new user key tmb>"
  },
  "key": {
    /* new user key */
  },
  "sig": "<b64ut>"
}
```

Because the agent was designated via `recovery/designate`, their `key/add` is valid even though no regular user key signed it.

### 10.5 External Recovery

External recovery delegates recovery authority to an external principal. The recovery agent verifies identity out-of-band and signs a recovery transaction on behalf of the locked-out user.

| Mechanism               | Description             | Trust Model       |
| ----------------------- | ----------------------- | ----------------- |
| **Social recovery**     | M-of-N trusted contacts | Distributed trust |
| **Third-party service** | Verification service    | Service trust     |

### 10.6 Social Recovery

For social recovery, multiple contacts sign:

- Each contact signs the same `key/add` transaction
- When `threshold` signatures are collected, the transaction is valid
- Contacts are identified by their PR

**Example:** 3-of-5 social recovery requires 3 contacts to sign the `key/add`.

### 10.7 Account Freeze

A **freeze** is a global protocol state where valid transactions are temporarily rejected to prevent unauthorized changes during a potential compromise. A freeze halts all key mutations (`key/*`) and may restrict other actions depending on service policy.

Freezes are **global** — they apply to the principal across all services that observe the freeze state.

#### 10.7.1 Self-Freeze

A user may initiate a freeze if they suspect their keys are compromised but do not yet want to revoke them (e.g., lost device).

- **Mechanism**: User signs a `freeze/init` transaction with an active key.
- **Effect**: Stops all mutations until unfrozen.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/freeze/init",
    "pre": "<previous AS>"
  },
  "sig": "<b64ut>"
}
```

#### 10.7.2 External Freeze

A designated **Recovery Authority** may initiate a freeze based on heuristics (irregular activity) or out-of-band communication (user phone call).

- **Mechanism**: Recovery agent signs `freeze/init`.
- **Effect**: Same as self-freeze.
- **Trust**: The principal explicitly delegates this power to the authority via `recovery/designate`.

#### 10.7.3 Thaw (Unfreeze)

To unfreeze an account:

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1628181264,
    "tmb": "<signing key tmb>",
    "typ": "<authority>/freeze/thaw",
    "pre": "<previous AS>"
  },
  "sig": "<b64ut>"
}
```

**Rules:**

- Self-freeze can be thawed by any active key
- External freeze requires the Recovery Authority to thaw (or the principal after a timeout, if configured)

### 10.8 Security Considerations

- **Timelocks (Level 5+):** Recovery can have a mandatory waiting period
- **Revocation:** Backup keys can be revoked if compromised
- **Multiple agents:** A principal MAY designate multiple fallback mechanisms, including M-of-N threshold requirements
- **Freeze abuse:** External freeze authority requires explicit delegation and trust

---

## 11. Timestamp Verification

When a key is compromised, attackers can sign messages with arbitrary `now` values. Timestamp verification prevents retroactive and future-dated attacks.

### 11.1 PS Timestamp Binding

The **latest known timestamp** for a principal is:

- The `now` field of the most recent transaction (if any)
- Otherwise, the key creation `now` (implicit accounts)

**Rule:** Services SHOULD reject actions where:

- `now` < latest known PS timestamp (too far in the past)
- `now` > server time + tolerance (too far in the future)

### 11.2 Tolerance Window

Services accept `now` values within an acceptable variance:

| Type             | Tolerance       | Rationale                                        |
| ---------------- | --------------- | ------------------------------------------------ |
| **Transactions** | ±60 seconds     | Strict — key mutations are security-critical     |
| **Actions**      | Service-defined | Looser — user data may legitimately be backdated |

**Implementation:** Compare `now` to server time at receipt. Reject if outside tolerance.

### 11.3 Revocation Timestamp Semantics

When a key is revoked with `rvk` = T:

- Signatures with `now` >= T are **invalid** (key was compromised)
- Signatures with `now` < T are **valid** (signed before compromise)
- Attackers cannot forge pre-revocation signatures if services enforce PS timestamp binding

### 11.4 Oracle Tiers

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
- Block timestamp proves signature existed before that time
- Irrefutable, but adds latency and cost

---

## 12. Derivations

A **derivation** is the digest of a state computed using a specific hash algorithm. States (KS, AS, PS) are singular, but can be referenced via multiple derivations.

### 12.1 Algorithm Mapping

Each key algorithm implies a hash algorithm:

| Key Algorithm | Hash Algorithm | Digest Size |
| ------------- | -------------- | ----------- |
| ES256         | SHA-256        | 32 bytes    |
| ES384         | SHA-384        | 48 bytes    |
| ES512         | SHA-512        | 64 bytes    |
| Ed25519       | SHA-512        | 64 bytes    |

### 12.2 Derivation Semantics

**Singular state, multiple references:**

- PR, PS, AS, KS are singular underlying states
- Each can be referenced by multiple derivations (one per hash algorithm)
- All derivations of the same state are equivalent references

**Active key dependency:**

- Derivations are computed for algorithms of **currently active keys**
- When a key is removed, its algorithm's derivation is no longer computed
- When a key is added, its algorithm's derivation begins being computed

**Example:** A principal with ES256 + ES384 keys has two derivations of PS:

```
PS_sha256 = SHA256(sort(AS, DS?, nonce?))
PS_sha384 = SHA384(sort(AS, DS?, nonce?))
```

If the ES384 key is removed, only `PS_sha256` is computed going forward.

### 12.3 Verification Context

When verifying a signature:

1. Identify the signing key's algorithm (from `alg` field)
2. Use the corresponding hash algorithm for derivation
3. Compute/compare state using that derivation

**Rule:** The derivation used for verification matches the signing key's algorithm.

---

## 13. Transaction Type Grammar

```
<typ> = <authority>/<action>
<action> = <noun>[/<noun>...]/<verb>
<verb> = create | read | update | upsert | delete | revoke
```

**Terminology note:** "Action" is used in three contexts:

1. **DS Action**: A signed user message recorded in Data State (Level 4+)
2. **Type Action**: The path after authority in a `typ` field
3. **Grammar verb**: The final component of a type (create, delete, etc.)

Context disambiguates usage.

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

## 14. Error Conditions

This section defines error conditions that implementations MUST detect. Error _responses_ (HTTP codes, messages, retry behavior) are implementation-defined.

### 14.1 Transaction Errors

| Error               | Condition                                        | Level |
| ------------------- | ------------------------------------------------ | ----- |
| `INVALID_SIGNATURE` | Signature does not verify against claimed key    | All   |
| `UNKNOWN_KEY`       | Referenced key (`tmb` or `id`) not in current KS | All   |
| `INVALID_PRIOR`     | `pre` does not match current AS                  | 2+    |
| `TIMESTAMP_PAST`    | `now` < latest known PS timestamp                | All   |
| `TIMESTAMP_FUTURE`  | `now` > server time + tolerance                  | All   |
| `KEY_REVOKED`       | Signing key has `rvk` ≤ `now`                    | 2+    |
| `MALFORMED_PAYLOAD` | Missing required fields for transaction type     | All   |
| `DUPLICATE_KEY`     | `key/add` for key already in KS                  | 3+    |
| `THRESHOLD_NOT_MET` | Signing keys do not meet required weight         | 5+    |

### 14.2 Recovery Errors

| Error                     | Condition                                        | Level |
| ------------------------- | ------------------------------------------------ | ----- |
| `RECOVERY_NOT_DESIGNATED` | Agent not registered via `recovery/designate`    | 3+    |
| `ACCOUNT_RECOVERABLE`     | Recovery attempted while regular keys are active | 3+    |
| `ACCOUNT_UNRECOVERABLE`   | No active keys AND no designated recovery agents | All   |

### 14.3 State Errors

| Error                 | Condition                                               | Level |
| --------------------- | ------------------------------------------------------- | ----- |
| `STATE_MISMATCH`      | Computed PS does not match claimed PS                   | All   |
| `CHAIN_BROKEN`        | `pre` references do not form valid chain to known state | 2+    |
| `DERIVATION_MISMATCH` | Derivation computed with wrong algorithm                | All   |

### 14.4 Action Errors (Level 4+)

| Error                 | Condition                               | Level |
| --------------------- | --------------------------------------- | ----- |
| `UNAUTHORIZED_ACTION` | Action `typ` not permitted for this key | 5+    |

### 14.5 Error Handling Guidance

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

## 15. Test Vectors

These golden test vectors enable implementation verification. All values use B64ut encoding.

- `tmb` = SHA-256(canonical(`{"alg":"ES256","pub":"..."}`))
- ES256 uses P-256 curve, SHA-256 for thumbprint

### 15.1 Golden Key (ES256)

```json
{
  "alg": "ES256",
  "now": 1623132000,
  "tag": "User Key 0",
  "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
}
```

### 15.1.1 Golden Key: "Key A" (ES256)

```json5
{
  alg: "ES256",
  now: 1768092490,
  tag: "User Key 1",
  pub: "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
  prv: "dRlV0LjnJOVfK_hNl_6rjVKutZWTHNL-Vs4_dVZ0bls",
  tmb: "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M",
}
```

### 15.1.2 Golden Key: Cyphrpass Server Key A (ES256)

```json5
{
  alg: "ES256",
  now: 1768092490,
  tag: "Cyphrpass Server Key A",
  tmb: "T0jUB_Bk4pzgvnNWMGfmV0pK4Gu63g_M08pu8HIUGkA",
  pub: "yfZ-PY4QdhWKJ0o41yc8-X9qnahpfKoTN6sr0zd68lMFNbAzOwj9LSVdRngno4Bs_CNyDJCQJ6uqq9Q65cjn-A",
  prv: "WG-hEn8De4fJJ3FxWAsOAADDp89XigiRajUCI9MFWSo",
}
```

### 15.2 Golden Message

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

### 15.3 State Derivation (Level 1/2)

For a single-key account with the golden key:

```
KS = tmb (implicit promotion)
AS = KS (no TS, no RS)
PS = AS (no DS)
PR = PS = "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
```

### 15.4 Transaction State (Level 3+)

Given a `key/add` transaction with `czd = "<transaction czd>"`:

```
TS = czd (single transaction, implicit promotion)
AS = H(sort(KS, TS))  # KS and TS are digests; sort by byte value, not label
PS = AS (no DS)
```

### 15.5 Implementation Notes

- All signatures must be verified using the key's `alg`
- ECDSA signatures must be low-S normalized (non-malleable)
- Thumbprints use the hash algorithm associated with `alg`
- State digests use the hash algorithm of the signing key

### 15.6 Integration Test Requirements

Language-agnostic test vectors are provided in `/test_vectors/`. Integration tests consuming these vectors SHOULD:

1. **Validate fixture `pre` values**: Before applying a transaction, verify that the fixture's `pre` field matches the implementation's computed Auth State. If they differ, the test SHOULD fail immediately, indicating a fixture data error rather than an implementation bug.

2. **Use fixture values directly**: Tests should use the `pre`, `czd`, and other fields from fixtures directly, not compute substitutes. This validates both implementation correctness and fixture accuracy.

3. **Test all error conditions**: Error test fixtures intentionally include invalid data (wrong `pre`, unknown keys, etc.). Implementations MUST NOT skip these tests due to complexity.

4. **Deterministic sorting**: All state computations involving multiple components (KS with multiple keys, AS with KS+TS, etc.) MUST use lexicographic byte-order sorting of the raw digest bytes before concatenation and hashing.

**Rationale**: Multiple implementations (Go, Rust) consuming the same fixtures ensures protocol specification correctness. Fixture validation catches spec drift early.

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
