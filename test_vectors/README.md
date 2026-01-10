# Cyphrpass Test Vectors

Language-agnostic test vectors for verifying Cyphrpass protocol implementations
per SPEC §15. These vectors enable any implementation to verify compliance with
the Cyphrpass identity protocol.

## Directory Structure

```
test_vectors/
├── genesis/        # Principal creation (implicit & explicit)
├── transactions/   # Key mutations (add, delete, replace, revoke)
├── state/          # State computation verification
├── actions/        # Level 4 data actions
├── errors/         # Error condition validation
└── edge_cases/     # Ordering and edge case verification
```

## Fixture Format

Each JSON fixture follows this structure:

```json
{
  "name": "fixture_name",
  "description": "Human-readable description",
  "version": "0.1.0",
  "keys": {
    /* Optional: Named key definitions */
  },
  "tests": [
    /* Array of test cases */
  ]
}
```

## Key Definitions

Fixtures may include a `keys` map for reusable key references:

```json
{
  "keys": {
    "golden": {
      "alg": "ES256",
      "pub": "2nTOaFVm2QLxmUO_...",
      "prv": "bNstg4_H3m3SlRO...", // Optional: for signing
      "tmb": "U5XUZots-WmQYcQ..."
    }
  }
}
```

The `prv` field is included only when needed to generate signatures.

## Coz Message Format

Transaction and action inputs use signed [Coz](https://github.com/Cyphrme/coz)
messages per SPEC §4. A Coz message contains:

```json
{
  "pay": {
    "alg": "ES256",
    "typ": "cyphr.me/key/add",
    "tmb": "<signer thumbprint>",
    "now": 1700000000,
    "pre": "<prior auth state>",
    "id": "<target key thumbprint>"
  },
  "key": {
    /* Optional: embedded key for key/add */
  },
  "sig": "<base64url signature>",
  "czd": "<base64url Coz digest>"
}
```

### Pay Object Fields

| Field | Required    | Description                                      |
| ----- | ----------- | ------------------------------------------------ |
| `alg` | Yes         | Signing algorithm (ES256, ES384, ES512, Ed25519) |
| `typ` | Yes         | Transaction type (e.g., `cyphr.me/key/add`)      |
| `tmb` | Yes         | Signer's key thumbprint                          |
| `now` | Yes         | Unix timestamp of transaction                    |
| `pre` | Conditional | Prior auth state (required for transactions)     |
| `id`  | Conditional | Target key thumbprint (for key mutations)        |
| `rvk` | Conditional | Revocation timestamp (for key/revoke)            |
| `msg` | Optional    | Action message content                           |

## Test Case Types

### Genesis Tests (`genesis/`)

Test principal creation with implicit and explicit genesis:

```json
{
  "name": "implicit_genesis_es256",
  "input": {
    "type": "implicit_genesis",
    "key": { "alg": "ES256", "pub": "...", "tmb": "..." }
  },
  "expected": {
    "pr": "<principal root>",
    "ps": "<principal state>",
    "as": "<auth state>",
    "ks": "<key state>",
    "ts": null,
    "ds": null,
    "level": 1
  }
}
```

### Transaction Tests (`transactions/`)

Test key mutations with signed Coz messages:

```json
{
  "name": "key_add_simple",
  "setup": {
    "genesis": "implicit",
    "initial_key": "golden"
  },
  "coz": {
    /* Single Coz message */
  },
  "coz_sequence": [
    /* OR: Array of Coz messages */
  ],
  "expected": {
    "key_count": 2,
    "active_keys": ["golden", "key_a"],
    "ks": "<expected key state>",
    "as": "<expected auth state>"
  }
}
```

### State Computation Tests (`state/`)

Verify state derivation rules per SPEC §7:

```json
{
  "name": "ks_promotion",
  "setup": { "genesis": "implicit", "initial_key": "golden" },
  "expected": {
    "ks_equals_tmb": true,
    "as_equals_ks": true,
    "ps_equals_as": true
  }
}
```

### Action Tests (`actions/`)

Test Level 4 data layer operations:

```json
{
  "name": "single_action",
  "setup": { "genesis": "implicit", "initial_key": "golden" },
  "actions": [
    {
      "pay": { "alg": "ES256", "typ": "cyphr.me/action", ... },
      "sig": "...",
      "czd": "..."
    }
  ],
  "expected": {
    "ds_equals_czd": true,
    "action_count": 1
  }
}
```

### Error Tests (`errors/`)

Verify error conditions per SPEC §14:

```json
{
  "name": "unknown_key_fails",
  "setup": { "genesis": "implicit", "initial_key": "golden" },
  "coz": {
    /* Message signed by unknown key */
  },
  "expected_error": "UnknownKey"
}
```

### Edge Case Tests (`edge_cases/`)

Verify ordering and idempotency guarantees:

- `key_thumbprint_sort_order`: Lexicographic byte sort for KS
- `same_keys_different_order`: KS idempotency
- `transaction_replay_order`: TS sequential dependency
- `action_after_key_add`: Combined transaction + action state

## Expected State Fields

| Field | Description                                     |
| ----- | ----------------------------------------------- |
| `pr`  | Principal Root (immutable identity anchor)      |
| `ps`  | Principal State (current overall state)         |
| `ks`  | Key State (hash of active key thumbprints)      |
| `ts`  | Transaction State (hash of transaction czds)    |
| `as`  | Auth State = H(KS, TS) or KS if no transactions |
| `ds`  | Data State (hash of action czds)                |

## Verification Algorithm

Implementations should:

1. **Parse** the fixture JSON
2. **Initialize** principal from `setup` (genesis + initial keys)
3. **Apply** transactions from `coz` or `coz_sequence`
4. **Record** actions from `actions` if present
5. **Compare** computed state against `expected` values
6. **Report** any mismatches

### Boolean Assertions

Some expected values are boolean assertions:

- `ks_equals_tmb`: KS should equal the single key's thumbprint
- `ts_is_hash`: TS should be a hash (not promoted)
- `as_is_hash_of_ks_ts`: AS should be H(sort(KS, TS))
- `ps_is_hash_of_as_ds`: PS should be H(sort(AS, DS))

## Encoding

All binary values use **Base64url without padding** (B64ut) per RFC 4648 §5.

## Generating Test Vectors

Use the `coz` CLI from [coz-rust](https://github.com/Cyphrme/coz-rust):

```bash
# Generate a new key
coz newkey es256

# Sign a transaction payload
coz signpay '{"typ":"cyphr.me/key/add","id":"...","pre":"...","now":1700000000}' key.json

# Get Coz metadata (cad, czd, can)
coz meta '{"pay":{...},"sig":"..."}'
```

## Golden Keys

### ES256 (SPEC §15.1)

```json
{
  "alg": "ES256",
  "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
}
```

### Key_A (ES256)

```json
{
  "alg": "ES256",
  "pub": "iYGklzRf1A1CqEfxXDgrgcKsZca6GZllIJ_WIE4Pve5cJwf0IyZIY79B_AHSTWxNB9sWhYUPToWF-xuIfFgaAQ",
  "prv": "dRlV0LjnJOVfK_hNl_6rjVKutZWTHNL-Vs4_dVZ0bls",
  "tmb": "CP7cFdWJnEyxobbaa6O5z-Bvd9WLOkfX5QkyGFCqP_M"
}
```

## Reference Implementation

The Rust test runner in `rs/tests/integration.rs` demonstrates fixture parsing
and verification. Run with:

```bash
cd rs && cargo test --test integration -- --nocapture
```

## Test Coverage Summary

| Category     | Tests | Description                                  |
| ------------ | ----- | -------------------------------------------- |
| Genesis      | 6     | Implicit/explicit with ES256, ES384, Ed25519 |
| Transactions | 7     | Key add, delete, replace, revoke, sequences  |
| State        | 8     | KS/TS/AS/PS computation rules                |
| Actions      | 5     | DS creation, hashing, metadata tracking      |
| Errors       | 6     | Pre mismatch, unknown key, revoked, etc.     |
| Edge Cases   | 4     | Sorting, idempotency, ordering               |

**Total: 36 test vectors**
