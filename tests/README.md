# Cyphrpass Test Fixtures

Language-agnostic integration test fixtures for Cyphrpass protocol implementations.

## Overview

This directory contains a **two-tiered fixture system**:

1. **Intent files** (`intents/*.toml`) — Human-readable test definitions
2. **Golden files** (`golden/**/*.json`) — Generated fixtures with real cryptographic signatures

Implementors in any language can consume the golden JSON files directly. The intent files are only needed if you want to understand the test logic or regenerate fixtures.

## Directory Structure

```
tests/
├── keys/
│   └── pool.toml         # Shared key pool (public + private keys)
├── intents/
│   └── *.toml            # Human-readable test definitions
├── golden/
│   └── <category>/*.json # Generated fixtures (one JSON per test case)
└── README.md
```

---

## For Implementors (Consuming Golden Files)

### Test Flow

For each JSON file in `golden/`:

1. **Parse the fixture** — Load the JSON and extract `principal`, `coz`/`coz_sequence`, `action`, `expected`
2. **Create Principal** — Use keys from `principal` array to create genesis
3. **Apply operations** — Apply `coz` (transactions) and/or `action` messages
4. **Verify state** — Assert computed state matches `expected`
5. **Handle errors** — If `expected.error` is set, verify the operation fails with that error

### Golden File Format

```json
{
  "name": "test_name",
  "principal": ["key_name_1", "key_name_2"],
  "setup": {                          // Optional
    "revoke_key": "key_name",
    "revoke_at": 1699999999
  },
  "coz": {                            // Single transaction (or use coz_sequence)
    "pay": { ... },
    "sig": "<base64url>",
    "czd": "<base64url>",
    "key": { "alg": "ES256", "pub": "<base64url>", "tmb": "<base64url>" }
  },
  "coz_sequence": [ ... ],            // Multi-step transactions
  "action": { ... },                  // Single action (Level 4)
  "action_sequence": [ ... ],         // Multi-step actions
  "expected": {
    "key_count": 2,
    "level": 3,
    "ks": "<base64url>",
    "as": "<base64url>",
    "ps": "<base64url>",
    "pr": "<base64url>",
    "ds": "<base64url>",              // Level 4 only
    "error": "ErrorName"              // For error tests
  }
}
```

### Test Categories

| Category              | Path                          | Description                                       |
| --------------------- | ----------------------------- | ------------------------------------------------- |
| `mutations`           | `golden/mutations/`           | Transaction mutations (key/add, key/delete, etc.) |
| `multi_key`           | `golden/multi_key/`           | Multi-key principal operations                    |
| `algorithm_diversity` | `golden/algorithm_diversity/` | Cross-algorithm key management                    |
| `state_computation`   | `golden/state_computation/`   | State digest verification (KS, TS, AS, PS)        |
| `edge_cases`          | `golden/edge_cases/`          | Ordering, idempotency, combined operations        |
| `actions`             | `golden/actions/`             | Level 4 action recording                          |
| `errors`              | `golden/errors/`              | Error condition rejection tests                   |

### Setup Modifiers

Some tests require setup before the main operation:

- `setup.revoke_key`: Pre-revoke a key (moves to revoked set before test)
- `setup.revoke_at`: Timestamp for the pre-revocation

### Error Tests

Tests with `expected.error` verify that operations are correctly rejected:

| Error                  | Trigger                                    |
| ---------------------- | ------------------------------------------ |
| `InvalidPrior`         | Transaction `pre` doesn't match current AS |
| `UnknownKey`           | Signer not in principal's key set          |
| `KeyRevoked`           | Signer key is revoked                      |
| `NoActiveKeys`         | Self-revoke of last key (Level 1 guard)    |
| `DuplicateKey`         | Adding key already in KS                   |
| `TimestampPast`        | Transaction timestamp older than previous  |
| `UnsupportedAlgorithm` | Genesis with unsupported algorithm         |

---

## Key Pool Reference

The `keys/pool.toml` contains all test keys. Use key `name` fields from `principal` array to look up keys.

| Name              | Algorithm | Notes                              |
| ----------------- | --------- | ---------------------------------- |
| `golden`          | ES256     | Primary test key (SPEC §15.1)      |
| `alice`           | ES256     | Multi-key testing                  |
| `bob`             | ES256     | Multi-key testing                  |
| `carol`           | ES256     | Multi-key testing                  |
| `key_a`           | ES256     | Transaction target                 |
| `key_b`           | ES256     | Transaction target (public only)   |
| `diana_es384`     | ES384     | Algorithm diversity (SHA-384)      |
| `eve_ed25519`     | Ed25519   | Algorithm diversity (SHA-512)      |
| `unsupported_key` | RS256     | Error test (unsupported algorithm) |

---

## Intent File Specification

Intent files define tests in a declarative TOML format. The generator produces golden JSON with real signatures.

### Core Structure

```toml
[[test]]
name      = "test_name"        # Unique test identifier
principal = ["key1", "key2"]   # Genesis key names from pool
```

### Test Types

#### 1. Genesis-Only Test

Tests principal creation with no operations. Verifies initial state.

```toml
[[test]]
name      = "ks_single_key_promotion"
principal = ["golden"]

[test.expected]
key_count = 1
level     = 1
```

#### 2. Single Transaction Test

```toml
[[test]]
name      = "key_add_increases_count"
principal = ["golden"]

[test.pay]
typ = "cyphr.me/key/add"
now = 1700000000

[test.crypto]
signer = "golden"
target = "key_a"

[test.expected]
key_count = 2
level     = 3
```

#### 3. Multi-Step Transaction Test

```toml
[[test]]
name      = "transaction_sequence_replay"
principal = ["golden"]

[[test.step]]
pay.typ       = "cyphr.me/key/add"
pay.now       = 1700000001
crypto.signer = "golden"
crypto.target = "key_a"

[[test.step]]
pay.typ       = "cyphr.me/key/add"
pay.now       = 1700000002
crypto.signer = "golden"
crypto.target = "key_b"

[test.expected]
key_count = 3
```

#### 4. Single Action Test (Level 4)

```toml
[[test]]
name      = "single_action_promotes_ds"
principal = ["golden"]

[test.action]
typ    = "cyphr.me/action"
now    = 1700000001
signer = "golden"
msg    = "First action"

[test.expected]
level = 4
```

#### 5. Multi-Action Test

```toml
[[test]]
name      = "multiple_actions_sorted"
principal = ["golden"]

[[test.action_step]]
typ    = "cyphr.me/action"
now    = 1700000001
signer = "golden"
msg    = "First action"

[[test.action_step]]
typ    = "cyphr.me/action"
now    = 1700000002
signer = "golden"
msg    = "Second action"

[test.expected]
level = 4
```

#### 6. Combined Transaction + Action Test

```toml
[[test]]
name      = "action_after_key_add"
principal = ["alice"]

[test.pay]
typ = "cyphr.me/key/add"
now = 1700000001

[test.crypto]
signer = "alice"
target = "bob"

[test.action]
typ    = "cyphr.me/action"
now    = 1700000002
signer = "bob"                 # Newly added key
msg    = "Action signed by newly added key"

[test.expected]
key_count = 2
level     = 4
```

#### 7. Error Test with Setup

```toml
[[test]]
name      = "revoked_key_fails"
principal = ["golden", "key_a"]

[test.setup]
revoke_key = "key_a"
revoke_at  = 1699999999

[test.pay]
typ = "cyphr.me/key/delete"
now = 1700000000

[test.crypto]
signer = "key_a"
target = "golden"

[test.expected]
error = "KeyRevoked"
```

#### 8. Error Test with Override

```toml
[[test]]
name      = "pre_mismatch_fails"
principal = ["golden"]

[test.pay]
typ = "cyphr.me/key/add"
now = 1700000000

[test.crypto]
signer = "golden"
target = "key_a"

[test.override]
pre = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

[test.expected]
error = "InvalidPrior"
```

### Intent Field Reference

| Field                | Type     | Description                                   |
| -------------------- | -------- | --------------------------------------------- |
| `name`               | string   | **Required.** Unique test identifier          |
| `principal`          | string[] | **Required.** Genesis key names from pool     |
| `setup.revoke_key`   | string   | Pre-revoke this key before test               |
| `setup.revoke_at`    | i64      | Revocation timestamp                          |
| `pay.typ`            | string   | Transaction type (`cyphr.me/key/add`, etc.)   |
| `pay.now`            | i64      | Transaction timestamp                         |
| `pay.rvk`            | i64      | Revocation timestamp (for key/revoke)         |
| `pay.msg`            | string   | Optional message field                        |
| `crypto.signer`      | string   | Signing key name                              |
| `crypto.target`      | string   | Target key name (for key operations)          |
| `step[]`             | array    | Multi-step transaction sequence               |
| `action.typ`         | string   | Action type (usually `cyphr.me/action`)       |
| `action.now`         | i64      | Action timestamp                              |
| `action.signer`      | string   | Action signer key name                        |
| `action.msg`         | string   | Action message content                        |
| `action_step[]`      | array    | Multi-action sequence                         |
| `override.pre`       | string   | Override `pre` field (for InvalidPrior tests) |
| `expected.key_count` | int      | Expected active key count                     |
| `expected.level`     | int      | Expected principal level (1-4)                |
| `expected.error`     | string   | Expected error name                           |

---

## Regenerating Fixtures

After modifying intent files:

```bash
cd rs
cargo run -p fixture-gen -- \
  --pool ../tests/keys/pool.toml \
  generate -r ../tests/intents/ ../tests/golden/
```

---

## Current Test Coverage

| Category            | Tests  |
| ------------------- | ------ |
| mutations           | 7      |
| multi_key           | 4      |
| algorithm_diversity | 2      |
| state_computation   | 9      |
| edge_cases          | 4      |
| actions             | 5      |
| errors              | 10     |
| **Total**           | **41** |
