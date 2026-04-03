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

1. **Parse the fixture** — Load the JSON and extract `principal`, `genesis_keys`, `commits`, `digests`, `expected`
2. **Create Principal** — Use `genesis_keys` to create genesis (full key material provided)
3. **Apply commits** — For each commit in `commits`, process its `txs` array; verify czd matches `digests[i]`
4. **Verify state** — Assert computed state matches `expected`
5. **Handle errors** — If `expected.error` is set, verify the last transaction fails with that error

### Golden File Format

```json
{
  "name": "test_name",
  "principal": ["key_name_1", "key_name_2"],
  "setup": {
    "revoke_key": "key_name",
    "revoke_at": 1699999999
  },
  "genesis_keys": [
    {"alg": "ES256", "pub": "<base64url>", "tmb": "<base64url>"}
  ],
  "commits": [
    {
      "txs": [
        {
          "pay": {"typ": "cyphr.me/key/create", "now": 1700000000, ...},
          "sig": "<base64url>",
          "key": {"alg": "ES256", "pub": "<base64url>", "tmb": "<base64url>"}
        }
      ],
      "cs": "<alg:base64url>"
    }
  ],
  "digests": ["<czd_base64url>"],
  "expected": {
    "key_count": 2,
    "level": 3,
    "ks": "<alg:base64url>",
    "as": "<alg:base64url>",
    "cs": "<alg:base64url>",
    "ps": "<alg:base64url>",
    "commit_id": "<alg:base64url>",
    "pr": "<alg:base64url>",
    "ds": "<base64url>",
    "error": "ErrorName"
  }
}
```

#### Field Descriptions

| Field          | Description                                                                |
| -------------- | -------------------------------------------------------------------------- |
| `principal`    | Key names from pool (for reference)                                        |
| `genesis_keys` | Full key material for genesis creation                                     |
| `commits`      | Atomic commit bundles, each containing `txs[]` and a computed `cs` digest  |
| `digests`      | Coz digests (czd) parallel to flattened transactions, for verification     |
| `expected`     | Expected state after all commits applied (includes `ks`, `as`, `cs`, `ps`) |

### Test Categories

| Category              | Path                          | Description                                          |
| --------------------- | ----------------------------- | ---------------------------------------------------- |
| `mutations`           | `golden/mutations/`           | Transaction mutations (key/add, key/delete, etc.)    |
| `multi_key`           | `golden/multi_key/`           | Multi-key principal operations                       |
| `algorithm_diversity` | `golden/algorithm_diversity/` | Cross-algorithm key management                       |
| `state_computation`   | `golden/state_computation/`   | State digest verification (KS, CommitID, AS, CS, PS) |
| `edge_cases`          | `golden/edge_cases/`          | Ordering, idempotency, combined operations           |
| `actions`             | `golden/actions/`             | Level 4 action recording                             |
| `errors`              | `golden/errors/`              | Error condition rejection tests                      |

### Setup Modifiers

Some tests require setup before the main operation:

- `setup.revoke_key`: Pre-revoke a key (moves to revoked set before test)
- `setup.revoke_at`: Timestamp for the pre-revocation

### Error Tests

Tests with `expected.error` verify that operations are correctly rejected:

| Error                  | Trigger                                    |
| ---------------------- | ------------------------------------------ |
| `InvalidPrior`         | Transaction `pre` doesn't match current CS |
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

#### 2. Single-Commit Transaction Test

```toml
[[test]]
name      = "key_add_increases_count"
principal = ["golden"]

[[test.commit]]
tx = [[{now = 1700000000, signer = "golden", target = "key_a", typ = "cyphr.me/key/create"}]]

[test.expected]
key_count = 2
level     = 3
```

#### 3. Multi-Commit Transaction Test

```toml
[[test]]
name      = "transaction_sequence_replay"
principal = ["golden"]

[[test.commit]]
tx = [[{now = 1700000001, signer = "golden", target = "key_a", typ = "cyphr.me/key/create"}]]

[[test.commit]]
tx = [[{now = 1700000002, signer = "golden", target = "key_b", typ = "cyphr.me/key/create"}]]

[test.expected]
key_count = 3
```

#### 4. Action Test (Level 4)

Single or multiple actions use the same `[[test.action]]` array-of-tables syntax.

```toml
[[test]]
name      = "multiple_actions_sorted"
principal = ["golden"]

[[test.action]]
msg    = "First action"
now    = 1700000001
signer = "golden"
typ    = "cyphr.me/action"

[[test.action]]
msg    = "Second action"
now    = 1700000002
signer = "golden"
typ    = "cyphr.me/action"

[test.expected]
level = 4
```

#### 5. Combined Transaction + Action Test

```toml
[[test]]
name      = "action_after_key_add"
principal = ["alice"]

[[test.commit]]
tx = [[{now = 1700000001, signer = "alice", target = "bob", typ = "cyphr.me/key/create"}]]

[[test.action]]
msg    = "Action signed by newly added key"
now    = 1700000002
signer = "bob"
typ    = "cyphr.me/action"

[test.expected]
key_count = 2
level     = 4
```

#### 6. Error Test with Setup

```toml
[[test]]
name      = "revoked_key_fails"
principal = ["golden", "key_a"]

[test.setup]
revoke_key = "key_a"
revoke_at  = 1699999999

[[test.commit]]
tx = [[{now = 1700000000, signer = "key_a", target = "golden", typ = "cyphr.me/key/delete"}]]

[test.expected]
error = "KeyRevoked"
```

#### 7. Error Test with Override

```toml
[[test]]
name      = "pre_mismatch_fails"
principal = ["golden"]

[[test.commit]]
tx = [[{now = 1700000000, signer = "golden", target = "key_a", typ = "cyphr.me/key/create"}]]

[test.override]
pre = "SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

[test.expected]
error = "InvalidPrior"
```

### Intent Field Reference

| Field                | Type     | Description                                         |
| -------------------- | -------- | --------------------------------------------------- |
| `name`               | string   | **Required.** Unique test identifier                |
| `principal`          | string[] | **Required.** Genesis key names from pool           |
| `setup.revoke_key`   | string   | Pre-revoke this key before test                     |
| `setup.revoke_at`    | i64      | Revocation timestamp                                |
| `commit[]`           | array    | Commit sequence; each contains `tx` (list-of-lists) |
| `commit.tx[][]`      | array    | Transaction list; each tx is a list of cozies       |
| `action[]`           | array    | Action sequence (Level 4 data recording)            |
| `action[].typ`       | string   | Action type (usually `cyphr.me/action`)             |
| `action[].now`       | i64      | Action timestamp                                    |
| `action[].signer`    | string   | Action signer key name                              |
| `action[].msg`       | string   | Action message content                              |
| `override.pre`       | string   | Override `pre` field (for InvalidPrior tests)       |
| `override.tmb`       | string   | Override `tmb` field (for UnknownKey tests)         |
| `expected.key_count` | int      | Expected active key count                           |
| `expected.level`     | int      | Expected principal level (1-4)                      |
| `expected.error`     | string   | Expected error name                                 |

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

### Golden Tests (Pre-Computed Fixtures)

| Category            | Tests  |
| ------------------- | ------ |
| mutations           | 6      |
| multi_key           | 4      |
| algorithm_diversity | 2      |
| state_computation   | 9      |
| edge_cases          | 4      |
| actions             | 5      |
| errors              | 10     |
| **Total**           | **40** |

---

## E2E Tests (Dynamic Intent-Driven)

In addition to golden tests, `tests/e2e/` contains **intent files** that are parsed at runtime to generate and verify tests dynamically. These provide round-trip verification:

1. Parse TOML intent
2. Generate transactions with real signatures
3. Apply to Principal
4. Export entries
5. Re-import and verify state matches

### E2E Intent Files

| File                       | Tests  | Description                                |
| -------------------------- | ------ | ------------------------------------------ |
| `round_trip.toml`          | 5      | Export/import round-trip verification      |
| `genesis_load.toml`        | 4      | Genesis creation and initial state         |
| `edge_cases.toml`          | 4      | Algorithm diversity, large history, timing |
| `error_conditions.toml`    | 6      | Error rejection (broken chain, revoked)    |
| `multihash_coherence.toml` | 2      | Multi-algorithm state coherence (SPEC §14) |
| **Total**                  | **21** |                                            |

### Running E2E Tests

**Go:**

```bash
cd go && go test ./cyphrpass/... -run TestE2E
```

**Rust:**

```bash
cd rs && cargo test -p cyphrpass-storage --test e2e
```

---

## Grand Total: 61 Integration Tests

| Type         | Tests  |
| ------------ | ------ |
| Golden       | 40     |
| E2E          | 21     |
| **Combined** | **61** |
