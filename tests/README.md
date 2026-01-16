# Cyphrpass Test Fixtures

Language-agnostic integration test fixtures for Cyphrpass protocol implementations.

## Directory Structure

```
tests/
├── keys/
│   └── pool.toml         # Shared key pool (public + private keys)
├── intents/
│   └── *.toml            # Human-readable test definitions
├── golden/
│   └── <intent>/*.json   # Generated golden fixtures (one per test)
└── README.md             # This file
```

## Fixture System Overview

The fixture system uses a two-tiered architecture:

1. **Intent files** (TOML): Define test logic without cryptographic values
2. **Golden files** (JSON): Generated fixtures with real signatures and digests

Golden files are **deterministically generated** from intents using `fixture-gen`:

```bash
fixture-gen generate -r tests/intents/ tests/golden/
```

## Using Fixtures

### Loading a Test Case

Each JSON file in `golden/` represents one test case:

```json
{
  "name": "key_add_increases_count",
  "coz": {
    "pay": { "alg": "ES256", "typ": "cyphr.me/key/add", ... },
    "sig": "<base64url>",
    "czd": "<base64url>",
    "key": { "alg": "ES256", "pub": "<base64url>", "tmb": "<base64url>" }
  },
  "expected": {
    "key_count": 2,
    "level": 3,
    "ks": "<base64url>",
    "as": "<base64url>",
    "ps": "<base64url>",
    "pr": "<base64url>"
  }
}
```

### Test Flow

For each fixture:

1. **Create Principal** from genesis keys (see `principal` field or infer from first `pre` value)
2. **Apply Coz message(s)** via your `verify_and_apply_transaction` implementation
3. **Assert state** matches `expected` (ks, as, ps, pr, key_count, level)

### Multi-Step Tests

Some fixtures have `coz_sequence` instead of `coz`:

```json
{
  "name": "transaction_sequence_replay",
  "coz_sequence": [
    { "pay": {...}, "sig": "...", "czd": "...", "key": {...} },
    { "pay": {...}, "sig": "...", "czd": "..." },
    ...
  ],
  "expected": { ... }
}
```

Apply each message in order, then verify final state.

## Genesis Testing

Genesis (Principal creation) is not covered by generated fixtures. Implementations should test this directly:

### Implicit Genesis (Level 1/2)

Create a Principal with a single key. Verify:

- `PR = PS = AS = KS = tmb` (all equal to key thumbprint)
- Level = 1
- Key count = 1

Test with multiple algorithms from the pool:

- `golden` (ES256) → 32-byte SHA-256 digests
- `diana_es384` (ES384) → 48-byte SHA-384 digests
- `eve_ed25519` (Ed25519) → 64-byte SHA-512 digests

### Explicit Genesis (Level 3)

Create a Principal with multiple keys. Verify:

- `PR = PS = AS = KS = H(sort(tmb₀, tmb₁, ...))` (hash of sorted thumbprints)
- Level = 3
- Key count = number of keys

Test with key combinations:

- `alice` + `bob` (two ES256 keys)
- `golden` + `key_a` (two ES256 keys)
- `alice` + `bob` + `carol` (three keys)

## Key Pool Reference

The `pool.toml` contains all test keys. Key names used in fixtures:

| Name          | Algorithm | Notes                         |
| ------------- | --------- | ----------------------------- |
| `golden`      | ES256     | Primary test key (SPEC §15.1) |
| `alice`       | ES256     | Multi-key testing             |
| `bob`         | ES256     | Multi-key testing             |
| `carol`       | ES256     | Multi-key testing             |
| `key_a`       | ES256     | Transaction target            |
| `key_b`       | ES256     | Transaction target            |
| `diana_es384` | ES384     | Algorithm diversity           |
| `eve_ed25519` | Ed25519   | Algorithm diversity           |

## Regenerating Fixtures

After modifying intent files:

```bash
cd rs
cargo run -p fixture-gen -- --pool ../tests/keys/pool.toml generate -r ../tests/intents/ ../tests/golden/
```

## Intent File Format

```toml
[[test]]
name = "key_add_increases_count"
principal = ["golden"]  # Genesis keys

[test.pay]
typ = "cyphr.me/key/add"
now = 1700000000

[test.crypto]
signer = "golden"
target = "key_a"

[test.expected]
key_count = 2
level = 3
```

See `test_vectors/SPEC.md` for complete intent format specification.
