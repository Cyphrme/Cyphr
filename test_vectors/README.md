# Cyphrpass Test Vectors

Language-agnostic test vectors for verifying Cyphrpass protocol implementations.

## Structure

```
test_vectors/
├── genesis/        # Principal creation (implicit & explicit)
├── transactions/   # Key mutations (add, delete, replace, revoke)
├── state/          # State computation verification
├── actions/        # Level 4 data actions
└── errors/         # Error condition validation
```

## Test Vector Format

Each JSON file contains an array of test cases following this schema:

```json
{
  "name": "test_case_name",
  "description": "Human-readable description",
  "input": { /* Test inputs */ },
  "expected": {
    "pr": "<base64url>",
    "ps": "<base64url>",
    "ks": "<base64url>",
    "as": "<base64url>",
    "ts": "<base64url>|null",
    "ds": "<base64url>|null",
    "level": 1|2|3|4,
    "error": "ErrorVariant|null"
  }
}
```

## Golden Keys

The following deterministic keys are used across test vectors:

### ES256 Golden Key (from SPEC §15.1)

```json
{
  "alg": "ES256",
  "now": 1623132000,
  "tag": "Zami's Majuscule Key.",
  "pub": "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
}
```

## Generation

Test vectors are generated using the `coz` CLI from the [coz-rust](https://github.com/Cyphrme/coz-rust) workspace.

Example:

```bash
coz newkey es256 > key.json
coz tmb key.json
coz signpay '{"typ":"cyphrpass/key/add", ...}' key.json
```

## Verification

Implementations should:

1. Parse each test fixture
2. Execute the operation described in `input`
3. Compare computed state against `expected` values
4. Report any mismatches

All digests use B64ut (Base64 URL-safe, no padding) encoding.
