# E2E Test Specification

End-to-end tests verify the full storage cycle: generate → export → storage → import → compare.

Unlike integration tests (which use pre-generated golden fixtures), e2e tests **only have intent files**.
The test runner generates fixtures at runtime and verifies the round-trip.

## Directory Structure

```
tests/e2e/
├── README.md       # This file
└── intents/
    ├── round_trip.toml     # Round-trip verification scenarios
    ├── error_conditions.toml
    └── ...
```

## Intent Format

E2E intents reference existing integration fixtures by path:

```toml
[[test]]
name = "rt_single_tx"
source = "mutations/key_add_increases_count"
verify = "round_trip"

[[test]]
name = "err_broken_chain"
source = "errors/pre_mismatch_fails"
verify = "error"
expected_error = "InvalidPrior"
```

### Fields

| Field            | Type   | Description                                               |
| ---------------- | ------ | --------------------------------------------------------- |
| `name`           | string | Unique test identifier                                    |
| `source`         | string | Path to integration fixture (relative to `tests/golden/`) |
| `verify`         | string | Verification type: `round_trip`, `error`, `state`         |
| `expected_error` | string | (optional) Expected error for error tests                 |

## Verification Types

- **round_trip**: Load fixture → export → import → compare state
- **error**: Apply entries, verify expected error on last entry
- **state**: Verify computed state digests match fixture
