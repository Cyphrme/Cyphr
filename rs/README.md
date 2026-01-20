# Cyphrpass Rust Implementation

Rust implementation of the Cyphrpass self-sovereign identity protocol.

## Installation

```toml
[dependencies]
cyphrpass = { path = "path/to/cyphrpass/rs" }
```

## Quick Start

### Create a Principal

```rust
use cyphrpass::{Principal, Key};
use coz::Algorithm;

fn main() -> cyphrpass::Result<()> {
    // Generate a key
    let key = Key::generate(Algorithm::ES256)?;

    // Implicit genesis: single key, identity = thumbprint
    let principal = Principal::implicit(key)?;

    println!("Identity (PR): {:?}", principal.pr());
    println!("Level: {:?}", principal.level()); // Level::One
    Ok(())
}
```

### Verify and Apply Transactions

```rust
use cyphrpass::{Principal, verify_transaction};

// Verify signature and parse transaction
let vtx = verify_transaction(
    pay_json,     // &[u8] - JSON payload
    sig,          // &[u8] - signature bytes
    &signer_key,  // key that signed
    czd,          // coz digest
    Some(new_key) // new key for add/replace
)?;

// Apply verified transaction (safe API)
principal.apply_verified(vtx)?;
```

### Record Actions (Level 4)

```rust
use cyphrpass::Action;

let action = Action {
    signer: signer_tmb.clone(),
    now: 1700000000,
    czd: action_czd,
};

principal.record_action(action)?;
// principal.level() is now Level::Four
// principal.data_state() contains action digest
```

## API Reference

### Genesis

| Function                    | Description                                   |
| --------------------------- | --------------------------------------------- |
| `Principal::implicit(key)`  | Single-key genesis, PR = key thumbprint       |
| `Principal::explicit(keys)` | Multi-key genesis, PR = H(sorted thumbprints) |

### State Accessors

| Method         | Returns              | Description                        |
| -------------- | -------------------- | ---------------------------------- |
| `pr()`         | `&PrincipalRoot`     | Permanent identity (never changes) |
| `ps()`         | `&PrincipalState`    | Current state (evolves)            |
| `auth_state()` | `&AuthState`         | Auth state = H(KS, TS?, RS?)       |
| `key_state()`  | `&KeyState`          | Key state = H(thumbprints)         |
| `data_state()` | `Option<&DataState>` | Data state = H(action czds)        |
| `level()`      | `Level`              | Current feature level              |

### Transactions

| Method                       | Description                                    |
| ---------------------------- | ---------------------------------------------- |
| `verify_transaction(...)`    | Verify signature, return `VerifiedTransaction` |
| `apply_verified(vtx)`        | Apply verified transaction (safe API)          |
| `apply_transaction(tx, key)` | Unsafe—no signature check                      |

### Keys

| Method               | Description               |
| -------------------- | ------------------------- |
| `get_key(tmb)`       | Get key by thumbprint     |
| `is_key_active(tmb)` | Check if key is active    |
| `active_keys()`      | Iterator over active keys |
| `active_key_count()` | Number of active keys     |

## Error Handling

```rust
use cyphrpass::Error;

match principal.apply_verified(vtx) {
    Ok(_) => { /* success */ }
    Err(Error::InvalidPrior) => { /* pre doesn't match AS */ }
    Err(Error::TimestampPast) => { /* timestamp too old */ }
    Err(Error::DuplicateKey) => { /* key already in KS */ }
    Err(Error::NoActiveKeys) => { /* would leave 0 keys */ }
    Err(e) => { /* other error */ }
}
```

## Testing

```bash
cd rs
cargo test
```

### Test Suites

| Suite             | Tests | Description                          |
| ----------------- | ----- | ------------------------------------ |
| `golden_fixtures` | 41    | Pre-computed fixtures (golden tests) |
| `e2e.rs`          | 19    | Dynamic intent-driven tests          |
| Unit tests        | ~20   | Crate-level unit tests               |

**Golden tests** consume pre-computed JSON fixtures from `../tests/golden/`.

**E2E tests** parse TOML intent files from `../tests/e2e/` and dynamically
generate transactions at runtime using the `test-fixtures` crate.

## See Also

- [SPEC.md](../SPEC.md) — Full protocol specification
- [tests/README.md](../tests/README.md) — Test fixture documentation
