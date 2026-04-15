# Cyphr Rust Implementation

Rust implementation of the Cyphr self-sovereign identity protocol.

## Installation

```toml
[dependencies]
cyphr = { path = "path/to/cyphr/rs" }
```

## Quick Start

### Create a Principal

```rust
use cyphr::{Principal, Key};
use coz::Algorithm;

fn main() -> cyphr::error::Result<()> {
    // Generate a key
    let key = Key::generate(Algorithm::ES256)?;

    // Implicit genesis: single key, identity = thumbprint
    let principal = Principal::implicit(key)?;

    println!("Identity (PR): {:?}", principal.pr());
    println!("Level: {:?}", principal.level()); // Level::L1
    Ok(())
}
```

### Verify and Apply Cozies

```rust
use cyphr::verify_coz;

// Verify signature and parse coz
let vtx = verify_coz(
    pay_json,     // &[u8] - JSON payload
    sig,          // &[u8] - signature bytes
    &signer_key,  // key that signed
    czd,          // coz digest
    Some(new_key) // new key for add/replace
)?;

// Apply verified coz as atomic commit
let commit = principal.apply_transaction(vtx)?;
```

### Multi-Coz Commits

```rust
let mut scope = principal.begin_commit();
scope.apply(vtx1)?;
scope.apply(vtx2)?;
let commit = scope.finalize()?;
```

### Record Actions (Level 4)

```rust
use cyphr::Action;

let action = Action::new(
    "cyphr.me/action".to_string(),
    signer_tmb,
    1700000000,
    action_czd,
    raw_coz_json,
);

principal.record_action(action)?;
// principal.level() is now Level::L4
// principal.data_root() contains action digest
```

## API Reference

### Genesis

| Function                    | Description                                   |
| --------------------------- | --------------------------------------------- |
| `Principal::implicit(key)`  | Single-key genesis, PR = key thumbprint       |
| `Principal::explicit(keys)` | Multi-key genesis, PR = H(sorted thumbprints) |

### State Accessors

| Method          | Returns                     | Description                             |
| --------------- | --------------------------- | --------------------------------------- |
| `pg()`          | `Option<&PrincipalGenesis>` | Permanent identity (None for L1/L2)     |
| `pr()`          | `&PrincipalRoot`            | Current principal root (evolves)        |
| `sr()`          | `Option<&StateRoot>`        | State root = MR(AR, DR?)                |
| `auth_root()`   | `&AuthRoot`                 | Auth root = MR(KR, RR?)                 |
| `key_root()`    | `&KeyRoot`                  | Key root = MR(thumbprints)              |
| `data_root()`   | `Option<&DataRoot>`         | Data root = H(action czds), None if L<4 |
| `cr()`          | `Option<&CommitRoot>`       | Commit root (MALT of TRs)               |
| `current_tr()`  | `Option<&TransactionRoot>`  | Transaction root of latest commit       |
| `level()`       | `Level`                     | Current feature level (L1-L4)           |
| `hash_alg()`    | `HashAlg`                   | Primary hash algorithm                  |
| `active_algs()` | `&[HashAlg]`                | Hash algorithms from active keyset      |

### Cozies

| Function / Method                         | Description                            |
| ----------------------------------------- | -------------------------------------- |
| `verify_coz(pay, sig, key, czd, new_key)` | Verify signature, return `VerifiedCoz` |
| `apply_transaction(vtx)`                  | Apply verified coz as atomic commit    |
| `begin_commit()`                          | Start multi-coz commit scope           |

### Keys

| Method               | Description               |
| -------------------- | ------------------------- |
| `get_key(tmb)`       | Get key by thumbprint     |
| `is_key_active(tmb)` | Check if key is active    |
| `active_keys()`      | Iterator over active keys |
| `active_key_count()` | Number of active keys     |

## Error Handling

```rust
use cyphr::Error;

match principal.apply_transaction(vtx) {
    Ok(_) => { /* success */ }
    Err(Error::InvalidPrior) => { /* pre doesn't match current PR */ }
    Err(Error::TimestampPast) => { /* timestamp too old */ }
    Err(Error::DuplicateKey) => { /* key already in KR */ }
    Err(Error::NoActiveKeys) => { /* would leave 0 keys */ }
    Err(Error::EmptyCommit) => { /* finalized with no cozies */ }
    Err(Error::CommitMismatch) => { /* arrow doesn't match computed state */ }
    Err(e) => { /* other error */ }
}
```

## Crate Structure

```
rs/
├── cyphr/            # Core protocol logic (Principal, state, multihash)
├── cyphr-storage/    # Storage backends (FileStore, export/import)
├── cyphr-cli/        # CLI binary
├── malt/             # Merkle Append-only Log Tree
├── test-fixtures/    # Golden fixture loading
└── fixture-gen/      # Fixture generation binary
```

## Testing

```bash
cd rs
cargo test
```

### Test Suites

| Suite             | Tests | Description                          |
| ----------------- | ----- | ------------------------------------ |
| `golden_fixtures` | 47    | Pre-computed fixtures (golden tests) |
| `e2e.rs`          | 21    | Dynamic intent-driven tests          |
| Unit tests        | ~20   | Crate-level unit tests               |

**Golden tests** consume pre-computed JSON fixtures from `../tests/golden/`.

**E2E tests** parse TOML intent files from `../tests/e2e/` and dynamically
generate transactions at runtime using the `test-fixtures` crate.

## See Also

- [SPEC.md](../SPEC.md) — Full protocol specification
- [tests/README.md](../tests/README.md) — Test fixture documentation
