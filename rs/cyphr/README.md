# cyphr

Rust core library implementation of the [Cyphr](https://cyphr.me) self-sovereign identity protocol.

This crate provides the core cryptographic state machines, validation logic, and data structures for the protocol:

- **`Principal`**: The core state container (identity, feature level, roots).
- **`coz` verification**: Verification and structural parsing of Coz payloads.
- **Transactions & Commits**: Multi-coz atomic commits to mutate identity state.

For storage backends (like `FileStore`), see the [`cyphr-storage`](https://crates.io/crates/cyphr-storage) crate.
For the reference command-line interface, see [`cyphr-cli`](https://crates.io/crates/cyphr-cli).

## Quick Start

```rust
use cyphr::{Principal, Key};
use coz::Algorithm;

fn main() -> cyphr::error::Result<()> {
    // Generate a new key
    let key = Key::generate(Algorithm::ES256)?;

    // Implicit genesis: single key, identity = thumbprint
    let principal = Principal::implicit(key)?;

    println!("Identity (PR): {:?}", principal.pr());
    println!("Level: {:?}", principal.level());
    Ok(())
}
```

## Documentation

- **[API Documentation](https://docs.rs/cyphr)**
- **[Protocol Specification](https://docs.cyphr.me)**
- **[Project Homepage](https://cyphr.me)**
