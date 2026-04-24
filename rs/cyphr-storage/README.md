# cyphr-storage

Storage backends for the [Cyphr](https://cyphr.me) self-sovereign identity protocol.

This crate complements the core [`cyphr`](https://crates.io/crates/cyphr) protocol library by providing:

- **`FileStore`**: A persistent filesystem-backed storage implementation for managing Principal state.
- **Export/Import**: Standardized logic for archiving and restoring Principals using cryptographic export formats.

## Quick Start

```rust
use cyphr_storage::FileStore;
use cyphr::{Principal, Key};
use coz::Algorithm;

fn main() -> cyphr::error::Result<()> {
    // Initialize a file store in a directory
    let mut store = FileStore::new("./cyphr-data")?;

    // Generate a new key and principal
    let key = Key::generate(Algorithm::ES256)?;
    let principal = Principal::implicit(key)?;

    // Save the principal to disk
    store.save_principal(&principal)?;

    // Load the principal back from disk
    let loaded_principal = store.load_principal(principal.pr())?;

    assert_eq!(principal.pr(), loaded_principal.pr());
    Ok(())
}
```

## Documentation

- **[API Documentation](https://docs.rs/cyphr-storage)**
- **[Protocol Specification](https://docs.cyphr.me)**
- **[Project Homepage](https://cyphr.me)**
