# cyphr-storage

Storage backends for the [Cyphr](https://cyphr.me) self-sovereign identity protocol.

This crate provides a modern, backend-agnostic storage engine that coordinates:

- **`StorageEngine<B, I, S>`**: A coordinated storage engine joining blob stores and indexers.
- **Blob Store (`BlobStore` trait)**: Stores immutable cryptographic payloads (cozies) with BLAKE3 hashing.
- **Indexer (`Indexer` trait)**: Maintains queryable metadata about principals, cozies, and commit structure.
- **Export/Import**: Standardized logic for archiving and restoring Principals using cryptographic export formats.

Included implementations:
- **`cyphr-blob-fjall`**: BLOB storage backed by the Fjall LSM-tree database.
- **`cyphr-index-fjall`**: Indexing backed by the Fjall LSM-tree database (KV, not relational).
- **Memory implementations** (for testing): In-memory blob stores and indexers.

## Quick Start

Load a principal from genesis:

```rust
use cyphr_storage::{Genesis, load_principal};
use cyphr::Key;
use coz::Thumbprint;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a key
    let key = Key {
        alg: "ES256".to_string(),
        tmb: Thumbprint::from_bytes(vec![0u8; 32]),
        pub_key: vec![0u8; 64],
        first_seen: 1000,
        last_used: None,
        revocation: None,
        tag: None,
    };

    // Implicit genesis: single key, no entries needed for basic case
    let genesis = Genesis::Implicit(key);
    let entries = [];

    // Load principal from genesis and entries
    let principal = load_principal(genesis, &entries)?;

    println!("Created principal: {:?}", principal.pr());
    Ok(())
}
```

For persistent blob/index storage, the `StorageEngine<B, I, S>` coordinates real `BlobStore` and `Indexer` implementations (see [`cyphr-blob-fjall`](https://docs.rs/cyphr-blob-fjall) and [`cyphr-index-fjall`](https://docs.rs/cyphr-index-fjall) for production backends). For a complete working example integrating storage with the CLI, see the [`cyphr-cli`](https://crates.io/crates/cyphr-cli) crate.

## Documentation

- **[API Documentation](https://docs.rs/cyphr-storage)**
- **[Protocol Specification](https://docs.cyphr.me)**
- **[Project Homepage](https://cyphr.me)**
