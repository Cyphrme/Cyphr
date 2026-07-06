# cyphr-storage

Storage backends for the [Cyphr](https://cyphr.me) self-sovereign identity protocol.

This crate provides a modern, backend-agnostic storage engine that coordinates:

- **`StorageEngine<B, I, S>`**: A coordinated storage engine joining blob stores and indexers.
- **Blob Store (`BlobStore` trait)**: Stores immutable cryptographic payloads (cozies) with BLAKE3 hashing.
- **Indexer (`Indexer` trait)**: Maintains queryable metadata about principals, cozies, and commit structure.
- **Export/Import**: Standardized logic for archiving and restoring Principals using cryptographic export formats.

Included implementations:
- **`cyphr-blob-fjall`**: BLOB storage backed by the Fjall LSM-tree database.
- **`cyphr-index-sqlite`**: Indexing backed by SQLite.
- **Memory implementations** (for testing): In-memory blob stores and indexers.

## Quick Start

```rust
use cyphr_storage::{engine::StorageEngine, import::load_principal};
use cyphr::Principal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // In practice, StorageEngine is constructed with real blob stores and indexers.
    // See the cyphr-cli crate for a complete working example.
    
    // Load a principal by its PR (principal root/identity)
    let principal: Principal = load_principal(
        &engine,
        &keystore,
        "KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc"
    )?;

    println!("Loaded principal: {:?}", principal.pr());
    Ok(())
}
```

For a complete working example, see the [`cyphr-cli`](https://crates.io/crates/cyphr-cli) crate, which demonstrates storage integration end-to-end.

## Documentation

- **[API Documentation](https://docs.rs/cyphr-storage)**
- **[Protocol Specification](https://docs.cyphr.me)**
- **[Project Homepage](https://cyphr.me)**
