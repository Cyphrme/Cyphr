+++
title       = "Rust"
description = "Create and manage Cyphr principals with the Rust crate"
weight      = 1
toc         = true
+++

## Installation

Requires Rust 1.85 or later.

```bash
cargo add cyphr
```

The crate depends on [coz-rs](https://crates.io/crates/coz-rs) for
cryptographic signing and key management.

## Creating a Principal

A **principal** is a self-sovereign identity. At Level 1, a principal is a
single key — the key's thumbprint _is_ the identity.

```rust
use cyphr::Principal;
use cyphr::key::Key;
use coz::SigningKey;

fn main() -> Result<(), cyphr::Error> {
    // Generate a new ES256 key pair.
    let sk = SigningKey::generate(coz::Alg::ES256);
    let key = Key::from_coz_key(sk.to_key());

    // Create a Level 1 principal (implicit genesis).
    let p = Principal::implicit(key)?;

    println!("Principal Root: {}", p.pr());
    println!("Level: {:?}", p.level());
    println!("Active keys: {}", p.active_key_count());
    Ok(())
}
```

At Level 1, implicit promotion means that the key thumbprint promotes through
KR → AR → SR → PR. One value. One identity. No ceremony.

## Inspecting State

Every principal exposes its internal Merkle state:

```rust
println!("KR: {:?}", p.key_root());    // Key Root
println!("AR: {:?}", p.auth_root());   // Auth Root
println!("SR: {:?}", p.sr());          // State Root
println!("PR: {:?}", p.pr());          // Principal Root
```

At Level 1 all four are identical — they diverge as you add keys, commit
transactions, and record actions.

## Type Safety: Nascent vs. Established

The Rust implementation encodes the principal lifecycle in the type system.
Internally, a `Principal` is either **Nascent** (L1/L2 — no Principal
Genesis exists) or **Established** (L3+ — PG is frozen by
`principal/create`). This distinction is invisible to most code thanks to
`Deref`, but it means invalid states — like a Level 1 principal with a
fabricated PG — are structurally unrepresentable.

```rust
// Nascent: pg() returns None
assert!(p.pg().is_none());

// After principal/create, PG is frozen and pg() returns Some
```

## Multi-Key Genesis (Level 3)

For principals with multiple concurrent keys, use explicit genesis:

```rust
let sk1 = SigningKey::generate(coz::Alg::ES256);
let sk2 = SigningKey::generate(coz::Alg::ES256);

let keys = vec![
    Key::from_coz_key(sk1.to_key()),
    Key::from_coz_key(sk2.to_key()),
];

let p = Principal::explicit(keys)?;

println!("Active keys: {}", p.active_key_count()); // 2
println!("Level: {:?}", p.level());                // L3
```

## Applying Transactions

State mutations are applied as verified Coz messages. The borrow checker
enforces that no code can observe intermediate state during a commit:

```rust
// Single-transaction atomic commit.
let commit = p.apply_transaction(verified_coz)?;
```

For multi-transaction commits, use the scoped API:

```rust
let mut scope = p.begin_commit();
scope.apply(vtx1)?;
scope.apply(vtx2)?;
let commit = scope.finalize()?;
```

The `CommitScope` holds `&mut Principal`, which means the Rust compiler
statically prevents reading the principal's state while the commit is
in-flight — a structural guarantee that the Go implementation enforces
by convention.

## Storage

The `cyphr-storage` crate provides export/import for principal state:

```bash
cargo add cyphr-storage
```

```rust
use cyphr_storage::FileStore;

// Export principal state to a directory.
let store = FileStore::new("./my-principal")?;
store.export(&principal)?;

// Import principal state from a directory.
let restored = store.import()?;
```

## Next Steps

- Read the [Protocol Specification](../specification.html) for the full
  formal treatment
- Browse the [source](https://github.com/Cyphrme/Cyphr/tree/main/rs) for
  implementation details
- Run `cargo test` from the `rs/` directory to execute the test suite
- Explore the CLI: `cargo install cyphr-cli` for command-line operations
