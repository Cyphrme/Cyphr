+++
title       = "Rust"
description = "Create and manage Cyphr principals with the Rust crate"
weight      = 1
toc         = true
+++

## Installation

Requires Rust 1.90 or later.

```bash
cargo add cyphr
```

The crate depends on [coz-rs](https://crates.io/crates/coz-rs) for
cryptographic signing and key management.

## Creating a Principal

A **principal** is a self-sovereign identity. At Level 1, a principal is a
single key — the key's thumbprint _is_ the identity. Constructing one is
async because it opens the principal's commit log.

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use coz::Alg;
use cyphr::signer::SoftwareSigner;
use cyphr::{Key, Principal};

async fn create() -> Result<(), Box<dyn std::error::Error>> {
    // Two ES256 keypairs: the genesis key and a second key.
    let first = Alg::ES256.generate_keypair();
    let second = Alg::ES256.generate_keypair();
    let first_key = Key::from_pub_key("ES256", first.pub_bytes.clone())?;
    let second_key = Key::from_pub_key("ES256", second.pub_bytes.clone())?;

    // Level 1: implicit genesis. The key's thumbprint is the identity.
    // The constructor is async because it opens the principal's commit
    // log (here in memory).
    let mut principal = Principal::implicit(first_key).await?;
    println!("Identity (PR): {:?}", principal.pr());
    println!("Level: {:?}", principal.level()); // L1

    // Level 3: the genesis commit, signed by the genesis key, creates the
    // second key and freezes the Principal Genesis (PG).
    let signer = SoftwareSigner::new("ES256", &first.prv_bytes, &first.pub_bytes, &first.thumbprint);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    principal
        .commit_genesis(&signer, &[second_key], now, "cyphr.me")
        .await?;
    println!("Genesis (PG): {:?}", principal.pg());
    println!("Level: {:?}", principal.level()); // L3
    Ok(())
}
```

At Level 1, implicit promotion means that the key thumbprint promotes through
KR → AR → SR → PR. One value. One identity. No ceremony. The genesis commit
then moves the principal to Level 3.

## Inspecting State

Every principal exposes its internal Merkle state:

```rust
println!("KR: {:?}", principal.key_root());  // Key Root
println!("AR: {:?}", principal.auth_root()); // Auth Root
println!("SR: {:?}", principal.sr());        // State Root
println!("PR: {:?}", principal.pr());        // Principal Root
```

At Level 1 all four are identical — they diverge as you add keys, commit
transactions, and record actions.

## Multi-Key Genesis (Level 3)

A principal with several keys is its genesis key plus the keys its genesis
commit creates. Pass them as `others` to `commit_genesis`, as in the example
above; `principal.pg()` is `None` before that commit and `Some` after it.

## Applying Transactions

State mutations are signed Coz messages. The borrow checker enforces that
no code can observe intermediate state during a commit: a `CommitScope` holds
`&mut Principal`.

```rust
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use coz::Alg;
use cyphr::signer::{Signer, SoftwareSigner};
use cyphr::{Key, Principal};

// `principal` and `signer` are the genesis key's, as above, and `prv` and
// `pub_key` its raw key bytes.
async fn add_key(
    principal: &mut Principal,
    signer: &SoftwareSigner,
    prv: &[u8],
    pub_key: &[u8],
    now: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let third = Alg::ES256.generate_keypair();
    let third_key = Key::from_pub_key("ES256", third.pub_bytes.clone())?;

    // A `key/create` coz: the genesis key signs the new key's thumbprint.
    let pay = serde_json::json!({
        "alg": "ES256",
        "id": Base64UrlUnpadded::encode_string(third.thumbprint.as_bytes()),
        "now": now + 1,
        "tmb": Base64UrlUnpadded::encode_string(signer.tmb().as_bytes()),
        "typ": "cyphr.me/cyphr/key/create",
    });
    let pay_json = serde_json::to_vec(&pay)?;
    let (sig, cad) = coz::sign_json(&pay_json, "ES256", prv, pub_key).ok_or("signing failed")?;
    let czd = coz::czd_for_alg(&cad, &sig, "ES256").ok_or("czd failed")?;

    // Verify the coz against the principal's state and apply it inside one
    // commit; the commit itself is signed too.
    let mut scope = principal.begin_commit();
    scope.verify_and_apply(&pay_json, &sig, czd, Some(third_key))?;
    scope.finalize_with_software(signer, now + 1, "cyphr.me").await?;
    Ok(())
}
```

For a single transaction, `principal.verify_and_apply_transaction(..)`
verifies and applies it as one commit. The scope's `stage()` and
`StagedCommit::commit()` split a commit into a verification step that writes
nothing and the one log write.

## Storage

The `cyphr-storage` crate stores principals durably. See its
[README](https://github.com/Cyphrme/Cyphr/blob/master/rs/cyphr-storage/README.md)
for `StorageEngine` and for replaying a principal's commits with
`load_principal_from_commits`.

## Next Steps

- Read the [Protocol Specification](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md) for the full
  formal treatment
- Browse the [source](https://github.com/Cyphrme/Cyphr/tree/main/rs) for
  implementation details
- Run `cargo test` from the `rs/` directory to execute the test suite
- Explore the CLI: `cargo install cyphr-cli` for command-line operations
