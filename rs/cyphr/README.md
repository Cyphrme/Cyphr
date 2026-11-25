# cyphr

Rust core library implementation of the [Cyphr](https://cyphr.me) self-sovereign identity protocol.

This crate provides the core cryptographic state machines, validation logic, and data structures for the protocol:

- **`Principal`**: The core state container (identity, feature level, roots).
- **`coz` verification**: Verification and structural parsing of Coz payloads.
- **Transactions & Commits**: Multi-coz atomic commits to mutate identity state.

For persistent storage, see the [`cyphr-storage`](https://crates.io/crates/cyphr-storage) crate.
For the reference command-line interface, see [`cyphr-cli`](https://crates.io/crates/cyphr-cli).

## Quick Start

Create a Principal from a key, then give it a genesis commit that adds a
second key:

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

Add a key later with a signed `key/create` coz:

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

Keys come from the [`coz`](https://docs.rs/coz-rs) crate; `SoftwareSigner`
signs with raw key bytes, and the `Signer` trait lets a backend that cannot
export its key sign instead.

## Documentation

- **[API Documentation](https://docs.rs/cyphr)**
- **[Protocol Specification](https://docs.cyphr.me)**
- **[Project Homepage](https://cyphr.me)**
