# Cyphr Rust Implementation

Rust implementation of the Cyphr self-sovereign identity protocol.

## Installation

```toml
[dependencies]
cyphr = { path = "path/to/Cyphr/rs/cyphr" }
coz   = { package = "coz-rs", version = "0.5" }
```

## Quick Start

### Create a Principal

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

### Add a Key

A mutation is a signed Coz message. `verify_and_apply` checks the signature
against the principal's state and applies it inside a commit; the commit is
then signed and finalized:

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

A commit holds one or more transactions, applied through the scope
(`scope.apply`, `scope.apply_tx`, `scope.verify_and_apply`). A commit is
two-phase: `scope.stage().await?` verifies it and computes every root, the
commit-log append included, with nothing written; the returned
`StagedCommit`'s `commit().await` performs the one log write and adopts the
new state. `finalize` is both. A caller that records the commit elsewhere
first (the storage engine writes its blob store) stages, records, then
commits. Every call that reads or writes the log is async; its futures are
`Send` whenever the storage is.

### Record an Action (Level 4)

A data action is a signed Coz message outside the chain. It joins the
principal's Data Tree in memory; no commit is made until a `ds/create`
includes it.

```rust
use cyphr::Principal;

fn record(
    principal: &mut Principal,
    pay_json: &[u8],
    sig: &[u8],
    czd: coz::Czd,
) -> Result<(), cyphr::Error> {
    principal.verify_and_record_action(pay_json, sig, czd)?;
    println!("actions held: {}", principal.action_count());
    Ok(())
}
```

## API Reference

### Genesis

| Function                                         | Description                                                               |
| ------------------------------------------------ | ------------------------------------------------------------------------- |
| `Principal::implicit(key)`                       | The only constructor: a principal is its genesis key, PR = key thumbprint |
| `Principal::open(key, storage)`                  | The same over a given storage backend (async)                             |
| `commit_genesis(signer, others, now, authority)` | Genesis commit (Level 3+): creates the genesis key and `others`, sets PG  |
| `fork()`                                         | Independent copy, only over storage that copies (`ForkStorage`)           |

### State Accessors

| Method          | Returns                     | Description                              |
| --------------- | --------------------------- | ---------------------------------------- |
| `pg()`          | `Option<&PrincipalGenesis>` | Permanent identity (None for L1/L2)      |
| `pr()`          | `&PrincipalRoot`            | Current principal root (evolves)         |
| `sr()`          | `Option<&StateRoot>`        | State root = MR(AR?, DR?); None if Dead  |
| `auth_root()`   | `Option<&AuthRoot>`         | Auth root = MR(KR, RR?); None if Dead    |
| `key_root()`    | `Option<&KeyRoot>`          | Key root = MR(thumbprints); None if Dead |
| `data_root()`   | `Option<&DataRoot>`         | Data root = H(action czds), None if L<4  |
| `cr()`          | `Option<&CommitRoot>`       | Commit root (EML of TRs)                 |
| `current_tr()`  | `Option<&TransactionRoot>`  | Transaction root of latest commit        |
| `level()`       | `Level`                     | Current feature level (L1-L4)            |
| `hash_alg()`    | `HashAlg`                   | Primary hash algorithm                   |
| `active_algs()` | `Vec<HashAlg>`              | Hash algorithms from active keyset       |

### Cozies

| Function / Method                         | Description                            |
| ----------------------------------------- | -------------------------------------- |
| `verify_coz(pay, sig, key, czd, new_key)` | Verify signature, return `VerifiedCoz` |
| `apply_transaction(vtx)`                  | Apply verified coz as atomic commit    |
| `verify_and_apply_transaction(..)`        | Verify and apply as one commit         |
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
use cyphr::{Error, Principal, VerifiedCoz};

async fn apply(principal: &mut Principal, vtx: VerifiedCoz) {
    match principal.apply_transaction(vtx).await {
        Ok(_) => { /* success */ }
        Err(Error::TimestampPast) => { /* timestamp too old */ }
        Err(Error::DuplicateKey) => { /* key already in KR */ }
        Err(Error::NoActiveKeys) => { /* key/delete would leave 0 keys */ }
        Err(Error::EmptyCommit) => { /* finalized with no cozies */ }
        Err(Error::CommitMismatch) => { /* arrow doesn't match computed state */ }
        Err(e) => { /* other error */ }
    }
}
```

## Crate Structure

```
rs/
├── cyphr/              # Protocol core (Principal, commits, Merkle trees)
├── cyphr-storage/      # Storage engine over a blob store and an index
├── cyphr-blob-fjall/   # Durable blob store and commit logs (fjall)
├── cyphr-index-fjall/  # Durable key-value index (fjall)
├── cyphr-net/          # Network library: verify core, HTTP and Noise connectors
├── cyphr-server/       # HTTP server and witness
├── cyphr-cli/          # Command-line client
├── cyphr-keystore/     # Key backend seam and the software key store
├── cyphr-scenarios/    # End-to-end scenario harness
├── test-fixtures/      # Golden fixture loading
├── fixture-gen/        # Golden fixture generator
└── fuzz/               # cargo-fuzz targets
```

## Testing

```bash
cd rs
cargo test --workspace
```

The suite is property tests, metamorphic relations, integration tests and
end-to-end scenarios against real `cyphr-server` instances. The golden
fixtures in `../tests/golden/` pin byte-exact formats; the corpus pipeline is
described in [tests/README.md](../tests/README.md). While working on one
crate, run `cargo test -p <crate>` instead of the whole workspace.

## See Also

- [Protocol specification](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md) — the normative text, at the pinned commit
- [tests/README.md](../tests/README.md) — Test fixture documentation
