//! The server's own Cyphr principal: explicit single-key L3 genesis,
//! created on first keyed boot, loaded idempotently on later boots, and
//! rotated on its own chain — all through the validated storage path.
//!
//! The first test pins the premise that a SINGLE-key explicit L3 genesis
//! is constructible at all (mirroring
//! `rs/cyphr-storage/tests/f40_multi_key_genesis.rs`, but one genesis key).
//! The rest exercise [`ServerPrincipal`] as the server boots it.

use std::sync::Arc;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_index_fjall::FjallIndexer;
use cyphr_server::AppState;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_storage::Genesis;
use cyphr_storage::engine::StorageEngine;

// ========================================================================
// Helpers
// ========================================================================

/// Write a fresh Ed25519 signing key file and return its path plus the
/// keypair (so a test knows the key material behind the file).
fn write_signing_key(dir: &std::path::Path) -> (std::path::PathBuf, coz::KeyPair) {
    let path = dir.join("signing-key.json");
    let kp = coz::Alg::Ed25519.generate_keypair();
    let file = serde_json::json!({
        "alg": kp.alg.name(),
        "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
        "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
    });
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    (path, kp)
}

/// Build a keyed `AppState` whose storage lives under `data_dir` and whose
/// signing key is `key_path`. Mirrors what `serve` constructs before it
/// bootstraps the principal (which these tests drive directly).
fn keyed_appstate(data_dir: &std::path::Path, key_path: &std::path::Path) -> AppState {
    let config = ServerConfig {
        data_dir: data_dir.to_path_buf(),
        signing_key_path: Some(key_path.to_path_buf()),
        ..Default::default()
    };
    AppState::new(config).expect("keyed AppState opens")
}

/// `Arc`-wrapped keyed state for tests that only read it.
fn keyed_state(data_dir: &std::path::Path, key_path: &std::path::Path) -> Arc<AppState> {
    Arc::new(keyed_appstate(data_dir, key_path))
}

/// The tmb of a keypair, as the domain `Thumbprint`.
fn tmb_of(kp: &coz::KeyPair) -> coz::Thumbprint {
    kp.alg
        .compute_thumbprint(&kp.pub_bytes)
        .expect("thumbprint")
}

#[tokio::test]
async fn single_key_explicit_genesis_establishes_pg() {
    let kp = coz::Alg::Ed25519.generate_keypair();
    let alg = kp.alg.name().to_string();
    let tmb = kp
        .alg
        .compute_thumbprint(&kp.pub_bytes)
        .expect("thumbprint for server key");
    let tmb_b64 = Base64UrlUnpadded::encode_string(tmb.as_bytes());

    let genesis_key = cyphr::Key {
        alg: alg.clone(),
        tmb: tmb.clone(),
        pub_key: kp.pub_bytes.clone(),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    };
    let genesis = Genesis::Explicit(vec![genesis_key.clone()]);

    // Client-side: build the explicit principal and derive its PG.
    let mut client = cyphr::Principal::explicit(vec![genesis_key]).expect("explicit genesis");
    let pg_tagged = client
        .pr_tagged()
        .expect("pr_tagged for a fresh single-key explicit genesis");

    let now = 1_700_000_000i64;
    let pc_pay = serde_json::json!({
        "alg": alg,
        "id": pg_tagged,
        "now": now,
        "tmb": tmb_b64,
        "typ": "cyphr.me/cyphr/principal/create",
    });
    let mut pc_pay = pc_pay;
    pc_pay.as_object_mut().unwrap().sort_keys();
    let pc_pay_bytes = serde_json::to_vec(&pc_pay).unwrap();
    let (pc_sig, pc_cad) =
        coz::sign_json(&pc_pay_bytes, &alg, &kp.prv_bytes, &kp.pub_bytes).expect("sign pc");
    let pc_czd = coz::czd_for_alg(&pc_cad, &pc_sig, &alg).expect("czd pc");

    let mut scope = client.begin_commit();
    scope
        .verify_and_apply(&pc_pay_bytes, &pc_sig, pc_czd, None)
        .expect("principal/create applies to single-key explicit genesis");
    let commit = scope
        .finalize_with_arrow(
            &alg,
            &kp.prv_bytes,
            &kp.pub_bytes,
            &tmb,
            now + 1,
            "cyphr.me",
        )
        .expect("genesis commit finalizes");

    // The commit/create finalizer comes off the finalized commit; the
    // principal/create blob is the one we signed and applied ourselves.
    // (last use of `commit`, which borrows `client`, so extract before the
    // immutable `client.pg()` reads.)
    let cc_blob = serde_json::to_vec(commit.commit_tx().0[0].raw()).unwrap();
    let pc_blob = {
        let pay_val: serde_json::Value = serde_json::from_slice(&pc_pay_bytes).unwrap();
        serde_json::to_vec(&serde_json::json!({
            "pay": pay_val,
            "sig": Base64UrlUnpadded::encode_string(&pc_sig),
        }))
        .unwrap()
    };

    let pg = client
        .pg()
        .expect("single-key explicit genesis MUST establish a PG");
    let pg_from_chain = pg.0.tagged_first().unwrap().to_string();
    assert_eq!(
        pg_from_chain, pg_tagged,
        "PG equals the nascent PR declared as principal/create's id"
    );

    // Submit through the real durable engine.
    let dir = tempfile::tempdir().expect("tempdir");
    let db = fjall::Database::builder(dir.path().join("blobs"))
        .open()
        .expect("db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let indexer = FjallIndexer::open(&dir.path().join("index")).expect("indexer");
    let engine = StorageEngine::with_storage_factory(blob_store, indexer, move |pid: &str| {
        cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), pid).map_err(|e| e.to_string())
    });

    engine
        .submit_commit(&pg_tagged, Some(genesis), &[&pc_blob, &cc_blob])
        .await
        .expect("genesis commit submits through the validated write path");

    let tip = engine
        .get_tip(&pg_tagged)
        .await
        .expect("get_tip ok")
        .expect("server principal tip present after genesis");
    assert_eq!(tip.principal_id, pg_tagged, "tip is the server's PG");
    assert_eq!(tip.commit_count, 1, "exactly one genesis commit");
}

/// First keyed boot creates the explicit L3 genesis and serves it through
/// the ordinary engine surface (`ac-explicit-genesis-on-first-keyed-boot`,
/// `c-chain-served-publicly`).
#[tokio::test]
async fn first_keyed_boot_creates_and_serves_the_principal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (key_path, _kp) = write_signing_key(dir.path());
    let state = keyed_state(&dir.path().join("data"), &key_path);
    let identity = state.identity.clone().expect("keyed state has identity");

    let sp = ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
        .await
        .expect("first keyed boot bootstraps the principal");

    assert!(!sp.pg().is_empty(), "a bootstrapped principal has a PG");

    let tip = state
        .engine
        .get_tip(sp.pg())
        .await
        .expect("get_tip ok")
        .expect("the server principal's chain is served under its PG");
    assert_eq!(tip.principal_id, sp.pg(), "chain served under the PG");
    assert_eq!(tip.commit_count, 1, "exactly one genesis commit exists");
}

/// A second boot with the same key and data directory loads the existing
/// principal — same PG, no duplicate chain
/// (`ac-explicit-genesis-on-first-keyed-boot`, idempotency).
#[tokio::test]
async fn second_boot_loads_without_duplicating_the_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (key_path, _kp) = write_signing_key(dir.path());
    let data_dir = dir.path().join("data");
    let state = keyed_state(&data_dir, &key_path);
    let identity = state.identity.clone().expect("identity");

    let sp1 = ServerPrincipal::bootstrap(
        &state.engine,
        identity.clone(),
        &key_path,
        &state.config.data_dir,
    )
    .await
    .expect("first boot");
    let pg1 = sp1.pg().to_string();
    let count1 = state
        .engine
        .get_tip(&pg1)
        .await
        .unwrap()
        .unwrap()
        .commit_count;

    let sp2 =
        ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
            .await
            .expect("second boot loads the existing principal");

    assert_eq!(sp2.pg(), pg1, "second boot resolves the same PG");
    let count2 = state
        .engine
        .get_tip(&pg1)
        .await
        .unwrap()
        .unwrap()
        .commit_count;
    assert_eq!(count2, count1, "second boot creates no additional commit");
    assert_eq!(count1, 1, "still exactly one genesis commit");
}

/// A key rotation on the server's own chain succeeds end to end: the PG is
/// unchanged, the old key is inactive, the new key is active, and the chain
/// has grown (`ac-rotation-exercised`, `c-pg-stable-across-rotation`).
#[tokio::test]
async fn rotation_preserves_pg_and_swaps_active_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (key_path, kp) = write_signing_key(dir.path());
    let state = keyed_state(&dir.path().join("data"), &key_path);
    let identity = state.identity.clone().expect("identity");

    let sp = ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
        .await
        .expect("bootstrap");
    let pg_before = sp.pg().to_string();

    let old_tmb = tmb_of(&kp);
    let new_kp = coz::Alg::Ed25519.generate_keypair();
    let new_tmb = tmb_of(&new_kp);

    sp.rotate(&state.engine, &new_kp)
        .await
        .expect("rotation succeeds on the server's own chain");

    assert_eq!(sp.pg(), pg_before, "PG is unchanged by rotation");

    // Reload the chain and inspect its key state.
    let principal = state
        .engine
        .load_principal(sp.pg(), Genesis::Explicit(vec![sp.genesis_key().clone()]))
        .await
        .expect("reload the rotated chain");

    assert!(
        !principal.is_key_active(&old_tmb),
        "the old signing key is no longer active after rotation"
    );
    assert!(
        principal.is_key_active(&new_tmb),
        "the new signing key is active after rotation"
    );

    let tip = state.engine.get_tip(sp.pg()).await.unwrap().unwrap();
    assert!(
        tip.commit_count > 1,
        "rotation extends the chain beyond the genesis commit"
    );
}

/// A restart after a rotation must load the principal, not brick on a stale
/// key. Rotation retires the old key on-chain, so the signing-key file must
/// hold the NEW key for a fresh boot to pass load()'s active-key check.
#[tokio::test]
async fn reboot_after_rotation_loads_the_rotated_principal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (key_path, _kp) = write_signing_key(dir.path());
    let state = keyed_state(&dir.path().join("data"), &key_path);
    let identity = state.identity.clone().expect("identity");

    let sp = ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
        .await
        .expect("bootstrap");
    let pg = sp.pg().to_string();

    let new_kp = coz::Alg::Ed25519.generate_keypair();
    sp.rotate(&state.engine, &new_kp)
        .await
        .expect("rotation succeeds");

    // Simulate a restart: the running process is gone. A fresh boot reads
    // the signing-key file (which rotation must have updated to the new
    // key) and bootstraps against the same store.
    let rebooted = Arc::new(
        cyphr_server::auth::ServerIdentity::load_from_path(&key_path)
            .expect("reload the signing key file"),
    );
    let sp2 =
        ServerPrincipal::bootstrap(&state.engine, rebooted, &key_path, &state.config.data_dir)
            .await
            .expect("a reboot after rotation must load the principal, not fail on a stale key");

    assert_eq!(sp2.pg(), pg, "reboot resolves the same PG");
}

/// The principal must be able to rotate again after a rotation: the second
/// rotation has to sign with the rotated-in key, not the retired one.
#[tokio::test]
async fn principal_can_rotate_again_after_rotation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (key_path, _kp) = write_signing_key(dir.path());
    let state = keyed_state(&dir.path().join("data"), &key_path);
    let identity = state.identity.clone().expect("identity");

    let sp = ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
        .await
        .expect("bootstrap");
    let pg = sp.pg().to_string();

    let kp1 = coz::Alg::Ed25519.generate_keypair();
    sp.rotate(&state.engine, &kp1)
        .await
        .expect("first rotation succeeds");
    let kp2 = coz::Alg::Ed25519.generate_keypair();
    sp.rotate(&state.engine, &kp2)
        .await
        .expect("a second rotation must sign with the rotated-in key, not a retired one");

    assert_eq!(sp.pg(), pg, "PG is stable across two rotations");

    let principal = state
        .engine
        .load_principal(sp.pg(), Genesis::Explicit(vec![sp.genesis_key().clone()]))
        .await
        .expect("reload the twice-rotated chain");
    assert!(
        principal.is_key_active(&tmb_of(&kp2)),
        "the twice-rotated-in key is active"
    );
    assert!(
        !principal.is_key_active(&tmb_of(&kp1)),
        "the intermediate key is retired"
    );

    let tip = state.engine.get_tip(sp.pg()).await.unwrap().unwrap();
    assert!(
        tip.commit_count >= 3,
        "genesis plus two rotations extend the chain"
    );
}

/// After a rotation, the live signing identity that token issuance and login
/// read (`AppState.identity`) must be the rotated-in key: a token issued now
/// is signed by the new key, not the retired one. This catches a rotation
/// that updates the chain and key file but leaves the in-memory identity
/// (the token/login consumer) stale.
#[tokio::test]
async fn token_after_rotation_is_signed_by_the_new_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (key_path, _kp) = write_signing_key(dir.path());
    let mut state = keyed_appstate(&dir.path().join("data"), &key_path);
    let identity = state.identity.clone().expect("identity");

    let sp = ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
        .await
        .expect("bootstrap");
    state.principal = Some(Arc::new(sp));

    let new_kp = coz::Alg::Ed25519.generate_keypair();
    state
        .rotate_signing_key(&new_kp)
        .await
        .expect("rotate the signing key through AppState");

    // Issue a token through the same handle login and token verification use.
    let now = 1_800_000_000i64;
    let token = state
        .identity
        .as_ref()
        .expect("identity present after rotation")
        .issue_token("some-principal", vec!["read".to_string()], now, 900)
        .expect("issue token");

    // The token carries the issuing key's thumbprint; after rotation it must
    // be the new key's, proving the token was signed by the rotated-in key.
    let claims = state
        .identity
        .as_ref()
        .unwrap()
        .verify_token(&token, now)
        .expect("the current identity verifies its own token");
    let new_tmb_b64 = Base64UrlUnpadded::encode_string(tmb_of(&new_kp).as_bytes());
    assert_eq!(
        claims.tmb, new_tmb_b64,
        "a token issued after rotation must be signed by the rotated-in key"
    );
}
