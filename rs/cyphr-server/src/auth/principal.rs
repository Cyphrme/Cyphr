//! The server's own Cyphr principal.
//!
//! When the server is keyed, its signing key is more than a bare keypair:
//! it is the sole genesis key of an explicit Level-3 principal whose
//! Principal Genesis (PG) is a stable, rotation-surviving identifier. This
//! module creates that principal on first keyed boot, loads it on later
//! boots, and exercises key rotation on its own chain — all through the
//! ordinary validated storage path, so the server is an ordinary principal
//! in its own store (SPEC.md §3.7.1, §5.1).
//!
//! Keyless operation is unaffected: with no signing key there is no
//! principal and nothing here runs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::Genesis;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::ServerIdentity;

/// `first_seen` stamped on the server's genesis key. Fixed (not wall-clock)
/// so the genesis key — and therefore the PG derived from it — is
/// reproducible: the same signing key always yields the same principal.
pub const GENESIS_FIRST_SEEN: i64 = 0;

/// The `typ` authority segment of the server's own chain cozies (SPEC
/// §7.2). Unlike a login audience, this segment is never matched against an
/// external value — it is only formatted into the `typ` and signed over
/// consistently (see `cyphr::commit`'s `finalize_with_arrow`), so a fixed
/// value is sufficient. It matches the authority the rest of the corpus
/// uses for constructed chains.
const CHAIN_AUTHORITY: &str = "cyphr.me";

/// File under the data directory that records where the server's own chain
/// lives, so a later boot loads it instead of creating a second one.
const STATE_FILE: &str = "server-principal.json";

/// The concrete storage engine the server runs on.
type ServerEngine = cyphr_storage::engine::StorageEngine<
    cyphr_blob_fjall::FjallBlobStore,
    cyphr_index_fjall::FjallIndexer,
    cyphr_blob_fjall::storage_fjall::FjallStorage,
>;

/// Errors bootstrapping or rotating the server's own principal.
#[derive(Debug, thiserror::Error)]
pub enum ServerPrincipalError {
    /// The storage engine rejected a read or write.
    #[error("server principal storage: {0}")]
    Engine(#[from] cyphr_storage::engine::EngineError),

    /// Chain construction or replay failed in the core protocol.
    #[error("server principal chain: {0}")]
    Chain(#[from] cyphr::Error),

    /// Reading or writing the on-disk genesis record failed.
    #[error("server principal genesis record io: {0}")]
    Io(#[from] std::io::Error),

    /// Loading or writing the signing-key file failed.
    #[error("server principal signing key: {0}")]
    KeyFile(#[from] super::AuthError),

    /// The genesis record was not valid JSON in the expected shape.
    #[error("server principal genesis record malformed: {0}")]
    Malformed(#[from] serde_json::Error),

    /// coz rejected the server key while signing a chain coz, or a stored
    /// key record could not be decoded.
    #[error("server key cannot sign chain cozies for algorithm {0}")]
    Signing(String),

    /// A persisted genesis record points at a chain that is missing from
    /// storage, or the configured key file is not an active key of that
    /// chain — the data directory and key file have drifted apart.
    #[error("server principal genesis record does not match the configured key or its chain")]
    RecordMismatch,

    /// The sidecar recording file (`server-principal.json`) is absent, but
    /// the engine already holds a chain at the PG this identity's key
    /// deterministically derives: the principal is established, only the
    /// small pointer file `load()` needs to find it again is gone (backup
    /// restore that missed one file, disk hiccup, operator error). Named
    /// distinctly from `RecordMismatch` so an operator is pointed at the
    /// documented, reconstructible cause instead of a raw protocol
    /// diagnostic from a doomed re-genesis attempt (issue #175).
    #[error("{0}")]
    MissingSidecar(String),
}

/// On-disk record locating the server's own chain between boots.
///
/// Holds only public material: the stable PG (the engine `principal_id`)
/// and the sole genesis key needed to reconstruct the chain via
/// `Genesis::Explicit`. The private signing key stays in the separate key
/// file, and this record survives a key rotation unchanged — after a
/// rotation the key file holds a different key, but the *genesis* key
/// recorded here does not change, so the chain remains loadable.
#[derive(Serialize, Deserialize)]
struct GenesisRecord {
    pg: String,
    genesis_key: GenesisKeyRecord,
}

/// The public fields of the genesis key, base64url-encoded.
#[derive(Serialize, Deserialize)]
struct GenesisKeyRecord {
    alg: String,
    pub_key: String,
    tmb: String,
    first_seen: i64,
}

impl GenesisKeyRecord {
    fn from_key(key: &cyphr::Key) -> Self {
        Self {
            alg: key.alg.clone(),
            pub_key: Base64UrlUnpadded::encode_string(&key.pub_key),
            tmb: Base64UrlUnpadded::encode_string(key.tmb.as_bytes()),
            first_seen: key.first_seen,
        }
    }

    fn to_key(&self) -> Result<cyphr::Key, ServerPrincipalError> {
        let pub_key = Base64UrlUnpadded::decode_vec(&self.pub_key)
            .map_err(|_| ServerPrincipalError::RecordMismatch)?;
        let tmb = Base64UrlUnpadded::decode_vec(&self.tmb)
            .map_err(|_| ServerPrincipalError::RecordMismatch)?;
        Ok(cyphr::Key {
            alg: self.alg.clone(),
            tmb: coz::Thumbprint::from_bytes(tmb),
            pub_key,
            first_seen: self.first_seen,
            last_used: None,
            revocation: None,
            tag: None,
        })
    }
}

/// The server acting as its own Cyphr principal.
///
/// Holds the stable PG (the engine `principal_id` under which the chain is
/// served) and the material needed to reload and extend that chain. The
/// current signing key is not held in memory: the signing-key file at
/// `signing_key_path` is the single source of truth, so a rotation that
/// rewrites that file (and the fresh boot that reads it) can never act on a
/// stale key.
pub struct ServerPrincipal {
    pg: String,
    genesis_key: cyphr::Key,
    signing_key_path: PathBuf,
}

impl ServerPrincipal {
    /// Create the server's principal on first keyed boot, or load it on a
    /// later boot. Idempotent: a second boot with the same key finds the
    /// existing chain and creates no duplicate.
    ///
    /// `identity` is the key currently on disk at `signing_key_path`; the
    /// path is retained so [`rotate`](Self::rotate) can rewrite the file.
    pub async fn bootstrap(
        engine: &ServerEngine,
        identity: Arc<ServerIdentity>,
        signing_key_path: &Path,
        data_dir: &Path,
    ) -> Result<Self, ServerPrincipalError> {
        let state_path = data_dir.join(STATE_FILE);

        if state_path.exists() {
            return Self::load(engine, &identity, signing_key_path, &state_path).await;
        }

        // No sidecar on disk: either this is a genuinely fresh boot, or the
        // sidecar was lost while the chain survives. The genesis key (and
        // therefore the PG) is deterministic from the identity, so it can
        // be recomputed and checked against the engine before committing to
        // either story -- re-attempting genesis against an
        // already-established PG would throw a raw, unnamed protocol error
        // that reads to an operator as store corruption, not a missing,
        // reconstructible file (#175).
        let genesis_key = genesis_key_from_identity(&identity)?;
        let (pg, blobs) = build_genesis(&identity, &genesis_key)?;

        if engine.get_tip(&pg).await?.is_some() {
            return Err(ServerPrincipalError::MissingSidecar(format!(
                "missing {} for an already-established server principal (pg={pg}); see \
                 docs/guides/operating-a-server.md for the recovery procedure",
                state_path.display()
            )));
        }

        let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
        engine
            .submit_commit(
                &pg,
                Some(Genesis::Explicit(vec![genesis_key.clone()])),
                &blob_refs,
            )
            .await?;

        let record = GenesisRecord {
            pg: pg.clone(),
            genesis_key: GenesisKeyRecord::from_key(&genesis_key),
        };
        std::fs::write(&state_path, serde_json::to_vec_pretty(&record)?)?;

        Ok(Self {
            pg,
            genesis_key,
            signing_key_path: signing_key_path.to_path_buf(),
        })
    }

    /// Load an already-established principal recorded at `state_path`.
    ///
    /// The genesis key comes from the record (not the current key file):
    /// after a rotation the two differ, and only the genesis key can
    /// reconstruct the chain. The current key file is verified to still be
    /// an active key of that chain, so a key/data-directory mismatch fails
    /// loudly rather than silently signing against the wrong chain.
    async fn load(
        engine: &ServerEngine,
        identity: &ServerIdentity,
        signing_key_path: &Path,
        state_path: &Path,
    ) -> Result<Self, ServerPrincipalError> {
        let record: GenesisRecord = serde_json::from_slice(&std::fs::read(state_path)?)?;
        let genesis_key = record.genesis_key.to_key()?;

        // A record with no served chain (e.g. the index was wiped out from
        // under it) must fail loudly, not silently "load" the nascent
        // principal `load_principal` would reconstruct from genesis alone.
        if engine.get_tip(&record.pg).await?.is_none() {
            return Err(ServerPrincipalError::RecordMismatch);
        }

        let principal = engine
            .load_principal(&record.pg, Genesis::Explicit(vec![genesis_key.clone()]))
            .await?;

        let current_tmb = identity_thumbprint(identity)?;
        if !principal.is_key_active(&current_tmb) {
            return Err(ServerPrincipalError::RecordMismatch);
        }

        Ok(Self {
            pg: record.pg,
            genesis_key,
            signing_key_path: signing_key_path.to_path_buf(),
        })
    }

    /// The server principal's stable tagged PG — the identifier its chain
    /// is served under (`engine.get_tip(pg)`).
    pub fn pg(&self) -> &str {
        &self.pg
    }

    /// The sole genesis key (public material), needed to reload or
    /// independently verify the chain via `Genesis::Explicit`.
    pub fn genesis_key(&self) -> &cyphr::Key {
        &self.genesis_key
    }

    /// Rotate the server's signing key on its own chain: activate
    /// `new_keypair`, retire the current key, leave the PG unchanged.
    ///
    /// Both halves of the swap are persisted. The chain is extended with a
    /// `key/replace` (the public truth), then `new_keypair` is written to
    /// the signing-key file (the private material). Because the current key
    /// is read fresh from that file each time, a later boot and a
    /// subsequent rotation both act on the rotated-in key, never a retired
    /// one. The PG is frozen at genesis and is unaffected.
    ///
    /// The two media cannot be updated atomically, so the order is
    /// deliberate: the chain (public truth) is committed first, then the key
    /// file (private material). A crash in the gap leaves the new chain with
    /// the old key file — which fails loudly at the next boot (load()'s
    /// active-key check rejects the retired key) and an operator recovers by
    /// rewriting the file to the rotated-in key. The reverse order — a new
    /// key file over an unrotated chain — would be a quieter, more confusing
    /// wreck, so it is avoided. This residual crash window is not closed
    /// here; it is made loud rather than silent.
    ///
    /// This persists the chain and key file only. It does NOT refresh the
    /// running process's live signing identity — the in-memory
    /// `AppState.identity` that login and token issuance read — which stays
    /// on the retired key until the process reloads it from the file (on a
    /// fresh boot, or via [`AppState::rotate_signing_key`](crate::AppState::rotate_signing_key)
    /// on an owned `AppState`). Nothing in the shipped code invokes a
    /// rotation on a live server today. Whoever later wires a live rotation
    /// trigger MUST also refresh the running process's identity view, not
    /// just the file and chain, or authenticated flows will keep signing
    /// with the retired key until the next restart.
    pub async fn rotate(
        &self,
        engine: &ServerEngine,
        new_keypair: &coz::KeyPair,
    ) -> Result<(), ServerPrincipalError> {
        // The current active key is whatever the signing-key file holds now
        // — the genesis key on the first rotation, the previously rotated-in
        // key on later ones.
        let current = ServerIdentity::load_from_path(&self.signing_key_path)?;
        let alg = current.alg().name();

        let mut principal = engine
            .load_principal(&self.pg, Genesis::Explicit(vec![self.genesis_key.clone()]))
            .await?;

        // Keep the new coz strictly monotonic over the chain's latest
        // timestamp even when rotation lands in the same wall-clock second
        // as an earlier commit (chain `now` is caller-set i64 seconds).
        let tip = engine
            .get_tip(&self.pg)
            .await?
            .ok_or(ServerPrincipalError::RecordMismatch)?;
        let now = super::server_now().max(tip.last_updated + 1);

        let signer_tmb = identity_thumbprint(&current)?;
        let signer_tmb_b64 = Base64UrlUnpadded::encode_string(signer_tmb.as_bytes());

        let new_tmb = new_keypair
            .alg
            .compute_thumbprint(&new_keypair.pub_bytes)
            .ok_or_else(|| ServerPrincipalError::Signing(new_keypair.alg.name().to_string()))?;
        let new_tmb_b64 = Base64UrlUnpadded::encode_string(new_tmb.as_bytes());
        let new_key = cyphr::Key {
            alg: new_keypair.alg.name().to_string(),
            tmb: new_tmb,
            pub_key: new_keypair.pub_bytes.clone(),
            first_seen: now,
            last_used: None,
            revocation: None,
            tag: None,
        };

        let pay = canonical_pay(json!({
            "alg": alg,
            "id": new_tmb_b64,
            "now": now,
            "tmb": signer_tmb_b64,
            "typ": format!("{CHAIN_AUTHORITY}/{}", cyphr::parsed_coz::typ::KEY_REPLACE),
        }));
        let (sig, czd) = sign_pay(&current, &pay)?;

        let mut scope = principal.begin_commit();
        scope.verify_and_apply(&pay, &sig, czd, Some(new_key))?;
        let commit = scope.finalize_with_arrow(
            alg,
            current.prv_key(),
            current.pub_key(),
            &signer_tmb,
            now + 1,
            CHAIN_AUTHORITY,
        )?;
        let cc_blob = serde_json::to_vec(commit.commit_tx().0[0].raw())?;
        let kr_blob = raw_blob(
            &pay,
            &sig,
            Some(json!({
                "alg": new_keypair.alg.name(),
                "pub": Base64UrlUnpadded::encode_string(&new_keypair.pub_bytes),
                "tmb": new_tmb_b64,
            })),
        )?;

        engine
            .submit_commit(
                &self.pg,
                Some(Genesis::Explicit(vec![self.genesis_key.clone()])),
                &[&kr_blob, &cc_blob],
            )
            .await?;

        // Persist the private half: the retired key must not remain on disk,
        // or a later boot would load an inactive key and refuse to start.
        super::write_key_file(&self.signing_key_path, new_keypair)?;

        Ok(())
    }
}

/// Sign a canonical pay with `identity`, returning the signature and its
/// coz digest.
fn sign_pay(
    identity: &ServerIdentity,
    pay: &[u8],
) -> Result<(Vec<u8>, coz::Czd), ServerPrincipalError> {
    let alg = identity.alg().name();
    let (sig, cad) = identity
        .sign(pay)
        .ok_or_else(|| ServerPrincipalError::Signing(alg.to_string()))?;
    let czd = coz::czd_for_alg(&cad, &sig, alg)
        .ok_or_else(|| ServerPrincipalError::Signing(alg.to_string()))?;
    Ok((sig, czd))
}

/// The thumbprint of the server's current signing key.
fn identity_thumbprint(identity: &ServerIdentity) -> Result<coz::Thumbprint, ServerPrincipalError> {
    identity
        .alg()
        .compute_thumbprint(identity.pub_key())
        .ok_or_else(|| ServerPrincipalError::Signing(identity.alg().name().to_string()))
}

/// Build the sole genesis key from the server's signing identity.
fn genesis_key_from_identity(
    identity: &ServerIdentity,
) -> Result<cyphr::Key, ServerPrincipalError> {
    Ok(cyphr::Key {
        alg: identity.alg().name().to_string(),
        tmb: identity_thumbprint(identity)?,
        pub_key: identity.pub_key().to_vec(),
        first_seen: GENESIS_FIRST_SEEN,
        last_used: None,
        revocation: None,
        tag: None,
    })
}

/// Construct and sign the two-coz genesis commit (principal/create +
/// commit/create) for a single-key explicit genesis, returning the PG and
/// the wire blobs ready for `submit_commit`.
fn build_genesis(
    identity: &ServerIdentity,
    genesis_key: &cyphr::Key,
) -> Result<(String, Vec<Vec<u8>>), ServerPrincipalError> {
    let alg = identity.alg().name();
    let tmb_b64 = Base64UrlUnpadded::encode_string(genesis_key.tmb.as_bytes());

    // The PG is the nascent PR of the fresh explicit genesis — computed
    // before any commit and independent of timestamps, so it is the same
    // every time this key bootstraps.
    let mut client = cyphr::Principal::explicit(vec![genesis_key.clone()])?;
    let pg = client.pr_tagged()?;

    let now = super::server_now();
    let pc_pay = canonical_pay(json!({
        "alg": alg,
        "id": pg,
        "now": now,
        "tmb": tmb_b64,
        "typ": format!("{CHAIN_AUTHORITY}/{}", cyphr::parsed_coz::typ::PRINCIPAL_CREATE),
    }));
    let (pc_sig, pc_cad) = identity
        .sign(&pc_pay)
        .ok_or_else(|| ServerPrincipalError::Signing(alg.to_string()))?;
    let pc_czd = coz::czd_for_alg(&pc_cad, &pc_sig, alg)
        .ok_or_else(|| ServerPrincipalError::Signing(alg.to_string()))?;

    let mut scope = client.begin_commit();
    scope.verify_and_apply(&pc_pay, &pc_sig, pc_czd, None)?;
    let commit = scope.finalize_with_arrow(
        alg,
        identity.prv_key(),
        identity.pub_key(),
        &genesis_key.tmb,
        now + 1,
        CHAIN_AUTHORITY,
    )?;

    let cc_blob = serde_json::to_vec(commit.commit_tx().0[0].raw())?;
    let pc_blob = raw_blob(&pc_pay, &pc_sig, None)?;
    Ok((pg, vec![pc_blob, cc_blob]))
}

/// Serialize a pay object with keys sorted, matching the server's
/// re-canonicalization so the signature verifies against re-derived bytes.
fn canonical_pay(mut pay: serde_json::Value) -> Vec<u8> {
    pay.as_object_mut()
        .expect("pay is a JSON object")
        .sort_keys();
    serde_json::to_vec(&pay).expect("a serde_json::Value re-serializes")
}

/// Assemble a wire coz blob (`{pay, sig, key?}`) as `submit_commit` parses
/// it, embedding key material for a key-introducing coz.
fn raw_blob(
    pay_bytes: &[u8],
    sig: &[u8],
    embedded_key: Option<serde_json::Value>,
) -> Result<Vec<u8>, serde_json::Error> {
    let pay: serde_json::Value = serde_json::from_slice(pay_bytes)?;
    let mut obj = serde_json::Map::new();
    obj.insert("pay".to_string(), pay);
    obj.insert(
        "sig".to_string(),
        json!(Base64UrlUnpadded::encode_string(sig)),
    );
    if let Some(key) = embedded_key {
        obj.insert("key".to_string(), key);
    }
    serde_json::to_vec(&serde_json::Value::Object(obj))
}
