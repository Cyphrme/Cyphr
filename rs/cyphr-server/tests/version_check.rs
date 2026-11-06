//! Every format the server reads back carries a version that is checked, so
//! an incompatible file, store or peer fails closed with a typed error naming
//! the format (N13).
//!
//! Pinned conventions (the implementer may change an encoding by editing the
//! constants below, predicate unchanged):
//!
//! - JSON documents carry a top-level integer `v`.
//! - A dedicated fjall store (death set, spent set) records its version in the keyspace
//!   [`META_KEYSPACE`] under [`VERSION_KEY`] as decimal text, written when the store is first
//!   opened.
//! - A refusal's text says "version", names the offending value and the format.
//!
//! Each test states its claim and the defect that turns it red. None is an
//! end-to-end scenario: the reader is the unit under claim and no scenario
//! reaches an on-disk format cheaply. The end-to-end form (a hostile peer
//! serving `v=99`) is the T0 `version-check` probe plus `s10_hostile`.

use std::path::Path;
use std::sync::Arc;

use cyphr_server::admission::{ResidentProbe, layer};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::AdmissionConfig;
use cyphr_server::envelope::Envelope;
use cyphr_server::observation::ObservationStore;
use fjall::{Database, KeyspaceCreateOptions, PersistMode};

mod common;

const META_KEYSPACE: &str = "meta";
const VERSION_KEY: &str = "format-version";
/// Versions no build knows: the floor and a far-future one.
const UNKNOWN: [u64; 2] = [0, 99];

/// A refusal must name the version it saw and say what it refused.
fn assert_names(msg: &str, format: &str, version: u64) {
    let msg = msg.to_lowercase();
    assert!(
        msg.contains("version") && msg.contains(format) && msg.contains(&version.to_string()),
        "a refusal must name the {format} format and version {version}: {msg}"
    );
}

/// Read a JSON document, set its top-level `v`, and write it back.
fn set_v(path: &Path, v: u64) {
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    doc["v"] = v.into();
    std::fs::write(path, serde_json::to_vec(&doc).unwrap()).unwrap();
}

fn stamped_v(path: &Path) -> Option<u64> {
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    doc["v"].as_u64()
}

/// The version recorded in a store's meta keyspace, if any.
fn stored_version(dir: &Path) -> Option<String> {
    let db = Database::builder(dir).open().expect("raw open");
    let meta = db
        .keyspace(META_KEYSPACE, KeyspaceCreateOptions::default)
        .expect("meta");
    meta.get(VERSION_KEY)
        .expect("read")
        .map(|v| String::from_utf8_lossy(&v).into_owned())
}

fn restamp(dir: &Path, v: u64) {
    let db = Database::builder(dir).open().expect("raw open");
    let meta = db
        .keyspace(META_KEYSPACE, KeyspaceCreateOptions::default)
        .expect("meta");
    meta.insert(VERSION_KEY, v.to_string()).expect("write");
    db.persist(PersistMode::SyncAll).expect("persist");
}

// ---- envelope ----------------------------------------------------------

/// Claim: a response envelope from a version this build does not know is
/// refused by its reader, named, never decoded as if it were v1 (the
/// `[envelope-r-migration]` ruling). The current version still reads. Turns
/// red on a reader that accepts every `v` (today's derived `Deserialize`).
#[test]
#[ignore = "RED(N13): Envelope deserializes any `v`"]
fn version_envelope_unknown_is_refused() {
    let doc =
        |v: u64| serde_json::json!({"v": v, "payload": {}, "statement": {"kind": "unsigned"}});
    serde_json::from_value::<Envelope<serde_json::Value>>(doc(1)).expect("v1 reads");
    for unknown in UNKNOWN {
        let err = serde_json::from_value::<Envelope<serde_json::Value>>(doc(unknown))
            .err()
            .unwrap_or_else(|| panic!("envelope v={unknown} was accepted"));
        assert_names(&err.to_string(), "envelope", unknown);
    }
}

// ---- server signing-key file -------------------------------------------

/// Claim: a signing-key file stamped with an unknown version is refused,
/// named, before any key is loaded from it. Turns red on a loader that
/// ignores the field (today serde skips unknown fields).
#[test]
#[ignore = "RED(N13): the signing-key file loader ignores `v`"]
fn version_signing_key_file_unknown_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = common::write_signing_key(dir.path());
    ServerIdentity::load_from_path(&path).expect("an unstamped current file loads");
    for unknown in UNKNOWN {
        set_v(&path, unknown);
        let err = ServerIdentity::load_from_path(&path)
            .err()
            .unwrap_or_else(|| panic!("key file v={unknown} was accepted"));
        assert_names(&err.to_string(), "signing key", unknown);
    }
}

// ---- server-principal.json ---------------------------------------------

/// Claim: the sidecar that locates the server's own chain states its
/// version, and a later boot refuses one it does not know, named, instead of
/// loading a chain from a record it cannot interpret. A re-boot over the
/// unmodified sidecar still loads. Turns red on a sidecar written unstamped,
/// or a loader that ignores `v`.
#[tokio::test]
#[ignore = "RED(N13): server-principal.json is unversioned"]
async fn version_server_principal_sidecar_unknown_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = common::write_signing_key(dir.path());
    let data = dir.path().join("data");
    let boot = || async {
        let state = common::keyed_appstate(&data, &key_path);
        let identity = state.identity.clone().expect("keyed");
        ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &data)
            .await
            .map(|_| ())
    };
    boot().await.expect("first boot creates the principal");
    let sidecar = data.join("record").join("server-principal.json");
    assert!(
        stamped_v(&sidecar).is_some(),
        "the sidecar must be stamped with a numeric `v`"
    );
    boot()
        .await
        .expect("a reboot over the current sidecar loads");
    for unknown in UNKNOWN {
        set_v(&sidecar, unknown);
        let err = boot()
            .await
            .err()
            .unwrap_or_else(|| panic!("sidecar v={unknown} was accepted"));
        assert_names(&err.to_string(), "server principal", unknown);
    }
}

// ---- death set ---------------------------------------------------------

/// Claim: the naked-revoke death set records its format version when first
/// opened and refuses a store of another version, named. A refused death set
/// must not be read: a mis-decoded set would un-revoke keys silently. Turns
/// red on a store that stamps nothing, or an `open` that ignores the stamp.
#[tokio::test]
#[ignore = "RED(N13): the death set records no format version"]
async fn version_death_set_unknown_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    drop(ObservationStore::open(dir.path()).expect("fresh open"));
    assert!(
        stored_version(dir.path()).is_some(),
        "a fresh death set must record its version"
    );
    ObservationStore::open(dir.path()).expect("the current version reopens");
    for unknown in UNKNOWN {
        restamp(dir.path(), unknown);
        let err = ObservationStore::open(dir.path())
            .err()
            .unwrap_or_else(|| panic!("death set v={unknown} was accepted"));
        assert_names(&err.to_string(), "death set", unknown);
    }
}

// ---- admission spent set -----------------------------------------------

fn open_spent_set(record: &Path, tokens: &Path) -> Result<(), String> {
    let resident: ResidentProbe = Arc::new(|_| Box::pin(async { false }));
    let cfg = AdmissionConfig::Invite {
        tokens_path: tokens.to_path_buf(),
    };
    layer(&cfg, record, resident, 1 << 20)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Claim: the invite spent set records its format version and refuses a
/// store of another version, named: a mis-decoded spent set would let a
/// consumed single-use token be spent again. Turns red on a store that
/// stamps nothing, or one that ignores the stamp.
#[test]
#[ignore = "RED(N13): the spent set records no format version"]
fn version_spent_set_unknown_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (record, tokens) = (dir.path().join("record"), dir.path().join("tokens"));
    std::fs::create_dir_all(&record).unwrap();
    std::fs::write(&tokens, format!("{}\n", "a".repeat(64))).unwrap();
    open_spent_set(&record, &tokens).expect("fresh open");
    let store = record.join("admission");
    assert!(
        stored_version(&store).is_some(),
        "a fresh spent set must record its version"
    );
    open_spent_set(&record, &tokens).expect("the current version reopens");
    for unknown in UNKNOWN {
        restamp(&store, unknown);
        let err = open_spent_set(&record, &tokens)
            .err()
            .unwrap_or_else(|| panic!("spent set v={unknown} was accepted"));
        assert_names(&err, "spent set", unknown);
    }
}
