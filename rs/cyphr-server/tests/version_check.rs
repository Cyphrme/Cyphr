//! Every format the server reads back carries a version that is checked, so
//! an incompatible file, store or peer fails closed with a typed error naming
//! the format (N13).
//!
//! Pinned conventions (the implementer may change an encoding by editing the
//! constants below, predicate unchanged):
//!
//! - JSON documents carry a top-level integer `v`.
//! - A dedicated fjall store (the admission spent set) records its version in the keyspace
//!   [`META_KEYSPACE`] under [`VERSION_KEY`] as decimal text, written when the store is first
//!   opened.
//! - An absent `v` (a sidecar or store from before versions) means v1: it loads, and is written back
//!   with `v` (`1`). A signing-key file with no `v` is refused, never rewritten. Any other unknown
//!   `v` is refused.
//! - A refusal is a typed `UnsupportedVersion` variant of the format's own error, pinned by
//!   `matches!` on the variant and the offending number. The envelope is read through its typed
//!   reader `Envelope::from_value`; its plain serde `Deserialize` can only flatten that to a
//!   message.
//!
//! Each test states its claim and the defect that turns it red. None is an
//! end-to-end scenario: the reader is the unit under claim and no scenario
//! reaches an on-disk format cheaply. The end-to-end form (a hostile peer
//! serving `v=99`) is the T0 `version-check` probe plus `s10_hostile`.

use std::path::Path;
use std::sync::Arc;

use cyphr_server::admission::{AdmissionError, ResidentProbe, layer};
use cyphr_server::auth::principal::{ServerPrincipal, ServerPrincipalError};
use cyphr_server::auth::{AuthError, ServerIdentity};
use cyphr_server::config::AdmissionConfig;
use fjall::{Database, KeyspaceCreateOptions, PersistMode};

mod common;

const META_KEYSPACE: &str = "meta";
const VERSION_KEY: &str = "format-version";
/// Versions no build knows: the floor and a far-future one.
const UNKNOWN: [u64; 2] = [0, 99];

/// A refusal must be the typed `UnsupportedVersion` variant of the format's
/// own error enum, carrying the offending number.
macro_rules! assert_unsupported {
    ($err:expr, $enum:ident, $format:expr, $version:expr) => {{
        let (err, version): (&$enum, u64) = (&$err, $version);
        assert!(
            matches!(err, $enum::UnsupportedVersion { found, .. } if u64::from(*found) == version),
            "{} v={version} must be refused as UnsupportedVersion: {err:?}",
            $format
        );
    }};
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

// ---- server signing-key file -------------------------------------------

/// Claim: a signing-key file stamped with an unknown version is refused,
/// named, before any key is loaded from it. Turns red on a loader that
/// ignores the field (today serde skips unknown fields).
#[test]
fn version_signing_key_file_unknown_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = common::write_signing_key(dir.path());
    ServerIdentity::load_from_path(&path).expect("an unstamped current file loads");
    for unknown in UNKNOWN {
        set_v(&path, unknown);
        let err = ServerIdentity::load_from_path(&path)
            .err()
            .unwrap_or_else(|| panic!("key file v={unknown} was accepted"));
        assert_unsupported!(err, AuthError, "signing key", unknown);
    }
}

// ---- server-principal.json ---------------------------------------------

/// Claim: the sidecar that locates the server's own chain states its
/// version, and a later boot refuses one it does not know, named, instead of
/// loading a chain from a record it cannot interpret. A re-boot over the
/// unmodified sidecar still loads. Turns red on a sidecar written unstamped,
/// or a loader that ignores `v`.
#[tokio::test]
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
        assert_unsupported!(err, ServerPrincipalError, "server principal", unknown);
    }
}

// ---- admission spent set -----------------------------------------------

fn open_spent_set(
    record: &Path,
    tokens: &Path,
) -> Result<(), cyphr_server::admission::AdmissionError> {
    let resident: ResidentProbe = Arc::new(|_| Box::pin(async { false }));
    let cfg = AdmissionConfig::Invite {
        tokens_path: tokens.to_path_buf(),
    };
    layer(
        &cfg,
        record,
        resident,
        1 << 20,
        &cyphr_server::metrics::HealthProbe::new(record),
    )
    .map(|_| ())
}

/// Claim: the invite spent set records its format version and refuses a
/// store of another version, named: a mis-decoded spent set would let a
/// consumed single-use token be spent again. Turns red on a store that
/// stamps nothing, or one that ignores the stamp.
#[test]
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
        assert_unsupported!(err, AdmissionError, "spent set", unknown);
    }
}

// ---- absent `v` means v1 -------------------------------------------------

fn unstamp(dir: &Path) {
    let db = Database::builder(dir).open().expect("raw open");
    let meta = db
        .keyspace(META_KEYSPACE, KeyspaceCreateOptions::default)
        .expect("meta");
    meta.remove(VERSION_KEY).expect("remove");
    db.persist(PersistMode::SyncAll).expect("persist");
}

fn unstamp_json(path: &Path) {
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    doc.as_object_mut().unwrap().remove("v");
    std::fs::write(path, serde_json::to_vec(&doc).unwrap()).unwrap();
}

/// Claim: a signing-key file from before versions (no `v`) is refused with
/// an error that says to add it, and the file is left as it was: no
/// migration rewrites a key file. Turns red on a loader that accepts the
/// absent version, or one that rewrites the file.
#[test]
fn version_signing_key_file_absent_is_refused_and_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = common::write_signing_key(dir.path());
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    doc.as_object_mut().unwrap().remove("v");
    let bytes = serde_json::to_vec(&doc).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let err = ServerIdentity::load_from_path(&path)
        .err()
        .expect("an absent `v` is refused");
    assert!(err.to_string().contains("\"v\""), "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), bytes, "the file is not rewritten");
}

/// Claim: a server-principal.json from before versions loads as v1 and is
/// written back with `v: 1`. Turns red on a sidecar left unstamped by a boot,
/// or a boot that refuses it.
#[tokio::test]
async fn version_server_principal_sidecar_absent_is_v1_and_written_back() {
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
    boot().await.expect("first boot");
    let sidecar = data.join("record").join("server-principal.json");
    unstamp_json(&sidecar);
    boot().await.expect("an absent `v` loads as v1");
    assert_eq!(
        stamped_v(&sidecar),
        Some(1),
        "the sidecar must be written back with v=1"
    );
}

/// Claim: a spent set from before versions loads as v1 and is stamped on
/// open. Turns red on an `open` that stamps nothing, or one that refuses it.
#[test]
fn version_spent_set_absent_is_v1() {
    let dir = tempfile::tempdir().unwrap();
    let (record, tokens) = (dir.path().join("record"), dir.path().join("tokens"));
    std::fs::create_dir_all(&record).unwrap();
    std::fs::write(&tokens, format!("{}\n", "a".repeat(64))).unwrap();
    open_spent_set(&record, &tokens).expect("fresh open");
    let store = record.join("admission");
    unstamp(&store);
    open_spent_set(&record, &tokens).expect("an absent version loads as v1");
    assert_eq!(stored_version(&store).as_deref(), Some("1"));
}
