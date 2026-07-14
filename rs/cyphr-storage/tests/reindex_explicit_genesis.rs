//! S4 investigation follow-up: F7's loud pool-exhaustion diagnostic.
//!
//! This node's first task was determining whether the raw/non-manifest
//! bootstrap loops in `reindex()` (`cyphr-storage/src/engine/mod.rs`) ever
//! need to correlate MULTIPLE wire-visible genesis-marker cozies into one
//! shared explicit multi-key genesis. That investigation (see the node's
//! completion report) found no such scenario anywhere in this codebase:
//! the only real, production-used explicit multi-key genesis pattern
//! (`rs/cyphr-cli`'s `Genesis::Explicit`, exercised end-to-end by
//! `f40_multi_key_genesis.rs`) supplies genesis membership entirely
//! out-of-band (a caller parameter / local keystore record), never as
//! wire-visible key-introducing cozies -- so there is nothing here to
//! correlate. This file therefore covers only this node's other,
//! unconditional deliverable: an incomplete commit found during raw
//! reindex (mutation cozies present, no finalizer at the target
//! timestamp) must log loudly instead of silently vanishing.

use std::sync::{Arc, Mutex};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::StateDigest;
use cyphr_storage::blob::{BlobStore, MemoryBlobStore};
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::MemoryIndexer;

fn load_golden(category: &str, name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/golden")
        .join(category)
        .join(format!("{name}.json"));
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {path:?}: {e}"))
}

fn golden_key_to_domain(gk: &serde_json::Value) -> cyphr::Key {
    let alg = gk["alg"].as_str().unwrap();
    let pub_b64 = gk["pub"].as_str().unwrap();
    let tmb_b64 = gk["tmb"].as_str().unwrap();
    let pub_bytes = Base64UrlUnpadded::decode_vec(pub_b64).unwrap();
    let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb_b64).unwrap();
    cyphr::Key {
        alg: alg.to_string(),
        tmb: coz::Thumbprint::from_bytes(tmb_bytes),
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

/// Extracts just the `message` field text from a `tracing` event, ignoring
/// every other field -- all this test needs to assert on.
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

/// Minimal `tracing::Subscriber` that records every WARN-or-more-severe
/// event's message into a shared buffer, so a test can assert on exactly
/// what was logged instead of only on the return value. Span-related
/// methods are no-ops: `reindex`'s `#[tracing::instrument]` opens a span,
/// but this test only cares about event messages, not span structure.
///
/// Hand-rolled rather than `tracing_subscriber::fmt`'s `MakeWriter`
/// pattern: that would need `tracing-subscriber` as a dev-dependency,
/// outside this node's file surface (`Cargo.toml` isn't in it).
#[derive(Clone, Default)]
struct CapturingSubscriber {
    messages: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        self.messages.lock().unwrap().push(visitor.0);
    }

    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Run `body` with a `tracing` subscriber installed that captures every
/// WARN-or-more-severe event's message into a `String`, returned alongside
/// `body`'s own result.
async fn with_captured_logs<F, Fut, T>(body: F) -> (T, String)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let subscriber = CapturingSubscriber::default();
    let messages = subscriber.messages.clone();

    let guard = tracing::subscriber::set_default(subscriber);
    let result = body().await;
    drop(guard);

    let captured = messages.lock().unwrap().join("\n");
    (result, captured)
}

/// F7: an incomplete commit (mutation cozies present, no `commit/create`
/// finalizer at the target timestamp) currently breaks out of reindex's
/// pool-processing loop with no trace at all. Silently dropping raw,
/// unmanifested content on the floor during a recovery pass is exactly
/// the kind of event an operator must be able to see -- this reindex runs
/// on every server startup, so an operator watching logs has no other
/// window into it.
#[tokio::test]
async fn incomplete_commit_logs_loudly_instead_of_vanishing_silently() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_key = &fixture["genesis_keys"][0];
    let key = golden_key_to_domain(genesis_key);

    let temp_principal = cyphr::Principal::implicit(key).unwrap();
    let pr_bytes = temp_principal
        .pr()
        .as_multihash()
        .get(cyphr::state::HashAlg::Sha256)
        .unwrap();
    let principal_id = format!("SHA-256:{}", Base64UrlUnpadded::encode_string(pr_bytes));

    let blob_store = MemoryBlobStore::new();
    let indexer = MemoryIndexer::new();
    let engine = StorageEngine::new(blob_store.clone(), indexer);

    // Seed a raw, unmanifested genesis marker directly into the blob
    // store, bypassing ingest_commit/submit_commit entirely -- this is
    // the raw/legacy-content scenario the mock-genesis bootstrap loop
    // exists to serve.
    let genesis_coz_json = serde_json::json!({
        "pay": {
            "typ": "cyphr.me/cyphr/key/create",
            "now": 1_000_000i64,
            "pre": "",
            "tmb": genesis_key["tmb"].as_str().unwrap(),
            "alg": genesis_key["alg"].as_str().unwrap(),
        },
        "sig": "mock-sig",
        "key": genesis_key,
    });
    blob_store
        .put(&serde_json::to_vec(&genesis_coz_json).unwrap())
        .await
        .unwrap();

    // Seed a raw mutation cozy (principal/delete: a transaction typ that
    // needs no embedded key material) at a LATER timestamp with no
    // accompanying commit/create at that same timestamp -- an incomplete/
    // crashed commit: mutation content durably present, finalizer never
    // arrived.
    let incomplete_now = 2_000_000i64;
    let mutation_coz_json = serde_json::json!({
        "pay": {
            "typ": "cyphr.me/cyphr/principal/delete",
            "now": incomplete_now,
            "tmb": genesis_key["tmb"].as_str().unwrap(),
            "alg": genesis_key["alg"].as_str().unwrap(),
        },
        "sig": "mock-sig",
    });
    blob_store
        .put(&serde_json::to_vec(&mutation_coz_json).unwrap())
        .await
        .unwrap();

    let (result, logs) =
        with_captured_logs(|| async { engine.reindex(&[], false).await }).await;

    result.expect(
        "an incomplete commit must not fail reindex outright -- its raw \
         content stays harmlessly unindexed until a finalizer arrives",
    );

    assert!(
        logs.contains(&principal_id) && logs.contains(&incomplete_now.to_string()),
        "expected a loud diagnostic naming the stalled principal and \
         timestamp, got: {logs:?}"
    );
}
