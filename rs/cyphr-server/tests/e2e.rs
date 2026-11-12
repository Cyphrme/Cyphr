//! End-to-end integration tests for the cyphr-server MSS API.
//!
//! These tests exercise the full HTTP stack — request parsing, route dispatch,
//! engine orchestration, and response serialization — without binding a TCP
//! port.  Uses `tower::ServiceExt::oneshot` against `build_router`.
//!
//! ## Bootstrap strategy
//!
//! Most tests bootstrap golden-fixture principals via the engine API
//! (which accepts an explicit genesis), then exercise the HTTP transport
//! layer for reads and error paths. `push_new_principal_happy_path` drives
//! a genesis commit through `/push` itself.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::build_router;

mod common;

use common::{
    bootstrap_principal, build_bundle, build_genesis_push_body, envelope_payload,
    fixture_principal_id, get_json, golden_principal_id, implicit_principal_id, keyless_server,
    load_golden, load_pool, make_genesis, post_json, sign_key_create_commit,
};

// ========================================================================
// Tests — read path (bootstrapped via engine, queried via HTTP)
// ========================================================================

/// GET /tip for a bootstrapped principal → 200 with correct state.
#[tokio::test]
async fn tip_after_bootstrap() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let principal_id = fixture_principal_id(&fixture);
    let principal_id = principal_id.as_str();

    let (state, _dir) = keyless_server();
    bootstrap_principal(&state, principal_id, &fixture).await;

    let app = build_router(state.clone());

    let (status, envelope) = get_json(app, &format!("/tip?pr={principal_id}")).await;
    assert_eq!(status, StatusCode::OK);
    let tip = envelope_payload(&envelope);

    let commits = fixture["commits"].as_array().unwrap();
    assert_eq!(
        tip["commit_count"].as_u64().unwrap(),
        commits.len() as u64,
        "tip commit_count should match number of submitted commits"
    );
    assert_eq!(
        tip["principal_id"],
        cyphr_storage::engine::bare_digest(principal_id),
        "the wire spelling of an id is its bare digest"
    );

    let engine_tip = state
        .engine
        .get_tip(principal_id)
        .await
        .unwrap()
        .expect("tip exists");
    assert_eq!(
        tip["cr"].as_str().expect("tip payload carries cr"),
        engine_tip.cr,
        "tip payload's cr must match the engine's TipState.cr exactly ([envelope-r-cr])"
    );
}

/// GET /patch for a bootstrapped principal → 200 with correct entries.
#[tokio::test]
async fn patch_after_bootstrap() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let principal_id = fixture_principal_id(&fixture);
    let principal_id = principal_id.as_str();

    let (state, _dir) = keyless_server();
    bootstrap_principal(&state, principal_id, &fixture).await;

    let app = build_router(state);

    let (status, envelope) = get_json(app, &format!("/patch?pr={principal_id}")).await;
    assert_eq!(status, StatusCode::OK);
    let patch = envelope_payload(&envelope);

    assert_eq!(
        patch["principal_id"],
        cyphr_storage::engine::bare_digest(principal_id),
        "the wire spelling of an id is its bare digest"
    );
    let entries = patch["entries"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        commits.len(),
        "patch should have one entry per commit"
    );

    // Each entry should have base64url-encoded blobs.
    for entry in entries {
        let blobs = common::wire_cozies(entry);
        assert!(!blobs.is_empty(), "each commit entry should contain blobs");
        // Verify each blob is valid base64url.
        for blob_str in blobs {
            let s = blob_str.as_str().unwrap();
            Base64UrlUnpadded::decode_vec(s)
                .unwrap_or_else(|_| panic!("blob should be valid base64url: {s}"));
        }
    }
}

/// GET /patch with range parameters → returns subset of commits.
#[tokio::test]
async fn patch_with_range() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let principal_id = fixture_principal_id(&fixture);
    let principal_id = principal_id.as_str();

    let (state, _dir) = keyless_server();
    bootstrap_principal(&state, principal_id, &fixture).await;

    let app = build_router(state);

    // Request only commit 0: `from` omitted (genesis has no anchor to
    // resume from) and `to=0` bounds the response to it. The pre-N4 fixture
    // used `from=0` under sequence-anchor semantics; `0` is no longer a
    // valid digest anchor (Zami #140: sequence is metadata, not a digest).
    let (status, envelope) = get_json(app, &format!("/patch?pr={principal_id}&to=0")).await;
    assert_eq!(status, StatusCode::OK);
    let patch = envelope_payload(&envelope);

    let entries = patch["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "range 0..0 should return exactly one commit"
    );
    assert_eq!(entries[0]["sequence"].as_u64().unwrap(), 0);
}

// ========================================================================
// Tests — error paths (no bootstrap needed)
// ========================================================================

/// GET /tip for unknown principal → 404.
#[tokio::test]
async fn tip_unknown_principal() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    let (status, _) = get_json(app, "/tip?pr=nonexistent").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// GET /e/{bad-digest} → 400 (malformed digest parse failure).
///
/// `entity`'s handler (`rs/cyphr-server/src/routes.rs`) always maps a
/// `TaggedDigest` parse failure to `AppError::bad_request` -- 404 only
/// arises later, for a well-formed digest that isn't found in the store.
#[tokio::test]
async fn entity_bad_digest() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    let (status, _) = get_json(app, "/e/not-a-valid-digest").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// POST /push with empty blob list → 400.
#[tokio::test]
async fn push_empty_blobs_rejected() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let body = serde_json::json!({
        "principal_id": "test",
        "txs": [],
    })
    .to_string();

    let (status, _) = post_json(app, "/push", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// POST /push with invalid base64url blob → 400.
#[tokio::test]
async fn push_bad_base64_rejected() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let body = serde_json::json!({
        "principal_id": "test",
        "txs": [["!!!not-base64!!!"]],
    })
    .to_string();

    let (status, _) = post_json(app, "/push", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// POST /push with malformed JSON blob (valid base64, not JSON) → 400.
///
/// Whichever path rejects it first -- `resolve_genesis`'s new-principal
/// branch (`genesis_from_blob`) for this never-before-seen principal, or
/// `submit_commit`'s own per-blob JSON parse -- both raise
/// `EngineError::MalformedBlob`, which `AppError::engine`
/// (`rs/cyphr-server/src/error.rs`) always maps to 400, never 422 (422 is
/// reserved for a well-formed-JSON blob that fails protocol validation).
#[tokio::test]
async fn push_malformed_json_rejected() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let garbage = Base64UrlUnpadded::encode_string(b"not json at all");
    let body = serde_json::json!({
        "principal_id": "test",
        "txs": [[garbage]],
    })
    .to_string();

    let (status, _) = post_json(app, "/push", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ========================================================================
// Tests — write concurrency (per-principal serialization)
// ========================================================================
//
// These drive `StorageEngine::submit_commit` directly rather than through
// `POST /push`: HTTP's genesis auto-detection (`resolve_genesis`'s
// existing-principal branch) cannot recover the true signer for these
// multi-commit fixtures once the genesis key no longer reappears with an
// embedded `"key"` field in the first commit's blobs (the same pre-existing
// limitation `bootstrap_principal` above already works around). Calling the
// engine directly with explicit genesis sidesteps that unrelated limitation
// while still exercising the real lock and the real `EngineError` it
// produces. The HTTP-facing 409 mapping itself is verified separately
// (`rs/cyphr-server/src/error.rs`'s own tests) against that exact
// `EngineError`, so together these cover "hits the HTTP layer" per this
// node's acceptance criteria.

/// N concurrent submissions of independent, mutually-exclusive next commits
/// for the SAME principal (each adds a different new key, so none collide on
/// `DuplicateKey` -- only on the sequence slot itself): only one can
/// genuinely claim the next sequence slot. The rest, once serialized behind
/// the winner, find the principal's state already advanced past what their
/// own signed commit assumed -- a genuine write conflict (`CommitMismatch`),
/// not silent index corruption and not an undifferentiated backend error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_commit_concurrent_same_principal_serializes_and_conflicts() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let principal_id = fixture_principal_id(&fixture);
    let principal_id = principal_id.as_str();

    let (state, _dir) = keyless_server();
    let pool = load_pool();

    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let commit0_blobs = build_bundle(&commits[0]);
    state
        .engine
        .submit_commit(
            principal_id,
            Some(make_genesis(genesis_keys)),
            &commit0_blobs,
        )
        .await
        .expect("bootstrap commit 0 failed");

    // A CommitEntry matching commit 0, replayed fresh (via the library's own
    // replay path) for every variant below -- each variant needs its own
    // independent `Principal` (see `sign_key_create_commit`'s doc comment
    // for why a shared clone doesn't work), all starting from the identical
    // post-commit-0 state.
    let commit0_entry: cyphr_storage::CommitEntry =
        serde_json::from_value(commits[0].clone()).expect("commit 0 matches CommitEntry shape");

    // Race N independent, mutually-exclusive "add a new key" commits for the
    // same already-established principal.
    // "key_a" is excluded: commit 0 introduces it, so it would collide with
    // `DuplicateKey` rather than testing the sequence-slot race.
    let candidate_keys = [
        "key_b",
        "alice",
        "bob",
        "carol",
        "diana_es384",
        "eve_ed25519",
    ];
    let n = candidate_keys.len();
    let mut handles = Vec::with_capacity(n);
    for new_key_name in candidate_keys {
        let state = state.clone();
        let principal_id = principal_id.to_string();
        let genesis_keys = genesis_keys.clone();
        let fresh_principal = cyphr_storage::load_principal_from_commits(
            make_genesis(&genesis_keys),
            std::slice::from_ref(&commit0_entry),
        )
        .await
        .expect("replay commit 0 onto a fresh principal");
        let variant_blobs = sign_key_create_commit(
            fresh_principal,
            &pool,
            "golden",
            new_key_name,
            1_700_000_100,
        )
        .await;
        handles.push(tokio::spawn(async move {
            state
                .engine
                .submit_commit(
                    &principal_id,
                    Some(make_genesis(&genesis_keys)),
                    &variant_blobs,
                )
                .await
        }));
    }

    let mut succeeded = 0;
    let mut conflicts = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => succeeded += 1,
            Err(cyphr_storage::engine::EngineError::Protocol(cyphr::Error::CommitMismatch)) => {
                conflicts += 1
            },
            // All racers are signed by one key, so past its retention quota
            // a loser is refused as BranchLimit: still a typed refusal.
            Err(cyphr_storage::engine::EngineError::BranchLimit { .. }) => conflicts += 1,
            Err(other) => panic!("unexpected error for a racing submission: {other}"),
        }
    }

    assert_eq!(
        succeeded, 1,
        "exactly one concurrent submission should win the sequence slot"
    );
    assert_eq!(
        conflicts,
        n - 1,
        "every losing submission should get a genuine, typed CommitMismatch conflict -- not a \
         silent success and not an undifferentiated backend error"
    );

    // No lost/duplicated update: the tip shows exactly commit 0 + the one
    // winning commit 1 -- never more (corruption) or fewer (lost update).
    let tip = state
        .engine
        .get_tip(principal_id)
        .await
        .unwrap()
        .expect("principal should exist");
    assert_eq!(
        tip.commit_count, 2,
        "exactly 2 commits should be durably recorded: bootstrap + the one race winner"
    );
}

/// A write stalled mid-critical-section for one principal must not stop a
/// write for any DISTINCT principal -- the per-principal lock is not a
/// global choke point.
///
/// Deterministic, no timing comparison: the engine's storage factory is
/// called by `submit_commit` only AFTER it has taken the principal's write
/// lock, so parking that factory call for principal A parks A's submission
/// while it holds A's lock. With A parked, every other principal's
/// submission must still complete. Under a single global write lock those
/// submissions would wait on A forever; the timeout is only a liveness
/// bound that turns that hang into a failure, and is never reached when the
/// lock is genuinely per-principal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_commit_concurrent_different_principals_do_not_block() {
    use std::sync::{Arc, Condvar, Mutex};

    use cyphr_storage::engine::LogFactory;

    /// Parks the storage factory for one principal until released.
    #[derive(Default)]
    struct Gate {
        // (armed, entered, released)
        state: Mutex<(bool, bool, bool)>,
        cv: Condvar,
    }

    /// The durable logs, parking the open of `parked_id`'s log on `gate` while
    /// it is armed.
    struct GatedLogs {
        inner: cyphr_blob_fjall::EmlLogs,
        gate: Arc<Gate>,
        parked_id: String,
    }

    impl LogFactory<cyphr_blob_fjall::storage_fjall::FjallStorage> for GatedLogs {
        fn generation(&self, principal_id: &str) -> Result<u64, String> {
            self.inner.generation(principal_id)
        }

        fn open(
            &self,
            principal_id: &str,
            generation: u64,
        ) -> Result<cyphr_blob_fjall::storage_fjall::FjallStorage, String> {
            if principal_id.ends_with(self.parked_id.as_str()) {
                let mut s = self.gate.state.lock().unwrap();
                if s.0 {
                    s.1 = true;
                    self.gate.cv.notify_all();
                    while !s.2 {
                        s = self.gate.cv.wait(s).unwrap();
                    }
                }
            }
            self.inner.open(principal_id, generation)
        }

        fn retire_below(&self, principal_id: &str, generation: u64) -> Result<(), String> {
            self.inner.retire_below(principal_id, generation)
        }
    }

    let pool = load_pool();
    let signers = ["golden", "alice", "bob", "carol"];
    let new_key = |signer: &str| -> &'static str {
        ["key_a", "key_b", "alice", "bob"]
            .into_iter()
            .find(|k| *k != signer)
            .expect("a key other than the signer")
    };
    let genesis_of = |signer: &str| {
        let key = pool.get(signer).expect("signer key in pool");
        cyphr_storage::Genesis::Implicit(
            cyphr::Key::new(
                key.alg.clone(),
                key.compute_tmb().expect("signer tmb"),
                Base64UrlUnpadded::decode_vec(&key.pub_key).expect("signer pub b64"),
            )
            .expect("key binds its tmb"),
        )
    };
    let principal_ids: Vec<String> = signers
        .iter()
        .map(|s| implicit_principal_id(&pool, s))
        .collect();
    // Principal A is signers[0]; its storage-factory call is the one parked.
    // The engine canonicalises ids with an algorithm prefix the helper omits.
    let parked_id = principal_ids[0].clone();

    let dir = tempfile::tempdir().expect("temp dir");
    let db = fjall::Database::builder(dir.path().join("blobs"))
        .open()
        .expect("open fjall db");
    let gate = Arc::new(Gate::default());
    let engine = Arc::new(cyphr_storage::engine::StorageEngine::with_log_factory(
        cyphr_blob_fjall::FjallBlobStore::from_database(db.clone()).expect("blob store"),
        cyphr_index_fjall::FjallIndexer::open(&dir.path().join("index")).expect("indexer"),
        GatedLogs {
            inner: cyphr_blob_fjall::EmlLogs::new(db).expect("logs"),
            gate: gate.clone(),
            parked_id: parked_id.clone(),
        },
    ));

    // Bootstrap every principal (gate unarmed), then sign each one's next
    // commit against its current state.
    let mut commit1_blobs = Vec::with_capacity(signers.len());
    for (i, signer) in signers.iter().enumerate() {
        let mut principal = cyphr::Principal::implicit(match genesis_of(signer) {
            cyphr_storage::Genesis::Implicit(k) => k,
            _ => unreachable!("genesis_of builds implicit"),
        })
        .await
        .expect("implicit genesis");
        // Commit 0 is the principal's genesis commit (SPEC 5.1).
        let commit0 = test_fixtures::bundle::genesis_bundle(
            &mut principal,
            pool.get(signer).expect("signer key in pool"),
            &[],
            1_700_000_100,
        )
        .await
        .expect("genesis commit");
        engine
            .submit_commit(&principal_ids[i], Some(genesis_of(signer)), &commit0)
            .await
            .expect("bootstrap commit 0 failed");

        let loaded = engine
            .load_principal(&principal_ids[i], genesis_of(signer))
            .await
            .expect("load principal at its current state");
        // The engine's principal is storage-backed; replay its commits onto
        // an in-memory one, which is what the signing helper takes.
        let entries = cyphr_storage::export_commits(&loaded).expect("export commits");
        let fresh = cyphr_storage::load_principal_from_commits(genesis_of(signer), &entries)
            .await
            .expect("replay commits onto a fresh principal");
        commit1_blobs.push(
            sign_key_create_commit(fresh, &pool, signer, new_key(signer), 1_700_000_200).await,
        );
    }

    // Arm the gate and start A's submission; wait until it is parked inside
    // its critical section (holding A's lock).
    gate.state.lock().unwrap().0 = true;
    // Releases the park even if an assertion below panics: a parked worker
    // thread would otherwise hang the runtime's shutdown instead of failing.
    struct ReleaseOnDrop(Arc<Gate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let mut s = self.0.state.lock().unwrap_or_else(|p| p.into_inner());
            s.2 = true;
            self.0.cv.notify_all();
        }
    }
    let release = ReleaseOnDrop(gate.clone());
    let submit = |i: usize| {
        let engine = engine.clone();
        let pid = principal_ids[i].clone();
        let genesis = genesis_of(signers[i]);
        let blobs = commit1_blobs[i].clone();
        tokio::spawn(async move { engine.submit_commit(&pid, Some(genesis), &blobs).await })
    };
    let a = submit(0);
    {
        let gate = gate.clone();
        tokio::task::spawn_blocking(move || {
            let mut s = gate.state.lock().unwrap();
            while !s.1 {
                let (g, t) = gate
                    .cv
                    .wait_timeout(s, std::time::Duration::from_secs(20))
                    .unwrap();
                s = g;
                assert!(
                    !t.timed_out(),
                    "principal A never reached its storage factory"
                );
            }
        })
        .await
        .expect("wait for A to park");
    }

    // With A parked under its lock, every other principal must still land.
    for i in 1..signers.len() {
        tokio::time::timeout(std::time::Duration::from_secs(30), submit(i))
            .await
            .expect(
                "a distinct principal's submission is blocked behind principal A's write lock -- \
                 the lock is not per-principal",
            )
            .unwrap()
            .expect("each distinct principal's submission should succeed independently");
    }
    assert!(
        !a.is_finished(),
        "principal A must still be parked while the others complete"
    );

    // Release A; it must then complete normally.
    drop(release);
    a.await
        .unwrap()
        .expect("principal A's submission succeeds once released");
}

// ========================================================================
// Tests — HTTP happy path via genuine genesis auto-detection
// ========================================================================
//
// Unlike every test above (which bootstraps via the engine's explicit-genesis
// API and only exercises HTTP for reads/error paths), this drives a brand new principal's
// first-ever commit through the real `POST /push` path end to end, including `resolve_genesis`'s
// genesis=None auto-detection (`rs/cyphr-storage/src/engine/mod.rs`).

/// A brand new principal's first-ever push -- its genesis commit (SPEC
/// 5.1), in which the genesis key creates itself and a second key, then
/// signs the `principal/create` and `commit/create` -- lands over real HTTP
/// with no explicit genesis, is readable back via `/tip`, and its blobs
/// round-trip via `/patch`.
///
/// This is this system's actual wire contract for bootstrapping a new
/// principal: every `key/create` of the genesis commit carries its key in
/// its own `"key"` field, and `resolve_genesis` reads the genesis from
/// exactly those (`genesis_from_raw_blobs`), the first `key/create` being
/// the genesis key's own.
#[tokio::test]
async fn push_new_principal_happy_path() {
    let pool = load_pool();
    let now = 1_700_000_000;
    let principal_id = golden_principal_id(&pool).await;
    let body: serde_json::Value =
        serde_json::from_str(&build_genesis_push_body(&pool, &principal_id, now).await)
            .expect("push body");
    let blobs = common::wire_cozies(&body);
    let typs: Vec<String> = blobs
        .iter()
        .map(|b| {
            let bytes = Base64UrlUnpadded::decode_vec(b.as_str().expect("b64")).expect("blob");
            let coz: serde_json::Value = serde_json::from_slice(&bytes).expect("coz json");
            coz["pay"]["typ"].as_str().expect("typ").to_string()
        })
        .collect();
    assert_eq!(
        typs,
        [
            "cyphr.me/cyphr/key/create",
            "cyphr.me/cyphr/key/create",
            "cyphr.me/cyphr/principal/create",
            "cyphr.me/cyphr/commit/create",
        ],
        "the bundle is a genesis commit"
    );
    let body = body.to_string();
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    let (push_status, push_envelope) = post_json(app.clone(), "/push", body).await;
    assert_eq!(push_status, StatusCode::CREATED);
    let push_json = envelope_payload(&push_envelope);
    assert_eq!(
        push_json["blob_hashes"].as_array().unwrap().len(),
        blobs.len(),
        "response should report a hash for every submitted blob"
    );

    let (tip_status, tip_envelope) =
        get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    assert_eq!(tip_status, StatusCode::OK);
    let tip = envelope_payload(&tip_envelope);
    // `/tip` names the principal by its bare canonical digest.
    assert_eq!(
        tip["principal_id"],
        principal_id.split_once(':').expect("labelled PG").1
    );
    assert_eq!(tip["commit_count"].as_u64().unwrap(), 1);

    let (patch_status, patch_envelope) = get_json(app, &format!("/patch?pr={principal_id}")).await;
    assert_eq!(patch_status, StatusCode::OK);
    let patch = envelope_payload(&patch_envelope);
    let entries = patch["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "one commit was pushed");
    assert_eq!(
        common::wire_cozies(&entries[0]).len(),
        blobs.len(),
        "patch should return every blob from the pushed commit"
    );
}
