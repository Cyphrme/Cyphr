//! End-to-end integration tests for the cyphr-server MSS API.
//!
//! These tests exercise the full HTTP stack — request parsing, route dispatch,
//! engine orchestration, and response serialization — without binding a TCP
//! port.  Uses `tower::ServiceExt::oneshot` against `build_router`.
//!
//! ## Bootstrap strategy
//!
//! Golden fixtures use a pre-existing genesis key that signs commits but
//! isn't embedded in the commit blobs (the embedded `"key"` field is the
//! key being *added*, not the genesis key).  This means the HTTP `/push`
//! endpoint's genesis auto-detection cannot bootstrap from raw fixture
//! data alone.
//!
//! Tests therefore bootstrap principals via the engine API (which accepts
//! explicit genesis), then exercise the HTTP transport layer for reads and
//! error paths.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::build_router;

mod common;

use common::{
    bootstrap_principal, build_raw_blobs, envelope_payload, get_json, keyless_server, load_golden,
    load_pool, make_genesis, post_json, sign_key_create_commit,
};

// ========================================================================
// Tests — read path (bootstrapped via engine, queried via HTTP)
// ========================================================================

/// GET /tip for a bootstrapped principal → 200 with correct state.
#[tokio::test]
async fn tip_after_bootstrap() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let principal_id = "e2e-tip";

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
    assert_eq!(tip["principal_id"], principal_id);

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
    let principal_id = "e2e-patch";

    let (state, _dir) = keyless_server();
    bootstrap_principal(&state, principal_id, &fixture).await;

    let app = build_router(state);

    let (status, envelope) = get_json(app, &format!("/patch?pr={principal_id}")).await;
    assert_eq!(status, StatusCode::OK);
    let patch = envelope_payload(&envelope);

    assert_eq!(patch["principal_id"], principal_id);
    let entries = patch["entries"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        commits.len(),
        "patch should have one entry per commit"
    );

    // Each entry should have base64url-encoded blobs.
    for entry in entries {
        let blobs = entry["blobs"].as_array().unwrap();
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
    let principal_id = "e2e-patch-range";

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
        "blobs": [],
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
        "blobs": ["!!!not-base64!!!"],
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
        "blobs": [garbage],
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
    let principal_id = "e2e-concurrent-same-principal";

    let (state, _dir) = keyless_server();
    let pool = load_pool();

    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let commit0_blobs = build_raw_blobs(&commits[0]);
    let commit0_slices: Vec<&[u8]> = commit0_blobs.iter().map(|b| b.as_slice()).collect();
    state
        .engine
        .submit_commit(
            principal_id,
            Some(make_genesis(genesis_keys)),
            &commit0_slices,
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
        let genesis_keys = genesis_keys.clone();
        let fresh_principal = cyphr_storage::load_principal_from_commits(
            make_genesis(&genesis_keys),
            std::slice::from_ref(&commit0_entry),
        )
        .expect("replay commit 0 onto a fresh principal");
        let variant_blobs = sign_key_create_commit(
            fresh_principal,
            &pool,
            "golden",
            new_key_name,
            1_700_000_100,
        );
        handles.push(tokio::spawn(async move {
            let variant_slices: Vec<&[u8]> = variant_blobs.iter().map(|b| b.as_slice()).collect();
            state
                .engine
                .submit_commit(
                    "e2e-concurrent-same-principal",
                    Some(make_genesis(&genesis_keys)),
                    &variant_slices,
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

/// M concurrent submissions for M DISTINCT principals must not interfere
/// with each other, and should complete meaningfully faster than the same
/// work forced sequential -- proving the per-principal lock scales with the
/// number of distinct principals rather than degrading into a single global
/// choke point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_commit_concurrent_different_principals_do_not_block() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    let m = 6;
    let principal_ids: Vec<String> = (0..m)
        .map(|i| format!("e2e-concurrent-distinct-{i}"))
        .collect();

    let (state, _dir) = keyless_server();
    for pid in &principal_ids {
        let commit0_blobs = build_raw_blobs(&commits[0]);
        let commit0_slices: Vec<&[u8]> = commit0_blobs.iter().map(|b| b.as_slice()).collect();
        state
            .engine
            .submit_commit(pid, Some(make_genesis(genesis_keys)), &commit0_slices)
            .await
            .expect("bootstrap commit 0 failed");
    }

    // Concurrent: submit commit 1 for every distinct principal at once.
    let concurrent_start = std::time::Instant::now();
    let mut handles = Vec::with_capacity(m);
    for pid in principal_ids.clone() {
        let state = state.clone();
        let genesis_keys = genesis_keys.clone();
        let commit1_blobs = build_raw_blobs(&commits[1]);
        handles.push(tokio::spawn(async move {
            let commit1_slices: Vec<&[u8]> = commit1_blobs.iter().map(|b| b.as_slice()).collect();
            state
                .engine
                .submit_commit(&pid, Some(make_genesis(&genesis_keys)), &commit1_slices)
                .await
        }));
    }
    for handle in handles {
        handle
            .await
            .unwrap()
            .expect("each distinct principal's submission should succeed independently");
    }
    let concurrent_elapsed = concurrent_start.elapsed();

    // Sequential baseline: the same M submissions, one at a time (commit 2,
    // so it isn't rejected as an already-applied duplicate of commit 1).
    let sequential_start = std::time::Instant::now();
    for pid in &principal_ids {
        let commit2_blobs = build_raw_blobs(&commits[2]);
        let commit2_slices: Vec<&[u8]> = commit2_blobs.iter().map(|b| b.as_slice()).collect();
        state
            .engine
            .submit_commit(pid, Some(make_genesis(genesis_keys)), &commit2_slices)
            .await
            .expect("sequential baseline submission should succeed");
    }
    let sequential_elapsed = sequential_start.elapsed();

    // Generous, qualitative margin (not a tight ratio) to avoid flaking
    // under CI scheduling noise: distinct principals genuinely running in
    // parallel should beat the same work forced one-at-a-time. A single
    // global lock masquerading as per-principal would make these roughly
    // equal instead.
    assert!(
        concurrent_elapsed < sequential_elapsed,
        "concurrent submissions for distinct principals ({concurrent_elapsed:?}) should be faster \
         than the same work forced sequential ({sequential_elapsed:?}) -- a global (not \
         per-principal) lock would make these roughly equal or concurrent slower"
    );
}

// ========================================================================
// Tests — HTTP happy path via genuine genesis auto-detection
// ========================================================================
//
// Unlike every test above (which bootstraps via the engine's explicit-genesis
// API and only exercises HTTP for reads/error paths -- golden fixtures don't
// embed genesis key material on wire blobs, see the module doc comment),
// this drives a brand new principal's first-ever commit through the real
// `POST /push` path end to end, including `resolve_genesis`'s genesis=None
// auto-detection (`rs/cyphr-storage/src/engine/mod.rs`).

/// A brand new principal's first-ever push -- a `key/create` adding a second
/// key, closed by `commit/create` -- lands over real HTTP with no explicit
/// genesis, is readable back via `/tip`, and its blobs round-trip via
/// `/patch`.
///
/// This is this system's actual wire contract for bootstrapping a new
/// principal: the closing `commit/create` cozy carries the genesis key in
/// its own `"key"` field (distinct from the `key/create` cozy's `"key"`,
/// which carries the *new* key being added) -- `resolve_genesis` scans for
/// exactly that (`genesis_from_raw_blobs`). Before that scan existed, this
/// exact scenario failed with 422 "unknown key" (F44): the new-principal
/// branch blindly read blob 0's `"key"` field, which is the new key, not
/// genesis.
#[tokio::test]
async fn push_new_principal_happy_path() {
    let pool = load_pool();
    let golden = pool.get("golden").expect("golden key in pool");
    let golden_key = cyphr::Key {
        alg: golden.alg.clone(),
        tmb: golden.compute_tmb().expect("golden tmb"),
        pub_key: Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("golden pub b64"),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    };

    let principal = cyphr::Principal::implicit(golden_key.clone()).expect("implicit genesis");
    let now = 1_700_000_000;
    let mut blobs = sign_key_create_commit(principal, &pool, "golden", "key_a", now);

    // Embed the genesis key on the closing commit/create cozy -- the wire
    // contract `resolve_genesis` requires for a brand new principal.
    let closing_idx = blobs.len() - 1;
    let mut closing: serde_json::Value = serde_json::from_slice(&blobs[closing_idx]).unwrap();
    assert_eq!(
        closing["pay"]["typ"], "cyphr.me/cyphr/commit/create",
        "expected the last cozy in the bundle to be the closing commit/create"
    );
    closing.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!({
            "alg": golden_key.alg,
            "pub": golden.pub_key,
            "tmb": Base64UrlUnpadded::encode_string(golden_key.tmb.as_bytes()),
        }),
    );
    blobs[closing_idx] = serde_json::to_vec(&closing).unwrap();

    let principal_id = "http-happy-path";
    let body = serde_json::json!({
        "principal_id": principal_id,
        "blobs": blobs
            .iter()
            .map(|b| Base64UrlUnpadded::encode_string(b))
            .collect::<Vec<_>>(),
    })
    .to_string();

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
    assert_eq!(tip["principal_id"], principal_id);
    assert_eq!(tip["commit_count"].as_u64().unwrap(), 1);

    let (patch_status, patch_envelope) = get_json(app, &format!("/patch?pr={principal_id}")).await;
    assert_eq!(patch_status, StatusCode::OK);
    let patch = envelope_payload(&patch_envelope);
    let entries = patch["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "one commit was pushed");
    assert_eq!(
        entries[0]["blobs"].as_array().unwrap().len(),
        blobs.len(),
        "patch should return every blob from the pushed commit"
    );
}
