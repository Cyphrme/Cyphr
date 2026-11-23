//! Reads that must not re-apply stored commits: each asks the engine for a
//! fact the index or the key history already holds, and the replay counter
//! ([`StorageEngine::commits_replayed`]) must not move.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::{MemoryIndexer, TipState};

mod common;

use common::*;

/// A resync PoP by `signer` at `now` over the PR `id`.
fn pop_over(signer: &Kp, id: &str, now: i64) -> serde_json::Value {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg, "id": id, "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/resync/create"
    }))
    .expect("pay");
    let (sig, _) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    })
}

/// After a restart (a fresh engine over the same blobs and logs, so the
/// roots memo is empty), the roots of a superseded commit are the ones
/// recorded at admission, read from the index; no stored commit is
/// re-applied. The resync arm is a forward guard: a resync naming an
/// earlier chain commit reads its signer from the key history, and the
/// counter does not move.
#[tokio::test]
async fn earlier_commit_reads_cost_no_replay() {
    let rig = Rig::new(4).await;
    // Durable logs and a kept state, as a server runs: an in-memory engine
    // keeps nothing and replays on every read, whatever the read asks.
    let dir = tempfile::tempdir().expect("tempdir");
    let db = fjall::Database::builder(dir.path().join("db"))
        .open()
        .expect("open db");
    let blobs = MemoryBlobStore::new();
    let open = || {
        StorageEngine::with_log_factory(
            blobs.clone(),
            MemoryIndexer::new(),
            cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs"),
        )
        .with_kept_states(4)
    };
    let first = open();
    let mut recorded = Vec::new();
    for s in &rig.states[..=3] {
        let admitted = first
            .submit_commit(&rig.id, Some(rig.genesis.clone()), &last(s))
            .await
            .expect("canonical chain");
        recorded.push(admitted.tip.expect("tip"));
    }

    let e = open();
    // Healed first: rebuilding the index from the blobs is not a read.
    let live = e.get_tip(&rig.id).await.expect("tip").expect("stored");
    assert_eq!(live.commit_count, 4);
    let before = e.commits_replayed();

    let at = &recorded[1];
    let tip = TipState {
        principal_id: rig.id.clone(),
        pr: at.pr.clone(),
        sr: at.sr.clone(),
        ar: at.ar.clone(),
        cr: at.cr.clone(),
        commit_id: at.commit_id.clone(),
        commit_count: 2,
        last_updated: 0,
    };
    let roots = e
        .derive_roots_at(&tip)
        .await
        .expect("roots")
        .expect("the chain holds the commit");
    assert_eq!(
        (roots.pr, roots.sr, roots.ar, roots.cr),
        (at.pr.clone(), at.sr.clone(), at.ar.clone(), at.cr.clone()),
        "the roots recorded at admission"
    );
    assert_eq!(e.commits_replayed(), before, "roots: no commit re-applied");

    // On the engine that admitted the chain, whose state is kept: a cold
    // load after a restart replays by itself, whatever the resync asks.
    let warm = first.commits_replayed();
    let pop = pop_over(
        &rig.keys[0],
        &rig.states[1].pr_tagged().expect("pr"),
        NOW + 900,
    );
    first
        .submit_resync(&rig.id, &pop, &[])
        .await
        .expect("resync");
    assert_eq!(
        first.commits_replayed(),
        warm,
        "resync: no commit re-applied"
    );
}
