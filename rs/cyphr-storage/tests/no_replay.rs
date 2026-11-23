//! Reads that must not re-apply stored commits: each asks the engine for a
//! fact the index or the key history already holds, and the replay counter
//! ([`StorageEngine::commits_replayed`]) must not move.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::{Indexer, MemoryIndexer, TipState};

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

/// The roots of an earlier commit come from the index, as the chain's own
/// PR says, and a resync naming an earlier commit of the chain reads its
/// signer from the key history.
#[tokio::test]
async fn earlier_commit_reads_cost_no_replay() {
    let rig = Rig::new(4).await;
    // Durable logs and a kept state, as a server runs: an in-memory engine
    // keeps nothing and replays on every read, whatever the read asks.
    let dir = tempfile::tempdir().expect("tempdir");
    let db = fjall::Database::builder(dir.path().join("db"))
        .open()
        .expect("open db");
    let e = StorageEngine::with_log_factory(
        MemoryBlobStore::new(),
        MemoryIndexer::new(),
        cyphr_blob_fjall::EmlLogs::new(db).expect("logs"),
    )
    .with_kept_states(4);
    for s in &rig.states[..=3] {
        e.submit_commit(&rig.id, Some(rig.genesis.clone()), &last(s))
            .await
            .expect("canonical chain");
    }
    let before = e.commits_replayed();

    let stored = e
        .indexer()
        .get_commit_chain(&rig.id, Some(1), Some(1))
        .await
        .expect("chain");
    let at = &stored[0];
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
    assert_eq!(roots.pr, rig.states[1].pr_tagged().expect("pr"));

    let pop = pop_over(
        &rig.keys[0],
        &rig.states[1].pr_tagged().expect("pr"),
        NOW + 900,
    );
    e.submit_resync(&rig.id, &pop, &[]).await.expect("resync");

    assert_eq!(e.commits_replayed(), before, "no stored commit re-applied");
}
