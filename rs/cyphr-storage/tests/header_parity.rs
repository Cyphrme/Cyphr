//! One header defect, one kind, on every path a coz can arrive by: a coz
//! whose pay lacks `tmb`, `now` or `typ` is refused as a malformed coz both
//! when it is pushed (`submit_commit`) and when a stored line carrying it is
//! replayed (`load_principal_from_commits`). The two used to disagree
//! (`MalformedBlob`, a 400 on the wire, against a bare protocol error), so a
//! consumer mapping errors to statuses or exit codes saw two kinds for one
//! defect.
//!
//! This also backs that a coz missing `typ` is never silently taken for a
//! data action: the push and the replay both stop it at the header parse.

use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::{EngineError, StorageEngine, genesis_principal_id};
use cyphr_storage::index::MemoryIndexer;
use cyphr_storage::{CommitEntry, Genesis, LoadError, load_principal_from_commits};
use proptest::prelude::*;

/// A 64-byte signature of zeros, base64url: its value is never checked,
/// since the header parse refuses the coz first.
const SIG: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn genesis() -> Genesis {
    Genesis::Implicit(
        cyphr::Key::from_pub_key("ES256", vec![0xAA; 64])
            .expect("dummy key")
            .with_first_seen(1000),
    )
}

/// A coz whose pay holds every header member except `missing`.
fn coz_without(genesis: &Genesis, missing: &[&str]) -> serde_json::Value {
    let tmb = genesis.key().expect("genesis key").tmb().to_b64();
    let mut pay = serde_json::json!({
        "alg": "ES256",
        "tmb": tmb,
        "now": 1000,
        "typ": "cyphr.me/comment/create",
    });
    for member in missing {
        pay.as_object_mut().expect("pay").remove(*member);
    }
    serde_json::json!({ "pay": pay, "sig": SIG })
}

proptest! {
    /// Claim: for any non-empty set of missing header members, the push
    /// refuses the coz as `MalformedBlob` and the replay as
    /// `LoadError::MalformedBlob`.
    ///
    /// Turns red if either path maps the defect to another kind (the replay
    /// to a bare protocol error, the push to a protocol one), or accepts it.
    /// Property test over the engine and the replay: yes.
    #[test]
    fn a_missing_header_member_is_malformed_on_push_and_on_replay(
        missing in proptest::sample::subsequence(vec!["tmb", "now", "typ"], 1..=3),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let genesis = genesis();
            let coz = coz_without(&genesis, &missing);

            let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
            let id = genesis_principal_id(&genesis).expect("id");
            let pushed = engine
                .submit_commit(
                    &id,
                    Some(genesis.clone()),
                    &cyphr::replay::WireBundle::actions(vec![
                        serde_json::to_vec(&coz).expect("coz"),
                    ]),
                )
                .await;
            prop_assert!(
                matches!(pushed, Err(EngineError::MalformedBlob(_))),
                "push, missing {missing:?}: {pushed:?}"
            );

            let line = CommitEntry {
                actions: vec![coz],
                ..CommitEntry::default()
            };
            let replayed = load_principal_from_commits(genesis, &[line]).await;
            prop_assert!(
                matches!(replayed, Err(LoadError::MalformedBlob { commit: 0, coz: Some(0), .. })),
                "replay, missing {missing:?}: {replayed:?}"
            );
            Ok(())
        })?;
    }
}
