//! One signed commit has one identity at the engine seam. The signed
//! `arrow` fixes the TMR, not how the cozies are grouped into transactions
//! (SPEC.md 494-497, 587-590), so a store that admits a regrouped form
//! gives the same signed commit a second commit id, and two holders that
//! see the forms in different orders end at different PRs.

#![recursion_limit = "256"]

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::MemoryIndexer;

const NOW: i64 = 1_700_300_000;

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

fn pool() -> test_fixtures::Pool {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool.toml")
}

struct Chain {
    id: String,
    genesis: Genesis,
    g: WireBundle,
    /// One commit of two nonces, each its own transaction.
    honest: WireBundle,
}

impl Chain {
    async fn new() -> Self {
        let pool = pool();
        let golden = pool.get("golden").expect("golden");
        let key_a = pool.get("key_a").expect("key_a").key().expect("key_a");
        let mut p = cyphr::Principal::implicit(golden.key().expect("golden"))
            .await
            .expect("implicit");
        let g = test_fixtures::bundle::genesis_bundle(
            &mut p,
            golden,
            std::slice::from_ref(&key_a),
            NOW,
        )
        .await
        .expect("genesis");
        let id = test_fixtures::bundle::genesis_id(&g).expect("genesis id");

        let prv = Base64UrlUnpadded::decode_vec(golden.prv.as_deref().expect("prv")).expect("prv");
        let pubb = Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("pub");
        let tmb = golden.compute_tmb().expect("tmb");
        let mut scope = p.begin_commit();
        for i in 0u8..2 {
            let pay = serde_json::to_vec(&serde_json::json!({
                "alg": golden.alg, "id": format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[i + 1; 32])),
                "now": NOW + 10, "tmb": tmb.to_b64(), "typ": "cyphr.me/cyphr/nonce/create"
            }))
            .expect("pay");
            let (sig, cad) = coz::sign_json(&pay, &golden.alg, &prv, &pubb).expect("sign");
            let czd = coz::czd_for_alg(&cad, &sig, &golden.alg).expect("czd");
            scope
                .verify_and_apply(&pay, &sig, czd, None)
                .expect("nonce");
        }
        scope
            .finalize_with_software(
                &golden.software_signer().expect("signer"),
                NOW + 11,
                "cyphr.me",
            )
            .await
            .expect("commit");
        Self {
            id,
            genesis: Genesis::Disclosed(vec![golden.key().expect("golden"), key_a]),
            g,
            honest: test_fixtures::bundle::last_commit_bundle(&p).expect("bundle"),
        }
    }

    /// `[[n1], [n2], [commit]]` regrouped as `[[n1, n2], [commit]]`.
    fn regrouped(&self) -> WireBundle {
        let mut w = self.honest.clone();
        let second = w.txs.remove(1);
        w.txs[0].extend(second);
        w
    }

    /// A store holding the genesis commit.
    async fn holder(&self) -> Engine {
        let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        self.push(&e, &self.g).await.expect("genesis admitted");
        e
    }

    async fn push(&self, e: &Engine, bundle: &WireBundle) -> Result<String, String> {
        e.submit_commit(&self.id, Some(self.genesis.clone()), bundle)
            .await
            .map(|r| r.tip.expect("tip").commit_id)
            .map_err(|e| e.to_string())
    }

    async fn pr(&self, e: &Engine) -> Option<String> {
        e.get_tip(&self.id).await.expect("tip").map(|t| t.pr)
    }
}

// Catches: an engine that stores the regrouped form of a signed commit that a holder
// of the honest form also stores, so one arrow reaches two commit ids.
#[tokio::test]
async fn fresh_holder_refuses_the_regrouped_form_and_admits_the_honest_one() {
    let c = Chain::new().await;
    let e = c.holder().await;
    let before = c.pr(&e).await;
    assert!(
        c.push(&e, &c.regrouped()).await.is_err(),
        "the regrouped form was admitted"
    );
    assert_eq!(c.pr(&e).await, before, "a refusal left the store changed");
    c.push(&e, &c.honest).await.expect("the honest form");
}

// Catches: holders that disagree on the PR of one signed commit depending on which
// grouping reached them first.
#[tokio::test]
async fn holders_fed_either_order_end_at_one_pr() {
    let c = Chain::new().await;
    let (a, b) = (c.holder().await, c.holder().await);
    let _ = c.push(&a, &c.regrouped()).await;
    let _ = c.push(&a, &c.honest).await;
    let _ = c.push(&b, &c.honest).await;
    let _ = c.push(&b, &c.regrouped()).await;
    let (pa, pb) = (c.pr(&a).await, c.pr(&b).await);
    let genesis_only = c.pr(&c.holder().await).await;
    assert_ne!(pa, genesis_only, "the honest form was not admitted by A");
    assert_eq!(pa, pb, "two holders ended at different PRs");
}
