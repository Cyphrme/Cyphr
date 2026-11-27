//! Transaction grouping end to end (SPEC be0663f 3.7.5, 4, 4.1, 4.6.2).
//!
//! A commit's `txs` is a list of transactions, each a list of cozies, and
//! `TX = MR(czd0, czd1?, ...)` is a leaf of TR (hence of the arrow, CR and
//! PR). The scenario is the SPEC 4 example: one `key/replace` transaction
//! signed by two keys (two cozies), one `key/create` transaction of one
//! coz, and the `commit/create`. It travels through every layer that
//! carries a bundle: push, the stored manifest, `/patch`, a following
//! client, a restarted server, export, import and replay.
//!
//! The bundles are built here as raw JSON from commits the core authored,
//! so the file states the wire shape it expects rather than borrowing it
//! from the code under test.

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::{Commit, Principal};
use cyphr_net::{ChannelBinding, ConnectError, Connector, PeerChain, Request};
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

mod common;

use common::{get_json, keyless_server, load_pool, post_json};

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";

fn typ(kind: &str) -> String {
    format!("{AUTHORITY}/cyphr/{kind}")
}

fn pool_key(name: &str) -> test_fixtures::PoolKey {
    load_pool().get(name).expect("pool key").clone()
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// One coz of a transaction: `signer` signs `kind` naming `target` by `id`.
#[derive(Clone)]
struct Coz<'a> {
    signer: &'a str,
    kind: &'a str,
    target: &'a str,
}

/// Author one commit of `txs` on `p` through the core: every coz of a
/// transaction is verified against the state the transaction meets, the
/// transaction is applied whole (`apply_tx`), and `closer` signs the
/// `commit/create`.
async fn author(p: &mut Principal, txs: &[Vec<Coz<'_>>], closer: &str) -> Result<(), cyphr::Error> {
    let mut scope = p.begin_commit();
    for tx in txs {
        let mut verified = Vec::new();
        for coz in tx {
            let signer = pool_key(coz.signer);
            let target = pool_key(coz.target);
            let pay = serde_json::to_vec(&json!({
                "alg": signer.alg,
                "id": target.compute_tmb_b64().expect("tmb"),
                "now": T,
                "tmb": signer.compute_tmb_b64().expect("tmb"),
                "typ": typ(coz.kind),
            }))
            .expect("pay");
            let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_deref().expect("prv")).unwrap();
            let pubk = Base64UrlUnpadded::decode_vec(&signer.pub_key).unwrap();
            let (sig, cad) = coz::sign_json(&pay, &signer.alg, &prv, &pubk).expect("sign");
            let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
            let introduces = cyphr::parsed_coz::typ::is_key_introducing(&typ(coz.kind));
            let new_key = introduces.then(|| target.key().expect("key").with_first_seen(T));
            verified.push(cyphr::parsed_coz::verify_coz(
                &pay,
                &sig,
                &signer.key().expect("key"),
                czd,
                new_key,
            )?);
        }
        scope.apply_tx(verified)?;
    }
    let closer = pool_key(closer).software_signer().expect("signer");
    scope.finalize_with_software(&closer, T, AUTHORITY).await?;
    Ok(())
}

/// The SPEC 4.6.2 wire form of `commit`, written out by hand: `txs` as a
/// list of transactions of base64url cozies, `keys` the keys introduced.
fn wire(commit: &Commit) -> Value {
    let txs: Vec<Vec<String>> = commit
        .transactions()
        .map(|tx| {
            tx.0.iter()
                .map(|c| b64(&serde_json::to_vec(c.raw()).expect("coz")))
                .collect()
        })
        .collect();
    let keys: Vec<Value> = commit
        .iter_all_cozies()
        .filter_map(|c| c.new_key())
        .map(|k| json!({"alg": k.alg(), "pub": b64(k.pub_key()), "tmb": k.tmb().to_b64()}))
        .collect();
    json!({"txs": txs, "keys": keys})
}

/// `wire` with every coz as a transaction of its own: the defect of a
/// layer that flattens the grouping.
fn flattened(bundle: &Value) -> Value {
    let txs: Vec<Value> = bundle["txs"]
        .as_array()
        .expect("txs")
        .iter()
        .flat_map(|tx| tx.as_array().expect("tx").iter().map(|c| json!([c])))
        .collect();
    json!({"txs": txs, "keys": bundle["keys"]})
}

fn push_body(principal_id: &cyphr::PrincipalGenesis, bundle: &Value) -> String {
    let mut body = bundle.clone();
    body["principal_id"] = principal_id.to_string().into();
    body.to_string()
}

/// The coz counts of a bundle's transactions, as served.
fn shape(bundle: &Value) -> Vec<usize> {
    bundle["txs"]
        .as_array()
        .map(|txs| {
            txs.iter()
                .map(|tx| tx.as_array().map_or(0, Vec::len))
                .collect()
        })
        .unwrap_or_default()
}

/// The commit's czds by transaction.
fn czds(commit: &Commit) -> Vec<Vec<Vec<u8>>> {
    commit
        .transactions()
        .map(|tx| tx.0.iter().map(|c| c.czd().as_bytes().to_vec()).collect())
        .collect()
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// A principal at `golden`'s single-key genesis commit, then a commit
/// adding `key_a`: the state the SPEC 4 example is signed on. Returns it
/// with the two commits' push bundles.
async fn two_key_principal() -> (Principal, cyphr::PrincipalGenesis, Vec<Value>) {
    let golden = pool_key("golden");
    let mut p = Principal::implicit(golden.key().expect("key"))
        .await
        .expect("implicit");
    p.commit_genesis(&golden.software_signer().unwrap(), &[], T, AUTHORITY)
        .await
        .expect("genesis commit");
    let pg = p.pg().expect("pg").clone();
    let genesis = wire(p.commits().last().unwrap());
    author(
        &mut p,
        &[vec![Coz {
            signer: "golden",
            kind: "key/create",
            target: "key_a",
        }]],
        "golden",
    )
    .await
    .expect("add key_a");
    let add = wire(p.commits().last().unwrap());
    (p, pg, vec![genesis, add])
}

/// The SPEC 4 example on `p`: `key/replace` signed by both keys (golden by
/// alice, key_a by bob) as one transaction, then `key/create` of carol by
/// alice, closed by alice. With `grouped` false the two replaces are two
/// transactions instead.
async fn spec_4_example(p: &mut Principal, grouped: bool) {
    let replace = |signer, target| Coz {
        signer,
        kind: "key/replace",
        target,
    };
    let create = vec![Coz {
        signer: "alice",
        kind: "key/create",
        target: "carol",
    }];
    let txs = if grouped {
        vec![
            vec![replace("golden", "alice"), replace("key_a", "bob")],
            create,
        ]
    } else {
        vec![
            vec![replace("golden", "alice")],
            vec![replace("key_a", "bob")],
            create,
        ]
    };
    author(p, &txs, "alice").await.expect("the example commits");
}

async fn push_all(app: &Router, pg: &cyphr::PrincipalGenesis, bundles: &[Value]) {
    for b in bundles {
        let (status, body) = post_json(app.clone(), "/push", push_body(pg, b)).await;
        assert_eq!(status, StatusCode::CREATED, "setup push refused: {body}");
    }
}

/// The carrier over the in-process router.
struct RouterConnector(Router);

impl Connector for RouterConnector {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let req = axum::http::Request::builder()
            .uri(&request.target)
            .body(axum::body::Body::empty())
            .map_err(|e| ConnectError::Unreachable(e.to_string()))?;
        let Ok(resp) = self.0.clone().oneshot(req).await;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ConnectError::Unreachable(e.to_string()))?
            .to_bytes();
        if !status.is_success() {
            return Err(ConnectError::NonSuccess(status.as_u16()));
        }
        Ok(bytes.to_vec())
    }
}

/// Claim: grouping is a hash input of TR, CR and PR (SPEC 3.7.5, 4.6.2),
/// and every layer that carries a bundle keeps it. The SPEC 4 example
/// pushed as one transaction of two cozies is accepted, its TR is
/// `MR(MR(czd0, czd1), czd2, czd3)` (SPEC 3.7.5: TR is the MR of every
/// transaction's TX in order, the commit transaction last; TX0 the two-coz
/// transaction), `/patch` serves it grouped
/// to a following client, a restarted server still serves it grouped (the
/// manifest records it), and export, import and replay reach the same PR.
/// The same pair pushed as two transactions is another commit with another
/// TR, and the grouped commit's cozies pushed flattened are refused (their
/// arrow binds the grouped TMR). Turns red if any layer flattens the
/// group. End-to-end scenario: yes.
#[tokio::test]
async fn grouped_transaction_end_to_end() {
    let (mut p, pg, setup) = two_key_principal().await;
    let mut split = p.fork().await.expect("fork");
    spec_4_example(&mut p, true).await;
    let commit = p.commits().last().unwrap().clone();
    let bundle = wire(&commit);
    assert_eq!(
        shape(&bundle),
        vec![2, 1, 1],
        "premise: the example's shape"
    );

    // The TR the grouping yields, from the czds alone.
    let c = czds(&commit);
    let tx0 = sha256(&[&c[0][0], &c[0][1]]);
    let expected_tr = format!("SHA-256:{}", b64(&sha256(&[&tx0, &c[1][0], &c[2][0]])));
    assert_eq!(
        commit.tr().0.tagged_first().unwrap().to_string(),
        expected_tr,
        "premise: the core's TR is the TX = MR(czd0, czd1) form"
    );

    let (state, dir) = keyless_server();
    let app = build_router(state.clone());
    push_all(&app, &pg, &setup).await;

    // A layer that flattens the group sends the cozies as single-coz
    // transactions: the arrow then does not bind them.
    let (status, _) = post_json(app.clone(), "/push", push_body(&pg, &flattened(&bundle))).await;
    assert!(
        status.is_client_error(),
        "the grouped commit's cozies pushed flattened must be refused, got {status}"
    );

    let (status, body) = post_json(app.clone(), "/push", push_body(&pg, &bundle)).await;
    assert_eq!(status, StatusCode::CREATED, "grouped push refused: {body}");
    assert_eq!(body["payload"]["commit_id"], json!(expected_tr), "push TR");

    // Served grouped, with the keys the commit introduced.
    let (_, patch) = get_json(app.clone(), &format!("/patch?pg={pg}")).await;
    let served = &patch["payload"]["entries"][2];
    assert_eq!(shape(served), vec![2, 1, 1], "patch shape: {served}");
    assert_eq!(served["keys"].as_array().map(Vec::len), Some(3), "keys");
    assert_eq!(served["commit_id"], json!(expected_tr));

    // A client following the server replays the grouped commit.
    let mut chain = PeerChain::pin(&pg, pool_key("golden").key().unwrap()).await;
    chain
        .follow(&RouterConnector(app.clone()))
        .await
        .expect("the client follows the grouped chain");
    let tip = chain.held_tip().expect("held tip");
    assert_eq!(tip.commits, 3);
    assert_eq!(tip.pr, p.pr_tagged().unwrap(), "client PR");

    // The manifest records the grouping: a restarted server reads it back.
    drop(app);
    let data_dir = state.config.data_dir.clone();
    drop(state);
    let restarted = Arc::new(
        AppState::new(ServerConfig {
            data_dir,
            ..Default::default()
        })
        .expect("reopen"),
    );
    let app = build_router(restarted.clone());
    let (_, patch) = get_json(app.clone(), &format!("/patch?pg={pg}")).await;
    assert_eq!(
        shape(&patch["payload"]["entries"][2]),
        vec![2, 1, 1],
        "the restarted server's patch shape"
    );

    // Replay from the store, export, import.
    let genesis = cyphr_storage::Genesis::Implicit(pool_key("golden").key().unwrap());
    let loaded = restarted
        .engine
        .load_principal(&pg, genesis.clone())
        .await
        .expect("replay from the store");
    assert_eq!(
        loaded.pr_tagged().unwrap(),
        p.pr_tagged().unwrap(),
        "replay PR"
    );
    let lines: Vec<Value> = cyphr_storage::export_commits(&loaded)
        .expect("export")
        .iter()
        .map(|l| serde_json::to_value(l).unwrap())
        .collect();
    assert_eq!(
        shape(&lines[2]),
        vec![2, 1, 1],
        "export shape: {}",
        lines[2]
    );
    let entries: Vec<cyphr_storage::CommitEntry> = lines
        .into_iter()
        .map(|l| serde_json::from_value(l).expect("a line reads back"))
        .collect();
    let imported = cyphr_storage::load_principal_from_commits(genesis, &entries)
        .await
        .expect("import");
    assert_eq!(
        imported.pr_tagged().unwrap(),
        p.pr_tagged().unwrap(),
        "import PR"
    );

    // The same pair as two transactions is another commit.
    spec_4_example(&mut split, false).await;
    let split_bundle = wire(split.commits().last().unwrap());
    assert_eq!(shape(&split_bundle), vec![1, 1, 1, 1]);
    let (other, _dir2) = keyless_server();
    let other_app = build_router(other);
    push_all(&other_app, &pg, &setup).await;
    let (status, body) = post_json(other_app, "/push", push_body(&pg, &split_bundle)).await;
    assert_eq!(status, StatusCode::CREATED, "split push refused: {body}");
    assert_ne!(
        body["payload"]["commit_id"],
        json!(expected_tr),
        "two transactions must give another TR"
    );
    assert_ne!(
        split.pr_tagged().unwrap(),
        p.pr_tagged().unwrap(),
        "and another PR"
    );
    drop(dir);
}

/// Claim: SPEC 4.1 "All cozies for a particular transaction contain an
/// identical `typ`" holds where data enters: a transaction of a
/// `key/create` and a `key/delete`, each validly signed, is refused through
/// push and through import with the same typed error,
/// `MixedTransactionTyp`. Its arrow is the one the two cozies signed as two
/// transactions bind (one mutation transaction of two cozies has the TMR of
/// two single-coz transactions), so the mix is the only defect. Turns red if
/// a mixed transaction is accepted on any path. End-to-end scenario: yes.
#[tokio::test]
async fn mixed_typ_transaction_is_refused_by_push_and_import() {
    let (mut p, pg, setup) = two_key_principal().await;
    author(
        &mut p,
        &[
            vec![Coz {
                signer: "golden",
                kind: "key/create",
                target: "carol",
            }],
            vec![Coz {
                signer: "golden",
                kind: "key/delete",
                target: "key_a",
            }],
        ],
        "golden",
    )
    .await
    .expect("as two transactions the cozies commit");
    let separate = wire(p.commits().last().unwrap());
    let txs = separate["txs"].as_array().unwrap();
    let mixed = json!({
        "txs": [[txs[0][0], txs[1][0]], txs[2]],
        "keys": separate["keys"],
    });
    let refusal = cyphr::Error::MixedTransactionTyp.to_string();

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    push_all(&app, &pg, &setup).await;
    let (status, body) = post_json(app, "/push", push_body(&pg, &mixed)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "push: {body}");
    assert!(
        body.to_string().contains(&refusal),
        "push must name the refusal {refusal:?}: {body}"
    );

    let line = |bundle: &Value| {
        let decode = |c: &Value| {
            serde_json::from_slice::<Value>(
                &Base64UrlUnpadded::decode_vec(c.as_str().unwrap()).unwrap(),
            )
            .unwrap()
        };
        let txs: Vec<Vec<Value>> = bundle["txs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tx| tx.as_array().unwrap().iter().map(decode).collect())
            .collect();
        serde_json::from_value::<cyphr_storage::CommitEntry>(json!({
            "v": 2, "txs": txs, "keys": bundle["keys"],
            "commit_id": "", "ar": null, "sr": null, "pr": "",
        }))
        .expect("a line")
    };
    let mut lines: Vec<_> = setup.iter().map(line).collect();
    lines.push(line(&mixed));
    let genesis = cyphr_storage::Genesis::Implicit(pool_key("golden").key().unwrap());
    let imported = cyphr_storage::load_principal_from_commits(genesis, &lines).await;
    assert!(
        matches!(
            imported,
            Err(cyphr_storage::LoadError::Protocol(
                cyphr::Error::MixedTransactionTyp
            ))
        ),
        "import must refuse with MixedTransactionTyp: {:?}",
        imported.err()
    );
}
