//! Which data actions a commit includes (SPEC 4.8.1, 4.8.2), over the
//! storage engine: DR changes only at a signed `ds/create`, and a
//! `ds/create` includes exactly the pending action bundles whose Merkle
//! root is the `id` it signed.
//!
//! A store can hold action bundles a `ds/create` never saw: another device
//! of the principal pushed them at the same chain position. The engine
//! keeps every bundle (I1) and decides inclusion from the blobs alone, so
//! the live ingest, a replay, a rebuild from blobs and a restart agree.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::{EngineError, StorageEngine};
use cyphr_storage::index::MemoryIndexer;

const NOW: i64 = 1_700_300_000;

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

fn pool() -> test_fixtures::Pool {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool.toml")
}

/// A data action signed by `golden`: its wire coz and (pay, sig, czd).
struct Signed {
    wire: Vec<u8>,
    pay: Vec<u8>,
    sig: Vec<u8>,
    czd: coz::Czd,
}

fn golden_signs(fields: serde_json::Value) -> Signed {
    let pool = pool();
    let g = pool.get("golden").expect("golden");
    let mut fields = fields;
    fields["alg"] = g.alg.clone().into();
    fields["tmb"] = g.compute_tmb_b64().expect("tmb").into();
    if let Some(obj) = fields.as_object_mut() {
        obj.sort_keys();
    }
    let pay = serde_json::to_vec(&fields).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(g.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&g.pub_key).expect("pub b64");
    let (sig, cad) = coz::sign_json(&pay, &g.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &g.alg).expect("czd");
    let wire = serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("coz");
    Signed {
        wire,
        pay,
        sig,
        czd,
    }
}

fn action(msg: &str, now: i64) -> Signed {
    golden_signs(serde_json::json!({"msg": msg, "now": now, "typ": "cyphr.me/comment/create"}))
}

/// Finalize one commit on `p` holding `typ` signed by `golden` at `now`
/// with `id`: a `ds/create` names the DR it includes, a `key/create` the
/// key it adds.
async fn commit(p: &mut cyphr::Principal, typ: &str, id: &str, key: Option<cyphr::Key>, now: i64) {
    let pool = pool();
    let g = pool.get("golden").expect("golden");
    let s = golden_signs(serde_json::json!({"id": id, "now": now, "typ": typ}));
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&s.pay, &s.sig, s.czd, key)
        .expect("applies");
    scope
        .finalize_with_software(&g.software_signer().expect("signer"), now, "cyphr.me")
        .await
        .expect("finalizes");
}

/// A `ds/create` on `p` naming the DR over every action `p` holds.
async fn ds_create(p: &mut cyphr::Principal, now: i64) {
    let id = p
        .begin_commit()
        .data_tree_id()
        .expect("DR")
        .expect("DT holds an action");
    commit(p, "cyphr.me/cyphr/ds/create", &id, None, now).await;
}

fn last(p: &cyphr::Principal) -> WireBundle {
    test_fixtures::bundle::last_commit_bundle(p).expect("bundle")
}

/// A principal after its genesis commit, its id and genesis.
async fn base() -> (cyphr::Principal, String, Genesis, WireBundle) {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let mut p = cyphr::Principal::implicit(golden.key().expect("golden"))
        .await
        .expect("implicit");
    let g = test_fixtures::bundle::genesis_bundle(&mut p, golden, &[], NOW)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&g).expect("genesis id");
    (p, id, Genesis::Implicit(golden.key().expect("golden")), g)
}

async fn push(e: &Engine, id: &str, genesis: &Genesis, bundle: &WireBundle) -> Result<(), String> {
    e.submit_commit(id, Some(genesis.clone()), bundle)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// What each read path says about a principal: the PR a replay derives,
/// the tip the index serves, and the action bundles `/patch` carries.
async fn view(e: &Engine, id: &str) -> (String, String, Vec<(u64, Vec<Vec<u8>>)>) {
    let pr = e.rederive_roots(id).await.expect("replay").pr;
    let tip = e.get_tip(id).await.expect("tip").expect("stored").pr;
    let actions = e
        .get_patch(id, None, None)
        .await
        .expect("patch")
        .actions
        .into_iter()
        .map(|a| (a.after, a.blobs))
        .collect();
    (pr, tip, actions)
}

/// Claim (rule 1, SPEC 4.8.2): an action enters DR only at a signed
/// `ds/create`. A commit with no `ds/create` leaves DR where it was, the
/// action stays pending across it, and a later `ds/create` includes it;
/// replay records the action at the position it was accepted at, so the
/// served roots are the signer's at every step.
///
/// Turns red if: an action enters DR (and so PR) at a commit without a
/// `ds/create`, or replay places it anywhere but its own position. End to
/// end over the engine: yes. Already green on the base the rule was ruled
/// on (the core moved DR only at a `ds/create` before this change); it
/// pins that behaviour under the inclusion rewrite.
#[tokio::test]
async fn rule1_no_ds_create_includes_nothing() {
    let (mut p, id, genesis, g) = base().await;
    let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&e, &id, &genesis, &g).await.expect("genesis");

    let x = action("x", NOW + 1);
    p.verify_and_record_action(&x.pay, &x.sig, x.czd.clone())
        .expect("x records");
    push(&e, &id, &genesis, &WireBundle::actions(vec![x.wire.clone()]))
        .await
        .expect("x");
    let key_a = pool().get("key_a").expect("key_a").key().expect("key");
    commit(
        &mut p,
        "cyphr.me/cyphr/key/create",
        &key_a.tmb().to_b64(),
        Some(key_a),
        NOW + 2,
    )
    .await;
    assert!(p.data_root().is_none(), "no ds/create, no DR");
    push(&e, &id, &genesis, &last(&p)).await.expect("key commit");
    let (pr, tip, _) = view(&e, &id).await;
    assert_eq!((&pr, &tip), (&p.pr_tagged().expect("pr"), &pr));

    ds_create(&mut p, NOW + 3).await;
    assert!(p.data_root().is_some(), "the ds/create includes x");
    push(&e, &id, &genesis, &last(&p)).await.expect("ds/create");
    let (pr, tip, actions) = view(&e, &id).await;
    assert_eq!((&pr, &tip), (&p.pr_tagged().expect("pr"), &pr));
    assert_eq!(actions, vec![(1, vec![x.wire])], "x at its own position");
}

/// Claim (rule 2, SPEC 4.8.2): a `ds/create` includes exactly the pending
/// bundles whose root is its signed `id`, decided from the blobs alone.
/// The laptop pushes an action at the position the phone then commits
/// at; the phone's `ds/create` never saw it, so it includes the phone's
/// bundle only. The ingest accepts it, and a replay, a rebuild from the
/// blobs, and a restart (a fresh engine over the same blobs) serve the
/// same PR and the same included bundles; the laptop's bundle is kept,
/// not included.
///
/// Turns red if: the `ds/create` is refused because the laptop's bundle
/// is counted in DT, or any two paths disagree on what it included. End
/// to end over the engine: yes.
#[tokio::test]
async fn rule2_a_rival_bundle_is_not_included() {
    let (mut phone, id, genesis, g) = base().await;
    let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&e, &id, &genesis, &g).await.expect("genesis");

    let laptop = action("laptop", NOW + 1);
    push(&e, &id, &genesis, &WireBundle::actions(vec![laptop.wire.clone()]))
        .await
        .expect("the laptop's action");
    let mine = action("phone", NOW + 2);
    phone
        .verify_and_record_action(&mine.pay, &mine.sig, mine.czd.clone())
        .expect("records");
    push(&e, &id, &genesis, &WireBundle::actions(vec![mine.wire.clone()]))
        .await
        .expect("the phone's action");
    ds_create(&mut phone, NOW + 3).await;
    push(&e, &id, &genesis, &last(&phone))
        .await
        .expect("the phone's ds/create includes its own bundle only");

    let want_pr = phone.pr_tagged().expect("pr");
    let live = view(&e, &id).await;
    assert_eq!((&live.0, &live.1), (&want_pr, &want_pr), "ingest and replay");
    assert_eq!(
        live.2,
        vec![(1, vec![mine.wire.clone()])],
        "/patch carries the included bundle only"
    );
    let kept = e.not_included(&id).await.expect("not included");
    assert_eq!(
        kept.iter().map(|a| (a.after, a.blobs.clone())).collect::<Vec<_>>(),
        vec![(1, vec![laptop.wire.clone()])],
        "the laptop's bundle is kept, marked not included"
    );

    e.rebuild_index_with_report().await.expect("rebuild");
    assert_eq!(view(&e, &id).await, live, "a rebuild agrees");
    let restarted = Engine::new(e.blob_store().clone(), MemoryIndexer::new());
    restarted
        .rebuild_index_from_manifests()
        .await
        .expect("restart");
    assert_eq!(view(&restarted, &id).await, live, "a restart agrees");
    let again = restarted.not_included(&id).await.expect("not included");
    assert_eq!(again, kept, "the mark rebuilds from the blobs");
}

/// Claim (rule 2's bound): the subset search tries at most
/// [`cyphr::principal::MAX_PENDING_BUNDLES`] bundles; a `ds/create` facing
/// more is refused with the typed error, never searched.
///
/// Turns red if: nine pending bundles are searched (the `ds/create` is
/// accepted) or refused with any other error. End to end over the engine:
/// yes.
#[tokio::test]
async fn rule2_nine_bundles_are_refused() {
    let (mut p, id, genesis, g) = base().await;
    let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&e, &id, &genesis, &g).await.expect("genesis");
    for i in 0..9 {
        let a = action(&format!("a{i}"), NOW + 1 + i);
        p.verify_and_record_action(&a.pay, &a.sig, a.czd.clone())
            .expect("records");
        push(&e, &id, &genesis, &WireBundle::actions(vec![a.wire]))
            .await
            .expect("an action-only bundle");
    }
    let id_dr = p
        .begin_commit()
        .data_tree_id()
        .expect("DR")
        .expect("DT holds actions");
    let s = golden_signs(
        serde_json::json!({"id": id_dr, "now": NOW + 20, "typ": "cyphr.me/cyphr/ds/create"}),
    );
    let bundle = WireBundle {
        txs: vec![vec![s.wire]],
        ..WireBundle::default()
    };
    // The local principal refuses it as the engine does.
    let mut scope = p.begin_commit();
    let local = scope.verify_and_apply(&s.pay, &s.sig, s.czd, None);
    assert!(
        matches!(local, Err(cyphr::Error::TooManyPendingBundles { pending: 9, .. })),
        "{local:?}"
    );
    drop(scope);
    // The `ds/create` is refused before the commit closes, so it travels
    // alone: the engine meets the same refusal first.
    let refused = e.submit_commit(&id, Some(genesis), &bundle).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(cyphr::Error::TooManyPendingBundles {
                pending: 9,
                ..
            }))
        ),
        "{refused:?}"
    );
}
