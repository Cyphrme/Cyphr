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
    push(
        &e,
        &id,
        &genesis,
        &WireBundle::actions(vec![x.wire.clone()]),
    )
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
    push(&e, &id, &genesis, &last(&p))
        .await
        .expect("key commit");
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
    push(
        &e,
        &id,
        &genesis,
        &WireBundle::actions(vec![laptop.wire.clone()]),
    )
    .await
    .expect("the laptop's action");
    let mine = action("phone", NOW + 2);
    phone
        .verify_and_record_action(&mine.pay, &mine.sig, mine.czd.clone())
        .expect("records");
    push(
        &e,
        &id,
        &genesis,
        &WireBundle::actions(vec![mine.wire.clone()]),
    )
    .await
    .expect("the phone's action");
    ds_create(&mut phone, NOW + 3).await;
    push(&e, &id, &genesis, &last(&phone))
        .await
        .expect("the phone's ds/create includes its own bundle only");

    let want_pr = phone.pr_tagged().expect("pr");
    let live = view(&e, &id).await;
    assert_eq!(
        (&live.0, &live.1),
        (&want_pr, &want_pr),
        "ingest and replay"
    );
    assert_eq!(
        live.2,
        vec![(1, vec![mine.wire.clone()])],
        "/patch carries the included bundle only"
    );
    let kept = e.not_included(&id).await.expect("not included");
    assert_eq!(
        kept.iter()
            .map(|a| (a.after, a.blobs.clone()))
            .collect::<Vec<_>>(),
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
/// [`cyphr::principal::MAX_PENDING_BUNDLES`] bundles. The phone pushes
/// eight actions, another device a ninth at the same position, and the
/// phone's `ds/create` names its own eight: all-in fails, nine bundles are
/// too many to search, and the engine refuses with the typed error.
///
/// Turns red if: nine pending bundles are searched (the `ds/create` is
/// accepted) or refused with any other error. End to end over the engine:
/// yes.
#[tokio::test]
async fn rule2_nine_bundles_are_refused() {
    let (mut p, id, genesis, g) = base().await;
    let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&e, &id, &genesis, &g).await.expect("genesis");
    for i in 0..8 {
        let a = action(&format!("a{i}"), NOW + 1 + i);
        p.verify_and_record_action(&a.pay, &a.sig, a.czd.clone())
            .expect("records");
        push(&e, &id, &genesis, &WireBundle::actions(vec![a.wire]))
            .await
            .expect("an action-only bundle");
    }
    let other = action("another device", NOW + 9);
    push(&e, &id, &genesis, &WireBundle::actions(vec![other.wire]))
        .await
        .expect("the other device's bundle");
    ds_create(&mut p, NOW + 20).await;
    let refused = e.submit_commit(&id, Some(genesis), &last(&p)).await;
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

/// Claim (rule 2, all-in uncapped): a single device that pushes ten
/// actions one at a time and then one `ds/create` over all of them is
/// accepted. Every pending bundle together is tried before any search, so
/// the search cap never refuses a chain that holds only its signer's
/// bundles.
///
/// Turns red if: the cap applies to all-in (ten bundles refused). End to
/// end over the engine: yes.
#[tokio::test]
async fn rule2_all_in_is_uncapped() {
    let (mut p, id, genesis, g) = base().await;
    let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&e, &id, &genesis, &g).await.expect("genesis");
    for i in 0..10 {
        let a = action(&format!("a{i}"), NOW + 1 + i);
        p.verify_and_record_action(&a.pay, &a.sig, a.czd.clone())
            .expect("records");
        push(&e, &id, &genesis, &WireBundle::actions(vec![a.wire]))
            .await
            .expect("an action-only bundle");
    }
    ds_create(&mut p, NOW + 20).await;
    push(&e, &id, &genesis, &last(&p))
        .await
        .expect("a ds/create over ten pushed bundles");
    let (pr, tip, actions) = view(&e, &id).await;
    assert_eq!((&pr, &tip), (&p.pr_tagged().expect("pr"), &pr));
    assert_eq!(actions.len(), 10, "all ten are included and served");
}

/// Claim: only actions a chain includes bound its timestamps. The phone
/// pushes an action; the laptop pushes one dated far ahead at the same
/// position. The phone's `ds/create`, dated before the laptop's action,
/// includes the phone's alone and is accepted, and so is the phone's next
/// commit; live and after a restart that replays the blobs.
///
/// Turns red if: a pending or left-out action bounds a commit (the
/// `ds/create` or the next commit is refused as `TimestampPast`). End to
/// end over the engine: yes.
#[tokio::test]
async fn left_out_action_does_not_bound_time() {
    let (mut phone, id, genesis, g) = base().await;
    let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&e, &id, &genesis, &g).await.expect("genesis");
    let mine = action("phone", NOW + 2);
    phone
        .verify_and_record_action(&mine.pay, &mine.sig, mine.czd.clone())
        .expect("records");
    push(&e, &id, &genesis, &WireBundle::actions(vec![mine.wire]))
        .await
        .expect("the phone's action");
    let laptop = action("laptop, dated ahead", NOW + 50);
    push(&e, &id, &genesis, &WireBundle::actions(vec![laptop.wire]))
        .await
        .expect("the laptop's action");
    ds_create(&mut phone, NOW + 3).await;
    push(&e, &id, &genesis, &last(&phone))
        .await
        .expect("the ds/create leaves the laptop's action out");
    let key_a = pool().get("key_a").expect("key_a").key().expect("key");
    commit(
        &mut phone,
        "cyphr.me/cyphr/key/create",
        &key_a.tmb().to_b64(),
        Some(key_a),
        NOW + 4,
    )
    .await;
    push(&e, &id, &genesis, &last(&phone))
        .await
        .expect("the left-out action bounds nothing");
    let live = view(&e, &id).await;
    assert_eq!(live.0, phone.pr_tagged().expect("pr"));
    let restarted = Engine::new(e.blob_store().clone(), MemoryIndexer::new());
    restarted
        .rebuild_index_from_manifests()
        .await
        .expect("restart");
    assert_eq!(view(&restarted, &id).await, live, "a restart agrees");
}

/// A bundle of `p` whose cozies are signed as given, outside the local
/// scope's own timestamp check: `txs` are applied on `p`'s scope (to
/// compute the arrow) and the `commit/create` is signed by `golden` at
/// `commit_now`.
async fn hand_signed(p: &mut cyphr::Principal, txs: Vec<Signed>, commit_now: i64) -> WireBundle {
    let pool = pool();
    let g = pool.get("golden").expect("golden");
    let mut scope = p.begin_commit();
    for tx in &txs {
        scope
            .verify_and_apply(&tx.pay, &tx.sig, tx.czd.clone(), None)
            .expect("applies locally");
    }
    let prepared = scope
        .prepare_commit(
            &g.software_signer().expect("signer"),
            commit_now,
            "cyphr.me",
        )
        .expect("prepares");
    let commit = golden_signs(prepared.pay().clone());
    let mut all: Vec<Vec<Vec<u8>>> = txs.into_iter().map(|t| vec![t.wire]).collect();
    all.push(vec![commit.wire]);
    WireBundle {
        txs: all,
        ..WireBundle::default()
    }
}

/// A store holding genesis and one pending action dated `NOW + 50`, and a
/// local principal holding the same.
async fn with_action_ahead() -> (cyphr::Principal, String, Genesis, Engine) {
    let (mut p, id, genesis, g) = base().await;
    let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&e, &id, &genesis, &g).await.expect("genesis");
    let a = action("dated ahead", NOW + 50);
    p.verify_and_record_action(&a.pay, &a.sig, a.czd.clone())
        .expect("records");
    push(&e, &id, &genesis, &WireBundle::actions(vec![a.wire]))
        .await
        .expect("the action");
    (p, id, genesis, e)
}

/// Claim: the actions a `ds/create` includes join the chain's latest
/// timestamp at once (SPEC 14.1, 4.8.2). After a `ds/create` includes an
/// action dated `NOW + 50`, the `commit/create` closing that same commit,
/// dated before it, is refused as `TimestampPast`. (A later commit is
/// dated after that `commit/create`, so it is bounded by it anyway; a
/// later transaction in the same commit is the other case, below.)
///
/// Turns red if: an included action does not raise the latest timestamp
/// (the commit is accepted with cozies older than what it includes). End
/// to end over the engine: yes.
#[tokio::test]
async fn included_action_bounds_the_rest_of_its_commit() {
    let (mut p, id, genesis, e) = with_action_ahead().await;
    let dr = p
        .begin_commit()
        .data_tree_id()
        .expect("DR")
        .expect("DT holds an action");
    let ds = golden_signs(
        serde_json::json!({"id": dr, "now": NOW + 3, "typ": "cyphr.me/cyphr/ds/create"}),
    );
    let closing_early = hand_signed(&mut p.fork().await.expect("fork"), vec![ds], NOW + 4).await;
    let refused = e
        .submit_commit(&id, Some(genesis.clone()), &closing_early)
        .await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(cyphr::Error::TimestampPast))
        ),
        "a commit/create dated before what its ds/create includes: {refused:?}"
    );
}

/// Claim: as [`included_action_bounds_the_rest_of_its_commit`], for a
/// transaction after the `ds/create` in the same commit: a `key/create`
/// dated before the included action is refused as `TimestampPast`.
///
/// Turns red if: an included action does not raise the latest timestamp.
/// End to end over the engine: yes.
#[tokio::test]
async fn included_action_bounds_a_later_transaction() {
    let (mut p, id, genesis, e) = with_action_ahead().await;
    let dr = p
        .begin_commit()
        .data_tree_id()
        .expect("DR")
        .expect("DT holds an action");
    let ds = golden_signs(
        serde_json::json!({"id": dr, "now": NOW + 3, "typ": "cyphr.me/cyphr/ds/create"}),
    );
    let key_a = pool().get("key_a").expect("key_a").key().expect("key");
    let key = golden_signs(serde_json::json!({
        "id": key_a.tmb().to_b64(), "now": NOW + 4, "typ": "cyphr.me/cyphr/key/create"
    }));
    // The `key/create` is refused before the commit closes, so the
    // bundle carries no `commit/create`: the engine meets that refusal
    // first.
    let bundle = WireBundle {
        txs: vec![vec![ds.wire], vec![key.wire]],
        keys: vec![cyphr::replay::KeyEntry::of(&key_a)],
        ..WireBundle::default()
    };
    let refused = e.submit_commit(&id, Some(genesis), &bundle).await;
    assert!(
        matches!(
            refused,
            Err(EngineError::Protocol(cyphr::Error::TimestampPast))
        ),
        "a transaction after the ds/create dated before what it includes: {refused:?}"
    );
}

/// Claim (rule 3): an action a `ds/create` left out was never applied on
/// the chain, so its owner can record it again (SPEC 7.6 ignores only an
/// applied coz) and a later `ds/create` naming it includes it. The laptop's
/// action is left out by the phone's `ds/create`; the phone then records
/// that same signed action, pushes it, and includes it. The served PR is
/// the phone's, live and after a restart.
///
/// Turns red if: the left-out action is still taken as applied (its
/// re-recording is ignored and the `ds/create` naming it is refused). End
/// to end over the engine: yes.
#[tokio::test]
async fn left_out_action_can_be_recorded_again() {
    let (mut phone, id, genesis, g) = base().await;
    let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&e, &id, &genesis, &g).await.expect("genesis");
    let mine = action("phone", NOW + 2);
    phone
        .verify_and_record_action(&mine.pay, &mine.sig, mine.czd.clone())
        .expect("records");
    push(&e, &id, &genesis, &WireBundle::actions(vec![mine.wire]))
        .await
        .expect("the phone's action");
    let laptop = action("laptop", NOW + 5);
    push(
        &e,
        &id,
        &genesis,
        &WireBundle::actions(vec![laptop.wire.clone()]),
    )
    .await
    .expect("the laptop's action");
    ds_create(&mut phone, NOW + 3).await;
    push(&e, &id, &genesis, &last(&phone))
        .await
        .expect("the ds/create leaves the laptop's action out");

    phone
        .verify_and_record_action(&laptop.pay, &laptop.sig, laptop.czd.clone())
        .expect("the phone records it");
    push(&e, &id, &genesis, &WireBundle::actions(vec![laptop.wire]))
        .await
        .expect("recorded again");
    ds_create(&mut phone, NOW + 6).await;
    push(&e, &id, &genesis, &last(&phone))
        .await
        .expect("a later ds/create includes it");
    let live = view(&e, &id).await;
    assert_eq!(live.0, phone.pr_tagged().expect("pr"));
    let restarted = Engine::new(e.blob_store().clone(), MemoryIndexer::new());
    restarted
        .rebuild_index_from_manifests()
        .await
        .expect("restart");
    assert_eq!(view(&restarted, &id).await.0, live.0, "a restart agrees");
}
