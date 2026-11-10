//! One genesis-derived identity has one stored spelling (SPEC 3.1).
//!
//! A principal id may be written bare (`X`, the PG's digest) or
//! algorithm-labelled (`SHA-256:X`). If the server keyed storage on whichever
//! spelling arrived, the same identity could be stored as two independent
//! principals: a fork refused under one spelling would be accepted under the
//! other, and a key the owner revoked under one spelling would keep signing
//! under the other. Both scenarios are end to end over `/push` and `/tip`.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::StateDigest;
use cyphr_server::build_router;

mod common;

use common::{
    build_genesis_push_body_with, build_second_commit_push_body, envelope_payload, get_json,
    keyless_server, load_pool, post_json,
};

const NOW: i64 = 1_700_100_000;

/// The two spellings of the standard principal's id (the PG of the genesis
/// in which `golden` creates itself and `key_a`): bare `X` and labelled
/// `SHA-256:X` (golden is an ES256 key).
fn spellings(pool: &test_fixtures::Pool) -> (String, String) {
    let labelled = common::golden_principal_id(pool);
    let bare = labelled.split_once(':').expect("labelled PG").1.to_string();
    (bare, labelled)
}

/// The two spellings of the id of a principal whose genesis creates only
/// `golden` (no nonce): its bare tmb `X` and `SHA-256:X` (SPEC 5.1).
fn implicit_spellings(pool: &test_fixtures::Pool) -> (String, String) {
    let bare = common::implicit_principal_id(pool, "golden");
    let labelled = format!("SHA-256:{bare}");
    (bare, labelled)
}

async fn tip(app: axum::Router, id: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) = get_json(app, &format!("/tip?pr={}", id.replace(':', "%3A"))).await;
    let payload = if status == StatusCode::OK {
        envelope_payload(&body).clone()
    } else {
        body
    };
    (status, payload)
}

/// Backs: a divergent commit is refused (409) under BOTH spellings of an
/// already-stored identity, and both spellings read the one chain. The
/// divergent commit continues another genesis of the same keys (signed at
/// another `now`, so the same PG but another post-genesis state), so its
/// `pre` forks the stored chain at its root. Turns red if the alias keys a
/// second, independent principal: the divergent commit is then accepted
/// under the labelled spelling. End to end: yes.
#[tokio::test]
async fn alias_spelling_cannot_fork_a_stored_principal() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let pool = load_pool();
    let (bare, labelled) = spellings(&pool);

    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body_with(&pool, "golden", "key_a", &bare, NOW),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");

    // Control: a commit on a divergent genesis (the same keys, signed at
    // another `now`) under the same spelling is a fork and is refused.
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_second_commit_push_body(&pool, &bare, NOW + 5, NOW + 10),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "control: {body:?}");

    // The same divergent commit under the other spelling is the same fork.
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_second_commit_push_body(&pool, &labelled, NOW + 5, NOW + 10),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the labelled spelling stored a second, divergent principal: {body:?}"
    );

    let (_, by_bare) = tip(app.clone(), &bare).await;
    let (_, by_label) = tip(app, &labelled).await;
    assert_eq!(by_bare, by_label, "both spellings must read one chain");
}

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp(pool: &test_fixtures::Pool, name: &str) -> Kp {
    let pk = pool.get(name).expect("pool key");
    Kp {
        alg: pk.alg.clone(),
        // key_b is only ever a sidecar here, so it may be public-only.
        prv: pk
            .prv
            .as_ref()
            .map(|p| Base64UrlUnpadded::decode_vec(p).expect("prv b64"))
            .unwrap_or_default(),
        pubb: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

fn sign(k: &Kp, pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&bytes, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (bytes, sig, czd)
}

fn signer_of(k: &Kp) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// A signed transaction and the key it discloses, if any.
type Tx = ((Vec<u8>, Vec<u8>, coz::Czd), Option<cyphr::Key>);

/// The genesis commit (SPEC 5.1): `g` (the principal's genesis key)
/// creates itself, then `extra` is applied (key/creates of further keys, a
/// nonce, all signed by `g`), then `principal/create` and `commit/create`.
fn genesis_commit(p: &mut cyphr::Principal, g: &Kp, extra: Vec<Tx>, now: i64) {
    let signer = signer_of(g);
    let mut scope = p.begin_commit();
    scope
        .create_genesis_keys(&signer, now, "cyphr.me")
        .expect("genesis key/create");
    for ((pay, sig, czd), sidecar) in extra {
        scope
            .verify_and_apply(&pay, &sig, czd, sidecar)
            .expect("genesis transaction");
    }
    scope
        .create_principal(&signer, now, "cyphr.me")
        .expect("principal/create");
    scope
        .finalize_with_software(&signer, now, "cyphr.me")
        .expect("finalize genesis");
}

/// One commit after genesis: apply `parts`, finalize with `finalizer`.
fn commit_one(
    p: &mut cyphr::Principal,
    finalizer: &Kp,
    parts: (Vec<u8>, Vec<u8>, coz::Czd),
    sidecar: Option<cyphr::Key>,
    now: i64,
) {
    let (pay, sig, czd) = parts;
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, sidecar)
        .expect("apply");
    scope
        .finalize_with_software(&signer_of(finalizer), now, "cyphr.me")
        .expect("finalize");
}

/// `signer` signs a `key/create` of `new` at `now`.
fn key_create(signer: &Kp, new: &Kp, now: i64) -> Tx {
    (
        sign(
            signer,
            serde_json::json!({"alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
                               "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
        ),
        Some(key_of(new)),
    )
}

/// Push body for commit `i` of `p` under `id`; every `key/create`
/// (the genesis commit's included) discloses its key.
fn wire(p: &cyphr::Principal, i: usize, id: &str) -> String {
    let entries = cyphr_storage::export_commits(p).expect("export");
    let entry = &entries[i];
    let mut key_idx = 0;
    let blobs: Vec<serde_json::Value> = entry
        .cozies
        .iter()
        .map(|c| {
            let mut c = c.clone();
            let typ = c["pay"]["typ"].as_str().unwrap_or("").to_string();
            if cyphr::parsed_coz::typ::is_key_introducing(&typ) && key_idx < entry.keys.len() {
                let k = &entry.keys[key_idx];
                c["key"] = serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.tmb});
                key_idx += 1;
            }
            c
        })
        .collect();
    serde_json::json!({
        "principal_id": id,
        "blobs": blobs
            .iter()
            .map(|b| Base64UrlUnpadded::encode_string(&serde_json::to_vec(b).expect("blob")))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

/// Backs: a key the owner self-revoked can neither commit nor rewind the
/// principal through the OTHER spelling of its id: both the owner's own
/// pre-revocation commit replayed and a fresh commit by the revoked key are
/// refused, and the tip does not move. Turns red if the alias keys a second
/// principal: the replay of the public genesis is accepted there and the
/// revoked key then commits (201). End to end: yes.
#[tokio::test]
async fn revoked_key_cannot_commit_through_the_alias_spelling() {
    let pool = load_pool();
    let (g, a, b) = (kp(&pool, "golden"), kp(&pool, "key_a"), kp(&pool, "key_b"));
    let (bare, labelled) = spellings(&pool);

    // Owner: the genesis commit in which golden creates itself and key_a;
    // then golden self-revokes, the commit finalized by key_a.
    let mut owner = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    genesis_commit(&mut owner, &g, vec![key_create(&g, &a, NOW)], NOW);
    commit_one(
        &mut owner,
        &a,
        sign(
            &g,
            serde_json::json!({"alg": g.alg, "now": NOW + 10, "rvk": NOW + 10,
                               "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/revoke"}),
        ),
        None,
        NOW + 10,
    );

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    for i in 0..2 {
        let (status, body) = post_json(app.clone(), "/push", wire(&owner, i, &bare)).await;
        assert_eq!(status, StatusCode::CREATED, "owner commit {i}: {body:?}");
    }
    let (_, before) = tip(app.clone(), &bare).await;

    // The attacker holds the revoked golden key and builds its own
    // continuation of the public genesis, adding key_b.
    let mut attacker = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    genesis_commit(&mut attacker, &g, vec![key_create(&g, &a, NOW)], NOW);
    let (parts, sidecar) = key_create(&g, &b, NOW + 20);
    commit_one(&mut attacker, &g, parts, sidecar, NOW + 20);

    // Control: under the spelling the owner used, the revoked key is refused.
    let (status, body) = post_json(app.clone(), "/push", wire(&attacker, 1, &bare)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "control: {body:?}"
    );

    // Replaying the owner's public first commit under the other spelling
    // must not open a second, pre-revocation copy of the principal.
    let (status, body) = post_json(app.clone(), "/push", wire(&owner, 0, &labelled)).await;
    assert!(
        status.is_client_error(),
        "the public genesis was accepted afresh under the alias: {status} {body:?}"
    );
    let (status, body) = post_json(app.clone(), "/push", wire(&attacker, 1, &labelled)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the revoked key committed through the alias spelling: {body:?}"
    );

    let (_, mut after) = tip(app, &bare).await;
    let mut before = before;
    // `now` is the response's own clock, not principal state.
    before.as_object_mut().expect("tip object").remove("now");
    after.as_object_mut().expect("tip object").remove("now");
    assert_eq!(before, after, "the alias push moved the principal");
}

/// Backs SPEC §3.7.1 ("PG is an immutable principal identifier"): a
/// principal whose genesis commit creates a key besides its genesis key
/// BEFORE `principal/create` has a PG (the PR at `principal/create`) that
/// differs from the lone genesis key's id, and is pushable under that PG.
/// Turns red if the engine accepts only the lone genesis key's id, so the
/// push under the PG is refused with 400. End to end: yes.
#[tokio::test]
async fn principal_with_keys_before_create_is_pushable_under_its_pg() {
    let pool = load_pool();
    let (g, a) = (kp(&pool, "golden"), kp(&pool, "key_a"));

    // genesis(golden): golden creates itself, then key_a, then
    // principal/create, whose `id` is the PR over both keys.
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    genesis_commit(&mut p, &g, vec![key_create(&g, &a, NOW)], NOW);
    let pg = p
        .pg()
        .expect("principal/create establishes the PG")
        .as_multihash()
        .tagged_first()
        .expect("PG digest")
        .to_string();
    let lone_key_id = implicit_spellings(&pool).1;
    assert_ne!(
        pg, lone_key_id,
        "premise: the PG differs from the lone genesis key's id"
    );

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (status, body) = post_json(app.clone(), "/push", wire(&p, 0, &pg)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the genesis commit pushed under the principal's PG {pg}: {body:?}"
    );
}

/// Every spelling a principal's PG has: each hash-variant label (`ALG:d`)
/// and each bare digest.
fn pg_spellings(p: &cyphr::Principal) -> Vec<String> {
    let mh = p
        .pg()
        .expect("established principal has a PG")
        .as_multihash();
    let mut out = Vec::new();
    for alg in mh.algorithms() {
        let tagged = mh.tagged(alg).expect("variant digest").to_string();
        let bare = tagged.split_once(':').expect("tagged digest").1.to_string();
        out.push(tagged);
        out.push(bare);
    }
    out
}

async fn patch(app: axum::Router, id: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) = get_json(app, &format!("/patch?pr={}", id.replace(':', "%3A"))).await;
    let payload = if status == StatusCode::OK {
        envelope_payload(&body).clone()
    } else {
        body
    };
    (status, payload)
}

/// `now` is the response's own clock, not principal state.
fn without_now(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(o) = v.as_object_mut() {
        o.remove("now");
    }
    v
}

/// Backs SPEC §12.1 (every PG hash variant names the same principal) and
/// the no-forged-label rule: a principal whose keys span ES256, ES384 and
/// Ed25519 (so its PG has SHA-256, SHA-384 and SHA-512 variants) is read
/// under every variant label and every bare digest with one tip and one
/// chain, is advanced by a push under a variant other than the one it was
/// created under, and refuses a label it does not have without creating
/// anything. Turns red if a variant is not resolved (the read is refused
/// or reads another principal), if a variant push forks or is refused, or
/// if a label the PG lacks is accepted. End to end: yes.
#[tokio::test]
async fn variant_labels_and_bare_digests_address_one_principal() {
    let pool = load_pool();
    let (g, a) = (kp(&pool, "golden"), kp(&pool, "key_a"));
    let (d, e) = (kp(&pool, "diana_es384"), kp(&pool, "eve_ed25519"));

    // Commit 0 is the genesis: golden (ES256) creates itself, diana (ES384)
    // and eve (Ed25519), then principal/create; commit 1 adds key_a.
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    genesis_commit(
        &mut p,
        &g,
        vec![key_create(&g, &d, NOW), key_create(&g, &e, NOW)],
        NOW,
    );
    let (parts, sidecar) = key_create(&g, &a, NOW + 3);
    commit_one(&mut p, &g, parts, sidecar, NOW + 3);

    let pg_all = pg_spellings(&p);
    assert_eq!(
        pg_all.len(),
        6,
        "premise: the PG has SHA-256, SHA-384 and SHA-512 variants: {pg_all:?}"
    );
    let label = |alg: &str| -> String {
        pg_all
            .iter()
            .find(|s| s.starts_with(&format!("{alg}:")))
            .unwrap_or_else(|| panic!("premise: PG has a {alg} variant: {pg_all:?}"))
            .clone()
    };
    let (pg256, pg384) = (label("SHA-256"), label("SHA-384"));

    // Created under the SHA-256 variant, the stored spelling.
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (status, body) = post_json(app.clone(), "/push", wire(&p, 0, &pg256)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "genesis under {pg256}: {body:?}"
    );

    // Every spelling reads the same tip and the same chain.
    let (status, want_tip) = tip(app.clone(), &pg256).await;
    assert_eq!(status, StatusCode::OK, "tip under {pg256}: {want_tip:?}");
    let want_tip = without_now(want_tip);
    let (status, want_chain) = patch(app.clone(), &pg256).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "patch under {pg256}: {want_chain:?}"
    );
    for s in &pg_all {
        let (status, got) = tip(app.clone(), s).await;
        assert_eq!(status, StatusCode::OK, "tip under {s}: {got:?}");
        assert_eq!(
            without_now(got),
            want_tip,
            "tip under {s} is another principal"
        );
        let (status, got) = patch(app.clone(), s).await;
        assert_eq!(status, StatusCode::OK, "patch under {s}: {got:?}");
        assert_eq!(got, want_chain, "chain under {s} is another principal");
    }

    // A push under a variant other than the creating one extends the one
    // principal: it lands (201), and every spelling then reads the new tip.
    let (status, body) = post_json(app.clone(), "/push", wire(&p, 1, &pg384)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "commit 1 under {pg384}: {body:?}"
    );
    let (_, new_tip) = tip(app.clone(), &pg256).await;
    let new_tip = without_now(new_tip);
    assert_ne!(
        new_tip, want_tip,
        "the variant push did not advance the tip"
    );
    for s in &pg_all {
        let (status, got) = tip(app.clone(), s).await;
        assert_eq!(status, StatusCode::OK, "tip under {s}: {got:?}");
        assert_eq!(
            without_now(got),
            new_tip,
            "{s} forked off the advanced chain"
        );
    }

    // A label the PG does not have is refused and creates nothing: the
    // SHA-256 digest relabelled SHA-512, and a label no variant carries.
    let sha256_digest = pg256.split_once(':').expect("tagged").1;
    for forged in [
        format!("SHA-512:{sha256_digest}"),
        format!("SHA3-256:{sha256_digest}"),
    ] {
        let (status, body) = tip(app.clone(), &forged).await;
        assert!(
            status.is_client_error(),
            "a label the PG does not have was accepted for read: {forged} {status} {body:?}"
        );
        let (status, body) = post_json(app.clone(), "/push", wire(&p, 1, &forged)).await;
        assert!(
            status.is_client_error(),
            "a label the PG does not have was accepted for push: {forged} {status} {body:?}"
        );
    }
    let (_, after) = tip(app, &pg256).await;
    assert_eq!(
        without_now(after),
        new_tip,
        "a forged label moved the principal"
    );
}

/// Backs SPEC §3.7.1 (the PG is THE permanent identifier; no other root is
/// an id): a Principal Root the principal has held that is not its PG --
/// the PR after its genesis commit, and the PR at its tip -- names nothing.
/// A read or a push under either is refused with a client error and moves
/// nothing, while the PG keeps working. Turns red if the index aliases
/// every PR the principal has had: the historical PR then reads the
/// principal (200) or accepts its push (201). End to end: yes.
#[tokio::test]
async fn historical_pr_is_not_an_alias() {
    let pool = load_pool();
    let (g, a, b) = (kp(&pool, "golden"), kp(&pool, "key_a"), kp(&pool, "key_b"));
    let (d, e) = (kp(&pool, "diana_es384"), kp(&pool, "eve_ed25519"));
    let tagged_pr = |p: &cyphr::Principal| {
        p.pr()
            .as_multihash()
            .tagged_first()
            .expect("pr")
            .to_string()
    };

    // Commit 0 is the genesis (golden creates itself, diana and eve, then
    // principal/create); commit 1 adds key_a; commit 2 adds key_b.
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    genesis_commit(
        &mut p,
        &g,
        vec![key_create(&g, &d, NOW), key_create(&g, &e, NOW)],
        NOW,
    );
    let pr_after_genesis = tagged_pr(&p);
    let (parts, sidecar) = key_create(&g, &a, NOW + 3);
    commit_one(&mut p, &g, parts, sidecar, NOW + 3);
    let pr_at_tip = tagged_pr(&p);
    let (parts, sidecar) = key_create(&g, &b, NOW + 4);
    commit_one(&mut p, &g, parts, sidecar, NOW + 4);

    let pg = pg_spellings(&p);
    let historical = [pr_after_genesis, pr_at_tip];
    for h in &historical {
        assert!(
            !pg.contains(h),
            "premise: {h} is a historical PR, not the PG"
        );
    }

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    for i in 0..2 {
        let (status, body) = post_json(app.clone(), "/push", wire(&p, i, &pg[0])).await;
        assert_eq!(status, StatusCode::CREATED, "commit {i}: {body:?}");
    }
    // Control: the PG reads the principal.
    let (status, want) = tip(app.clone(), &pg[0]).await;
    assert_eq!(status, StatusCode::OK, "control, the PG: {want:?}");
    let want = without_now(want);

    for h in &historical {
        let (status, body) = tip(app.clone(), h).await;
        assert!(
            status.is_client_error(),
            "historical PR {h} read the principal: {status} {body:?}"
        );
        let (status, body) = post_json(app.clone(), "/push", wire(&p, 2, h)).await;
        assert!(
            status.is_client_error(),
            "historical PR {h} accepted a push: {status} {body:?}"
        );
    }
    let (_, after) = tip(app, &pg[0]).await;
    assert_eq!(
        without_now(after),
        want,
        "a historical-PR push moved the principal"
    );
}

/// Backs SPEC §3.7.1 on an attestor-mode server: a principal whose genesis
/// commit creates a key besides its genesis key before `principal/create`
/// is pushed under its PG exactly as on a keyless server, and the receipt is
/// signed. Turns red if the attestor route gate (`principal_id` must be
/// genesis-shaped, routes.rs) refuses the PG, or if the push lands without
/// an attestation. End to end: yes.
#[tokio::test]
async fn attestor_server_accepts_a_push_under_the_pg() {
    let pool = load_pool();
    let (g, a) = (kp(&pool, "golden"), kp(&pool, "key_a"));
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    genesis_commit(&mut p, &g, vec![key_create(&g, &a, NOW)], NOW);
    let pg = p
        .pg()
        .expect("PG")
        .as_multihash()
        .tagged_first()
        .expect("PG digest")
        .to_string();

    let (state, _identity, _dir) = common::attestor_server().await;
    let app = build_router(state);
    let (status, body) = post_json(app.clone(), "/push", wire(&p, 0, &pg)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "attestor: genesis pushed under the PG {pg}: {body:?}"
    );
    assert_eq!(
        body["statement"]["kind"],
        serde_json::json!("signed"),
        "attestor: genesis landed without a signed receipt: {body:?}"
    );
}

/// Backs option B on the first push: a principal's genesis commit
/// establishes its PG, so its own post-commit PR is a historical root, not
/// an id. Pushing the genesis commit under that PR is refused with a client
/// error and stores nothing (it used to be stored, then reported as a 500
/// because the claimed id resolved to nothing). Turns red on the 500 or on
/// a stored principal. End to end: yes.
#[tokio::test]
async fn first_commit_under_its_own_post_commit_pr_is_refused_cleanly() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let genesis_id = implicit_spellings(&pool).1;
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    genesis_commit(&mut p, &g, Vec::new(), NOW);
    let post = p
        .pr()
        .as_multihash()
        .tagged_first()
        .expect("pr")
        .to_string();
    assert_ne!(
        post, genesis_id,
        "premise: the post-commit PR is not the PG"
    );

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (status, body) = post_json(app.clone(), "/push", wire(&p, 0, &post)).await;
    assert!(
        status.is_client_error(),
        "a non-PG historical root was accepted or failed as a server error: {status} {body:?}"
    );
    let (status, _) = tip(app, &genesis_id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the refused push stored a principal"
    );
}

/// A nonce-embedded principal on `g`: its genesis commit inserts `nonce` at
/// the KT root after golden's own `key/create`, so its PG differs from the
/// bare key's. Returns it with the id it is stored under: its PG (`SHA-256:`
/// form), which the nonce makes unique (SPEC 5.1 step 3 and "a nonce
/// embedding for a unique PG").
fn nonce_principal(g: &Kp, nonce: u8) -> (cyphr::Principal, String) {
    let mut p = cyphr::Principal::implicit(key_of(g)).expect("genesis");
    let nonce_create = sign(
        g,
        serde_json::json!({
            "alg": g.alg,
            "id": format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[nonce; 32])),
            "now": NOW, "tmb": g.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/AT/KT/nonce/create",
        }),
    );
    genesis_commit(&mut p, g, vec![(nonce_create, None)], NOW);
    let id = p
        .pg()
        .expect("the genesis commit establishes the PG")
        .as_multihash()
        .tagged_first()
        .expect("pg")
        .to_string();
    (p, id)
}

/// Backs SPEC be0663f 5.1 l764 (the bare key thumbprint is the identity of
/// the single-key, no-nonce principal ONLY): after a nonce-embedded
/// principal on the golden key is pushed, `/tip` under the bare tmb (either
/// spelling) must not answer with that principal. Turns red if the engine
/// keys a stored principal by its genesis-key tmb, so the bare tmb resolves
/// to the nonce principal (200, its tip). Control: the same principal is
/// served under its own PG, so a server that serves nothing fails. A lying
/// fix that answers 404 for the bare tmb by refusing the key, or that
/// resolves it by first match, is caught by the sibling test below. End to
/// end: yes.
#[tokio::test]
async fn bare_tmb_never_resolves_to_a_nonce_principal() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let (n, pg) = nonce_principal(&g, 0x11);
    let (bare, labelled) = implicit_spellings(&pool);
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    let (status, body) = post_json(app.clone(), "/push", wire(&n, 0, &pg)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "nonce principal commit 0: {body:?}"
    );
    let (status, t) = tip(app.clone(), &pg).await;
    assert_eq!(status, StatusCode::OK, "control: its own id: {t:?}");
    for id in [&bare, &labelled] {
        let (status, t) = tip(app.clone(), id).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "the bare key id {id} resolved to a nonce principal: {t:?}"
        );
    }
}

/// Backs the same identity rule from the other side: a no-nonce single-key
/// principal and a nonce-embedded principal on the SAME key coexist, and
/// the bare tmb names the first only, each tip being its own. Turns red if
/// the second push collides (non-201: both would be stored under the one
/// tmb key), if the bare tmb answers with the nonce principal's root, or if
/// either push moves the other's tip. Order is covered both ways. End to
/// end: yes.
#[tokio::test]
async fn bare_tmb_resolves_to_the_no_nonce_principal_beside_a_nonce_sibling() {
    for nonce_first in [true, false] {
        let pool = load_pool();
        let g = kp(&pool, "golden");
        let (n, pg) = nonce_principal(&g, 0x22);
        let mut plain = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
        genesis_commit(&mut plain, &g, Vec::new(), NOW);
        let plain_pr_0 = plain
            .pr()
            .as_multihash()
            .tagged_first()
            .expect("pr")
            .to_string();
        let (bare, labelled) = implicit_spellings(&pool);
        let (state, _dir) = keyless_server();
        let app = build_router(state);

        let push_nonce = || post_json(app.clone(), "/push", wire(&n, 0, &pg));
        let push_plain = || post_json(app.clone(), "/push", wire(&plain, 0, &labelled));
        let (a, b) = if nonce_first {
            let a = push_nonce().await;
            (a, push_plain().await)
        } else {
            let b = push_plain().await;
            (push_nonce().await, b)
        };
        assert_eq!(a.0, StatusCode::CREATED, "nonce_first={nonce_first}: {a:?}");
        assert_eq!(b.0, StatusCode::CREATED, "nonce_first={nonce_first}: {b:?}");

        let (_, by_bare) = tip(app.clone(), &bare).await;
        let (_, by_label) = tip(app.clone(), &labelled).await;
        assert_eq!(by_bare, by_label, "the two spellings read different chains");
        let plain_bare = plain_pr_0.split_once(':').expect("tagged").1;
        assert!(
            by_bare["pr"]
                .as_str()
                .is_some_and(|v| v.contains(plain_bare)),
            "the bare tmb does not read the no-nonce principal: {by_bare:?}"
        );
        let (status, own) = tip(app.clone(), &pg).await;
        assert_eq!(status, StatusCode::OK, "{own:?}");
        assert_ne!(
            by_bare["pr"], own["pr"],
            "the bare tmb reads the nonce principal"
        );
        assert_eq!(by_bare["commit_count"], serde_json::json!(1), "{by_bare:?}");
        assert_eq!(own["commit_count"], serde_json::json!(1), "{own:?}");
    }
}
