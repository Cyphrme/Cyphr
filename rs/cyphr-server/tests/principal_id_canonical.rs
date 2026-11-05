//! One genesis-derived identity has one stored spelling (SPEC 3.1).
//!
//! A principal id may be written bare (`X`, an implicit genesis's tmb) or
//! algorithm-labelled (`SHA-256:X`). If the server keyed storage on whichever
//! spelling arrived, the same identity could be stored as two independent
//! principals: a fork refused under one spelling would be accepted under the
//! other, and a key the owner revoked under one spelling would keep signing
//! under the other. Both scenarios are end to end over `/push` and `/tip`.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::build_router;

mod common;

use common::{
    build_genesis_push_body_with, envelope_payload, get_json, keyless_server, load_pool, post_json,
};

const NOW: i64 = 1_700_100_000;

/// The two spellings of the golden implicit genesis's id: bare `X` and
/// labelled `SHA-256:X` (golden is an ES256 key).
fn spellings(pool: &test_fixtures::Pool) -> (String, String) {
    let bare = common::golden_principal_id(pool);
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

/// Backs: a divergent first commit is refused (409) under BOTH spellings of
/// an already-stored identity, and both spellings read the one chain. Turns
/// red if the alias keys a second, independent principal: the divergent
/// genesis is then accepted (201) under the labelled spelling. End to end:
/// yes.
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

    // Control: a divergent genesis (key_b instead of key_a) under the same
    // spelling is a fork and is refused.
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body_with(&pool, "golden", "key_b", &bare, NOW),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "control: {body:?}");

    // The same divergent genesis under the other spelling is the same fork.
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body_with(&pool, "golden", "key_b", &labelled, NOW),
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

/// One commit: apply `parts` (signed by `author`), finalize with `finalizer`.
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
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &finalizer.alg,
                &finalizer.prv,
                &finalizer.pubb,
                &finalizer.tmb,
            ),
            now,
            "cyphr.me",
        )
        .expect("finalize");
}

/// Push body for commit `i` of `p` under `id`; commit 0 also embeds the
/// genesis key on its closing cozy, as the wire contract requires.
fn wire(p: &cyphr::Principal, i: usize, genesis: &Kp, id: &str) -> String {
    let entries = cyphr_storage::export_commits(p).expect("export");
    let entry = &entries[i];
    let mut key_idx = 0;
    let mut blobs: Vec<serde_json::Value> = entry
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
    if i == 0 {
        let last = blobs.len() - 1;
        blobs[last]["key"] = serde_json::json!({
            "alg": genesis.alg,
            "pub": Base64UrlUnpadded::encode_string(&genesis.pubb),
            "tmb": genesis.tmb.to_b64(),
        });
    }
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
    let create = |signer: &Kp, id: &Kp, now: i64| {
        sign(
            signer,
            serde_json::json!({"alg": signer.alg, "id": id.tmb.to_b64(), "now": now,
                               "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
        )
    };

    // Owner: genesis(golden) + key/create key_a; then golden self-revokes,
    // the commit finalized by key_a.
    let mut owner = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(&mut owner, &g, create(&g, &a, NOW), Some(key_of(&a)), NOW);
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
        let (status, body) = post_json(app.clone(), "/push", wire(&owner, i, &g, &bare)).await;
        assert_eq!(status, StatusCode::CREATED, "owner commit {i}: {body:?}");
    }
    let (_, before) = tip(app.clone(), &bare).await;

    // The attacker holds the revoked golden key and builds its own
    // continuation of the public genesis, adding key_b.
    let mut attacker = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(
        &mut attacker,
        &g,
        create(&g, &a, NOW),
        Some(key_of(&a)),
        NOW,
    );
    commit_one(
        &mut attacker,
        &g,
        create(&g, &b, NOW + 20),
        Some(key_of(&b)),
        NOW + 20,
    );

    // Control: under the spelling the owner used, the revoked key is refused.
    let (status, body) = post_json(app.clone(), "/push", wire(&attacker, 1, &g, &bare)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "control: {body:?}"
    );

    // Replaying the owner's public first commit under the other spelling
    // must not open a second, pre-revocation copy of the principal.
    let (status, body) = post_json(app.clone(), "/push", wire(&owner, 0, &g, &labelled)).await;
    assert!(
        status.is_client_error(),
        "the public genesis was accepted afresh under the alias: {status} {body:?}"
    );
    let (status, body) = post_json(app.clone(), "/push", wire(&attacker, 1, &g, &labelled)).await;
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
/// principal that added a key BEFORE `principal/create` is established
/// with a PG that differs from its genesis-time Principal Root (the PG is
/// the PR at `principal/create`), and must be pushable under that PG.
/// Turns red (as it is today) because the engine accepts only the
/// genesis-derived id, so the push under the PG is refused with 400.
/// End to end: yes.
#[tokio::test]
async fn principal_with_keys_before_create_is_pushable_under_its_pg() {
    use cyphr::StateDigest;

    let pool = load_pool();
    let (g, a) = (kp(&pool, "golden"), kp(&pool, "key_a"));

    // genesis(golden); commit 0 adds key_a; commit 1 is principal/create
    // whose `id` is the PR after commit 0, so PG != the genesis tmb.
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(
        &mut p,
        &g,
        sign(
            &g,
            serde_json::json!({"alg": g.alg, "id": a.tmb.to_b64(), "now": NOW,
                               "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
        ),
        Some(key_of(&a)),
        NOW,
    );
    let pr_after_keys = p.pr_tagged().expect("pr");
    commit_one(
        &mut p,
        &g,
        sign(
            &g,
            serde_json::json!({"alg": g.alg, "id": pr_after_keys, "now": NOW + 1,
                               "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/principal/create"}),
        ),
        None,
        NOW + 1,
    );
    let pg = p
        .pg()
        .expect("principal/create establishes the PG")
        .as_multihash()
        .tagged_first()
        .expect("PG digest")
        .to_string();
    let genesis_id = common::golden_principal_id(&pool);
    assert_ne!(
        pg,
        format!("SHA-256:{genesis_id}"),
        "premise: the PG differs from the genesis-time id"
    );

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    for i in 0..2 {
        let (status, body) = post_json(app.clone(), "/push", wire(&p, i, &g, &pg)).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "commit {i} pushed under the principal's PG {pg}: {body:?}"
        );
    }
}

/// Every spelling a principal's PG has: each hash-variant label (`ALG:d`)
/// and each bare digest.
fn pg_spellings(p: &cyphr::Principal) -> Vec<String> {
    use cyphr::StateDigest;
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
    let add = |signer: &Kp, new: &Kp, now: i64| {
        sign(
            signer,
            serde_json::json!({"alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
                               "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
        )
    };

    // genesis(golden, ES256); commit 0 adds diana (ES384); commit 1 adds
    // eve (Ed25519); commit 2 is principal/create; commit 3 adds key_a.
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(&mut p, &g, add(&g, &d, NOW), Some(key_of(&d)), NOW);
    commit_one(&mut p, &g, add(&g, &e, NOW + 1), Some(key_of(&e)), NOW + 1);
    let pr_after_keys = p.pr_tagged().expect("pr");
    commit_one(
        &mut p,
        &g,
        sign(
            &g,
            serde_json::json!({"alg": g.alg, "id": pr_after_keys, "now": NOW + 2,
                               "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/principal/create"}),
        ),
        None,
        NOW + 2,
    );
    commit_one(&mut p, &g, add(&g, &a, NOW + 3), Some(key_of(&a)), NOW + 3);

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

    // Created under the genesis-derived id (which the engine accepts today),
    // so this test isolates PG-variant resolution from PG-as-push-id (the
    let genesis_id = self::spellings(&pool).1;
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    for i in 0..3 {
        let (status, body) = post_json(app.clone(), "/push", wire(&p, i, &g, &genesis_id)).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "commit {i} under {genesis_id}: {body:?}"
        );
    }

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
    let (status, body) = post_json(app.clone(), "/push", wire(&p, 3, &g, &pg384)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "commit 3 under {pg384}: {body:?}"
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
        let (status, body) = post_json(app.clone(), "/push", wire(&p, 3, &g, &forged)).await;
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
/// an id): a Principal Root the principal held in the past that is not its
/// PG -- one before the PG was established, and one after -- names nothing.
/// A read or a push under either is refused with a client error and moves
/// nothing, while the PG and the genesis-derived id keep working. Turns red
/// if the index aliases every PR the principal has had: the historical PR
/// then reads the principal (200) or accepts its push (201). End to end:
/// yes.
#[tokio::test]
#[ignore = "RED(AD1): every historical PR is aliased, not only the PG"]
async fn historical_pr_is_not_an_alias() {
    use cyphr::StateDigest;

    let pool = load_pool();
    let (g, a) = (kp(&pool, "golden"), kp(&pool, "key_a"));
    let (d, e) = (kp(&pool, "diana_es384"), kp(&pool, "eve_ed25519"));
    let add = |signer: &Kp, new: &Kp, now: i64| {
        sign(
            signer,
            serde_json::json!({"alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
                               "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
        )
    };
    let tagged_pr = |p: &cyphr::Principal| {
        p.pr()
            .as_multihash()
            .tagged_first()
            .expect("pr")
            .to_string()
    };

    // commit 0 adds diana, commit 1 adds eve, commit 2 is principal/create
    // (PG = the PR after commit 1), commit 3 adds key_a.
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(&mut p, &g, add(&g, &d, NOW), Some(key_of(&d)), NOW);
    let pr_before_pg = tagged_pr(&p);
    commit_one(&mut p, &g, add(&g, &e, NOW + 1), Some(key_of(&e)), NOW + 1);
    let pr_after_keys = p.pr_tagged().expect("pr");
    commit_one(
        &mut p,
        &g,
        sign(
            &g,
            serde_json::json!({"alg": g.alg, "id": pr_after_keys, "now": NOW + 2,
                               "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/principal/create"}),
        ),
        None,
        NOW + 2,
    );
    let pr_after_create = tagged_pr(&p);
    commit_one(&mut p, &g, add(&g, &a, NOW + 3), Some(key_of(&a)), NOW + 3);

    let pg = pg_spellings(&p);
    let genesis_id = spellings(&pool).1;
    let historical = [pr_before_pg, pr_after_create];
    for h in &historical {
        assert!(
            !pg.contains(h) && *h != genesis_id,
            "premise: {h} is a historical PR, not the PG or the genesis id"
        );
    }

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    for i in 0..3 {
        let (status, body) = post_json(app.clone(), "/push", wire(&p, i, &g, &genesis_id)).await;
        assert_eq!(status, StatusCode::CREATED, "commit {i}: {body:?}");
    }
    let (status, want) = tip(app.clone(), &genesis_id).await;
    assert_eq!(status, StatusCode::OK, "control: {want:?}");
    let want = without_now(want);
    // Control: the PG reads the principal.
    let (status, body) = tip(app.clone(), &pg[0]).await;
    assert_eq!(status, StatusCode::OK, "control, the PG: {body:?}");

    for h in &historical {
        let (status, body) = tip(app.clone(), h).await;
        assert!(
            status.is_client_error(),
            "historical PR {h} read the principal: {status} {body:?}"
        );
        let (status, body) = post_json(app.clone(), "/push", wire(&p, 3, &g, h)).await;
        assert!(
            status.is_client_error(),
            "historical PR {h} accepted a push: {status} {body:?}"
        );
    }
    let (_, after) = tip(app, &genesis_id).await;
    assert_eq!(
        without_now(after),
        want,
        "a historical-PR push moved the principal"
    );
}

/// Backs SPEC §3.7.1 on an attestor-mode server: a principal that added
/// keys before `principal/create` is pushed under its PG exactly as on a
/// keyless server, and the receipt is signed. Turns red if the attestor
/// route gate (`principal_id` must be genesis-shaped, routes.rs) refuses
/// the PG, or if the push lands without an attestation. End to end: yes.
#[tokio::test]
async fn attestor_server_accepts_a_push_under_the_pg() {
    use cyphr::StateDigest;

    let pool = load_pool();
    let (g, a) = (kp(&pool, "golden"), kp(&pool, "key_a"));
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(
        &mut p,
        &g,
        sign(
            &g,
            serde_json::json!({"alg": g.alg, "id": a.tmb.to_b64(), "now": NOW,
                               "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
        ),
        Some(key_of(&a)),
        NOW,
    );
    let pr_after_keys = p.pr_tagged().expect("pr");
    commit_one(
        &mut p,
        &g,
        sign(
            &g,
            serde_json::json!({"alg": g.alg, "id": pr_after_keys, "now": NOW + 1,
                               "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/principal/create"}),
        ),
        None,
        NOW + 1,
    );
    let pg = p
        .pg()
        .expect("PG")
        .as_multihash()
        .tagged_first()
        .expect("PG digest")
        .to_string();

    let (state, _identity, _dir) = common::attestor_server().await;
    let app = build_router(state);
    for i in 0..2 {
        let (status, body) = post_json(app.clone(), "/push", wire(&p, i, &g, &pg)).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "attestor: commit {i} pushed under the PG {pg}: {body:?}"
        );
        assert_eq!(
            body["statement"]["kind"],
            serde_json::json!("signed"),
            "attestor: commit {i} landed without a signed receipt: {body:?}"
        );
    }
}
