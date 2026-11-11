//! Embedded principals at default weight (SPEC be0663f §10.3, §10.5, §10.7).
//!
//! Principal A (`alice`) embeds principal B (`bob` + `carol`) by putting
//! B's PR in its Key Tree with `cyphr/AT/KT/nonce/create`; the verifier
//! reveals that digest as B and follows B's tip through a fake
//! [`TipSource`]. Every test drives the wire: cozies signed by B's keys are
//! verified and applied on A through the public commit API.

use std::collections::VecDeque;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use cyphr::{EmbedStatus, Error, Key, Principal, Tip, TipSource, Tracking};
use serde_json::json;

const T: i64 = 1_700_000_000;

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn pool_key(name: &str) -> Kp {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/keys/pool.toml");
    let pool = test_fixtures::Pool::load(&path).expect("pool");
    let pk = pool.get(name).expect("key in pool");
    let d = |s: &str| Base64UrlUnpadded::decode_vec(s).expect("b64");
    Kp {
        alg: pk.alg.clone(),
        pubb: d(&pk.pub_key),
        prv: d(pk.prv.as_ref().expect("signing key has prv")),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

fn software(k: &Kp) -> SoftwareSigner {
    SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

type Signed = (Vec<u8>, Vec<u8>, coz::Czd);

fn sign(k: &Kp, typ: &str, id: &str, now: i64) -> Signed {
    let mut pay = json!({"alg": k.alg, "id": id, "now": now,
        "tmb": Base64UrlUnpadded::encode_string(k.tmb.as_bytes()),
        "typ": format!("cyphr.me/cyphr/{typ}")});
    pay.as_object_mut().expect("object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&v, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (v, sig, czd)
}

/// One commit on `p`: `parts` signed by `signer`, finalized by `signer`.
async fn commit(
    p: &mut Principal,
    signer: &Kp,
    parts: Signed,
    sidecar: Option<Key>,
    now: i64,
) -> cyphr::error::Result<()> {
    let (pay, sig, czd) = parts;
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&pay, &sig, czd, sidecar)?;
    scope
        .finalize_with_software(&software(signer), now, "cyphr.me")
        .await
        .map(|_| ())
}

fn tmb_id(k: &Kp) -> String {
    Base64UrlUnpadded::encode_string(k.tmb.as_bytes())
}

/// `carol` signs a `key/create` of `new` on A, and finalizes it.
async fn b_adds(a: &mut Principal, carol: &Kp, new: &Kp, now: i64) -> cyphr::error::Result<()> {
    let parts = sign(carol, "key/create", &tmb_id(new), now);
    commit(a, carol, parts, Some(key_of(new)), now).await
}

/// A fake source handing out the tips queued in it, one per request, and
/// counting the requests.
#[derive(Default)]
struct Fake {
    tips: VecDeque<Tip>,
    asked: Vec<String>,
}

impl TipSource for Fake {
    async fn tip(&mut self, member: &str) -> Option<Tip> {
        self.asked.push(member.to_owned());
        self.tips.pop_front()
    }
}

struct World {
    a: Principal,
    b: Principal,
    alice: Kp,
    bob: Kp,
    carol: Kp,
    b_pr: String,
}

/// B (`bob`, `carol`) and A (`alice`) after their genesis commits, with B's
/// genesis PR in A's KT and revealed as followed. Nothing pulled yet.
async fn world() -> World {
    let (alice, bob, carol) = (pool_key("alice"), pool_key("bob"), pool_key("carol"));
    let mut b = Principal::implicit(key_of(&bob)).await.expect("B");
    b.commit_genesis(&software(&bob), &[key_of(&carol)], T, "cyphr.me")
        .await
        .expect("B genesis");
    let mut a = Principal::implicit(key_of(&alice)).await.expect("A");
    a.commit_genesis(&software(&alice), &[], T, "cyphr.me")
        .await
        .expect("A genesis");
    let b_pr = b.pr_tagged().expect("B PR");
    let embed = sign(&alice, "AT/KT/nonce/create", &b_pr, T + 1);
    commit(&mut a, &alice, embed, None, T + 1)
        .await
        .expect("A embeds B");
    a.reveal_embedded(&b_pr, Tracking::Follow)
        .expect("reveal B");
    World {
        a,
        b,
        alice,
        bob,
        carol,
        b_pr,
    }
}

/// Backs SPEC 10.5 (conjunctive authorization) and 10.3 (an embedded
/// principal is one member of KR): a key of B signs for A only while B's
/// own rules authorize it (it is an active key at B's tip) and B is a
/// member of A (its digest is in A's KT). Turns red if B's key signs for A
/// with no tip, after A removes the embedding, on a key B never held, or
/// if B's key replaces itself into A's KT.
/// End to end: yes (signed cozies through `begin_commit`).
#[tokio::test]
async fn b_signs_for_a_only_as_a_member_and_under_its_own_rules() {
    let World {
        mut a,
        b,
        alice,
        carol,
        b_pr,
        ..
    } = world().await;
    let key_a = pool_key("key_a");

    // Revealed but never pulled: nothing is known of B's keys.
    assert!(matches!(
        b_adds(&mut a, &carol, &key_a, T + 2).await,
        Err(Error::UnknownKey)
    ));

    let mut src = Fake::default();
    src.tips.push_back(Tip::new(&b, T + 50));
    let report = a.follow_embedded(&mut src).await;
    assert_eq!(src.asked, vec![b_pr.clone()]);
    assert_eq!(
        report[0].status,
        EmbedStatus::Followed {
            pulled_at: T + 50,
            newest_now: T
        },
        "a followed tip carries its pull time and B's newest now"
    );

    // A key B does not hold is refused whatever B authorizes.
    let golden = pool_key("golden");
    assert!(matches!(
        b_adds(&mut a, &golden, &key_a, T + 2).await,
        Err(Error::UnknownKey)
    ));

    // Both conjuncts hold: B's key adds a key to A.
    b_adds(&mut a, &carol, &key_a, T + 2)
        .await
        .expect("B's key signs for A");
    assert!(a.is_key_active(&key_a.tmb));
    // B's key is B's: it has no key of A's to replace.
    let replace = sign(&carol, "key/replace", &tmb_id(&golden), T + 3);
    assert!(matches!(
        commit(&mut a, &carol, replace, Some(key_of(&golden)), T + 3).await,
        Err(Error::UnknownKey)
    ));

    // A removes the embedding: B is no longer a member, so its key is not.
    let unembed = sign(&alice, "AT/KT/nonce/delete", &b_pr, T + 3);
    commit(&mut a, &alice, unembed, None, T + 3)
        .await
        .expect("A removes B");
    assert!(matches!(
        b_adds(&mut a, &carol, &pool_key("golden"), T + 4).await,
        Err(Error::UnknownKey)
    ));
}

/// Backs SPEC 10.5 with 6.2/6.4 and the spec author's "verdicts must not
/// change after the fact" (#200): once the verifier holds a tip in which B
/// deleted `carol`, `carol` cannot newly authorize on A even with a `now`
/// before the deletion, and a key the source saw naked-revoked is refused
/// as revoked; the commit `carol` made on A before the deletion stays
/// accepted (A's PR and keys unchanged). Turns red if the backdated coz is
/// accepted, if the revoked key signs, or if a refreshed tip re-judges A's
/// history. End to end: yes.
#[tokio::test]
async fn a_removed_key_of_b_cannot_newly_authorize_and_old_verdicts_stand() {
    let World {
        mut a,
        mut b,
        bob,
        carol,
        ..
    } = world().await;
    let key_a = pool_key("key_a");

    let mut src = Fake::default();
    src.tips.push_back(Tip::new(&b, T + 5));
    a.follow_embedded(&mut src).await;
    b_adds(&mut a, &carol, &key_a, T + 10)
        .await
        .expect("carol signs for A while B holds it");
    let accepted = (a.pr().clone(), a.commits().count());

    // B deletes carol at T + 20; bob is naked-revoked as the source saw.
    let delete = sign(&bob, "key/delete", &tmb_id(&carol), T + 20);
    commit(&mut b, &bob, delete, None, T + 20)
        .await
        .expect("B deletes carol");
    src.tips
        .push_back(Tip::new(&b, T + 30).with_revoked([&bob.tmb]));
    let report = a.follow_embedded(&mut src).await;
    assert_eq!(
        report[0].status,
        EmbedStatus::Followed {
            pulled_at: T + 30,
            newest_now: T + 20
        }
    );

    // Backdated to T + 15, before the deletion and after A's latest `now`.
    let golden = pool_key("golden");
    assert!(matches!(
        b_adds(&mut a, &carol, &golden, T + 15).await,
        Err(Error::UnknownKey)
    ));
    assert!(matches!(
        b_adds(&mut a, &bob, &golden, T + 15).await,
        Err(Error::KeyRevoked)
    ));

    assert_eq!((a.pr().clone(), a.commits().count()), accepted);
    assert!(a.is_key_active(&key_a.tmb), "the earlier verdict stands");
}

/// Backs SPEC 10.5 with 11.1 (`Error`): when the source finds B in `Error`
/// (a fork), authorization through B is `Error` too, for a key B still
/// holds. Turns red if a key of a principal in `Error` authorizes. End to
/// end: yes.
#[tokio::test]
async fn b_in_error_makes_authorization_through_b_error() {
    let World {
        mut a, b, carol, ..
    } = world().await;
    let mut src = Fake::default();
    src.tips
        .push_back(Tip::new(&b, T + 5).in_error());
    a.follow_embedded(&mut src).await;
    let before = a.pr().clone();
    assert!(matches!(
        b_adds(&mut a, &carol, &pool_key("key_a"), T + 10).await,
        Err(Error::EmbeddedErrored)
    ));
    assert_eq!(a.pr(), &before);
}
