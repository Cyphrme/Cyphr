//! Pinned roots and certificates across hash-algorithm epochs (frame
//! NETSIM-FIX, E10). Red until `cyphr::proof` is implemented: every test
//! reaches a `stub:` `unimplemented!()` first (or a wrong verdict, as
//! named), so a pass can only come from the real verifier.
//!
//! Families: Ed25519 hashes under SHA-512, ES256 under SHA-256, ES384
//! under SHA-384. A `key/replace` from one to the other closes the
//! signer's family and opens the new key's at the replace commit.
//!
//! Certificates are opaque; the tamper tests edit their serde form, the
//! wire documented in `cyphr::proof`, through the `Wire` adapter below,
//! the one place to change if the wire is reshaped.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::commit_root::{CommitTrees, MaltHasher, hash_alg_to_u64};
use cyphr::proof::{
    Anchor, Certificate, ProofError, Root, legacy as old, verify_extension, verify_membership,
};
use cyphr::signer::SoftwareSigner;
use cyphr::{HashAlg, Key, Principal, TransactionRoot};
use serde_json::{Value, json};

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp(alg: coz::Alg) -> Kp {
    let k = alg.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
    Kp {
        alg: k.alg.name().to_string(),
        pubb: k.pub_bytes,
        prv: k.prv_bytes,
        tmb,
    }
}

fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

fn signer(k: &Kp) -> SoftwareSigner {
    SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

fn at(k: usize) -> i64 {
    T + 10 * k as i64
}

/// One commit by `by`: `typ` (`create`/`delete`/`replace`) of `id`.
async fn commit_key(p: &mut Principal, by: &Kp, typ: &str, id: &Kp, now: i64) {
    let b64 = |t: &coz::Thumbprint| Base64UrlUnpadded::encode_string(t.as_bytes());
    let mut pay = json!({"alg": by.alg, "id": b64(&id.tmb), "now": now,
                         "tmb": b64(&by.tmb), "typ": format!("{AUTHORITY}/cyphr/key/{typ}")});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    let sidecar = (typ != "delete").then(|| key_of(id));
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&v, &sig, czd, sidecar)
        .expect("apply");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

/// A data action by `by`, then a `ds/create` commit over it.
async fn data_commit(p: &mut Principal, by: &Kp, now: i64) {
    let tmb = Base64UrlUnpadded::encode_string(by.tmb.as_bytes());
    let mut pay = json!({"msg": "hello", "now": now, "tmb": tmb, "alg": by.alg,
                         "typ": format!("{AUTHORITY}/comment/create")});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    p.verify_and_record_action(&v, &sig, czd).expect("record");

    let mut scope = p.begin_commit();
    let dr = scope.data_tree_id().expect("dr").expect("a data action");
    let mut pay = json!({"id": dr, "now": now + 1, "tmb": tmb, "alg": by.alg,
                         "typ": format!("{AUTHORITY}/{}", cyphr::parsed_coz::typ::DS_CREATE)});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    scope
        .verify_and_apply(&v, &sig, czd, None)
        .expect("ds/create");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

async fn genesis(owner: &Kp) -> Principal {
    let mut p = Principal::implicit(key_of(owner)).await.expect("open");
    p.commit_genesis(&signer(owner), &[], T, AUTHORITY)
        .await
        .expect("genesis commit");
    p
}

/// A PR-level nonce create by `by`, as its own commit.
async fn commit_nonce(p: &mut Principal, by: &Kp, seed: u8, now: i64) {
    let id = format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[seed; 32]));
    let mut pay = json!({"alg": by.alg, "id": id, "now": now,
                         "tmb": Base64UrlUnpadded::encode_string(by.tmb.as_bytes()),
                         "typ": format!("{AUTHORITY}/cyphr/nonce/create")});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&v, &sig, czd, None).expect("nonce");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

/// Genesis (Ed25519, SHA-512), `nonces` PR-level nonce commits, `pre` data
/// commits, a `key/replace` to an ES256 key (SHA-256), then `post` data
/// commits by the new key. Ed25519 signs deterministically, so two builds
/// with the same keys agree commit for commit until `skew` (a commit
/// index from which every `now` is one second later), which forks them.
async fn single_with(
    (a, b): (&Kp, &Kp),
    (nonces, pre, post): (usize, usize, usize),
    skew: Option<usize>,
) -> Principal {
    let t = |i: usize| at(i) + i64::from(skew.is_some_and(|f| i >= f));
    let mut p = genesis(a).await;
    let mut i = 1;
    for k in 0..nonces {
        commit_nonce(&mut p, a, k as u8 + 1, t(i)).await;
        i += 1;
    }
    for _ in 0..pre {
        data_commit(&mut p, a, t(i)).await;
        i += 1;
    }
    commit_key(&mut p, a, "replace", b, t(i)).await;
    i += 1;
    for _ in 0..post {
        data_commit(&mut p, b, t(i)).await;
        i += 1;
    }
    p
}

/// `pre + post + 2` commits, the replace at index `pre + 1`.
async fn single(pre: usize, post: usize) -> Principal {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    single_with((&a, &b), (0, pre, post), None).await
}

/// Ed25519 -> ES256 at index 3 -> ES384 (SHA-384) at index 6; nine
/// commits, two data commits in each era after the genesis.
async fn double() -> (Principal, Kp) {
    let (a, b, c) = (
        kp(coz::Alg::Ed25519),
        kp(coz::Alg::ES256),
        kp(coz::Alg::ES384),
    );
    let mut p = genesis(&a).await;
    for k in 1..=2 {
        data_commit(&mut p, &a, at(k)).await;
    }
    commit_key(&mut p, &a, "replace", &b, at(3)).await;
    for k in 4..=5 {
        data_commit(&mut p, &b, at(k)).await;
    }
    commit_key(&mut p, &b, "replace", &c, at(6)).await;
    for k in 7..=8 {
        data_commit(&mut p, &c, at(k)).await;
    }
    (p, a)
}

/// ES256 pairs in (1), the Ed25519 key is deleted (2), so index 3 is
/// covered by ES256 alone; Ed25519 returns (4), ES256 is deleted (5),
/// index 6 is Ed25519 alone; ES256 returns (7). Ten commits; the tip has
/// both families.
async fn resume() -> Principal {
    let (a0, b0, a1, b1) = (
        kp(coz::Alg::Ed25519),
        kp(coz::Alg::ES256),
        kp(coz::Alg::Ed25519),
        kp(coz::Alg::ES256),
    );
    let mut p = genesis(&a0).await;
    commit_key(&mut p, &a0, "create", &b0, at(1)).await;
    commit_key(&mut p, &b0, "delete", &a0, at(2)).await;
    data_commit(&mut p, &b0, at(3)).await;
    commit_key(&mut p, &b0, "create", &a1, at(4)).await;
    commit_key(&mut p, &a1, "delete", &b0, at(5)).await;
    data_commit(&mut p, &a1, at(6)).await;
    commit_key(&mut p, &a1, "create", &b1, at(7)).await;
    data_commit(&mut p, &b1, at(8)).await;
    p
}

fn tr_of(p: &Principal, i: u64) -> &cyphr::TransactionRoot {
    p.commit_at(usize::try_from(i).expect("index"))
        .expect("commit")
        .tr()
}

/// Ed25519 (A, SHA-512) creates ES384 (C) at 1 and ES256 (B) at 2, so
/// the stitch at 2 opens `CR_1 = {A, C}` under A's arrow; B then deletes C
/// (3) and A (4), and signs two data commits: seven commits, tip B alone.
async fn three_families() -> Principal {
    let (a, c, b) = (
        kp(coz::Alg::Ed25519),
        kp(coz::Alg::ES384),
        kp(coz::Alg::ES256),
    );
    let mut p = genesis(&a).await;
    commit_key(&mut p, &a, "create", &c, at(1)).await;
    commit_key(&mut p, &a, "create", &b, at(2)).await;
    commit_key(&mut p, &b, "delete", &c, at(3)).await;
    commit_key(&mut p, &b, "delete", &a, at(4)).await;
    for k in 5..7 {
        data_commit(&mut p, &b, at(k)).await;
    }
    p
}

/// A (`alice`, ES256, SHA-256) embeds B (`bob`, ES256, and `eve`,
/// Ed25519, SHA-512). Returns A after its genesis and the embedding, with
/// B followed, and the keys a test signs with.
struct Embedded {
    a: Principal,
    alice: Kp,
    eve: Kp,
}

fn pool_kp(name: &str) -> Kp {
    let pool = test_fixtures::Pool::load(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml"),
    )
    .expect("pool");
    let k = pool.get(name).expect("key in pool");
    let d = |s: &str| Base64UrlUnpadded::decode_vec(s).expect("b64");
    Kp {
        alg: k.alg.clone(),
        pubb: d(&k.pub_key),
        prv: d(k.prv.as_ref().expect("prv")),
        tmb: k.compute_tmb().expect("tmb"),
    }
}

/// One commit on `p` of the single coz `typ` of `id`, signed and finalized
/// by `by`, with `side` as the sidecar key.
async fn commit_as(
    p: &mut Principal,
    by: &Kp,
    typ: &str,
    id: &str,
    side: Option<Key>,
    now: i64,
) -> cyphr::error::Result<()> {
    let tmb = Base64UrlUnpadded::encode_string(by.tmb.as_bytes());
    let mut pay = json!({"alg": by.alg, "id": id, "now": now, "tmb": tmb,
                         "typ": format!("{AUTHORITY}/cyphr/{typ}")});
    pay.as_object_mut().expect("object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&v, &sig, czd, side)?;
    scope
        .finalize_with_software(&signer(by), now, AUTHORITY)
        .await
        .map(|_| ())
}

async fn embedded() -> Embedded {
    use cyphr::{Tip, TipSource, Tracking};
    struct Once(Option<Tip>);
    impl TipSource for Once {
        async fn tip(&mut self, _: &str) -> Option<Tip> {
            self.0.take()
        }
    }
    let (alice, bob, eve) = (pool_kp("alice"), pool_kp("bob"), pool_kp("eve_ed25519"));
    let mut b = Principal::implicit(key_of(&bob)).await.expect("B");
    b.commit_genesis(&signer(&bob), &[key_of(&eve)], T, AUTHORITY)
        .await
        .expect("B genesis");
    let mut a = genesis(&alice).await;
    let b_pr = b.pr_tagged().expect("B PR");
    commit_as(&mut a, &alice, "AT/KT/nonce/create", &b_pr, None, T + 1)
        .await
        .expect("A embeds B");
    a.reveal_embedded(&b_pr, Tracking::Follow).expect("reveal");
    a.follow_embedded(&mut Once(Some(Tip::new(&b, T + 50))))
        .await;
    Embedded { a, alice, eve }
}

fn b64(k: &Kp) -> String {
    Base64UrlUnpadded::encode_string(k.tmb.as_bytes())
}

/// Case 2 (one variant): the embedded chain of the red pin above; the
/// stitch at commit 2 has `PR_1 = {SHA-256}` and a SHA-512 arrow.
async fn case_two() -> Principal {
    let Embedded { mut a, alice, eve } = embedded().await;
    let diana = pool_kp("diana_es384");
    commit_as(
        &mut a,
        &eve,
        "key/create",
        &b64(&diana),
        Some(key_of(&diana)),
        T + 3,
    )
    .await
    .expect("eve creates the ES384 key");
    commit_as(&mut a, &diana, "key/delete", &b64(&alice), None, T + 4)
        .await
        .expect("the ES384 key retires alice");
    a
}

/// Case 3 (several variants, none the arrow's): A holds ES256 and ES384,
/// then B's Ed25519 key creates a fresh Ed25519 key (SHA-512 starts at
/// commit 3, `PR_2 = {SHA-256, SHA-384}`), which retires both: tip SHA-512.
async fn case_three() -> Principal {
    let Embedded { mut a, alice, eve } = embedded().await;
    let (diana, fresh) = (pool_kp("diana_es384"), kp(coz::Alg::Ed25519));
    commit_as(
        &mut a,
        &alice,
        "key/create",
        &b64(&diana),
        Some(key_of(&diana)),
        T + 2,
    )
    .await
    .expect("alice adds ES384");
    commit_as(
        &mut a,
        &eve,
        "key/create",
        &b64(&fresh),
        Some(key_of(&fresh)),
        T + 3,
    )
    .await
    .expect("eve adds an Ed25519 key");
    commit_as(&mut a, &fresh, "key/delete", &b64(&alice), None, T + 4)
        .await
        .expect("retire ES256");
    commit_as(&mut a, &fresh, "key/delete", &b64(&diana), None, T + 5)
        .await
        .expect("retire ES384");
    a
}

fn pre_algs(p: &Principal, before: usize) -> Vec<HashAlg> {
    p.commit_at(before)
        .expect("commit")
        .pr()
        .0
        .algorithms()
        .collect()
}

/// Commit 1 is one transaction of two cozies (`key/create` of an ES256 and
/// an ES384 key, SPEC 4.1 grouping); then the ES256 key retires the
/// genesis key, so index 0 is covered by SHA-512 alone and the walk must
/// stitch at the multi-coz commit.
async fn multi_coz(grouped: bool) -> Principal {
    let (a, b, c) = (
        kp(coz::Alg::Ed25519),
        kp(coz::Alg::ES256),
        kp(coz::Alg::ES384),
    );
    let mut p = genesis(&a).await;
    let tmb = |k: &Kp| Base64UrlUnpadded::encode_string(k.tmb.as_bytes());
    let mut scope = p.begin_commit();
    let sign = |typ: &str, id: String| {
        let mut pay = json!({"alg": a.alg, "id": id, "now": at(1), "tmb": tmb(&a),
                             "typ": format!("{AUTHORITY}/cyphr/{typ}")});
        pay.as_object_mut().expect("object").sort_keys();
        let v = serde_json::to_vec(&pay).expect("pay");
        let (sig, cad) = coz::sign_json(&v, &a.alg, &a.prv, &a.pubb).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, &a.alg).expect("czd");
        (v, sig, czd)
    };
    let verified = |scope: &cyphr::CommitScope<'_, _>, typ: &str, id: String, side| {
        let (v, sig, czd) = sign(typ, id);
        scope.verify(&v, &sig, czd, side).expect("verify")
    };
    if grouped {
        let group = vec![
            verified(&scope, "key/create", tmb(&b), Some(key_of(&b))),
            verified(&scope, "key/create", tmb(&c), Some(key_of(&c))),
        ];
        scope
            .apply_tx(group)
            .expect("one transaction of two cozies");
    } else {
        let key = verified(&scope, "key/create", tmb(&b), Some(key_of(&b)));
        scope.apply(key).expect("key/create");
        let nonce = format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[9; 32]));
        let nonce = verified(&scope, "nonce/create", nonce, None);
        scope
            .apply(nonce)
            .expect("a second transaction, of another typ");
    }
    scope
        .finalize_with_software(&signer(&a), at(1) + 1, AUTHORITY)
        .await
        .expect("commit");
    commit_key(&mut p, &b, "delete", &a, at(2)).await;
    data_commit(&mut p, &b, at(3)).await;
    p
}

/// A one-commit chain after genesis (`key/create` of an ES256 key) and
/// its honest wire bundle, with the keys.
async fn one_commit() -> (Kp, cyphr::replay::WireBundle) {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    let mut x = genesis(&a).await;
    commit_key(&mut x, &a, "create", &b, at(1)).await;
    (
        a,
        cyphr::replay::WireBundle::of_commit(x.commit_at(1).expect("commit")).expect("bundle"),
    )
}

/// `pay` signed by `by`, as a wire coz blob.
fn blob(by: &Kp, mut pay: serde_json::Value) -> Vec<u8> {
    pay.as_object_mut().expect("object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    serde_json::to_vec(&json!({"pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig)}))
        .expect("blob")
}

/// `n` commits with the rotation late (at `n - 4`), so a scan of history
/// before the stitch is as long as the chain.
async fn late(n: usize) -> Principal {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    let p = single_with((&a, &b), (0, n - 5, 3), None).await;
    assert_eq!(p.commit_count(), n);
    p
}

/// The principal as a client's record holds it: its log reopened from a
/// frontier, with the nodes of the last size only.
async fn detached(p: &Principal) -> Principal {
    p.fork()
        .await
        .expect("fork")
        .detach()
        .await
        .expect("detach")
}

fn log2_ceil(n: usize) -> u64 {
    u64::from(n.next_power_of_two().trailing_zeros())
}

/// `n` commits with the replace as the last one (index `n - 1`): every
/// probe of a bisection below it crosses exactly one stitch, at any n.
async fn replace_last(n: usize) -> Principal {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    let p = single_with((&a, &b), (0, n - 2, 0), None).await;
    assert_eq!(p.commit_count(), n);
    p
}

/// Genesis (Ed25519), a data commit, a replace to ES256 at 2, a data
/// commit, a replace to ES384 at 4, then `n - 5` data commits by the last
/// key: the walk from the tip to index 1 crosses two epoch starts but the
/// last epoch is as long as the chain.
async fn long_last_epoch(n: usize) -> Principal {
    let (a, b, c) = (
        kp(coz::Alg::Ed25519),
        kp(coz::Alg::ES256),
        kp(coz::Alg::ES384),
    );
    let mut p = genesis(&a).await;
    data_commit(&mut p, &a, at(1)).await;
    commit_key(&mut p, &a, "replace", &b, at(2)).await;
    data_commit(&mut p, &b, at(3)).await;
    commit_key(&mut p, &b, "replace", &c, at(4)).await;
    for k in 0..n - 5 {
        data_commit(&mut p, &c, at(5 + k)).await;
    }
    assert_eq!(p.commit_count(), n);
    p
}

/// A PR-level nonce create of `id` (a tagged string) by `by`, as a commit.
async fn commit_nonce_id(p: &mut Principal, by: &Kp, id: &str, now: i64) {
    let mut pay = json!({"alg": by.alg, "id": id, "now": now,
                         "tmb": Base64UrlUnpadded::encode_string(by.tmb.as_bytes()),
                         "typ": format!("{AUTHORITY}/cyphr/nonce/create")});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&v, &sig, czd, None).expect("nonce");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

/// F1's chain: Ed25519 genesis, a PR-level SHA-512 nonce `N` (the root of
/// a tree of two chosen fake leaves `l0`, `l1`), a replace to ES256, two
/// data commits. The stitch at the replace (commit 2) opens `PR_1`, whose
/// cells are `[SR, CR, N]`.
async fn nonce_chain(n: &[u8]) -> Principal {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    let mut p = genesis(&a).await;
    let id = format!("SHA-512:{}", Base64UrlUnpadded::encode_string(n));
    commit_nonce_id(&mut p, &a, &id, at(1)).await;
    commit_key(&mut p, &a, "replace", &b, at(2)).await;
    for k in 3..5 {
        data_commit(&mut p, &b, at(k)).await;
    }
    p
}

/// The fake leaves and `N = H_512(l0 || l1)`.
fn fake_leaves() -> ([u8; 64], [u8; 64], Vec<u8>) {
    let (l0, l1) = ([0x11u8; 64], [0x22u8; 64]);
    let n = HashAlg::Sha512.hash_bytes(&[l0.as_slice(), l1.as_slice()].concat());
    (l0, l1, n)
}

fn sha512_id() -> u64 {
    hash_alg_to_u64(HashAlg::Sha512)
}

fn cell_of(variants: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let m: std::collections::BTreeMap<u64, Vec<u8>> = variants.iter().cloned().collect();
    serde_json::to_vec(&m).expect("cell")
}

// ---- the certificate's wire, and verification helpers ----

fn jb(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

fn bytes_of(v: &Value) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(v.as_str().expect("a byte string")).expect("base64url")
}

fn set_bytes(v: &mut Value, b: &[u8]) {
    *v = json!(jb(b));
}

fn flip(v: &mut Value) {
    let mut b = bytes_of(v);
    b[0] ^= 1;
    set_bytes(v, &b);
}

/// A certificate's serde form. The only place that knows the wire.
#[derive(Clone)]
struct Wire(Value);

impl Wire {
    fn of(c: &Certificate) -> Self {
        Self(serde_json::to_value(c).expect("a certificate serializes"))
    }

    /// The parse a verifier does; a parse refusal reads as `Mismatch`.
    fn cert(&self) -> Result<Certificate, ProofError> {
        serde_json::from_value(self.0.clone())
            .map_err(|e| ProofError::Mismatch(format!("parse: {e}")))
    }

    fn stitches(&self) -> usize {
        self.0["stitches"].as_array().map_or(0, Vec::len)
    }

    fn stitch(&mut self, i: usize) -> &mut Value {
        &mut self.0["stitches"][i]
    }

    fn opening(&mut self, i: usize) -> &mut Value {
        &mut self.0["stitches"][i]["opening"]
    }

    fn terminal(&mut self) -> &mut Value {
        &mut self.0["terminal"]
    }

    fn top(&mut self) -> &mut Value {
        &mut self.0["top"]
    }

    fn len(&self) -> usize {
        serde_json::to_vec(&self.0).expect("bytes").len()
    }
}

fn wire_steps(steps: &[cyphr::eml::ProofStep]) -> Value {
    steps
        .iter()
        .map(|s| {
            json!({"position": s.position,
                   "siblings": s.siblings.iter().map(|x| jb(x)).collect::<Vec<_>>()})
        })
        .collect()
}

/// A terminal path in `alg`'s tree of `size` leaves, from the prover's
/// own log; `None` when the log has no such path (the prover refuses).
async fn wire_path(p: &Principal, alg: HashAlg, index: u64, size: u64) -> Option<Value> {
    let steps = match alg {
        HashAlg::Sha256 => p.log_path::<old::Sha256>(index, size).await.ok()?.steps,
        HashAlg::Sha384 => p.log_path::<old::Sha384>(index, size).await.ok()?.steps,
        HashAlg::Sha512 => p.log_path::<old::Sha512>(index, size).await.ok()?.steps,
    };
    Some(json!({"alg": alg.to_string(), "index": index, "size": size,
                "steps": wire_steps(&steps)}))
}

fn wire_consistency(alg: HashAlg, c: &cyphr::eml::ConsistencyProof) -> Value {
    json!({"alg": alg.to_string(), "boundary_hash": jb(&c.boundary_hash),
           "peak_path": wire_steps(&c.peak_path),
           "new_peaks": c.new_peaks.iter().map(|h| jb(h)).collect::<Vec<_>>(),
           "split_index": c.split_index})
}

fn n_of(p: &Principal) -> u64 {
    p.commit_count() as u64
}

fn keys() -> (Kp, Kp) {
    (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256))
}

/// The first `m` commits of a chain by `a` alone: genesis and data
/// commits, the same bytes as the head of any longer chain built the same.
async fn prefix(a: &Kp, m: usize) -> Principal {
    let mut p = genesis(a).await;
    for k in 1..m {
        data_commit(&mut p, a, at(k)).await;
    }
    p
}

async fn cert_m(p: &Principal, index: u64) -> Wire {
    Wire::of(&p.prove_membership(index, n_of(p)).await.expect("prove"))
}

async fn cert_e(p: &Principal, from: u64) -> Wire {
    Wire::of(&p.prove_extension(from, n_of(p)).await.expect("prove"))
}

fn member_with(
    anchor: &Anchor<'_>,
    size: u64,
    w: &Wire,
    index: u64,
    tr: &TransactionRoot,
) -> Result<(), ProofError> {
    verify_membership(anchor, &w.cert()?, size, index, tr)
}

/// Membership of the tip's commit `index` of `p`, against `anchor`.
fn member(anchor: &Anchor<'_>, p: &Principal, w: &Wire, index: u64) -> Result<(), ProofError> {
    member_with(anchor, n_of(p), w, index, tr_of(p, index))
}

/// ... as a holder of the chain.
fn chain_member(p: &Principal, w: &Wire, index: u64) -> Result<(), ProofError> {
    member(&Anchor::of_chain(p.state()), p, w, index)
}

/// ... as a thin client holding only the pinned tip root.
fn pin_member(p: &Principal, w: &Wire, index: u64) -> Result<(), ProofError> {
    member(&Anchor::pin(p.root_at(n_of(p)).expect("root")), p, w, index)
}

fn extends(holder: &Principal, w: &Wire, from: u64, head: &Root) -> Result<(), ProofError> {
    verify_extension(&Anchor::of_chain(holder.state()), &w.cert()?, from, head)
}

fn refused_at_parse_or_fold(r: &Result<(), ProofError>) -> bool {
    matches!(
        r,
        Err(ProofError::PtCell | ProofError::Path | ProofError::Mismatch(_))
    )
}

// ---- membership and extension across one replace ----

// The holder's chain is a prefix of the peer's; one stitch crosses the
// replace and the head is checked against what the holder pinned.
#[tokio::test]
async fn extension_across_a_replace_is_one_stitch() {
    let (a, b) = keys();
    let p = single_with((&a, &b), (0, 3, 3), None).await; // replace at 4, n = 8
    let holder = prefix(&a, 3).await;
    let head = p.root_at(8).expect("head");
    assert_eq!(
        holder.root_at(3),
        p.root_at(3),
        "setup: the holder's chain is the prefix"
    );
    let w = cert_e(&p, 3).await;
    assert_eq!(w.stitches(), 1, "one boundary crossed");
    assert_eq!(extends(&holder, &w, 3, &head), Ok(()));
}

// O(h (log n + c)): with one boundary, n = 8 -> 64 grows by the log term
// only, never linearly.
#[tokio::test]
async fn extension_proof_size_is_logarithmic_across_a_replace() {
    let (a, b) = keys();
    let mut len = Vec::new();
    for post in [3, 59] {
        let p = single_with((&a, &b), (0, 3, post), None).await;
        let w = cert_e(&p, 3).await;
        assert_eq!(w.stitches(), 1);
        len.push(w.len());
    }
    assert!(
        len[1] < 3 * len[0],
        "n=8: {} bytes, n=64: {}",
        len[0],
        len[1]
    );
}

// A thin client pins only the tip root; a chain holder anchors on its
// whole chain. Both reach every commit, the old era by one stitch.
#[tokio::test]
async fn an_old_era_commit_is_a_member_of_a_pinned_tip() {
    let p = single(3, 3).await; // A-era indices 0..=3, replace at 4
    for i in 0..8u64 {
        let w = cert_m(&p, i).await;
        assert_eq!(w.stitches(), usize::from(i < 4), "index {i}");
        assert_eq!(pin_member(&p, &w, i), Ok(()), "pinned, index {i}");
        assert_eq!(chain_member(&p, &w, i), Ok(()), "chain, index {i}");
    }
}

#[tokio::test]
async fn two_rotations_cost_two_stitches() {
    let (p, a) = double().await; // boundaries at 3 and 6, n = 9
    for i in 0..9u64 {
        let want = match i {
            0..=2 => 2,
            3..=5 => 1,
            _ => 0,
        };
        let w = cert_m(&p, i).await;
        assert_eq!(w.stitches(), want, "one hop per boundary, index {i}");
        assert_eq!(pin_member(&p, &w, i), Ok(()), "index {i}");
    }
    let holder = prefix(&a, 2).await;
    let w = cert_e(&p, 2).await;
    assert_eq!(w.stitches(), 2);
    let head = p.root_at(9).expect("head");
    assert_eq!(extends(&holder, &w, 2, &head), Ok(()));
}

#[tokio::test]
async fn a_commit_in_a_closed_familys_gap_is_provable() {
    let p = resume().await;
    for i in 0..n_of(&p) {
        let w = cert_m(&p, i).await;
        assert!(w.stitches() <= 2, "index {i}: {}", w.stitches());
        assert_eq!(pin_member(&p, &w, i), Ok(()), "index {i}");
    }
}

#[tokio::test]
async fn without_a_rotation_there_is_no_stitch() {
    let a = kp(coz::Alg::Ed25519);
    let p = prefix(&a, 8).await;
    for i in 0..8u64 {
        let w = cert_m(&p, i).await;
        assert_eq!(w.stitches(), 0, "index {i}");
        assert_eq!(pin_member(&p, &w, i), Ok(()));
        assert_eq!(chain_member(&p, &w, i), Ok(()));
    }
    let holder = prefix(&a, 3).await;
    let w = cert_e(&p, 3).await;
    assert_eq!(w.stitches(), 0);
    assert_eq!(
        extends(&holder, &w, 3, &p.root_at(8).expect("head")),
        Ok(())
    );
}

// The frame says the PT has exactly three cells; principal_tree.rs builds
// SR, CR and one cell per nonce (two for a nonce-less principal). What
// the cost argument needs is independence from n: with k nonces the same
// opening at n = 8 and n = 64.
#[tokio::test]
async fn the_opening_is_independent_of_the_log_length() {
    for k in [0usize, 3] {
        let (a, b) = keys();
        let mut shape = Vec::new();
        for n in [8usize, 64] {
            let p = single_with((&a, &b), (k, 2, n - k - 4), None).await;
            assert_eq!(p.commit_count(), n);
            let mut w = cert_m(&p, 1).await;
            let o = w.opening(0).clone();
            let cells: Vec<Vec<u8>> = o["pt_cells"]
                .as_array()
                .expect("cells")
                .iter()
                .map(bytes_of)
                .collect();
            shape.push((
                cells.len(),
                cells.iter().map(Vec::len).sum::<usize>(),
                o["tr_path"].as_array().expect("path").len(),
            ));
        }
        assert_eq!(shape[0], shape[1], "k = {k}: opening at n = 8 vs 64");
        assert_eq!(shape[0].0, 2 + k, "SR, CR and one cell per nonce");
    }
}

// ---- negatives ----

async fn genuine() -> (Principal, Wire) {
    let p = single(3, 3).await;
    let w = cert_m(&p, 2).await;
    assert_eq!(
        chain_member(&p, &w, 2),
        Ok(()),
        "control: the genuine certificate"
    );
    (p, w)
}

#[tokio::test]
async fn a_tampered_forward_state_root_is_refused() {
    let (p, mut w) = genuine().await;
    assert!(
        w.opening(0)["fwd_variants"][0].is_array(),
        "setup: the commit has a fwd"
    );
    flip(&mut w.opening(0)["fwd_variants"][0][1]);
    assert_eq!(chain_member(&p, &w, 2), Err(ProofError::Arrow));
    assert_eq!(pin_member(&p, &w, 2), Err(ProofError::Arrow));
}

#[tokio::test]
async fn a_tampered_pt_cell_is_refused() {
    let (p, mut w) = genuine().await;
    flip(&mut w.opening(0)["pt_cells"][1]); // the CR cell
    let r = chain_member(&p, &w, 2);
    assert!(
        matches!(r, Err(ProofError::PtCell | ProofError::Mismatch(_))),
        "{r:?}"
    );
}

// The Principal Tree opening at the head end is carried and checked: a
// cell of it that does not fold to the pinned PR is refused.
#[tokio::test]
async fn a_tampered_top_opening_is_refused() {
    let (p, mut w) = genuine().await;
    assert!(
        w.top()["pt_cells"].is_array(),
        "setup: the head end is opened"
    );
    flip(&mut w.top()["pt_cells"][0]);
    assert!(refused_at_parse_or_fold(&chain_member(&p, &w, 2)));
    assert!(refused_at_parse_or_fold(&pin_member(&p, &w, 2)));
}

#[tokio::test]
async fn another_principals_head_is_refused() {
    let (_, w) = genuine().await;
    let (other, _) = genuine().await;
    assert!(refused_at_parse_or_fold(&chain_member(&other, &w, 2)));
}

// A path under a family that was inactive at the position: the prover
// refuses, or its path hits a null leaf and the verifier refuses it.
#[tokio::test]
async fn a_path_under_an_inactive_family_is_refused() {
    let (p, mut w) = genuine().await;
    if let Some(path) = wire_path(&p, HashAlg::Sha256, 2, 8).await {
        w.0["stitches"] = json!([]);
        *w.terminal() = path;
        assert_eq!(chain_member(&p, &w, 2), Err(ProofError::Path));
    }
}

// A family absent at the holder's size: a SHA-256 consistency from 3, when
// the holder pinned a SHA-512 chain only, is refused at run time.
#[tokio::test]
async fn a_family_absent_at_the_old_size_is_refused() {
    let (a, b) = keys();
    let p = single_with((&a, &b), (0, 3, 3), None).await;
    let holder = prefix(&a, 3).await;
    let head = p.root_at(8).expect("head");
    let mut w = cert_e(&p, 3).await;
    assert_eq!(extends(&holder, &w, 3, &head), Ok(()), "control");
    if let Ok(c) = p.family_consistency::<old::Sha256>(3, 8).await {
        w.0["stitches"] = json!([]);
        *w.terminal() = wire_consistency(HashAlg::Sha256, &c.proof);
        assert_eq!(extends(&holder, &w, 3, &head), Err(ProofError::Family));
    }
}

/// The forger's tree for family SHA-512 over `size` leaves: the genuine
/// leaves below `m`, then (when `invent`) invented ones; its consistency
/// proof from `m`, in wire form.
async fn forged_consistency(p: &Principal, m: u64, size: u64, invent: bool) -> Value {
    let alg = hash_alg_to_u64(HashAlg::Sha512);
    let mut t = CommitTrees::open(cyphr::eml::MemoryStorage::new())
        .await
        .expect("open");
    t.add_algorithm(alg, Box::new(MaltHasher::new(HashAlg::Sha512)))
        .await
        .expect("register");
    for i in 0..size {
        let leaf = if i < m || !invent {
            p.commit_trees().get_leaf(i).await.expect("leaf")
        } else {
            // A well-formed leaf (a map with a SHA-512 variant) that is not
            // the genuine one: a malformed leaf hashes to null, which eml
            // cannot build a consistency proof over.
            let variants = std::collections::BTreeMap::from([(alg, vec![i as u8 + 1; 64])]);
            serde_json::to_vec(&variants).expect("invented leaf")
        };
        t.append(&leaf).await.expect("append");
    }
    if !invent {
        let genuine = p.commit_trees().root_at(alg, size).await.expect("root");
        assert_eq!(
            t.root(alg).expect("root"),
            genuine,
            "the construction is faithful"
        );
    }
    wire_consistency(
        HashAlg::Sha512,
        &t.consistency_proof(alg, m).await.expect("consistency"),
    )
}

// E4.1: the forger shares the trusted prefix below m, invents leaves
// m..j-1 and ends with the genuine leaf j. Its SHA-512 consistency from m
// is internally sound; the stitch's CR_{j-1}[SHA-512] is what it fails.
#[tokio::test]
async fn the_forgers_alternate_history_is_refused() {
    let (a, b) = keys();
    let p = single_with((&a, &b), (0, 3, 3), None).await; // j = 4
    let holder = prefix(&a, 2).await;
    let head = p.root_at(8).expect("head");
    let mut w = cert_e(&p, 2).await;
    assert_eq!(w.stitches(), 1);
    // Control first: the faithful tree's proof is the genuine one.
    *w.terminal() = forged_consistency(&p, 2, 4, false).await;
    assert_eq!(
        extends(&holder, &w, 2, &head),
        Ok(()),
        "control: genuine leaves"
    );
    *w.terminal() = forged_consistency(&p, 2, 4, true).await;
    assert_eq!(
        extends(&holder, &w, 2, &head),
        Err(ProofError::NotAnExtension)
    );
}

// Every test above hands the verifier the matching TR, so a verifier that
// never hashes `tr` into the leaf would pass them all.
#[tokio::test]
async fn a_certificate_does_not_vouch_for_another_commits_tr() {
    let (p, w) = genuine().await;
    for j in [0u64, 1, 3, 5, 7] {
        let r = member_with(&Anchor::of_chain(p.state()), 8, &w, 2, tr_of(&p, j));
        assert!(
            matches!(r, Err(ProofError::Mismatch(_))),
            "tr of {j}: {r:?}"
        );
    }
    let other = single(3, 3).await; // the same position of another chain
    let r = member_with(&Anchor::of_chain(p.state()), 8, &w, 2, tr_of(&other, 2));
    assert!(
        matches!(r, Err(ProofError::Mismatch(_))),
        "foreign tr: {r:?}"
    );
}

// The genuine leaf path for one commit with the genuine opening of
// another: each part checks alone, only the binding refuses it.
#[tokio::test]
async fn a_spliced_opening_is_refused() {
    let (p, _) = double().await;
    let mut w = cert_m(&p, 1).await;
    assert_eq!(w.stitches(), 2);
    assert_eq!(chain_member(&p, &w, 1), Ok(()), "control");
    let (first, second) = (w.opening(0).clone(), w.opening(1).clone());
    *w.opening(0) = second;
    *w.opening(1) = first;
    assert!(chain_member(&p, &w, 1).is_err());
}

// A commit's arrow is on its last coz; the replace coz before it carries
// none and is a genuine coz of the same commit.
#[tokio::test]
async fn an_opening_through_a_coz_other_than_the_closing_one_is_refused() {
    let (p, mut w) = genuine().await; // replace at 4
    let blobs: Vec<Vec<u8>> = cyphr::replay::WireBundle::of_commit(p.commit_at(4).expect("commit"))
        .expect("bundle")
        .cozies()
        .map(<[u8]>::to_vec)
        .collect();
    assert!(
        blobs.len() >= 2,
        "a replace commit has its coz and a closing coz"
    );
    assert_eq!(bytes_of(&w.opening(0)["coz"]), blobs[blobs.len() - 1]);
    set_bytes(&mut w.opening(0)["coz"], &blobs[0]);
    assert_eq!(chain_member(&p, &w, 2), Err(ProofError::Arrow));
}

// A genuine, signed fork that diverges at f = 2, below the trusted size
// m = 3, and its own honest certificate. Every signature and stitch is
// real; the holder's CR_3 is simply not a prefix of it.
#[tokio::test]
async fn a_real_fork_below_the_trusted_size_is_refused() {
    let (a, b) = keys();
    let x = single_with((&a, &b), (0, 3, 3), None).await;
    let y = single_with((&a, &b), (0, 3, 3), Some(2)).await;
    assert_eq!(
        tr_of(&x, 1),
        tr_of(&y, 1),
        "they share the first two commits"
    );
    assert_ne!(tr_of(&x, 2), tr_of(&y, 2), "and part at commit 2");
    let holder = prefix(&a, 3).await; // the shared head of x
    let honest = cert_e(&x, 3).await;
    assert_eq!(
        extends(&holder, &honest, 3, &x.root_at(8).expect("head")),
        Ok(()),
        "control: its own chain"
    );
    let forked = cert_e(&y, 3).await;
    let r = extends(&holder, &forked, 3, &y.root_at(8).expect("head"));
    assert_eq!(r, Err(ProofError::NotAnExtension));
}

// The API derives the sizes and never trusts a size the certificate
// states: a stated size other than the implied one is refused.
#[tokio::test]
async fn a_size_the_certificate_states_wrongly_is_refused() {
    let (p, genuine) = genuine().await; // tip 8; the SHA-512 tree closes at 4
    let mut at_anchor = genuine.clone();
    at_anchor.stitch(0)["leaf"]["size"] = json!(9);
    let mut at_cr = genuine;
    at_cr.terminal()["size"] = json!(5);
    for (what, bad) in [("anchor size", at_anchor), ("CR size", at_cr)] {
        let r = chain_member(&p, &bad, 2);
        assert!(
            matches!(r, Err(ProofError::Mismatch(_) | ProofError::Path)),
            "{what}: {r:?}"
        );
    }
}

#[tokio::test]
async fn the_stitch_list_cannot_be_edited_into_a_false_certificate() {
    // Dropping the only stitch of an index only the retired family covers.
    let (p, mut dropped) = genuine().await;
    dropped.0["stitches"] = json!([]);
    assert!(
        chain_member(&p, &dropped, 2).is_err(),
        "the tip has no SHA-512 root"
    );

    // Inserting a genuine extra stitch (taken from a longer certificate):
    // whatever is accepted must not prove any other (index, TR).
    let (d, _) = double().await;
    let long = cert_m(&d, 1).await;
    for i in [1u64, 4, 7] {
        let base = cert_m(&d, i).await;
        for extra in long.0["stitches"].as_array().expect("stitches") {
            let (mut front, mut back) = (base.clone(), base.clone());
            front.0["stitches"]
                .as_array_mut()
                .expect("list")
                .insert(0, extra.clone());
            back.0["stitches"]
                .as_array_mut()
                .expect("list")
                .push(extra.clone());
            for (what, w) in [("front", front), ("back", back)] {
                for j in (0..9u64).filter(|&j| j != i) {
                    let r = member_with(&Anchor::of_chain(d.state()), 9, &w, j, tr_of(&d, j));
                    assert!(r.is_err(), "{what} extra on {i} proved {j}");
                }
            }
        }
    }
}

// ---- E5: a stitch authenticates the signer's family only ----

// PR_{s-1}[G] binds CR_{s-1}[G] alone, so the stitch trusts the signer's
// family (A) and no other variant of the CR cell. Rewriting C's variant
// in the cell changes nothing; continuing the walk in C is refused.
#[tokio::test]
async fn a_stitch_trusts_only_the_signers_family() {
    let p = three_families().await;
    let mut w = cert_m(&p, 0).await;
    assert_eq!(w.stitches(), 1, "B starts at 2; index 0 is A's");
    assert_eq!(chain_member(&p, &w, 0), Ok(()), "control");

    let cell = &mut w.opening(0)["pt_cells"][1];
    let mut variants: std::collections::BTreeMap<u64, Vec<u8>> =
        serde_json::from_slice(&bytes_of(cell)).expect("the CR cell is a map of variants");
    variants
        .get_mut(&hash_alg_to_u64(HashAlg::Sha384))
        .expect("CR_1 carries C")
        .fill(7);
    set_bytes(cell, &serde_json::to_vec(&variants).expect("cell"));
    assert_eq!(
        chain_member(&p, &w, 0),
        Ok(()),
        "a non-signer variant is ignored, not checked"
    );

    // Continue in C from the same stitch: C's tree at size 2 holds leaf 1.
    *w.terminal() = wire_path(&p, HashAlg::Sha384, 1, 2)
        .await
        .expect("C's path");
    let r = member_with(&Anchor::of_chain(p.state()), 7, &w, 1, tr_of(&p, 1));
    assert_eq!(r, Err(ProofError::Family));
}

// F2 (E8.5), structurally: no API returns an Anchor or Root from a
// certificate, so nothing a peer added can be vouched for. The runtime
// half: a keyless forger's SHA-256 tree around the genuine leaf 4 with
// invented leaves after it fails against the holder's own chain.
#[tokio::test]
async fn a_fabricated_tree_vouches_for_nothing_it_added() {
    let (a, b) = keys();
    let p = single_with((&a, &b), (0, 3, 3), None).await; // the replace is commit 4
    let (b_id, a_id) = (
        hash_alg_to_u64(HashAlg::Sha256),
        hash_alg_to_u64(HashAlg::Sha512),
    );
    let mut t = CommitTrees::open(cyphr::eml::MemoryStorage::new())
        .await
        .expect("open");
    t.add_algorithm(a_id, Box::new(MaltHasher::new(HashAlg::Sha512)))
        .await
        .expect("register");
    for i in 0..4 {
        t.append(&p.commit_trees().get_leaf(i).await.expect("leaf"))
            .await
            .expect("append");
    }
    t.add_algorithm(b_id, Box::new(MaltHasher::new(HashAlg::Sha256)))
        .await
        .expect("register");
    t.append(&p.commit_trees().get_leaf(4).await.expect("leaf"))
        .await
        .expect("append");
    for i in 5..8u64 {
        let v = std::collections::BTreeMap::from([(b_id, vec![i as u8 + 1; 32])]);
        t.append(&serde_json::to_vec(&v).expect("leaf"))
            .await
            .expect("append");
    }
    let mut w = cert_m(&p, 5).await;
    assert_eq!(chain_member(&p, &w, 5), Ok(()), "control");
    let forged = t.inclusion_proof(b_id, 6).await.expect("forged path");
    *w.terminal() = json!({"alg": HashAlg::Sha256.to_string(), "index": 6, "size": 8,
                           "steps": wire_steps(&forged.path)});
    let invented = TransactionRoot(
        cyphr::multihash::MultihashDigest::from_single(HashAlg::Sha256, vec![7u8; 32])
            .expect("digest"),
    );
    let r = member_with(&Anchor::of_chain(p.state()), 8, &w, 6, &invented);
    assert_eq!(r, Err(ProofError::Path));
    // And a head the certificate does not open is no extension.
    let holder = prefix(&a, 3).await;
    let honest = cert_e(&p, 3).await;
    let other = single(3, 3).await;
    let r = extends(&holder, &honest, 3, &other.root_at(8).expect("head"));
    assert!(refused_at_parse_or_fold(&r), "{r:?}");
}

// ---- conversion cases: what the arrow's `pre` binds ----

// Case 3: the arrow binds the hash of every PR_{s-1} variant, so the
// stitch yields both SHA-256 and SHA-384 roots, supplied whole.
#[tokio::test]
async fn a_stitch_through_a_concatenated_pre_yields_every_family() {
    let a = case_three().await;
    assert_eq!(
        pre_algs(&a, 2),
        [HashAlg::Sha256, HashAlg::Sha384],
        "setup: PR_2 has two variants and no SHA-512 (case 3)"
    );
    let mut w = cert_m(&a, 0).await;
    assert_eq!(w.stitches(), 1);
    let supplied: Vec<String> = w.opening(0)["pre_variants"]
        .as_array()
        .expect("pre variants")
        .iter()
        .map(|v| v[0].as_str().expect("alg").to_owned())
        .collect();
    assert_eq!(
        supplied,
        [HashAlg::Sha256.to_string(), HashAlg::Sha384.to_string()]
    );
    for i in 0..n_of(&a) {
        let w = cert_m(&a, i).await;
        assert_eq!(pin_member(&a, &w, i), Ok(()), "index {i}");
    }
}

#[tokio::test]
async fn a_tampered_variant_in_the_concatenated_pre_is_refused() {
    let a = case_three().await;
    let mut w = cert_m(&a, 0).await;
    assert_eq!(chain_member(&a, &w, 0), Ok(()), "control");
    flip(&mut w.opening(0)["pre_variants"][1][1]);
    assert_eq!(chain_member(&a, &w, 0), Err(ProofError::Arrow));
}

// Case 2 becomes case 3 when `pre` carries a second variant: the
// conversion changes, so the arrow no longer recomputes.
#[tokio::test]
async fn an_invented_extra_variant_in_a_single_variant_pre_is_refused() {
    let a = case_two().await;
    assert_eq!(
        pre_algs(&a, 1),
        [HashAlg::Sha256],
        "setup: PR_1 is single-variant (case 2)"
    );
    let mut w = cert_m(&a, 0).await;
    assert_eq!(chain_member(&a, &w, 0), Ok(()), "control");
    let o = w.opening(0);
    assert_eq!(o["pre_variants"].as_array().expect("variants").len(), 1);
    o["pre_variants"]
        .as_array_mut()
        .expect("variants")
        .push(json!([HashAlg::Sha384.to_string(), jb(&[9; 48])]));
    assert_eq!(chain_member(&a, &w, 0), Err(ProofError::Arrow));
}

// Case 3 becomes case 2: dropping a variant from the concatenated pre
// changes the conversion (one variant is promoted as is).
#[tokio::test]
async fn a_variant_dropped_from_the_concatenated_pre_is_refused() {
    let a = case_three().await;
    let mut w = cert_m(&a, 0).await;
    assert_eq!(chain_member(&a, &w, 0), Ok(()), "control");
    let list = w.opening(0)["pre_variants"]
        .as_array_mut()
        .expect("variants");
    assert_eq!(list.len(), 2);
    list.remove(1);
    assert_eq!(chain_member(&a, &w, 0), Err(ProofError::Arrow));
}

// Case 1 becomes case 2: PR_1 has the arrow's family (SHA-512) and
// another (SHA-384). Supplying only the genuine SHA-384 variant presents
// a single-variant pre, which promotes SHA-384's bytes.
#[tokio::test]
async fn a_case_one_pre_reduced_to_a_non_signer_variant_is_refused() {
    let p = three_families().await;
    let mut algs = pre_algs(&p, 1);
    algs.sort();
    assert_eq!(
        algs,
        [HashAlg::Sha384, HashAlg::Sha512],
        "setup: PR_1 has the arrow's SHA-512 and SHA-384 (case 1)"
    );
    let genuine = p
        .commit_at(1)
        .expect("commit")
        .pr()
        .0
        .get(HashAlg::Sha384)
        .expect("variant");
    let mut w = cert_m(&p, 0).await;
    assert_eq!(chain_member(&p, &w, 0), Ok(()), "control");
    w.opening(0)["pre_variants"] = json!([[HashAlg::Sha384.to_string(), jb(genuine)]]);
    assert_eq!(chain_member(&p, &w, 0), Err(ProofError::Arrow));
}

// Variants supplied out of sorted order: refused, or the same roots and
// so the same true certificate; it never proves another (index, TR).
#[tokio::test]
async fn a_reordered_concatenated_pre_proves_only_the_truth() {
    let a = case_three().await;
    let mut w = cert_m(&a, 0).await;
    assert_eq!(chain_member(&a, &w, 0), Ok(()), "control");
    w.opening(0)["pre_variants"]
        .as_array_mut()
        .expect("variants")
        .reverse();
    for j in 1..n_of(&a) {
        assert!(chain_member_as(&a, &w, 0, j).is_err(), "proved {j}");
    }
}

/// Claim index `claimed` with the TR of commit `claimed`, on a certificate
/// built for `built`.
fn chain_member_as(p: &Principal, w: &Wire, _built: u64, claimed: u64) -> Result<(), ProofError> {
    member(&Anchor::of_chain(p.state()), p, w, claimed)
}

// The verifier takes each arrow component's width from the declared
// variants and never infers it from the preimage: moving one byte from
// the start of `fwd` to the end of `pre` keeps the concatenation, so the
// arrow recomputes, and only the declared widths can refuse it.
#[tokio::test]
async fn a_pre_fwd_boundary_shifted_inside_the_preimage_is_refused() {
    let (p, mut w) = genuine().await; // the replace at 4: pre 64 bytes, fwd 32
    let o = w.opening(0);
    let (pre, fwd) = (
        bytes_of(&o["pre_variants"][0][1]),
        bytes_of(&o["fwd_variants"][0][1]),
    );
    assert_ne!(pre.len(), fwd.len(), "setup: unequal widths");
    set_bytes(
        &mut o["pre_variants"][0][1],
        &[pre.as_slice(), &fwd[..1]].concat(),
    );
    set_bytes(&mut o["fwd_variants"][0][1], &fwd[1..]);
    let r = chain_member(&p, &w, 2);
    assert!(
        matches!(
            r,
            Err(ProofError::Arrow | ProofError::Mismatch(_) | ProofError::PtCell)
        ),
        "{r:?}"
    );
    let r = pin_member(&p, &w, 2);
    assert!(r.is_err(), "{r:?}");
}

// SPEC 3.7 omits an empty component, so a two-component arrow is
// [pre, fwd] or [pre, TMR] and must not be misread. fwd is absent when a
// commit leaves no key and no data; TMR is null only for a commit with no
// mutation, which admission refuses (so that case cannot arise). Green by
// design: the arrow of every commit is the ordered hash of its components.
#[tokio::test]
async fn a_two_component_arrow_is_not_misread() {
    use cyphr::state::TaggedCzd;
    use cyphr::transaction_root::{compute_tmr, compute_tx};
    let expected = |p: &Principal, i: usize, g: HashAlg| -> Vec<u8> {
        let (c, prev) = (
            p.commit_at(i).expect("commit"),
            p.commit_at(i - 1).expect("prev"),
        );
        let mut cat = prev.pr().0.arrow_component_bytes(g).expect("pre").to_vec();
        if let Some(sr) = c.sr() {
            cat.extend(sr.0.arrow_component_bytes(g).expect("fwd").as_ref());
        }
        let txs = c.transactions();
        let mds: Vec<_> = txs[..txs.len() - 1]
            .iter()
            .map(|tx| {
                let czds: Vec<_> =
                    tx.0.iter()
                        .map(|z| TaggedCzd::new(z.czd(), z.hash_alg()))
                        .collect();
                compute_tx(&czds, &[g]).expect("tx root")
            })
            .collect();
        let tmr = compute_tmr(&mds.iter().collect::<Vec<_>>(), &[g]).expect("tmr");
        cat.extend(tmr.0.arrow_component_bytes(g).expect("tmr").as_ref());
        g.hash_bytes(&cat)
    };
    let check = |p: &Principal, i: usize| {
        let z = p.commit_at(i).expect("commit").commit_tx().0[0].clone();
        let g = z.hash_alg();
        assert_eq!(
            z.arrow().expect("arrow").get(g),
            Some(expected(p, i, g).as_slice()),
            "commit {i}"
        );
    };
    let normal = single(3, 3).await;
    for i in 1..8 {
        check(&normal, i);
    }
    // A commit that leaves no key: fwd is absent, the arrow is [pre, TMR].
    let a = kp(coz::Alg::Ed25519);
    let mut dead = prefix(&a, 1).await; // no data, so no State Root once the key goes
    commit_key(&mut dead, &a, "delete", &a, at(1)).await;
    assert!(
        dead.commit_at(1).expect("commit").sr().is_none(),
        "setup: no forward SR"
    );
    check(&dead, 1);
    // A commit with no mutation is refused, so a null TMR cannot occur.
    let mut p = prefix(&a, 2).await;
    let scope = p.begin_commit();
    let r = scope
        .finalize_with_software(&signer(&a), at(2), AUTHORITY)
        .await;
    assert!(r.is_err(), "a commit with no mutation was admitted");
}

// ---- multi-coz commits ----

// A commit with several cozies must be provable like any other: the
// stitch opens the TR path to the closing coz whatever the shape of the
// commit's transactions, one grouped transaction of two cozies or
// several transactions of one (cozies of one typ are grouped at finalize).
#[tokio::test]
async fn a_stitch_at_a_multi_coz_commit_is_provable() {
    for grouped in [true, false] {
        let p = multi_coz(grouped).await;
        let txs = p.commit_at(1).expect("commit").transactions();
        assert_eq!(
            txs.iter().map(|t| t.0.len()).collect::<Vec<_>>(),
            if grouped { vec![2, 1] } else { vec![1, 1, 1] },
            "setup: commit 1 transactions (the last is the closing coz)"
        );
        for i in 0..n_of(&p) {
            let w = cert_m(&p, i).await;
            assert_eq!(pin_member(&p, &w, i), Ok(()), "grouped={grouped} index {i}");
        }
    }
}

// SPEC 4.3 allows a commit transaction of several cozies (then `seq` is
// required), and the stitch prover refuses one (proof.rs `let [closing]`).
// Such a commit cannot be built, because admission refuses every shape:
// a non-last commit/create coz has no arrow and is a malformed payload
// (with or without `seq`), and one that has an arrow is not last. So the
// prover's refusal is unreachable, and `seq` is never the reason for a
// refusal. Green characterization of today's admission, for the
// downstream-vs-SPEC 4.3 question: revise it if admission changes.
#[tokio::test]
async fn a_commit_transaction_of_several_cozies_is_refused_at_admission() {
    let (a, honest) = one_commit().await;
    let closing: serde_json::Value = serde_json::from_slice(
        honest
            .txs
            .last()
            .and_then(|t| t.last())
            .expect("closing coz"),
    )
    .expect("blob");
    for (shape, seq, first_arrow, want) in [
        (
            "two cozies, no seq",
            false,
            false,
            cyphr::Error::MalformedPayload,
        ),
        (
            "two cozies with seq 0/1 and 1/1",
            true,
            false,
            cyphr::Error::MalformedPayload,
        ),
        (
            "two cozies each with an arrow",
            true,
            true,
            cyphr::Error::CommitNotLast,
        ),
    ] {
        let (mut first, mut last) = (closing["pay"].clone(), closing["pay"].clone());
        if !first_arrow {
            first.as_object_mut().expect("object").remove("arrow");
        }
        if seq {
            first["seq"] = json!("0/1");
            last["seq"] = json!("1/1");
        }
        let mut bundle = honest.clone();
        *bundle.txs.last_mut().expect("tx") = vec![blob(&a, first), blob(&a, last)];
        let mut y = genesis(&a).await;
        let r = cyphr::replay::replay_bundle(&mut y, &bundle.decode().expect("decodes")).await;
        let e = r.expect_err(shape);
        assert_eq!(format!("{:?}", e.source), format!("{want:?}"), "{shape}");
    }
}

// What apply.rs uses of the commit transaction: `commit_genesis` returns
// `commit_tx().0.first()` as the closing coz, and `stage_commit` checks the
// arrow on the last coz of all. On a multi-coz commit transaction they
// would name different cozies; they do not disagree observably today,
// because every admitted commit transaction is exactly one coz, the one
// carrying the arrow. This pins that (no choice between the two is made).
#[tokio::test]
async fn first_and_last_of_the_commit_transaction_coincide_on_every_admitted_commit() {
    let a = kp(coz::Alg::Ed25519);
    let mut g = Principal::implicit(key_of(&a)).await.expect("open");
    let cozies = g
        .commit_genesis(&signer(&a), &[], T, AUTHORITY)
        .await
        .expect("genesis");
    let tx = &g.commit_at(0).expect("genesis commit").commit_tx().0;
    assert_eq!(
        cozies.last().expect("closing"),
        &serde_json::to_value(tx[0].raw()).expect("raw"),
        "commit_genesis returns the commit transaction's first coz as the closing one"
    );
    let chains = [
        single(3, 3).await,
        double().await.0,
        multi_coz(true).await,
        g,
    ];
    for p in &chains {
        for i in 0..p.commit_count() {
            let tx = &p.commit_at(i).expect("commit").commit_tx().0;
            let last = p
                .commit_at(i)
                .expect("commit")
                .iter_all_cozies()
                .last()
                .expect("a coz");
            assert_eq!(tx.len(), 1, "commit {i}: the commit transaction is one coz");
            assert_eq!(
                tx.first().expect("coz").czd(),
                tx.last().expect("coz").czd()
            );
            assert_eq!(
                tx[0].czd(),
                last.czd(),
                "commit {i}: it is the last coz of all"
            );
            assert!(
                tx[0].arrow().is_some(),
                "commit {i}: and it carries the arrow"
            );
        }
    }
}

// ---- embedded signers (E6) ----

// A stitch at a commit signed by such an embedded key: eve creates an ES384
// key (SHA-384 starts at commit 2), the ES384 key deletes alice (SHA-256
// closes), so index 0 is covered by SHA-256 only and the walk from the
// SHA-384 tip must stitch at commit 2, whose arrow family (SHA-512) is in
// no CR.
#[tokio::test]
async fn a_stitch_at_an_embedded_signers_commit_still_reaches_old_history() {
    let Embedded { mut a, alice, eve } = embedded().await;
    let diana = pool_kp("diana_es384");
    commit_as(
        &mut a,
        &eve,
        "key/create",
        &b64(&diana),
        Some(key_of(&diana)),
        T + 3,
    )
    .await
    .expect("eve creates the ES384 key");
    commit_as(&mut a, &diana, "key/delete", &b64(&alice), None, T + 4)
        .await
        .expect("the ES384 key retires alice");
    for k in 0..2 {
        let id = format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[k + 1; 32]));
        commit_as(
            &mut a,
            &diana,
            "nonce/create",
            &id,
            None,
            T + 5 + i64::from(k),
        )
        .await
        .expect("a commit by the ES384 key");
    }
    for i in 0..n_of(&a) {
        let w = cert_m(&a, i).await;
        assert_eq!(
            pin_member(&a, &w, i),
            Ok(()),
            "index {i} through an embedded stitch"
        );
        assert_eq!(
            chain_member(&a, &w, i),
            Ok(()),
            "index {i}, holding the chain"
        );
    }
}

// ---- compute bounds, at n = 8 against n = 40 or 128 (u3_bounds style) ----

// Bound: the holder's root at an earlier size is a read of what the commit
// stores (PR at size - 1), on a detached record too: no refold of the
// commits, at most one commit read.
#[tokio::test]
async fn a_root_at_an_earlier_size_is_a_read_not_a_refold() {
    for n in [8usize, 40] {
        let d = detached(&late(n).await).await;
        let (h0, r0) = (cyphr::probe::hashes(), cyphr::probe::commits_read());
        d.root_at((n / 2) as u64).expect("a root at n / 2");
        let (hashes, read) = (
            cyphr::probe::hashes() - h0,
            cyphr::probe::commits_read() - r0,
        );
        assert!(hashes <= 4 * log2_ceil(n) + 4, "n={n}: {hashes} hashes");
        assert!(read <= 1, "n={n}: {read} commits read");
    }
}

// Bound: the server's certificate for an old commit across the rotation
// reads O(log n) commits, not every earlier one.
#[tokio::test]
async fn a_stitch_opening_does_not_scan_history() {
    for n in [8usize, 40] {
        let p = late(n).await;
        let before = cyphr::probe::commits_read();
        p.prove_membership(0, n as u64).await.expect("prove");
        let read = cyphr::probe::commits_read() - before;
        let cap = 2 * log2_ceil(n) + 8;
        assert!(read <= cap, "n={n}: {read} commits read, cap {cap}");
    }
}

// Bound: a fork search across the rotation, run as locate_fork runs it (a
// bisection over the overlap, each probe the peer's certificate from there
// and its verification against the record), costs hashes and commit
// reads, client and server together, that grow as log^2 n. With the replace
// last, every probe needs one stitch at every n, so 128 against 8 commits
// is (7/3)^2 = 5.4x for log^2, capped at 11x. Linear per-probe work is
// (128 x 7) / (8 x 3) = 37x and trips it.
#[tokio::test]
async fn a_fork_search_across_a_rotation_costs_polylog_work() {
    let mut work = Vec::new();
    for n in [8usize, 128] {
        let peer = replace_last(n).await;
        let record = detached(&peer).await;
        let head = peer.root_at(n as u64).expect("head");
        let fork = n / 2;
        let before = (cyphr::probe::hashes(), cyphr::probe::commits_read());
        let (mut low, mut high) = (0usize, n);
        while high - low > 1 {
            let mid = low + (high - low) / 2;
            let w = Wire::of(
                &peer
                    .prove_extension(mid as u64, n as u64)
                    .await
                    .expect("the peer's certificate"),
            );
            assert_eq!(w.stitches(), 1, "n={n}, probe {mid}: one stitch");
            assert_eq!(extends(&record, &w, mid as u64, &head), Ok(()));
            if mid <= fork {
                low = mid;
            } else {
                high = mid;
            }
        }
        work.push(cyphr::probe::hashes() - before.0 + cyphr::probe::commits_read() - before.1);
    }
    assert!(
        work[1] <= 11 * work[0],
        "work at n=8: {}, at n=128: {}",
        work[0],
        work[1]
    );
}

// Bound: planning the walk to an old commit reads O(log n) commits, not
// the whole epoch of the family the tip is in.
#[tokio::test]
async fn planning_a_walk_does_not_scan_the_last_epoch() {
    for n in [8usize, 128] {
        let p = long_last_epoch(n).await;
        let before = cyphr::probe::commits_read();
        let c = p.prove_membership(1, n as u64).await.expect("prove");
        let read = cyphr::probe::commits_read() - before;
        assert_eq!(
            Wire::of(&c).stitches(),
            2,
            "n={n}: two epoch starts crossed"
        );
        let cap = 2 * log2_ceil(n) + 8;
        assert!(read <= cap, "n={n}: {read} commits read, cap {cap}");
    }
}

// ---- security review: F1 (framing), roles, F3 and F4 (bounds) ----

fn cell_maps(o: &Value) -> Vec<std::collections::BTreeMap<u64, Vec<u8>>> {
    o["pt_cells"]
        .as_array()
        .expect("cells")
        .iter()
        .map(|c| serde_json::from_slice(&bytes_of(c)).expect("a cell is a map of variants"))
        .collect()
}

fn cells_json(cells: &[Vec<u8>]) -> Value {
    cells.iter().map(|c| json!(jb(c))).collect()
}

// F1, the cell re-partition forgery: the PT fold concatenates the cells'
// variants with no framing, so `[SR, CR, N]` and `[SR||CR, N, ""]` fold to
// the same PR. The forged stitch reads N as `CR_1[SHA-512]`; N is the root
// of two leaves the forger chose, so it forges membership of a TR that no
// commit holds at index 0. The parse or the verifier must frame the cells.
#[tokio::test]
async fn a_repartitioned_pt_opening_forges_nothing() {
    let (l0, l1, n) = fake_leaves();
    let p = nonce_chain(&n).await;
    let mut w = cert_m(&p, 0).await;
    assert_eq!(
        chain_member(&p, &w, 0),
        Ok(()),
        "control: the genuine certificate"
    );

    let cells = cell_maps(w.opening(0));
    assert_eq!(cells.len(), 3, "setup: SR, CR and the nonce");
    assert_eq!(cells[2][&sha512_id()], n, "setup: the nonce cell holds N");
    let (sr, cr) = (&cells[0][&sha512_id()], &cells[1][&sha512_id()]);
    w.opening(0)["pt_cells"] = cells_json(&[
        cell_of(&[(sha512_id(), [sr.as_slice(), cr.as_slice()].concat())]),
        cell_of(&[(sha512_id(), n.clone())]),
        cell_of(&[(sha512_id(), Vec::new())]),
    ]);
    assert_eq!(
        (
            w.terminal()["index"].as_u64(),
            w.terminal()["size"].as_u64()
        ),
        (Some(0), Some(2)),
        "setup: leaf 0 of CR_1"
    );
    w.terminal()["steps"][0]["siblings"][0] = json!(jb(&l1));
    let forged = TransactionRoot(
        cyphr::multihash::MultihashDigest::from_single(HashAlg::Sha512, l0.to_vec())
            .expect("digest"),
    );
    let r = member_with(&Anchor::of_chain(p.state()), n_of(&p), &w, 0, &forged);
    assert!(
        matches!(r, Err(ProofError::PtCell | ProofError::Mismatch(_))),
        "a TR nobody committed was accepted: {r:?}"
    );
}

// Every cell must carry exactly the family's width, and the cell count
// must be what the PR implies (SR, CR and one per nonce): an extra empty
// cell, or a nonce cut in two, fold to the same PR and must be refused.
#[tokio::test]
async fn cells_of_the_wrong_count_or_width_are_refused() {
    let (_, _, n) = fake_leaves();
    let p = nonce_chain(&n).await;
    let genuine = cert_m(&p, 0).await;
    assert_eq!(chain_member(&p, &genuine, 0), Ok(()), "control");
    let n = cell_maps(&genuine.0["stitches"][0]["opening"])[2][&sha512_id()].clone();
    let empty = cell_of(&[(sha512_id(), Vec::new())]);
    for (what, keep, extra) in [
        ("an extra empty cell", 3, vec![empty]),
        (
            "the nonce cut in two",
            2,
            vec![
                cell_of(&[(sha512_id(), n[..30].to_vec())]),
                cell_of(&[(sha512_id(), n[30..].to_vec())]),
            ],
        ),
    ] {
        let mut w = genuine.clone();
        let mut cells: Vec<Vec<u8>> = w.opening(0)["pt_cells"]
            .as_array()
            .expect("cells")
            .iter()
            .map(bytes_of)
            .collect();
        cells.truncate(keep);
        cells.extend(extra);
        w.opening(0)["pt_cells"] = cells_json(&cells);
        let r = chain_member(&p, &w, 0);
        assert!(
            matches!(r, Err(ProofError::PtCell | ProofError::Mismatch(_))),
            "{what}: {r:?}"
        );
    }
}

/// The d6fba591 construction on stitch `i` of `w`: `fwd` (a Key Root of
/// two keys, H(l0 || l1) of known leaves) in the `pre` role, `pre` in
/// `fwd`'s, the cells `[l0, l1]` that fold to `fwd`; the stitch then reads
/// `l1` as CR_{s-1}[SHA-512] and a size-1 tree "proves" TR = `l1`. Returns
/// the false TR.
fn swap_pre_and_fwd(w: &mut Wire, i: usize, a: &Kp, b: &Kp) -> TransactionRoot {
    let o = w.opening(i);
    let (pre, fwd) = (
        bytes_of(&o["pre_variants"][0][1]),
        bytes_of(&o["fwd_variants"][0][1]),
    );
    let mut leaves = [
        a.tmb.as_bytes().to_vec(),
        HashAlg::Sha512.hash_bytes(b.tmb.as_bytes()),
    ];
    leaves.sort();
    assert_eq!(
        HashAlg::Sha512.hash_bytes(&[leaves[0].as_slice(), leaves[1].as_slice()].concat()),
        fwd,
        "setup: fwd is the hash of the two sorted leaves"
    );
    set_bytes(&mut o["pre_variants"][0][1], &fwd);
    set_bytes(&mut o["fwd_variants"][0][1], &pre);
    o["pt_cells"] = cells_json(&[
        cell_of(&[(sha512_id(), leaves[0].clone())]),
        cell_of(&[(sha512_id(), leaves[1].clone())]),
    ]);
    TransactionRoot(
        cyphr::multihash::MultihashDigest::from_single(HashAlg::Sha512, leaves[1].clone())
            .expect("digest"),
    )
}

/// Genesis (Ed25519), a create of an ES256 key, the ES256 key retiring
/// the genesis key, a data commit: the stitch at commit 1 has a SHA-512
/// arrow over PR_0 and the forward Key Root of {A, B}.
async fn swap_chain() -> (Principal, Kp, Kp) {
    let (a, b) = keys();
    let mut p = genesis(&a).await;
    commit_key(&mut p, &a, "create", &b, at(1)).await;
    commit_key(&mut p, &b, "delete", &a, at(2)).await;
    data_commit(&mut p, &b, at(3)).await;
    (p, a, b)
}

// d6fba591, closed by the ordered arrow: SPEC 4.2's order binds position 0
// as `pre`, so `fwd` there hashes to another arrow. Refused under a chain
// anchor and under a thin client's pin alike.
#[tokio::test]
async fn a_state_root_supplied_as_pre_is_refused() {
    let (p, a, b) = swap_chain().await;
    let mut w = cert_m(&p, 0).await;
    assert_eq!(w.stitches(), 1, "setup: the stitch is at commit 1");
    assert_eq!(chain_member(&p, &w, 0), Ok(()), "control");
    let false_tr = swap_pre_and_fwd(&mut w, 0, &a, &b);
    let n = n_of(&p);
    let chain = member_with(&Anchor::of_chain(p.state()), n, &w, 0, &false_tr);
    let pin = member_with(
        &Anchor::pin(p.root_at(n).expect("root")),
        n,
        &w,
        0,
        &false_tr,
    );
    assert_eq!(chain, Err(ProofError::Arrow), "under a chain anchor");
    assert_eq!(pin, Err(ProofError::Arrow), "under a pin");
}

// The same swap on a commit with two mutation transactions, under a pin.
#[tokio::test]
async fn a_role_swap_under_a_pin_is_refused() {
    let p = multi_coz(false).await; // commit 1: a key create and a nonce create
    let mut w = cert_m(&p, 0).await;
    assert_eq!(pin_member(&p, &w, 0), Ok(()), "control");
    let n = n_of(&p);
    let (pre, fwd) = (
        bytes_of(&w.opening(0)["pre_variants"][0][1]),
        bytes_of(&w.opening(0)["fwd_variants"][0][1]),
    );
    set_bytes(&mut w.opening(0)["pre_variants"][0][1], &fwd);
    set_bytes(&mut w.opening(0)["fwd_variants"][0][1], &pre);
    let r = member_with(
        &Anchor::pin(p.root_at(n).expect("root")),
        n,
        &w,
        0,
        tr_of(&p, 0),
    );
    assert!(r.is_err(), "the swap verified under a pin");
}

// An extension's new segment: the stitch at commit 2 is past the size the
// holder pinned (1), so the holder's chain pins nothing there. The roles
// are bound by the arrow's order alone; the swap must be refused.
#[tokio::test]
async fn the_role_swap_in_an_extensions_new_segment_is_refused() {
    let (a, b) = keys();
    let mut p = genesis(&a).await;
    data_commit(&mut p, &a, at(1)).await;
    commit_key(&mut p, &a, "create", &b, at(2)).await;
    commit_key(&mut p, &b, "delete", &a, at(3)).await;
    data_commit(&mut p, &b, at(4)).await;
    let holder = prefix(&a, 1).await;
    let head = p.root_at(n_of(&p)).expect("head");
    let mut w = cert_e(&p, 1).await;
    assert_eq!(extends(&holder, &w, 1, &head), Ok(()), "control");
    assert_eq!(w.stitches(), 1);
    let _ = swap_pre_and_fwd(&mut w, 0, &a, &b);
    assert!(
        extends(&holder, &w, 1, &head).is_err(),
        "the swap verified in the new segment"
    );
}

// ---- E10: roots, anchors, heads ----

// A thin client pins one root and verifies membership at that size only.
#[tokio::test]
async fn a_pinned_root_verifies_membership_at_its_own_size() {
    let p = single(3, 3).await;
    for size in [3u64, 5, 8] {
        let pin = Anchor::pin(p.root_at(size).expect("root"));
        for i in 0..size {
            let w = Wire::of(&p.prove_membership(i, size).await.expect("prove"));
            assert_eq!(
                member_with(&pin, size, &w, i, tr_of(&p, i)),
                Ok(()),
                "size {size}, index {i}"
            );
        }
    }
    // A pin vouches for its own size only.
    let w = cert_m(&p, 2).await;
    let r = member_with(
        &Anchor::pin(p.root_at(5).expect("root")),
        8,
        &w,
        2,
        tr_of(&p, 2),
    );
    assert!(matches!(r, Err(ProofError::Mismatch(_))), "{r:?}");
}

// PR at size n is a function of the commit history, equal for every party
// holding it, PR-level nonces included.
#[tokio::test]
async fn the_head_is_the_same_for_every_holder() {
    use cyphr::replay::{WireBundle, replay_bundle};
    let (a, b) = keys();
    let x = single_with((&a, &b), (3, 2, 3), None).await; // three PR-level nonces
    let mut y = genesis(&a).await;
    for i in 1..x.commit_count() {
        let bundle = WireBundle::of_commit(x.commit_at(i).expect("commit"))
            .expect("bundle")
            .decode()
            .expect("decodes");
        replay_bundle(&mut y, &bundle).await.expect("replays");
    }
    assert_eq!(y.commit_count(), x.commit_count());
    for size in 1..=n_of(&x) {
        assert!(x.root_at(size).is_some(), "a root at {size}");
        assert_eq!(x.root_at(size), y.root_at(size), "size {size}");
    }
    assert_eq!(x.root_at(0), None);
    assert_eq!(x.root_at(n_of(&x) + 1), None);
}

// The PR a certificate opens must be the anchor's pin at that size.
#[tokio::test]
async fn an_opened_pr_that_differs_from_a_pin_is_refused() {
    let (p, w) = genuine().await;
    let other = single(3, 3).await; // another chain, the same size
    let r = member_with(
        &Anchor::pin(other.root_at(8).expect("root")),
        8,
        &w,
        2,
        tr_of(&p, 2),
    );
    assert!(
        matches!(r, Err(ProofError::PtCell | ProofError::Mismatch(_))),
        "{r:?}"
    );
    let r = chain_member(&other, &w, 2);
    assert!(refused_at_parse_or_fold(&r), "{r:?}");
}

// F3: an honest chain with more epoch flips than the parser's old stitch
// cap (64) must round-trip through the wire form and verify: 140 replaces
// alternating ES256 and ES384 give one stitch per flip from the tip.
#[tokio::test]
async fn a_chain_with_many_epoch_flips_round_trips_and_verifies() {
    let mut keys = vec![kp(coz::Alg::Ed25519)];
    let mut p = genesis(&keys[0]).await;
    for i in 1..=140usize {
        let next = kp(if i % 2 == 1 {
            coz::Alg::ES256
        } else {
            coz::Alg::ES384
        });
        commit_key(&mut p, &keys[i - 1], "replace", &next, at(i)).await;
        keys.push(next);
    }
    let w = cert_m(&p, 0).await;
    assert!(w.stitches() > 64, "setup: {} stitches", w.stitches());
    let back = w
        .cert()
        .unwrap_or_else(|e| panic!("an honest {}-stitch certificate: {e}", w.stitches()));
    let n = n_of(&p);
    assert_eq!(
        verify_membership(
            &Anchor::pin(p.root_at(n).expect("root")),
            &back,
            n,
            0,
            tr_of(&p, 0)
        ),
        Ok(())
    );
}

// F4: a field far over any honest size is refused at parse, before any
// hashing (1 MiB in a Principal Tree cell, a coz, a leaf map, a fwd).
#[tokio::test]
async fn an_oversized_field_is_refused_before_any_hashing() {
    let (_, genuine) = genuine().await;
    let big = vec![0u8; 1 << 20];
    type Edit = fn(&mut Wire, Vec<u8>);
    let edits: [(&str, Edit); 4] = [
        ("a pt cell", |w, b| {
            set_bytes(&mut w.opening(0)["pt_cells"][0], &b)
        }),
        ("the coz", |w, b| set_bytes(&mut w.opening(0)["coz"], &b)),
        ("the leaf map", |w, b| {
            set_bytes(&mut w.opening(0)["tr_map"], &b)
        }),
        ("the fwd", |w, b| {
            set_bytes(&mut w.opening(0)["fwd_variants"][0][1], &b)
        }),
    ];
    for (what, edit) in edits {
        let mut w = genuine.clone();
        edit(&mut w, big.clone());
        let before = cyphr::probe::hashes();
        let r = w.cert();
        assert!(r.is_err(), "{what}: 1 MiB was accepted at parse");
        assert_eq!(
            cyphr::probe::hashes() - before,
            0,
            "{what}: hashed before refusing"
        );
    }
}

// The implementer's probe, green: two CR cells equal in one variant give
// equal PRs in that family and different PRs in the other.
#[test]
fn pr_binds_only_the_matching_variant_of_the_cr_cell() {
    use std::collections::BTreeMap;

    use cyphr::StateRoot;
    use cyphr::commit_root::CommitRoot;
    use cyphr::multihash::MultihashDigest;
    use cyphr::principal_tree::PrincipalTree;
    let md = |a: u8, b: u8| {
        MultihashDigest::new(BTreeMap::from([
            (HashAlg::Sha256, vec![a; 32].into_boxed_slice()),
            (HashAlg::Sha512, vec![b; 64].into_boxed_slice()),
        ]))
        .expect("multihash")
    };
    let algs = [HashAlg::Sha256, HashAlg::Sha512];
    let pr = |cr: CommitRoot| {
        let mut pt = PrincipalTree::new();
        pt.set_sr(&StateRoot(md(1, 2)), &algs).expect("sr");
        pt.set_cr(&cr, &algs).expect("cr");
        pt.pr(&algs).expect("pr")
    };
    let (x, y) = (pr(CommitRoot(md(3, 4))), pr(CommitRoot(md(3, 5))));
    assert_eq!(x.0.get(HashAlg::Sha256), y.0.get(HashAlg::Sha256));
    assert_ne!(x.0.get(HashAlg::Sha512), y.0.get(HashAlg::Sha512));
}

// REFUTES E5's claim 1 (the arrow's family is in CR_{s-1} for every
// admitted commit): B's Ed25519 key signs a commit of A, which hashes
// under SHA-256 only. The commit is admitted, its closing coz and arrow
// are SHA-512, and no commit before it has a SHA-512 variant. Green
// characterization of what the core does today.
#[tokio::test]
async fn an_embedded_signer_of_a_family_the_log_lacks_is_admitted() {
    let Embedded { mut a, eve, .. } = embedded().await;
    let golden = pool_kp("golden");
    commit_as(
        &mut a,
        &eve,
        "key/create",
        &b64(&golden),
        Some(key_of(&golden)),
        T + 3,
    )
    .await
    .expect("admitted");
    let last = a.iter_all_cozies().last().expect("a coz");
    assert_eq!(last.hash_alg(), HashAlg::Sha512, "the coz is Ed25519's");
    assert_eq!(
        last.arrow()
            .expect("closing coz")
            .algorithms()
            .collect::<Vec<_>>(),
        [HashAlg::Sha512],
        "and so is its arrow"
    );
    let before = a.commit_at(a.commit_count() - 2).expect("previous commit");
    assert!(
        !before.pr().0.contains(HashAlg::Sha512),
        "yet CR_{{s-1}} has no SHA-512 variant to stitch into"
    );
}

// Setup guard, green by design: the forger's tree is built faithfully
// (the same leaves give the genuine root), and inventing leaves does
// change it, so the forger test fails on the history and not on a bug in
// its own construction.
#[tokio::test]
async fn the_forgery_construction_is_sound() {
    let p = single(3, 3).await;
    let alg = hash_alg_to_u64(HashAlg::Sha512);
    let _ = forged_consistency(&p, 2, 4, false).await; // asserts the root
    let genuine = p.commit_trees().root_at(alg, 4).await.expect("root");
    let mut t = CommitTrees::open(cyphr::eml::MemoryStorage::new())
        .await
        .expect("open");
    t.add_algorithm(alg, Box::new(MaltHasher::new(HashAlg::Sha512)))
        .await
        .expect("register");
    for i in 0..4u64 {
        let leaf = if i < 2 {
            p.commit_trees().get_leaf(i).await.expect("leaf")
        } else {
            // A well-formed leaf (a map with a SHA-512 variant) that is not
            // the genuine one: a malformed leaf hashes to null, which eml
            // cannot build a consistency proof over.
            let variants = std::collections::BTreeMap::from([(alg, vec![i as u8 + 1; 64])]);
            serde_json::to_vec(&variants).expect("invented leaf")
        };
        t.append(&leaf).await.expect("append");
    }
    assert_ne!(t.root(alg).expect("root"), genuine);
}
