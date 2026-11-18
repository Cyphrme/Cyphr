//! Tip-anchored membership and extension across hash-algorithm epochs
//! (frame NETSIM-FIX, Follow-up E4). Red until `cyphr::proof` is
//! implemented: every test reaches a `stub:` `unimplemented!()` first,
//! so a pass can only come from the real verifier.
//!
//! Families: Ed25519 hashes under SHA-512, ES256 under SHA-256, ES384
//! under SHA-384. A `key/replace` from one to the other closes the
//! signer's family and opens the new key's at the replace commit.

use std::marker::PhantomData;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::commit_root::{CommitTrees, MaltHasher, hash_alg_to_u64};
use cyphr::proof::{
    AnyConsistency, AnyPath, AnyStitch, Claimed, Consistency, FullCr, ProofError, Rooted, Sha256,
    Sha384, Sha512, Trusted, verify_extension, verify_membership,
};
use cyphr::signer::SoftwareSigner;
use cyphr::{HashAlg, Key, Principal};
use serde_json::json;

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

/// Genesis (Ed25519, SHA-512), `pre` data commits, a `key/replace` to an
/// ES256 key (SHA-256) at index `pre + 1`, then `post` data commits by the
/// new key: `pre + post + 2` commits.
async fn single(pre: usize, post: usize) -> Principal {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    let mut p = genesis(&a).await;
    for k in 0..pre {
        data_commit(&mut p, &a, at(k + 1)).await;
    }
    commit_key(&mut p, &a, "replace", &b, at(pre + 1)).await;
    for k in 0..post {
        data_commit(&mut p, &b, at(pre + 2 + k)).await;
    }
    p
}

/// Ed25519 -> ES256 at index 3 -> ES384 (SHA-384) at index 6; nine
/// commits, two data commits in each era after the genesis.
async fn double() -> Principal {
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
    p
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

/// No rotation: genesis and `n - 1` data commits, all Ed25519.
async fn direct(n: usize) -> Principal {
    let a = kp(coz::Alg::Ed25519);
    let mut p = genesis(&a).await;
    for k in 1..n {
        data_commit(&mut p, &a, at(k)).await;
    }
    p
}

fn tr_of(p: &Principal, i: u64) -> &cyphr::TransactionRoot {
    p.commit_at(usize::try_from(i).expect("index"))
        .expect("commit")
        .tr()
}

fn tip(p: &Principal) -> Rooted<Trusted, FullCr> {
    Rooted::<Trusted, FullCr>::of_principal(p).expect("tip commit root")
}

fn claim_of(p: &Principal) -> Rooted<Claimed, FullCr> {
    Rooted::<Claimed, FullCr>::claim(tip(p).get().clone())
}

fn opening_of(s: &mut AnyStitch) -> &mut cyphr::proof::CommitOpening {
    match s {
        AnyStitch::Sha256(s) => &mut s.opening,
        AnyStitch::Sha384(s) => &mut s.opening,
        AnyStitch::Sha512(s) => &mut s.opening,
    }
}

// ---- 1 and 2: extension across one key/replace ----

// Frame E4.3: old CR_m trusted, new head claimed; one stitch crosses the
// rotation and the head is upgraded only when the consistency check holds.
#[tokio::test]
async fn extension_across_a_replace_is_one_stitch() {
    let p = single(3, 3).await; // replace at 4, n = 8
    let old = Rooted::<Trusted, FullCr>::at_size(&p, 3)
        .await
        .expect("old");
    let head = claim_of(&p);
    let proof = p.prove_extension(3).await.expect("prove");
    assert_eq!(proof.stitches.len(), 1, "one boundary crossed");
    let upgraded = verify_extension(&old, head, &proof).expect("extension verifies");
    assert_eq!(upgraded.get(), tip(&p).get(), "the head is upgraded");
}

// E4.3 cost: O(h (log n + c)); h = 1 here, so n = 8 -> 64 must grow by
// the log term only, never linearly (E3 had it O(n - m)).
#[tokio::test]
async fn extension_proof_size_is_logarithmic_across_a_replace() {
    let mut len = Vec::new();
    for post in [3, 59] {
        let p = single(3, post).await; // n = 8, then 64
        let proof = p.prove_extension(3).await.expect("prove");
        assert_eq!(proof.stitches.len(), 1);
        len.push(proof.encoded_len());
    }
    // Linear growth would be near 8x; one log level per doubling is ~2x.
    assert!(
        len[1] < 3 * len[0],
        "n=8: {} bytes, n=64: {}",
        len[0],
        len[1]
    );
}

// ---- 3: tip-anchored membership, no held history ----

#[tokio::test]
async fn an_old_era_commit_is_a_member_of_the_tip() {
    let p = single(3, 3).await; // A-era indices 0..=3, replace at 4
    let tip = tip(&p);
    for i in 0..8u64 {
        let proof = p.prove_membership(i).await.expect("prove");
        assert_eq!(proof.stitches.len(), usize::from(i < 4), "index {i}");
        verify_membership(&tip, &proof, tr_of(&p, i)).expect("member");
    }
}

// ---- 4: two rotations, two stitches (and one hop per boundary) ----

#[tokio::test]
async fn two_rotations_cost_two_stitches() {
    let p = double().await; // boundaries at 3 and 6, n = 9
    let tip = tip(&p);
    for i in 0..9u64 {
        let want = match i {
            0..=2 => 2,
            3..=5 => 1,
            _ => 0,
        };
        let proof = p.prove_membership(i).await.expect("prove");
        assert_eq!(
            proof.stitches.len(),
            want,
            "one hop per boundary, index {i}"
        );
        verify_membership(&tip, &proof, tr_of(&p, i)).expect("member");
    }
    let old = Rooted::<Trusted, FullCr>::at_size(&p, 2)
        .await
        .expect("old");
    let head = claim_of(&p);
    let ext = p.prove_extension(2).await.expect("prove");
    assert_eq!(ext.stitches.len(), 2);
    verify_extension(&old, head, &ext).expect("extension across both");
}

// ---- 5: a family closes and resumes ----

#[tokio::test]
async fn a_commit_in_a_closed_familys_gap_is_provable() {
    let p = resume().await;
    let tip = tip(&p);
    for i in 0..10u64 {
        let proof = p.prove_membership(i).await.expect("prove");
        assert!(
            proof.stitches.len() <= 2,
            "index {i}: {}",
            proof.stitches.len()
        );
        verify_membership(&tip, &proof, tr_of(&p, i)).expect("member");
    }
}

// ---- 6: the direct case is the same verifier ----

#[tokio::test]
async fn without_a_rotation_there_is_no_stitch() {
    let p = direct(8).await;
    let tip = tip(&p);
    for i in 0..8u64 {
        let proof = p.prove_membership(i).await.expect("prove");
        assert!(proof.stitches.is_empty(), "index {i}");
        verify_membership(&tip, &proof, tr_of(&p, i)).expect("member");
    }
    let old = Rooted::<Trusted, FullCr>::at_size(&p, 3)
        .await
        .expect("old");
    let ext = p.prove_extension(3).await.expect("prove");
    assert!(ext.stitches.is_empty());
    verify_extension(&old, claim_of(&p), &ext).expect("direct extension");
}

// ---- 7 (claims 2 and 5): the opening is bounded ----

// The frame says the PT has exactly three cells. principal_tree.rs builds
// SR, CR and one cell per nonce, so a nonce-less principal has two. This
// pins what matters, that the count is bounded and independent of n.
#[tokio::test]
async fn the_opening_does_not_grow_with_the_log() {
    let mut shape = Vec::new();
    for post in [3, 59] {
        let p = single(3, post).await;
        let mut proof = p.prove_membership(2).await.expect("prove");
        let o = opening_of(&mut proof.stitches[0]);
        shape.push((o.pt_cells.len(), o.tr_path.len()));
    }
    assert_eq!(shape[0], shape[1], "same opening at n = 8 and n = 64");
    assert!(shape[0].0 <= 3, "PT cells: {}", shape[0].0);
}

// ---- 8: negatives, all through the two entry points ----

async fn genuine() -> (Principal, cyphr::proof::MembershipProof) {
    let p = single(3, 3).await;
    let proof = p.prove_membership(2).await.expect("prove");
    verify_membership(&tip(&p), &proof, tr_of(&p, 2)).expect("control: genuine proof");
    (p, proof)
}

fn refused(p: &Principal, proof: &cyphr::proof::MembershipProof) -> Result<(), ProofError> {
    verify_membership(&tip(p), proof, tr_of(p, 2)).map(|_| ())
}

#[tokio::test]
async fn a_tampered_arrow_preimage_is_refused() {
    let (p, mut proof) = genuine().await;
    opening_of(&mut proof.stitches[0]).arrow_preimage[0] ^= 1;
    assert_eq!(refused(&p, &proof), Err(ProofError::Arrow));
}

#[tokio::test]
async fn a_tampered_pt_cell_is_refused() {
    let (p, mut proof) = genuine().await;
    opening_of(&mut proof.stitches[0]).pt_cells[1][0] ^= 1; // the CR cell
    assert_eq!(refused(&p, &proof), Err(ProofError::PtCell));
}

// Another principal's head: the first thing a stitch checks is that leaf
// j reaches the root it is given.
#[tokio::test]
async fn another_principals_head_is_refused() {
    let (_, proof) = genuine().await;
    let (other, _) = genuine().await;
    assert_eq!(refused(&other, &proof), Err(ProofError::Path));
}

// A path under a family that was inactive at the position: the prover
// refuses, or its path hits a null leaf and the verifier refuses it.
#[tokio::test]
async fn a_path_under_an_inactive_family_is_refused() {
    let (p, mut proof) = genuine().await;
    match p.log_path::<Sha256>(2, 8).await {
        Err(ProofError::Unprovable(_)) => {},
        Ok(path) => {
            proof.terminal = AnyPath::Sha256(path);
            assert_eq!(refused(&p, &proof), Err(ProofError::Path));
        },
        Err(e) => panic!("wrong refusal: {e}"),
    }
}

// Consistency under the wrong family cannot be written (see the
// compile_fail doctests); at run time the family is simply absent.
#[tokio::test]
async fn a_family_absent_at_the_old_size_is_refused() {
    let p = single(3, 3).await;
    assert!(tip(&p).family::<Sha384>().is_none(), "no SHA-384 anywhere");
    let old = Rooted::<Trusted, FullCr>::at_size(&p, 3)
        .await
        .expect("old");
    assert!(old.family::<Sha256>().is_none(), "SHA-256 had no tree at 3");
    let mut proof = p.prove_extension(3).await.expect("prove");
    verify_extension(&old, claim_of(&p), &proof).expect("control");
    if let Ok(c) = p.family_consistency::<Sha256>(3, 8).await {
        proof.terminal = AnyConsistency::Sha256(c);
        assert_eq!(
            verify_extension(&old, claim_of(&p), &proof).map(|_| ()),
            Err(ProofError::Family)
        );
    }
}

#[test]
fn a_digest_of_the_wrong_width_is_refused() {
    use cyphr::proof::Digest;
    assert!(Digest::<Sha512>::from_bytes(&[0; 64]).is_ok());
    assert_eq!(
        Digest::<Sha256>::from_bytes(&[0; 64]).map(|_| ()),
        Err(ProofError::Width { want: 32, got: 64 })
    );
}

/// The forger's tree for family SHA-512 over `size` leaves: the genuine
/// leaves below `m`, then (when `invent`) invented ones.
async fn forged_consistency(p: &Principal, m: u64, size: u64, invent: bool) -> Consistency<Sha512> {
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
            format!("invented {i}").into_bytes()
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
    Consistency {
        proof: t.consistency_proof(alg, m).await.expect("consistency"),
        family: PhantomData,
    }
}

// E4.1: the forger shares the trusted prefix below m, invents leaves
// m..j-1 and ends with the genuine leaf j. Its SHA-512 consistency from m
// is internally sound; the stitch's CR_{j-1}[SHA-512] is what it fails.
#[tokio::test]
async fn the_forgers_alternate_history_is_refused() {
    let p = single(3, 3).await; // j = 4
    let old = Rooted::<Trusted, FullCr>::at_size(&p, 2)
        .await
        .expect("old");
    let head = claim_of(&p);
    let mut proof = p.prove_extension(2).await.expect("prove");
    assert_eq!(proof.stitches.len(), 1);
    // Control first: the faithful tree's proof is the genuine one.
    proof.terminal = AnyConsistency::Sha512(forged_consistency(&p, 2, 4, false).await);
    verify_extension(&old, claim_of(&p), &proof).expect("control: genuine leaves");

    proof.terminal = AnyConsistency::Sha512(forged_consistency(&p, 2, 4, true).await);
    assert_eq!(
        verify_extension(&old, head, &proof).map(|_| ()),
        Err(ProofError::NotAnExtension)
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
            format!("invented {i}").into_bytes()
        };
        t.append(&leaf).await.expect("append");
    }
    assert_ne!(t.root(alg).expect("root"), genuine);
}
