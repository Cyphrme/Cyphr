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
    AnyConsistency, AnyFamilyRoot, AnyPath, AnyStitch, Claimed, Consistency, FullCr, ProofError,
    Rooted, Sha256, Sha384, Sha512, Trusted, verify_extension, verify_membership,
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

fn alg_of(r: &AnyFamilyRoot) -> HashAlg {
    match r {
        AnyFamilyRoot::Sha256(_) => HashAlg::Sha256,
        AnyFamilyRoot::Sha384(_) => HashAlg::Sha384,
        AnyFamilyRoot::Sha512(_) => HashAlg::Sha512,
    }
}

/// The holder's own tip root in the family its tip hashes under.
fn tip_variant(p: &Principal) -> AnyFamilyRoot {
    tip(p)
        .get()
        .variants
        .iter()
        .find(|v| alg_of(v) == p.hash_alg())
        .expect("the tip's family is in its commit root")
        .clone()
}

/// What a peer states: its head in one family (a whole Commit Root is
/// never one claim, E5.2).
fn claim_of(p: &Principal) -> Rooted<Claimed, AnyFamilyRoot> {
    Rooted::<Claimed, AnyFamilyRoot>::claim(tip_variant(p))
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
    assert_eq!(
        upgraded.get(),
        &tip_variant(&p),
        "the head is upgraded, in its own family"
    );
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
    for i in 0..p.commit_count() as u64 {
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

// ---- 7 (claims 2 and 5): the opening is independent of n ----

// The frame says the PT has exactly three cells; principal_tree.rs builds
// SR, CR and one cell per nonce (two for a nonce-less principal). What
// the cost argument needs is independence from n: with k nonces the same
// opening at n = 8 and n = 64. (Claim 5, the bound by the transaction
// limits, is not settled here.)
#[tokio::test]
async fn the_opening_is_independent_of_the_log_length() {
    for k in [0usize, 3] {
        let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
        let mut shape = Vec::new();
        for n in [8usize, 64] {
            let p = single_with((&a, &b), (k, 2, n - k - 4), None).await;
            assert_eq!(p.commit_count(), n);
            let mut proof = p.prove_membership(1).await.expect("prove");
            let o = opening_of(&mut proof.stitches[0]);
            let bytes: usize = o.pt_cells.iter().map(Vec::len).sum();
            shape.push((
                o.pt_cells.len(),
                bytes,
                o.tr_path.len(),
                o.arrow_preimage.len(),
            ));
        }
        assert_eq!(shape[0], shape[1], "k = {k}: opening at n = 8 vs 64");
        assert_eq!(shape[0].0, 2 + k, "SR, CR and one cell per nonce");
    }
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

// ---- binding: what the proof must tie together ----

// Every test above hands the verifier the matching TR, so a verifier that
// never hashes `tr` into the leaf would pass them all.
#[tokio::test]
async fn a_proof_does_not_vouch_for_another_commits_tr() {
    let p = single(3, 3).await;
    let proof = p.prove_membership(2).await.expect("prove");
    verify_membership(&tip(&p), &proof, tr_of(&p, 2)).expect("control");
    for j in [0u64, 1, 3, 5, 7] {
        let r = verify_membership(&tip(&p), &proof, tr_of(&p, j));
        assert!(
            matches!(r, Err(ProofError::Mismatch(_))),
            "tr of {j}: {r:?}"
        );
    }
    // The same position of another principal's chain.
    let other = single(3, 3).await;
    let r = verify_membership(&tip(&p), &proof, tr_of(&other, 2));
    assert!(
        matches!(r, Err(ProofError::Mismatch(_))),
        "foreign tr: {r:?}"
    );
}

// The genuine leaf path for one commit with the genuine opening of
// another: each part checks alone, only the binding refuses it.
#[tokio::test]
async fn a_spliced_opening_is_refused() {
    let p = double().await;
    let mut proof = p.prove_membership(1).await.expect("prove");
    assert_eq!(proof.stitches.len(), 2);
    verify_membership(&tip(&p), &proof, tr_of(&p, 1)).expect("control");
    let (first, second) = (
        opening_of(&mut proof.stitches[0]).clone(),
        opening_of(&mut proof.stitches[1]).clone(),
    );
    *opening_of(&mut proof.stitches[0]) = second;
    *opening_of(&mut proof.stitches[1]) = first;
    let r = verify_membership(&tip(&p), &proof, tr_of(&p, 1));
    assert!(
        matches!(r, Err(ProofError::Path | ProofError::Arrow)),
        "{r:?}"
    );
}

// A commit's arrow is on its last coz; the replace coz before it carries
// none and is a genuine coz of the same commit.
#[tokio::test]
async fn an_opening_through_a_coz_other_than_the_closing_one_is_refused() {
    let p = single(3, 3).await; // replace at 4
    let blobs: Vec<Vec<u8>> = cyphr::replay::WireBundle::of_commit(p.commit_at(4).expect("commit"))
        .expect("bundle")
        .cozies()
        .map(<[u8]>::to_vec)
        .collect();
    assert!(
        blobs.len() >= 2,
        "a replace commit has its coz and a closing coz"
    );
    let mut proof = p.prove_membership(2).await.expect("prove");
    assert_eq!(
        opening_of(&mut proof.stitches[0]).coz,
        blobs[blobs.len() - 1]
    );
    opening_of(&mut proof.stitches[0]).coz = blobs[0].clone();
    let r = verify_membership(&tip(&p), &proof, tr_of(&p, 2));
    assert!(matches!(r, Err(ProofError::Arrow)), "{r:?}");
}

// A genuine, signed fork that diverges at f = 2, below the trusted size
// m = 3, and its own honest proof. Every signature and stitch is real; the
// trusted CR_3 is simply not a prefix of it.
#[tokio::test]
async fn a_real_fork_below_the_trusted_size_is_refused() {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    let x = single_with((&a, &b), (0, 3, 3), None).await;
    let y = single_with((&a, &b), (0, 3, 3), Some(2)).await;
    assert_eq!(
        tr_of(&x, 1),
        tr_of(&y, 1),
        "they share the first two commits"
    );
    assert_ne!(tr_of(&x, 2), tr_of(&y, 2), "and part at commit 2");
    let old = Rooted::<Trusted, FullCr>::at_size(&x, 3)
        .await
        .expect("old");
    let honest = x.prove_extension(3).await.expect("prove");
    verify_extension(&old, claim_of(&x), &honest).expect("control: its own chain");
    let forked = y.prove_extension(3).await.expect("the fork's honest proof");
    let r = verify_extension(&old, claim_of(&y), &forked);
    assert_eq!(r.map(|_| ()), Err(ProofError::NotAnExtension));
}

fn leaf_size_mut(s: &mut AnyStitch) -> &mut u64 {
    match s {
        AnyStitch::Sha256(s) => &mut s.leaf.size,
        AnyStitch::Sha384(s) => &mut s.leaf.size,
        AnyStitch::Sha512(s) => &mut s.leaf.size,
    }
}

fn path_size_mut(p: &mut AnyPath) -> &mut u64 {
    match p {
        AnyPath::Sha256(p) => &mut p.size,
        AnyPath::Sha384(p) => &mut p.size,
        AnyPath::Sha512(p) => &mut p.size,
    }
}

// The API derives the sizes (the anchor's, and CR_{s-1}'s from s) and
// never trusts a size the proof states: a stated size other than the
// implied one is refused.
#[tokio::test]
async fn a_size_the_proof_states_wrongly_is_refused() {
    let p = single(3, 3).await; // tip 8; the SHA-512 tree closes at 4
    let genuine = p.prove_membership(2).await.expect("prove");
    verify_membership(&tip(&p), &genuine, tr_of(&p, 2)).expect("control");
    let mut at_anchor = genuine.clone();
    *leaf_size_mut(&mut at_anchor.stitches[0]) = 9;
    let mut at_cr = genuine;
    *path_size_mut(&mut at_cr.terminal) = 5;
    for (what, bad) in [("anchor size", at_anchor), ("CR size", at_cr)] {
        let r = verify_membership(&tip(&p), &bad, tr_of(&p, 2));
        assert!(
            matches!(r, Err(ProofError::Mismatch(_) | ProofError::Path)),
            "{what}: {r:?}"
        );
    }
}

/// The property: whatever the verifier accepts proves the true index.
fn proves_only_the_truth(
    r: Result<cyphr::proof::Verified<cyphr::proof::Membership>, ProofError>,
    i: u64,
) {
    if let Ok(v) = r {
        assert_eq!(
            v.get().index,
            i,
            "accepted, so it must prove the true index"
        );
    }
}

#[tokio::test]
async fn the_stitch_list_cannot_be_edited_into_a_false_proof() {
    // Dropping the only stitch of an index only the retired family covers.
    let p = single(3, 3).await;
    let mut dropped = p.prove_membership(2).await.expect("prove");
    verify_membership(&tip(&p), &dropped, tr_of(&p, 2)).expect("control");
    dropped.stitches.clear();
    let r = verify_membership(&tip(&p), &dropped, tr_of(&p, 2));
    assert!(r.is_err(), "the tip has no SHA-512 root: {r:?}");

    // Inserting a genuine extra stitch (taken from a longer proof).
    let d = double().await;
    let long = d.prove_membership(1).await.expect("prove");
    for i in [1u64, 4, 7] {
        let mut proof = d.prove_membership(i).await.expect("prove");
        verify_membership(&tip(&d), &proof, tr_of(&d, i)).expect("control");
        for extra in &long.stitches {
            proof.stitches.insert(0, extra.clone());
            proves_only_the_truth(verify_membership(&tip(&d), &proof, tr_of(&d, i)), i);
            proof.stitches.remove(0);
            proof.stitches.push(extra.clone());
            proves_only_the_truth(verify_membership(&tip(&d), &proof, tr_of(&d, i)), i);
            proof.stitches.pop();
        }
    }
}

// ---- E5: a stitch authenticates the signer's family only ----

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

// PR_{s-1}[G] binds CR_{s-1}[G] alone, so the stitch trusts the signer's
// family (A) and no other variant of the CR cell. Rewriting C's variant
// in the cell changes nothing; continuing the walk in C is refused.
#[tokio::test]
async fn a_stitch_trusts_only_the_signers_family() {
    let p = three_families().await;
    let mut proof = p.prove_membership(0).await.expect("prove");
    assert_eq!(proof.stitches.len(), 1, "B starts at 2; index 0 is A's");
    verify_membership(&tip(&p), &proof, tr_of(&p, 0)).expect("control");

    let cell = &mut opening_of(&mut proof.stitches[0]).pt_cells[1];
    let mut variants: std::collections::BTreeMap<u64, Vec<u8>> =
        serde_json::from_slice(cell).expect("the CR cell is a map of variants");
    let c_id = hash_alg_to_u64(HashAlg::Sha384);
    variants.get_mut(&c_id).expect("CR_1 carries C").fill(7);
    *cell = serde_json::to_vec(&variants).expect("cell");
    verify_membership(&tip(&p), &proof, tr_of(&p, 0))
        .expect("a non-signer variant is ignored, not checked");

    // Continue in C from the same stitch: C's tree at size 2 holds leaf 1.
    let c_path = p.log_path::<Sha384>(1, 2).await.expect("C's path");
    proof.terminal = AnyPath::Sha384(c_path);
    let r = verify_membership(&tip(&p), &proof, tr_of(&p, 1));
    assert_eq!(r.map(|_| ()), Err(ProofError::Family));
}

// A head upgraded in one family anchors membership of any commit, by
// the walk, with no other family trusted.
#[tokio::test]
async fn an_upgraded_single_family_head_anchors_any_membership() {
    let p = single(3, 3).await;
    let old = Rooted::<Trusted, FullCr>::at_size(&p, 3)
        .await
        .expect("old");
    let ext = p.prove_extension(3).await.expect("prove");
    let head = verify_extension(&old, claim_of(&p), &ext).expect("upgrade");
    for i in 0..8u64 {
        let proof = p.prove_membership(i).await.expect("prove");
        verify_membership(&head, &proof, tr_of(&p, i)).expect("anchored in the upgraded head");
        assert_eq!(proof.stitches.len(), usize::from(i < 4));
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

// Consequence of the above, red: a stitch at a commit signed by such an
// embedded key. eve creates an ES384 key (SHA-384 starts at commit 2), the
// ES384 key deletes alice (SHA-256 closes), so index 0 is covered by
// SHA-256 only and the walk from the SHA-384 tip must stitch at commit 2,
// whose arrow family (SHA-512) is in no CR.
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
        commit_as(
            &mut a,
            &diana,
            "nonce/create",
            &format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[k + 1; 32])),
            None,
            T + 5 + i64::from(k),
        )
        .await
        .expect("a commit by the ES384 key");
    }
    let tip = tip(&a);
    for i in 0..a.commit_count() as u64 {
        let proof = a.prove_membership(i).await.expect("prove");
        verify_membership(&tip, &proof, tr_of(&a, i))
            .unwrap_or_else(|e| panic!("index {i} through an embedded signer's stitch: {e}"));
    }
}

// ---- E6: what the arrow's `pre` binds (component conversion rule) ----

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
    let tip = tip(&a);
    let mut proof = a.prove_membership(0).await.expect("prove");
    assert_eq!(proof.stitches.len(), 1);
    let supplied: Vec<HashAlg> = opening_of(&mut proof.stitches[0])
        .pre_variants
        .iter()
        .map(|(alg, _)| *alg)
        .collect();
    assert_eq!(supplied, [HashAlg::Sha256, HashAlg::Sha384]);
    for i in 0..a.commit_count() as u64 {
        let proof = a.prove_membership(i).await.expect("prove");
        verify_membership(&tip, &proof, tr_of(&a, i)).unwrap_or_else(|e| panic!("index {i}: {e}"));
    }
}

#[tokio::test]
async fn a_tampered_variant_in_the_concatenated_pre_is_refused() {
    let a = case_three().await;
    let mut proof = a.prove_membership(0).await.expect("prove");
    verify_membership(&tip(&a), &proof, tr_of(&a, 0)).expect("control");
    opening_of(&mut proof.stitches[0]).pre_variants[1].1[0] ^= 1;
    let r = verify_membership(&tip(&a), &proof, tr_of(&a, 0));
    assert_eq!(r.map(|_| ()), Err(ProofError::Arrow));
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
    let mut proof = a.prove_membership(0).await.expect("prove");
    verify_membership(&tip(&a), &proof, tr_of(&a, 0)).expect("control");
    let o = opening_of(&mut proof.stitches[0]);
    assert_eq!(o.pre_variants.len(), 1);
    o.pre_variants.push((HashAlg::Sha384, vec![9; 48]));
    let r = verify_membership(&tip(&a), &proof, tr_of(&a, 0));
    assert_eq!(r.map(|_| ()), Err(ProofError::Arrow));
}

// Case 3 becomes case 2: dropping a variant from the concatenated pre
// changes the conversion (one variant is promoted as is), so the arrow no
// longer recomputes.
#[tokio::test]
async fn a_variant_dropped_from_the_concatenated_pre_is_refused() {
    let a = case_three().await;
    let mut proof = a.prove_membership(0).await.expect("prove");
    verify_membership(&tip(&a), &proof, tr_of(&a, 0)).expect("control");
    assert_eq!(opening_of(&mut proof.stitches[0]).pre_variants.len(), 2);
    opening_of(&mut proof.stitches[0]).pre_variants.remove(1);
    let r = verify_membership(&tip(&a), &proof, tr_of(&a, 0));
    assert_eq!(r.map(|_| ()), Err(ProofError::Arrow));
}

// Case 1 becomes case 2: PR_1 has the arrow's family (SHA-512) and
// another (SHA-384). Supplying only the genuine SHA-384 variant presents
// a single-variant pre, which promotes SHA-384's bytes: not what the
// signer's arrow binds.
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
    let mut proof = p.prove_membership(0).await.expect("prove");
    verify_membership(&tip(&p), &proof, tr_of(&p, 0)).expect("control");
    opening_of(&mut proof.stitches[0]).pre_variants = vec![(HashAlg::Sha384, genuine.to_vec())];
    let r = verify_membership(&tip(&p), &proof, tr_of(&p, 0));
    assert_eq!(r.map(|_| ()), Err(ProofError::Arrow));
}

// The second path through `impl Anchor`: the TR is bound whichever
// anchor starts the walk.
#[tokio::test]
async fn an_upgraded_anchor_still_binds_the_tr() {
    let p = single(3, 3).await;
    let old = Rooted::<Trusted, FullCr>::at_size(&p, 3)
        .await
        .expect("old");
    let ext = p.prove_extension(3).await.expect("prove");
    let head = verify_extension(&old, claim_of(&p), &ext).expect("upgrade");
    let proof = p.prove_membership(2).await.expect("prove");
    verify_membership(&head, &proof, tr_of(&p, 2)).expect("control");
    for j in [0u64, 1, 3, 5, 7] {
        let r = verify_membership(&head, &proof, tr_of(&p, j));
        assert!(
            matches!(r, Err(ProofError::Mismatch(_))),
            "tr of {j}: {r:?}"
        );
    }
    let other = single(3, 3).await;
    let r = verify_membership(&head, &proof, tr_of(&other, 2));
    assert!(
        matches!(r, Err(ProofError::Mismatch(_))),
        "foreign tr: {r:?}"
    );
}

// Variants supplied out of sorted order: refused, or the same roots and
// so the same true proof.
#[tokio::test]
async fn a_reordered_concatenated_pre_proves_only_the_truth() {
    let a = case_three().await;
    let mut proof = a.prove_membership(0).await.expect("prove");
    verify_membership(&tip(&a), &proof, tr_of(&a, 0)).expect("control");
    opening_of(&mut proof.stitches[0]).pre_variants.reverse();
    proves_only_the_truth(verify_membership(&tip(&a), &proof, tr_of(&a, 0)), 0);
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
        let tip = tip(&p);
        for i in 0..p.commit_count() as u64 {
            let proof = p
                .prove_membership(i)
                .await
                .unwrap_or_else(|e| panic!("grouped={grouped} index {i}: {e}"));
            verify_membership(&tip, &proof, tr_of(&p, i))
                .unwrap_or_else(|e| panic!("grouped={grouped} index {i}: {e}"));
        }
    }
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
