//! `WireBundle::decode()?.commit_id(alg)` names a commit from its bytes
//! alone: it must equal the commit's own Transaction Root in that hash
//! algorithm (SPEC 3.7.5), whatever the shape of the commit.
//!
//! Two properties. Over the golden corpus, every commit that states a
//! `commit_id` (two transactions, or more such as
//! `key_replace_signed_by_two_keys`, in each algorithm the corpus uses): the
//! bundle built from the commit's cozies names it. Over a live principal
//! with two hash algorithms (an ES256 and an ES384 key), each of its
//! commits: the bundle's id in each algorithm is the commit's `tr()` in it.

use std::path::{Path, PathBuf};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr::state::TaggedDigest;
use cyphr::{HashAlg, Principal};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden")
}

fn json_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("golden dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            json_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

/// A golden commit line as a wire bundle: each coz object becomes the
/// base64url of its JSON, the transport form.
fn bundle_of(line: &serde_json::Value) -> WireBundle {
    let enc = |coz: &serde_json::Value| {
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(coz).expect("coz json"))
    };
    let txs: Vec<Vec<String>> = line["txs"]
        .as_array()
        .expect("txs")
        .iter()
        .map(|tx| tx.as_array().expect("tx").iter().map(enc).collect())
        .collect();
    serde_json::from_value(serde_json::json!({ "txs": txs })).expect("a wire bundle")
}

/// Catches a commit id that is not the commit's own TR: over every golden
/// commit that states one. Also asserts the corpus holds a commit of two
/// transactions and one of three or more, so the shapes are exercised (a
/// commit has no single-transaction form: its commit transaction comes with
/// at least one mutation transaction).
#[test]
fn a_bundle_names_every_golden_commit() {
    let mut files = Vec::new();
    json_files(&golden_dir(), &mut files);
    let (mut checked, mut shapes) = (0, std::collections::BTreeSet::new());
    for path in files {
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        // A refusal vector's stated commit id is not the id of a commit the
        // principal took, so only vectors that are applied count.
        if doc["expected"]["error"].is_string() {
            continue;
        }
        for line in doc["commits"].as_array().into_iter().flatten() {
            let Some(stated) = line["commit_id"].as_str().filter(|s| !s.is_empty()) else {
                continue;
            };
            let want: TaggedDigest = stated.parse().expect("a tagged commit id");
            let bundle = bundle_of(line);
            let got = bundle
                .decode()
                .unwrap_or_else(|e| panic!("{}: decode: {e:?}", path.display()))
                .commit_id(want.alg());
            assert_eq!(
                got.map(|d| d.to_string()),
                Some(want.to_string()),
                "{}: {} transactions",
                path.display(),
                line["txs"].as_array().map_or(0, Vec::len)
            );
            shapes.insert(line["txs"].as_array().map_or(0, Vec::len).min(3));
            checked += 1;
        }
    }
    assert!(checked > 20, "the corpus was read: {checked} commits");
    assert!(shapes.contains(&2), "a two-transaction commit: {shapes:?}");
    assert!(
        shapes.contains(&3),
        "a three-transaction commit: {shapes:?}"
    );
}

/// Catches a commit id wrong in one algorithm of a multi-algorithm
/// principal: its genesis keys are ES256 (golden) and ES384 (diana), so its
/// commits carry a SHA-256 and a SHA-384 root; the bundle must name each.
#[tokio::test]
async fn a_bundle_names_a_commit_in_each_algorithm_of_a_two_hash_principal() {
    let path = golden_dir().join("../keys/pool.toml");
    let pool = test_fixtures::Pool::load(&path).expect("pool.toml");
    let g = pool.get("golden").expect("golden");
    let diana = pool.get("diana_es384").expect("diana");
    let mut p = Principal::implicit(g.key().expect("key"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(
        &mut p,
        g,
        &[diana.key().expect("diana key")],
        1_700_000_000,
    )
    .await
    .expect("genesis");
    let mut bundles = vec![genesis];
    let key_a = pool.get("key_a").expect("key_a").key().expect("key");
    let pay = serde_json::json!({
        "alg": g.alg, "id": key_a.tmb().to_b64(), "now": 1_700_000_100_i64,
        "tmb": g.compute_tmb_b64().expect("tmb"), "typ": "cyphr.me/cyphr/key/create"
    });
    let mut pay = pay;
    pay.as_object_mut().expect("object").sort_keys();
    let pay = serde_json::to_vec(&pay).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(g.prv.as_ref().expect("prv")).expect("prv");
    let pubb = Base64UrlUnpadded::decode_vec(&g.pub_key).expect("pub");
    let (sig, cad) = coz::sign_json(&pay, &g.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &g.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_a))
        .expect("apply");
    scope
        .finalize_with_software(
            &g.software_signer().expect("signer"),
            1_700_000_100,
            "cyphr.me",
        )
        .await
        .expect("finalize");
    bundles.push(WireBundle::of_commit(p.commits().last().expect("commit")).expect("bundle"));

    let mut named = 0;
    for (commit, bundle) in p.commits().zip(&bundles) {
        for alg in [HashAlg::Sha256, HashAlg::Sha384] {
            let want = commit
                .tr()
                .0
                .tagged(alg)
                .expect("the commit's root")
                .to_string();
            let got = bundle.decode().expect("decode").commit_id(alg);
            assert_eq!(got.map(|d| d.to_string()), Some(want), "{alg:?}");
            named += 1;
        }
    }
    assert_eq!(named, 4, "two commits, two algorithms");
}
