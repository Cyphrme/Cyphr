//! Certificates for commits as large as admission allows: more than 256
//! Principal Tree cells (PR-level nonces accumulate without bound), a
//! transaction of more than 256 cozies, and a commit of more than 256
//! mutation transactions. Each must prove, round-trip through the
//! certificate's own parser, and verify. Below, the cost of a certificate
//! across algorithm changes, counted in hashes and bytes against the
//! length of the history and the number of changes.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::proof::{Anchor, Certificate, Claim, verify};
use cyphr::signer::SoftwareSigner;
use cyphr::{Key, Principal};
use serde_json::json;

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";
/// More than any count the first implementation capped.
const MANY: usize = 257;

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

fn tmb(k: &Kp) -> String {
    Base64UrlUnpadded::encode_string(k.tmb.as_bytes())
}

fn verified(
    scope: &cyphr::CommitScope<'_, cyphr::eml::MemoryStorage>,
    by: &Kp,
    typ: &str,
    id: String,
    now: i64,
    side: Option<Key>,
) -> cyphr::VerifiedCoz {
    let mut pay = json!({"alg": by.alg, "id": id, "now": now, "tmb": tmb(by),
                         "typ": format!("{AUTHORITY}/cyphr/{typ}")});
    pay.as_object_mut().expect("object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    scope.verify(&v, &sig, czd, side).expect("verify")
}

fn nonce(i: usize) -> String {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&seed))
}

/// How the `MANY` nonces of a commit are laid out.
#[derive(Clone, Copy)]
enum Shape {
    /// One transaction of `MANY` cozies.
    Grouped,
    /// `MANY` transactions of one coz.
    Separate,
}

/// Genesis (Ed25519), then one commit of `MANY` PR-level nonces and a
/// `key/replace` to ES256 (so a stitch opens exactly this commit), then
/// data-free commits by the new key to leave a tip: the PR carries
/// `MANY` nonce cells from the first commit on.
async fn chain(shape: Shape) -> Principal {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    let mut p = Principal::implicit(key_of(&a)).await.expect("open");
    p.commit_genesis(&signer(&a), &[], T, AUTHORITY)
        .await
        .expect("genesis");
    let now = T + 10;
    let mut scope = p.begin_commit();
    let nonces: Vec<_> = (0..MANY)
        .map(|i| verified(&scope, &a, "nonce/create", nonce(i), now, None))
        .collect();
    match shape {
        Shape::Grouped => scope.apply_tx(nonces).expect("one transaction"),
        Shape::Separate => {
            for n in nonces {
                scope.apply(n).expect("a nonce");
            }
        },
    }
    let replace = verified(&scope, &a, "key/replace", tmb(&b), now, Some(key_of(&b)));
    scope.apply(replace).expect("replace");
    scope
        .finalize_with_software(&signer(&a), now + 1, AUTHORITY)
        .await
        .expect("commit");
    for k in 0..2 {
        let mut scope = p.begin_commit();
        let id = nonce(MANY + k);
        let n = verified(&scope, &b, "nonce/create", id, now + 20 + k as i64, None);
        scope.apply(n).expect("a nonce");
        scope
            .finalize_with_software(&signer(&b), now + 21 + k as i64, AUTHORITY)
            .await
            .expect("commit");
    }
    p
}

async fn proves_and_verifies(shape: Shape) {
    let p = chain(shape).await;
    let n = p.commit_count() as u64;
    let txs = p.commit_at(1).expect("commit").transactions().len();
    match shape {
        Shape::Grouped => assert_eq!(txs, 3, "a group, the replace, the closing coz"),
        Shape::Separate => assert_eq!(txs, MANY + 2, "every nonce its own transaction"),
    }
    for i in 0..n {
        let bundle = cyphr::replay::WireBundle::of_commit(p.commit_at(i as usize).expect("commit"))
            .expect("bundle");
        let claim = Claim::Member {
            index: i,
            commit: bundle,
        };
        let cert = p.prove(n, &claim).await.expect("prove");
        let back: Certificate =
            serde_json::from_value(serde_json::to_value(&cert).expect("serialize"))
                .unwrap_or_else(|e| panic!("index {i}: an honest certificate is refused: {e}"));
        assert_eq!(
            verify(&Anchor::of_chain(p.state()), &back, n, &claim),
            Ok(()),
            "chain, index {i}"
        );
        assert_eq!(
            verify(&Anchor::pin(p.root_at(n).expect("root")), &back, n, &claim),
            Ok(()),
            "pin, index {i}"
        );
    }
    // And an extension across the same commit, from the genesis alone.
    let holder = {
        let a = kp(coz::Alg::Ed25519);
        let _ = a;
        p.fork().await.expect("fork")
    };
    let head = p.root_at(n).expect("head");
    let claim = Claim::Extends {
        from: 1,
        head: head.pr.clone(),
    };
    let cert = holder.prove(n, &claim).await.expect("prove");
    let back: Certificate =
        serde_json::from_value(serde_json::to_value(&cert).expect("serialize")).expect("parses");
    assert_eq!(
        verify(&Anchor::of_chain(p.state()), &back, n, &claim),
        Ok(())
    );
}

// More than 256 Principal Tree cells (the PR holds MANY nonces) and a
// transaction of more than 256 cozies.
#[tokio::test]
async fn a_grouped_transaction_of_many_cozies_and_many_cells_is_provable() {
    proves_and_verifies(Shape::Grouped).await;
}

// A commit of more than 256 mutation transactions, the transaction root
// over all of them.
#[tokio::test]
async fn a_commit_of_many_transactions_is_provable() {
    proves_and_verifies(Shape::Separate).await;
}

// ---- cost of a proof across algorithm epochs, against n and k ----

/// The algorithm of each epoch in turn. Distinct hash families for the
/// first three (SHA-512, SHA-256, SHA-384); the fourth returns to SHA-512,
/// the shape `resume` in `stitch.rs` already proves.
const EPOCHS: [coz::Alg; 4] = [
    coz::Alg::Ed25519,
    coz::Alg::ES256,
    coz::Alg::ES384,
    coz::Alg::ES512,
];

/// One commit by `by`: `typ` (`create`/`delete`/`replace`) of `id`.
async fn commit_key(p: &mut Principal, by: &Kp, typ: &str, id: &Kp, now: i64) {
    let mut pay = json!({"alg": by.alg, "id": tmb(id), "now": now,
                         "tmb": tmb(by), "typ": format!("{AUTHORITY}/cyphr/key/{typ}")});
    pay.as_object_mut().expect("object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    let side = (typ != "delete").then(|| key_of(id));
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&v, &sig, czd, side).expect("apply");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

/// `n` commits and `k` algorithm changes, the changes spread evenly: the
/// epoch's key toggles a spare key of its own algorithm in and out between
/// them (the Principal Tree stays the same size, and the epoch's family
/// closes only at the change: the spare is out by then).
async fn epochs(n: usize, k: usize) -> Principal {
    let mut era = vec![kp(EPOCHS[0])];
    let mut p = Principal::implicit(key_of(&era[0])).await.expect("open");
    p.commit_genesis(&signer(&era[0]), &[], T, AUTHORITY)
        .await
        .expect("genesis");
    let mut spare = kp(EPOCHS[0]);
    let mut spare_in = false;
    let mut changes = 0;
    for i in 1..n {
        let due = changes < k && i >= (changes + 1) * n / (k + 1);
        let now = T + 10 * i as i64;
        let by = era.last().expect("an era");
        if due && !spare_in {
            let next = kp(EPOCHS[changes + 1]);
            commit_key(&mut p, by, "replace", &next, now).await;
            era.push(next);
            spare = kp(EPOCHS[changes + 1]);
            changes += 1;
        } else {
            let typ = if spare_in { "delete" } else { "create" };
            commit_key(&mut p, by, typ, &spare, now).await;
            spare_in = !spare_in;
        }
    }
    assert_eq!(p.commit_count(), n);
    assert_eq!(changes, k, "every change fell inside the chain");
    p
}

/// What a certificate costs: the hashes it carries (path siblings,
/// consistency peaks and boundary), its stitches, its bytes on the wire.
#[derive(Debug, Clone, Copy)]
struct Cost {
    hashes: usize,
    stitches: usize,
    bytes: usize,
}

fn cost(cert: &Certificate) -> Cost {
    fn hashes(v: &serde_json::Value) -> usize {
        match v {
            serde_json::Value::Object(o) => o
                .iter()
                .map(|(k, v)| {
                    let own = match k.as_str() {
                        "siblings" | "new_peaks" => v.as_array().map_or(0, Vec::len),
                        "boundary_hash" => 1,
                        _ => 0,
                    };
                    own + hashes(v)
                })
                .sum(),
            serde_json::Value::Array(a) => a.iter().map(hashes).sum(),
            _ => 0,
        }
    }
    let v = serde_json::to_value(cert).expect("serialize");
    Cost {
        hashes: hashes(&v),
        stitches: v["stitches"].as_array().map_or(0, Vec::len),
        bytes: serde_json::to_vec(&v).expect("bytes").len(),
    }
}

/// The cost of proving the oldest commit after the genesis a member of the
/// head, and the head an extension of the genesis and that commit: the
/// proofs that cross every change.
async fn oldest_costs(p: &Principal) -> (Cost, Cost) {
    let n = p.commit_count() as u64;
    let bundle =
        cyphr::replay::WireBundle::of_commit(p.commit_at(1).expect("commit")).expect("bundle");
    let member = Claim::Member {
        index: 1,
        commit: bundle,
    };
    let member = cost(&p.prove(n, &member).await.expect("prove member"));
    let head = p.root_at(n).expect("head").pr;
    let holder = p.fork().await.expect("fork");
    let extends = Claim::Extends { from: 2, head };
    let extends = cost(&holder.prove(n, &extends).await.expect("prove extends"));
    (member, extends)
}

fn log2_ceil(n: usize) -> usize {
    n.next_power_of_two().trailing_zeros() as usize
}

/// Bound: a `member` or `extends` certificate of the oldest commits across
/// `k` algorithm changes carries O(log n) hashes per stitch and a size that
/// grows with log n, at every n of `sizes`.
///
/// Slope checked, at fixed k: hashes <= (stitches + 1) (2 ceil(log2 n) + 2),
/// and bytes(n) <= 3 bytes(smallest n). Over a span of 16x (fast) or 128x
/// (large) log n grows x2.3 or x2.75, so a certificate that grows with n
/// (x16, x128) is red against the ratio at once; the fixed opening of each
/// stitch keeps the real ratio near 1.5 and the factor of 3 leaves room for
/// that and no room for n.
async fn logarithmic_in_history(k: usize, sizes: &[usize]) {
    let mut first: Option<(Cost, Cost)> = None;
    for &n in sizes {
        let p = epochs(n, k).await;
        let (member, extends) = oldest_costs(&p).await;
        // Past the third change the chain is back in a family it started
        // in, which never closed: index 1 needs no stitch there.
        assert!(member.stitches <= k && extends.stitches == k, "n={n} k={k}");
        for (what, c) in [("member", member), ("extends", extends)] {
            let cap = (c.stitches + 1) * (2 * log2_ceil(n) + 2);
            assert!(
                c.hashes <= cap,
                "{what}, n={n} k={k}: {} hashes, cap {cap}",
                c.hashes
            );
        }
        let (m0, e0) = *first.get_or_insert((member, extends));
        assert!(
            member.bytes <= 3 * m0.bytes && extends.bytes <= 3 * e0.bytes,
            "k={k}: member {} bytes at n={n}, {} at n={}; extends {} and {}",
            member.bytes,
            m0.bytes,
            sizes[0],
            extends.bytes,
            e0.bytes
        );
    }
}

/// Bound: at fixed n, the extra bytes of a certificate are linear in the
/// number of algorithm changes: each stitch carries one opening of the
/// same shape and one path, whatever the stitches before it.
///
/// Slope checked: bytes(k) - bytes(0) <= 1.5 k (bytes(1) - bytes(0)) for
/// k = 2 and 3. Growing like k(k + 1) / 2 (every stitch re-carrying those
/// before it) would show 3x the one-stitch increase at k = 2 and 6x at
/// k = 3 against allowed 3x and 4.5x, so k = 3 is red; k stops at 3, the
/// changes `EPOCHS` can name, so the separation is that of one point.
async fn linear_in_changes(n: usize) {
    let mut bytes = Vec::new();
    for k in 0..=3 {
        let (_, extends) = oldest_costs(&epochs(n, k).await).await;
        bytes.push(extends.bytes);
    }
    let step = (bytes[1] - bytes[0]) as f64;
    for k in 2..=3usize {
        let extra = (bytes[k] - bytes[0]) as f64;
        assert!(
            extra <= 1.5 * k as f64 * step,
            "n={n}: extension bytes by changes {bytes:?}"
        );
    }
}

macro_rules! suite {
    ($m:ident, $sizes:expr, $mid:expr $(, #[$attr:meta])?) => {
        mod $m {
            use super::*;

            const SIZES: &[usize] = &$sizes;

            #[tokio::test]
            $(#[$attr])?
            async fn no_change_is_logarithmic_in_history() {
                logarithmic_in_history(0, SIZES).await;
            }

            #[tokio::test]
            $(#[$attr])?
            async fn one_change_is_logarithmic_in_history() {
                logarithmic_in_history(1, SIZES).await;
            }

            #[tokio::test]
            $(#[$attr])?
            async fn two_changes_are_logarithmic_in_history() {
                logarithmic_in_history(2, SIZES).await;
            }

            #[tokio::test]
            $(#[$attr])?
            async fn three_changes_are_logarithmic_in_history() {
                logarithmic_in_history(3, SIZES).await;
            }

            #[tokio::test]
            $(#[$attr])?
            async fn bytes_are_linear_in_changes() {
                linear_in_changes($mid).await;
            }
        }
    };
}

// Span 16x of n, in the normal run; k from 0 to 3 at n = 32.
suite!(fast, [8, 32, 128], 32);
// Span 128x of n (the 2048-commit chains take about a minute each to
// build, five minutes in all), ignored for it; k at n = 256.
suite!(
    large,
    [16, 256, 2048],
    256,
    #[ignore = "large: 2048-commit chains take about 5 minutes to build"]
);
