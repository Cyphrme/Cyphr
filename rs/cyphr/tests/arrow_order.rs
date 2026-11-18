//! The commit `arrow` is `MR(pre, fwd, TMR)` in that order (SPEC 4.2).
//!
//! SPEC 3.7 sorts an MR's children "unless sort order is otherwise
//! defined"; 4.2 defines the arrow's order by naming `pre`, `fwd` and
//! TMR. Sorting the three would not bind roles: a proof could present
//! `pre` and `fwd` swapped and still recompute the signed arrow.
//!
//! Every expected value is computed here from raw digests, never through
//! the code under test.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::multihash::MultihashDigest;
use cyphr::signer::SoftwareSigner;
use cyphr::state::HashAlg;
use cyphr::{Key, Principal};
use test_fixtures::Pool;

const AUTHORITY: &str = "cyphr.me";
const NOW: i64 = 1_700_000_000;

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pub_key: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp(name: &str) -> Kp {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    let pk = Pool::load(&path)
        .expect("pool.toml loads")
        .get(name)
        .unwrap_or_else(|| panic!("pool key {name} missing"))
        .clone();
    Kp {
        alg: pk.alg.clone(),
        prv: Base64UrlUnpadded::decode_vec(pk.prv.as_ref().expect("prv")).expect("prv b64"),
        pub_key: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pub_key.clone())
        .expect("key binds its tmb")
        .with_first_seen(NOW)
}

fn signer(k: &Kp) -> SoftwareSigner {
    SoftwareSigner::new(&k.alg, &k.prv, &k.pub_key, &k.tmb)
}

fn h(parts: &[&[u8]]) -> Vec<u8> {
    HashAlg::Sha256.hash_bytes(&parts.concat())
}

/// What the commit's scope is checked against.
struct Setup {
    pre: Vec<u8>,
    fwd: Vec<u8>,
    tmr: Vec<u8>,
}

impl Setup {
    /// The components of the arrow, as raw digests.
    fn arrow(&self, order: [&[u8]; 3]) -> MultihashDigest {
        MultihashDigest::from_single(HashAlg::Sha256, h(&order)).expect("sha-256 digest")
    }

    fn defined(&self) -> MultihashDigest {
        self.arrow([&self.pre, &self.fwd, &self.tmr])
    }

    fn sorted(&self) -> MultihashDigest {
        let mut v = [&self.pre[..], &self.fwd[..], &self.tmr[..]];
        v.sort();
        self.arrow(v)
    }

    fn pre_fwd_swapped(&self) -> MultihashDigest {
        self.arrow([&self.fwd, &self.pre, &self.tmr])
    }
}

/// A pending second commit: `golden` creates `key_a` (SPEC 4.2: `pre` is
/// the prior PR, `fwd` the SR over both keys, TMR the lone mutation).
/// All keys are ES256, so every component is a SHA-256 digest; with no
/// rules or data, the SR is the Key Root, the hash of the two sorted
/// thumbprints, and a lone mutation's TMR is its `czd` promoted.
///
/// `pre` and TMR depend on signatures, which are not deterministic, so
/// the byte order of the three components varies between runs.
/// `attempt` varies `now` to draw a fresh commit.
async fn pending_commit<R>(attempt: i64, f: impl FnOnce(&Setup, cyphr::CommitScope<'_>) -> R) -> R {
    let (golden, key_a) = (kp("golden"), kp("key_a"));
    let mut p = Principal::implicit(key_of(&golden)).await.expect("open");
    p.commit_genesis(&signer(&golden), &[], NOW + attempt, AUTHORITY)
        .await
        .expect("genesis");

    let b64 = |t: &coz::Thumbprint| Base64UrlUnpadded::encode_string(t.as_bytes());
    let pay = serde_json::json!({"alg": golden.alg, "id": b64(&key_a.tmb), "now": NOW + attempt + 1,
        "tmb": b64(&golden.tmb), "typ": format!("{AUTHORITY}/cyphr/key/create")});
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&v, &golden.alg, &golden.prv, &golden.pub_key).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &golden.alg).expect("czd");

    let setup = Setup {
        pre: p.pr().0.get(HashAlg::Sha256).expect("sha-256 PR").to_vec(),
        fwd: {
            let mut leaves = [golden.tmb.as_bytes(), key_a.tmb.as_bytes()];
            leaves.sort();
            h(&leaves)
        },
        tmr: czd.as_bytes().to_vec(),
    };

    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&v, &sig, czd, Some(key_of(&key_a)))
        .expect("apply key/create");
    f(&setup, scope)
}

/// Draw commits until `want` holds of the component order, then run `f`
/// on it. Each draw is one of six orders, so a miss in 256 is not a
/// flake but a broken draw.
async fn commit_where(want: fn(&Setup) -> bool, f: impl Fn(&Setup, cyphr::CommitScope<'_>)) {
    for attempt in 0..256 {
        let ran = pending_commit(attempt, |s, scope| want(s).then(|| f(s, scope)).is_some()).await;
        if ran {
            return;
        }
    }
    panic!("no commit with the wanted component order in 256 draws");
}

/// (a) The arrow is `H(pre || fwd || TMR)`: the defined order is checked,
/// and, on a commit whose sorted order differs, the sorted value (the old
/// computation) is not.
#[tokio::test]
async fn arrow_is_defined_order_not_sorted() {
    commit_where(
        |s| s.defined() != s.sorted(),
        |s, scope| {
            assert!(
                scope.matches_arrow(&s.defined()),
                "H(pre || fwd || TMR) is the arrow"
            );
            assert!(
                !scope.matches_arrow(&s.sorted()),
                "the sorted-component arrow must not verify"
            );
        },
    )
    .await;
}

/// (b) Swapping `pre` and `fwd` changes the arrow, and the swapped
/// commit is refused at admission. The commit drawn is one where the
/// sorted order puts `fwd` before `pre`, so a sorting check would accept
/// the swap: the forgery a proof could present.
#[tokio::test]
async fn swapped_pre_and_fwd_is_refused() {
    commit_where(
        |s| s.sorted() == s.pre_fwd_swapped(),
        |s, scope| {
            assert_ne!(s.defined(), s.pre_fwd_swapped(), "the preimage binds roles");
            assert!(
                !scope.matches_arrow(&s.pre_fwd_swapped()),
                "an arrow computed with pre and fwd swapped must be refused"
            );
            assert!(
                scope.matches_arrow(&s.defined()),
                "control: the defined arrow"
            );
        },
    )
    .await;
}
