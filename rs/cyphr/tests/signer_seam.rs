//! Acceptance suite for the `Signer` seam (node SG1).
//!
//! Every commit-finalizing path must sign through a [`Signer`] that need
//! never expose key bytes, so non-exportable keys (hardware, WebCrypto) can
//! sign. Test standard: each test states the CLAIM it backs, the DEFECT that
//! turns it red, and whether it is an end-to-end scenario.
//!
//! # Pinned API (the only coupling to the not-yet-written implementation)
//!
//! ```ignore
//! // cyphr::signer
//! pub trait Signer {
//!     fn alg(&self) -> &str;
//!     fn pub_key(&self) -> &[u8];
//!     fn tmb(&self) -> &coz::Thumbprint;
//!     /// MUST return the canonical low-S form; the core never normalizes.
//!     fn sign(&self, cad: &coz::Cad)
//!         -> impl Future<Output = Result<Vec<u8>, SignerError>>; // no `Send` bound
//! }
//! pub enum SignerError { Backend(String), .. }
//!
//! // cyphr::commit
//! impl CommitScope<'_> {
//!     pub async fn finalize_with_signer<S: Signer + ?Sized>(
//!         self, signer: &S, now: i64, authority: &str,
//!     ) -> cyphr::error::Result<&Commit>;
//! }
//! // cyphr::Error gains `Signer(SignerError)`; a returned signature that
//! // fails `coz::verify_json` is `Error::InvalidSignature`.
//! ```
//!
//! Trait naming and exact signatures are the implementer's to adapt (the
//! brief marks them plastic); the PROPERTIES below are not. Adapt the shim
//! in `OpaqueSigner`/`finalize` and keep every assertion.
//!
//! Run: `cd rs && cargo test -p cyphr --test signer_seam`

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use coz::base64ct::{Base64UrlUnpadded as B64, Encoding};
use coz::{Cad, Thumbprint};
use cyphr::key::Key;
use cyphr::signer::{Signer, SignerError};
use cyphr::{Error, Principal};
use proptest::prelude::*;

const NOW: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";

// ============================================================================
// Fixtures
// ============================================================================

/// Minimal single-threaded driver: poll with a no-op waker until ready.
///
/// A signer future, and the core futures awaiting it, must be drivable by an
/// arbitrary caller-owned executor (tokio, wasm-bindgen-futures, ...): this
/// one knows nothing of the core and polls `!Send` futures, so passing here
/// shows the seam needs no particular runtime. Over in-memory storage every
/// core future completes without suspending.
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("repo root above rs/cyphr")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("load pool.toml")
}

fn domain_key(pk: &test_fixtures::PoolKey) -> Key {
    Key::new(
        pk.alg.clone(),
        pk.compute_tmb().expect("tmb"),
        B64::decode_vec(&pk.pub_key).expect("pub b64"),
    )
    .expect("key binds its tmb")
}

/// `p` with its genesis committed (SPEC 5.1: a commit chain begins with the
/// genesis key's `key/create` of itself, the `principal/create` and the
/// `commit/create`), signed by its genesis key `k`, which creates
/// each of `others` after itself.
async fn genesis_of(mut p: Principal, k: &test_fixtures::PoolKey, others: &[Key]) -> Principal {
    p.commit_genesis(
        &cyphr::signer::SoftwareSigner::new(
            &k.alg,
            &coz::base64ct::Base64UrlUnpadded::decode_vec(k.prv.as_deref().expect("prv"))
                .expect("prv b64"),
            &coz::base64ct::Base64UrlUnpadded::decode_vec(&k.pub_key).expect("pub b64"),
            &k.compute_tmb().expect("tmb"),
        ),
        others,
        1,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");
    p
}

/// Software signer whose private key is unreachable from outside this
/// struct: no accessor, no `Debug` of the bytes. Stands in for a hardware /
/// WebCrypto key — the test bodies below never hold private-key bytes.
struct OpaqueSigner {
    alg: String,
    pub_key: Vec<u8>,
    tmb: Thumbprint,
    prv: Vec<u8>,
}

impl OpaqueSigner {
    fn from_pool(pool: &test_fixtures::Pool, name: &str) -> Self {
        let pk = pool.get(name).expect("pool key");
        Self {
            alg: pk.alg.clone(),
            pub_key: B64::decode_vec(&pk.pub_key).expect("pub b64"),
            tmb: pk.compute_tmb().expect("tmb"),
            prv: B64::decode_vec(pk.prv.as_ref().expect("pool key has prv")).expect("prv b64"),
        }
    }

    fn raw_sign(&self, cad: &Cad) -> Vec<u8> {
        match self.alg.as_str() {
            "ES256" => coz::signing_key_from_bytes::<coz::ES256>(&self.prv)
                .expect("es256 key")
                .sign(cad.as_bytes()),
            "ES384" => coz::signing_key_from_bytes::<coz::ES384>(&self.prv)
                .expect("es384 key")
                .sign(cad.as_bytes()),
            "Ed25519" => coz::signing_key_from_bytes::<coz::Ed25519>(&self.prv)
                .expect("ed25519 key")
                .sign(cad.as_bytes()),
            other => panic!("unsupported test alg {other}"),
        }
    }
}

impl Signer for OpaqueSigner {
    fn alg(&self) -> &str {
        &self.alg
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn tmb(&self) -> &Thumbprint {
        &self.tmb
    }

    async fn sign(&self, cad: &Cad) -> Result<Vec<u8>, SignerError> {
        Ok(self.raw_sign(cad))
    }
}

/// How a misbehaving backend corrupts (or refuses) the signature it hands
/// back. Wraps a real signer so the ONLY difference from a good run is the
/// named defect.
#[derive(Clone, Debug)]
enum Fault {
    /// Backend reports failure (device unplugged, user denied).
    Backend,
    /// Returns an empty signature instead of an error.
    Empty,
    /// Valid signature with one byte dropped.
    Truncated,
    /// Valid signature with one byte appended.
    Extended,
    /// Valid signature over a *different* cad.
    WrongCad,
    /// ES256 only: the mathematically valid high-S twin (`s' = n - s`).
    HighS,
    /// Arbitrary bytes.
    Bytes(Vec<u8>),
    /// A genuine signature with one bit flipped.
    BitFlip(usize),
}

struct FaultySigner {
    inner: OpaqueSigner,
    fault: Fault,
}

/// P-256 group order `n`, big-endian.
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// `n - s` over 32-byte big-endian integers (s < n).
fn p256_flip_s(sig: &[u8]) -> Vec<u8> {
    assert_eq!(sig.len(), 64, "ES256 signature is r || s");
    let mut out = sig.to_vec();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(P256_N[i]) - i16::from(sig[32 + i]) - borrow;
        borrow = i16::from(d < 0);
        if d < 0 {
            d += 256;
        }
        out[32 + i] = u8::try_from(d).expect("digit in range");
    }
    out
}

impl Signer for FaultySigner {
    fn alg(&self) -> &str {
        self.inner.alg()
    }

    fn pub_key(&self) -> &[u8] {
        self.inner.pub_key()
    }

    fn tmb(&self) -> &Thumbprint {
        self.inner.tmb()
    }

    async fn sign(&self, cad: &Cad) -> Result<Vec<u8>, SignerError> {
        let good = self.inner.raw_sign(cad);
        match &self.fault {
            Fault::Backend => Err(SignerError::Backend("device unplugged".into())),
            Fault::Empty => Ok(Vec::new()),
            Fault::Truncated => Ok(good[..good.len() - 1].to_vec()),
            Fault::Extended => Ok([good, vec![0u8]].concat()),
            Fault::WrongCad => Ok(self
                .inner
                .raw_sign(&Cad::from_bytes(vec![7u8; cad.as_bytes().len()]))),
            Fault::HighS => Ok(p256_flip_s(&good)),
            Fault::Bytes(b) => Ok(b.clone()),
            Fault::BitFlip(i) => {
                let mut s = good;
                let bit = i % (s.len() * 8);
                s[bit / 8] ^= 1 << (bit % 8);
                Ok(s)
            },
        }
    }
}

/// Sign `pay` (serde_json sorts keys) through the seam; returns `(pay bytes, sig, czd)`.
/// Used for the mutation coz so that NO test body holds private-key bytes.
fn sign_pay_via<S: Signer>(signer: &S, pay: &serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let pay_vec = serde_json::to_vec(pay).expect("pay json");
    let cad = coz::canonical_hash_for_alg(&pay_vec, signer.alg(), None).expect("cad");
    let sig = block_on(signer.sign(&cad)).expect("good signer signs");
    let czd = coz::czd_for_alg(&cad, &sig, signer.alg()).expect("czd");
    (pay_vec, sig, czd)
}

/// A genesis principal plus one signed `key/create` applied to an open scope.
fn open_scope<'p, S: Signer>(
    principal: &'p mut Principal,
    signer: &S,
    target: &test_fixtures::PoolKey,
) -> cyphr::CommitScope<'p> {
    open_scope_at(principal, signer, target, NOW)
}

fn open_scope_at<'p, S: Signer>(
    principal: &'p mut Principal,
    signer: &S,
    target: &test_fixtures::PoolKey,
    now: i64,
) -> cyphr::CommitScope<'p> {
    let pay = serde_json::json!({
        "alg": signer.alg(),
        "id": target.compute_tmb_b64().expect("target tmb"),
        "now": now,
        "tmb": signer.tmb().to_b64(),
        "typ": "cyphr.me/cyphr/key/create",
    });
    let (pay_vec, sig, czd) = sign_pay_via(signer, &pay);
    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay_vec, &sig, czd, Some(domain_key(target)))
        .expect("mutation applies");
    scope
}

fn finalize<'a, S: Signer>(
    scope: cyphr::CommitScope<'a>,
    signer: &S,
) -> cyphr::error::Result<&'a cyphr::Commit> {
    block_on(scope.finalize_with_signer(signer, NOW + 1, AUTHORITY))
}

// ============================================================================
// Claim 1 + golden: finalize through a key-opaque signer; bytes unchanged
// ============================================================================

/// Vectors over fixed inputs (pool key -> its genesis commit -> `key_a`
/// key/create at NOW -> commit at NOW+1), stable across repeated runs (RFC
/// 6979 / Ed25519 are deterministic). First recorded from the pre-seam
/// raw-key finalize; re-recorded when every chain gained its genesis
/// commit, which changes the commit's `pre` and so its bytes, and again
/// when TR became the flat MR of the transaction ids (SPEC 3.7.5): the
/// genesis commit has two mutation transactions, so its TR, and with it
/// the `pre` this commit's arrow binds, moved.
const GOLDEN: &[(&str, &str, &str)] = &[
    (
        "golden",
        "38bmkp-QLwM-mjje3KV2Wp7kXG71KMqGv1zgl6-TjVc",
        "KIm8vJ-WNh9z4b445FgwmFRle7Kk5fxjrLxFPnyEgJJgTcGSy3k3wsZH0JzfreI12IA7jFh1O5-qIAwp1vCu_g",
    ),
    (
        "diana_es384",
        "7igmbf2sUpFlz5XGkExCCrMmI7kTrkYmBnfVaSeVPPcFB4xKBEwDkOIk8CRS5MlD",
        "1KCf9ZL0-NGvJdFTL7ecreyoEE4rNvGix2ob30rJ8jih5yTrpktzU8KFX2vrPu_eN9pl0ivhyfrxUijcelbcEPrbGg4Nb5mgdlgJ8TtadEglb1DbD8cOkmWeLVlWCMkS",
    ),
    (
        "eve_ed25519",
        "pZdvd_ySMHE8gNIrYsYJ3A5n4Eh0VJMOP6CJEluzFk4tH0UP-XV0uNeQQYT6fdp-whu68P7Hg8VZfVgxXtG6TQ",
        "zxOONpBdFtV_x1XToPez84zT3nx3qhNQ08gmGqN3esb3qL-Gp_hc2QU95bz8C3KgZB6P8kgJL42pLrCj2U2-AQ",
    ),
];

/// CLAIM (a-red-first, a-golden; scenario: yes, genesis -> mutation ->
/// signer-finalized commit -> independent verification, ES256/ES384/Ed25519):
/// a commit can be finalized through a `Signer` whose key bytes the caller
/// never holds, and the seam changes no signed byte.
///
/// RED IF: the seam still needs raw private bytes somewhere on the path
/// (this file would not compile without them), the commit coz is signed by a
/// different key/alg than the signer's, the signer is handed anything but the
/// cad of the commit pay, or signing through the seam alters sig/czd/cad
/// relative to the legacy golden vectors.
#[tokio::test]
async fn opaque_signer_finalizes_commit_with_legacy_bytes() {
    let pool = pool();
    for (name, want_czd, want_sig) in GOLDEN {
        let signer = OpaqueSigner::from_pool(&pool, name);
        let target = pool.get("key_a").expect("key_a");
        let mut principal = genesis_of(
            Principal::implicit(domain_key(pool.get(name).expect("genesis")))
                .await
                .expect("genesis principal"),
            pool.get(name).expect("genesis"),
            &[],
        )
        .await;
        let scope = open_scope(&mut principal, &signer, target);

        let commit = finalize(scope, &signer).unwrap_or_else(|e| panic!("{name}: finalize: {e}"));

        let coz = commit.commit_tx().0[0].coz();
        let raw = coz.raw();
        // Independent verification: the commit coz verifies under the
        // signer's public key, and names the signer's thumbprint and alg.
        let pay_vec = serde_json::to_vec(&raw.pay).expect("pay");
        assert_eq!(
            coz::verify_json(&pay_vec, &raw.sig, signer.alg(), signer.pub_key()),
            Some(true),
            "{name}: commit coz must verify under the signer's key"
        );
        assert_eq!(raw.pay["tmb"], signer.tmb().to_b64(), "{name}: tmb");
        assert_eq!(raw.pay["alg"], signer.alg(), "{name}: alg");
        // Golden: byte-identical to the pre-seam path.
        assert_eq!(&coz.czd().to_b64(), want_czd, "{name}: commit czd drifted");
        assert_eq!(
            &B64::encode_string(&raw.sig),
            want_sig,
            "{name}: commit sig drifted"
        );
        assert_eq!(
            principal.commits().count(),
            2,
            "{name}: the genesis, then exactly one commit"
        );
    }
}

// ============================================================================
// Claim 2: async + !Send
// ============================================================================

/// Pending exactly once, then ready — models WebCrypto's promise round-trip.
struct YieldOnce(bool);
impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// `!Send` signer (holds `Rc`) that genuinely suspends before answering and
/// records the cad it was asked to sign.
struct LocalSigner {
    inner: OpaqueSigner,
    calls: Rc<Cell<u32>>,
    seen_cad: Rc<std::cell::RefCell<Option<Vec<u8>>>>,
}

impl Signer for LocalSigner {
    fn alg(&self) -> &str {
        self.inner.alg()
    }

    fn pub_key(&self) -> &[u8] {
        self.inner.pub_key()
    }

    fn tmb(&self) -> &Thumbprint {
        self.inner.tmb()
    }

    async fn sign(&self, cad: &Cad) -> Result<Vec<u8>, SignerError> {
        self.calls.set(self.calls.get() + 1);
        *self.seen_cad.borrow_mut() = Some(cad.as_bytes().to_vec());
        YieldOnce(false).await;
        Ok(self.inner.raw_sign(cad))
    }
}

/// CLAIM (c-signer-shape; scenario: yes — a suspended, `!Send` backend
/// drives a full commit): the trait is usable from async and `!Send`
/// contexts, signs exactly the cad of the commit pay, and is invoked once.
///
/// RED IF: the trait or the finalize future requires `Send` (this file stops
/// compiling: `LocalSigner` holds `Rc`); the core does not await the
/// signature (never-ready future is dropped, no commit); the core signs more
/// than once per commit; or the cad handed over is not
/// `canonical_hash(commit pay)`.
#[tokio::test]
async fn not_send_suspending_signer_finalizes_exactly_once() {
    let pool = pool();
    let calls = Rc::new(Cell::new(0));
    let seen_cad = Rc::new(std::cell::RefCell::new(None));
    let signer = LocalSigner {
        inner: OpaqueSigner::from_pool(&pool, "golden"),
        calls: Rc::clone(&calls),
        seen_cad: Rc::clone(&seen_cad),
    };
    let target = pool.get("key_a").expect("key_a");
    let mut principal = genesis_of(
        Principal::implicit(domain_key(pool.get("golden").expect("genesis")))
            .await
            .expect("genesis principal"),
        pool.get("golden").expect("genesis"),
        &[],
    )
    .await;
    // Mutation signing also goes through the signer; reset the counter after.
    let scope = open_scope(&mut principal, &signer, target);
    calls.set(0);

    let commit = finalize(scope, &signer).expect("finalize through !Send signer");

    assert_eq!(calls.get(), 1, "one signature per commit");
    let pay_vec = serde_json::to_vec(&commit.commit_tx().0[0].coz().raw().pay).expect("pay");
    let want = coz::canonical_hash_for_alg(&pay_vec, "ES256", None).expect("cad");
    assert_eq!(
        seen_cad.borrow().as_deref(),
        Some(want.as_bytes()),
        "signer must be handed the cad of the commit pay"
    );
}

/// CLAIM (c-signer-shape, split API; scenario: yes — full genesis ->
/// mutation -> prepare/sign/finish): the three-step API lets a caller sign
/// on an executor of its own (here `futures::executor`) between the
/// synchronous prepare and the finish, and the signature it returns commits.
///
/// RED IF: prepare becomes async or mutates the scope, or finish signs
/// again instead of taking the caller's signature.
#[tokio::test]
async fn split_api_works_under_a_futures_executor() {
    let pool = pool();
    let signer = OpaqueSigner::from_pool(&pool, "golden");
    let target = pool.get("key_a").expect("key_a");
    let mut principal = genesis_of(
        Principal::implicit(domain_key(pool.get("golden").expect("genesis")))
            .await
            .expect("genesis principal"),
        pool.get("golden").expect("genesis"),
        &[],
    )
    .await;
    let scope = open_scope(&mut principal, &signer, target);

    let prepared = scope
        .prepare_commit(&signer, NOW + 1, AUTHORITY)
        .expect("prepare is synchronous");
    let sig = futures::executor::block_on(signer.sign(prepared.cad())).expect("sign");
    let commit = scope.finish_commit(prepared, sig).await.expect("finish");

    assert_eq!(&commit.commit_tx().0[0].coz().czd().to_b64(), GOLDEN[0].1);
}

// ============================================================================
// Claims 3+4: typed errors; single low-S owner
// ============================================================================

fn assert_no_commit(principal: &Principal, pr_before: &str, what: &str) {
    // The genesis commit is the only one.
    assert_eq!(
        principal.commits().count(),
        1,
        "{what}: no commit may be recorded"
    );
    assert_eq!(
        principal.pr_tagged().expect("pr"),
        pr_before,
        "{what}: principal state must not move"
    );
}

/// Run one faulty finalize on a fresh principal and return the error,
/// asserting no commit landed.
async fn faulty_finalize_err(pool: &test_fixtures::Pool, name: &str, fault: Fault) -> Error {
    let what = format!("{name}/{fault:?}");
    let good = OpaqueSigner::from_pool(pool, name);
    let target = pool.get("key_a").expect("key_a");
    let mut principal = genesis_of(
        Principal::implicit(domain_key(pool.get(name).expect("genesis")))
            .await
            .expect("genesis principal"),
        pool.get(name).expect("genesis"),
        &[],
    )
    .await;
    let pr_before = principal.pr_tagged().expect("pr");
    // The mutation is signed by the honest signer; only the commit signer is faulty.
    let scope = open_scope(&mut principal, &good, target);
    let faulty = FaultySigner { inner: good, fault };
    let result = finalize(scope, &faulty);
    let err = match result {
        Ok(_) => panic!("{what}: a faulty signer must not yield a commit"),
        Err(e) => e,
    };
    assert_no_commit(&principal, &pr_before, &what);
    err
}

/// CLAIM (a-typed-errors; scenario: yes — each fault runs a whole
/// genesis -> mutation -> finalize against the real chain): a failing signer
/// yields a typed `Error::Signer`; an empty, truncated, over-long or
/// wrong-message signature yields `Error::InvalidSignature`; in no case is a
/// commit recorded or the principal's state moved.
///
/// RED IF: a backend error is swallowed into an empty signature; an
/// unverified signature reaches a commit; or a fault surfaces as the wrong
/// type (e.g. `MalformedPayload`, the legacy catch-all for sign failure).
#[tokio::test]
async fn faulty_signers_yield_typed_errors_and_no_commit() {
    let pool = pool();
    for name in ["golden", "diana_es384", "eve_ed25519"] {
        let e = faulty_finalize_err(&pool, name, Fault::Backend).await;
        assert!(
            matches!(e, Error::Signer(SignerError::Backend(_))),
            "{name}: backend failure -> typed Signer error, got {e:?}"
        );
        for fault in [
            Fault::Empty,
            Fault::Truncated,
            Fault::Extended,
            Fault::WrongCad,
        ] {
            let e = faulty_finalize_err(&pool, name, fault.clone()).await;
            assert!(
                matches!(e, Error::InvalidSignature),
                "{name}/{fault:?}: expected InvalidSignature, got {e:?}"
            );
        }
    }
}

/// CLAIM (c-signer-shape, low-S single owner): low-S canonicality is owned by
/// the SIGNER (its contract returns the canonical form); the core owns only
/// verification and never normalizes. A high-S signature that is
/// mathematically valid for the cad is therefore REJECTED, not silently
/// flipped and accepted.
///
/// RED IF: the core normalizes S (the high-S twin succeeds — owner is
/// ambiguous), or skips `verify_json` (high-S commits). Non-vacuity: the same
/// scenario with the genuine low-S signature succeeds, and the grounding
/// asserts below show the high-S twin is really high-S yet cryptographically
/// valid for the cad, so rejection can only come from the canonicality check.
#[tokio::test]
async fn high_s_signature_is_rejected_not_normalized() {
    let pool = pool();
    let good = OpaqueSigner::from_pool(&pool, "golden");
    assert_eq!(good.alg(), "ES256");

    // Grounding: twin differs from genuine only in S, and verify_json
    // (coz's canonicality-enforcing verifier) accepts one and rejects the other.
    let probe = serde_json::json!({"alg": "ES256", "now": NOW, "typ": "x"});
    let (pay_vec, low, _) = sign_pay_via(&good, &probe);
    let high = p256_flip_s(&low);
    assert_eq!(&low[..32], &high[..32], "r unchanged");
    assert_ne!(low, high, "s flipped");
    assert_eq!(
        coz::verify_json(&pay_vec, &low, "ES256", good.pub_key()),
        Some(true)
    );
    assert_eq!(
        coz::verify_json(&pay_vec, &high, "ES256", good.pub_key()),
        Some(false)
    );

    let e = faulty_finalize_err(&pool, "golden", Fault::HighS).await;
    assert!(
        matches!(e, Error::InvalidSignature),
        "high-S must be rejected as InvalidSignature, got {e:?}"
    );

    // Counterpart: genuine low-S passes through the identical path.
    let target = pool.get("key_a").expect("key_a");
    let mut principal = genesis_of(
        Principal::implicit(domain_key(pool.get("golden").expect("genesis")))
            .await
            .expect("genesis principal"),
        pool.get("golden").expect("genesis"),
        &[],
    )
    .await;
    let scope = open_scope(&mut principal, &good, target);
    finalize(scope, &good).expect("low-S signature commits");
}

proptest! {
    // 64 cases sample the signature space (256 cost ~27 s).
    #![proptest_config(ProptestConfig::with_cases(64))]
    /// CLAIM (a-typed-errors, property): for ANY byte string a signer returns
    /// that is not the genuine signature — arbitrary bytes, or a genuine
    /// signature with any single bit flipped — finalize yields
    /// `Error::InvalidSignature` and records no commit. Invariant over the
    /// signature space, not a sampled example.
    ///
    /// RED IF: any non-verifying signature reaches a commit (e.g. verification
    /// is skipped, partial, or length-only).
    #[test]
    fn any_non_verifying_signature_never_commits(
        name_idx in 0usize..3,
        bytes in proptest::collection::vec(any::<u8>(), 0..140),
        flip in any::<usize>(),
        use_flip in any::<bool>(),
    ) {
        block_on(async move {
        let name = ["golden", "diana_es384", "eve_ed25519"][name_idx];
        let fault = if use_flip { Fault::BitFlip(flip) } else { Fault::Bytes(bytes) };
        let e = faulty_finalize_err(&pool(), name, fault).await;
        prop_assert!(matches!(e, Error::InvalidSignature), "got {e:?}");
            Ok::<(), TestCaseError>(())
        })?;
    }
}

// ============================================================================
// Claim 5: the commit signer must be an ACTIVE key of the principal
// ============================================================================
//
// `finish_commit` verifies the signature against the public key the signer
// itself reports. A self-consistent signer (own tmb, own pub, own signature)
// therefore verifies against itself regardless of the principal. The core
// must bind the signer to the principal: the reported tmb must be an active
// key, and the signature must verify under THAT key's public bytes.

/// Reports `tmb` while taking alg, public key and signatures from `key`.
/// With `tmb` = `key`'s own thumbprint it is just a self-consistent foreign
/// signer; with another key's `tmb` it is an impostor.
struct ClaimedSigner {
    tmb: Thumbprint,
    key: OpaqueSigner,
}

impl Signer for ClaimedSigner {
    fn alg(&self) -> &str {
        self.key.alg()
    }

    fn pub_key(&self) -> &[u8] {
        self.key.pub_key()
    }

    fn tmb(&self) -> &Thumbprint {
        &self.tmb
    }

    async fn sign(&self, cad: &Cad) -> Result<Vec<u8>, SignerError> {
        Ok(self.key.raw_sign(cad))
    }
}

fn commit_err(
    principal: &mut Principal,
    scope_signer: &OpaqueSigner,
    target: &str,
    commit_signer: &impl Signer,
    pool: &test_fixtures::Pool,
    what: &str,
) -> Error {
    let pr_before = principal.pr_tagged().expect("pr");
    let scope = open_scope(principal, scope_signer, pool.get(target).expect("target"));
    let err = match finalize(scope, commit_signer) {
        Ok(_) => panic!("{what}: commit must not be recorded"),
        Err(e) => e,
    };
    assert_no_commit(principal, &pr_before, what);
    err
}

/// CLAIM (signer bound to principal; scenario: yes — full
/// genesis -> mutation -> finalize on the real chain, genesis in each of
/// ES256/ES384/Ed25519): a signer holding a perfectly valid key the principal
/// never added cannot close a commit. Expected: `Error::UnknownKey`.
///
/// RED IF: the core accepts any self-consistent signer (checks the signature
/// only against the key the signer reports), i.e. `finalize` returns `Ok`.
#[tokio::test]
async fn signer_outside_principal_is_unknown_key() {
    let pool = pool();
    // (genesis, outsider): the outsider is a real pool key, absent from the principal.
    for (genesis, outsider) in [
        ("golden", "alice"),
        ("diana_es384", "golden"),
        ("eve_ed25519", "golden"),
    ] {
        let what = format!("{genesis}/outsider {outsider}");
        let honest = OpaqueSigner::from_pool(&pool, genesis);
        let foreign = OpaqueSigner::from_pool(&pool, outsider);
        let mut principal = genesis_of(
            Principal::implicit(domain_key(pool.get(genesis).expect("genesis")))
                .await
                .expect("genesis principal"),
            pool.get(genesis).expect("genesis"),
            &[],
        )
        .await;
        let e = commit_err(&mut principal, &honest, "key_a", &foreign, &pool, &what);
        assert!(
            matches!(e, Error::UnknownKey),
            "{what}: expected UnknownKey, got {e:?}"
        );
    }
}

/// CLAIM (tmb bound to key): a signer that reports the principal's real tmb
/// but holds and signs with a different key cannot close a commit; the
/// signature must verify under the public key of the key the tmb NAMES, not
/// under the pub the signer reports. Expected: `Error::InvalidSignature`
/// (the signature does not verify under the named key; the same-alg impostor
/// isolates this from any alg check). Cross-alg impostors (ES384/Ed25519
/// genesis, which have no same-alg sibling in the pool) only pin that no
/// commit lands and the error is typed; the exact variant there depends on
/// whether alg or signature is checked first.
///
/// RED IF: finalize returns `Ok` (tmb/pub mismatch unchecked).
#[tokio::test]
async fn signer_claiming_anothers_tmb_is_rejected() {
    let pool = pool();
    for (genesis, impostor) in [
        ("golden", "alice"),
        ("diana_es384", "golden"),
        ("eve_ed25519", "golden"),
    ] {
        let what = format!("{genesis}/impostor {impostor}");
        let honest = OpaqueSigner::from_pool(&pool, genesis);
        let claimed = ClaimedSigner {
            tmb: honest.tmb().clone(),
            key: OpaqueSigner::from_pool(&pool, impostor),
        };
        let mut principal = genesis_of(
            Principal::implicit(domain_key(pool.get(genesis).expect("genesis")))
                .await
                .expect("genesis principal"),
            pool.get(genesis).expect("genesis"),
            &[],
        )
        .await;
        let e = commit_err(&mut principal, &honest, "key_a", &claimed, &pool, &what);
        if genesis == "golden" {
            assert!(
                matches!(e, Error::InvalidSignature),
                "{what}: expected InvalidSignature, got {e:?}"
            );
        }
    }
}

/// CLAIM (revocation honoured; scenario: yes — two commits): a key that the
/// principal added and then revoked cannot close a later commit, for revoked
/// keys of each algorithm. Expected: `Error::KeyRevoked`.
///
/// RED IF: the core never consults the principal's revocation state for the
/// commit signer (finalize returns `Ok`).
#[tokio::test]
async fn revoked_signer_is_key_revoked() {
    let pool = pool();
    for revoked_name in ["key_a", "diana_es384", "eve_ed25519"] {
        let what = format!("revoked {revoked_name}");
        let genesis = OpaqueSigner::from_pool(&pool, "golden");
        let revoked = OpaqueSigner::from_pool(&pool, revoked_name);
        let mut principal = genesis_of(
            Principal::implicit(domain_key(pool.get("golden").expect("genesis")))
                .await
                .expect("genesis principal"),
            pool.get("golden").expect("genesis"),
            &[],
        )
        .await;

        // Commit 1: genesis adds the key that will later be revoked.
        let scope = open_scope(
            &mut principal,
            &genesis,
            pool.get(revoked_name).expect("revoked key"),
        );
        finalize(scope, &genesis).expect("commit 1");
        principal
            .pre_revoke_key(revoked.tmb(), 1000)
            .expect("revoke");

        // Commit 2: genesis adds another key, but the revoked key tries to close it.
        let pr_before = principal.pr_tagged().expect("pr");
        let commits_before = principal.commits().count();
        let scope = open_scope_at(
            &mut principal,
            &genesis,
            pool.get("bob").expect("bob"),
            NOW + 10,
        );
        let err = match block_on(scope.finalize_with_signer(&revoked, NOW + 11, AUTHORITY)) {
            Ok(_) => panic!("{what}: revoked key closed a commit"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::KeyRevoked),
            "{what}: expected KeyRevoked, got {err:?}"
        );
        assert_eq!(
            principal.commits().count(),
            commits_before,
            "{what}: no commit recorded"
        );
        assert_eq!(
            principal.pr_tagged().expect("pr"),
            pr_before,
            "{what}: state must not move"
        );
    }
}
