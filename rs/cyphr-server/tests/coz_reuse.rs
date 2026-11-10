//! SPEC 7.6 through the server push path: a commit that re-includes a
//! transaction coz the principal already included is refused with the typed
//! `COZ_REUSE` error, and the stored chain stays exactly as it was (the first
//! inclusion is authoritative).
//!
//! ## Why the replay commit is a recorded fixture
//!
//! Once the core refuses reuse it can no longer be asked to build the very
//! commit this suite needs to push. `REPLAY_BLOBS` is therefore the wire
//! bundle for commit 3 (`[D, commit/create]`, D being commit 1's coz);
//! ES256 signatures are deterministic, so commits 0-2, rebuilt here at run
//! time, are byte-identical to the ones it chains onto (the premise assert
//! pins D). Recorded over the genesis-commit chain (SPEC 5.1): commit 0 is
//! `golden`'s genesis, then `[create key_a, delete key_a]` (all by
//! `golden`, all with `now = T`). D is the blob commit 1 exports; the
//! closing `commit/create` was signed by `golden` over the arrow
//! `MR(pre, sr, tmr)` (SPEC 4.2) computed by hand, with `pre` the PR after
//! commit 2 and `sr`/`tmr` those of commit 1 (same keys, same single
//! mutation D), a computation checked to reproduce commit 2's own arrow.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Principal;
use cyphr::signer::SoftwareSigner;
use cyphr_server::build_router;

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

/// Every `now` in the chain; equal values keep the timestamp rule from being
/// what refuses the replay.
const T: i64 = 1_700_000_000;

/// Recorded blobs (base64url) of the replay bundle, see the module docs:
/// `[D, commit/create]`. Pushed under the PG of `golden`'s genesis.
const REPLAY_BLOBS: [&str; 2] = [
    "eyJwYXkiOnsiYWxnIjoiRVMyNTYiLCJpZCI6InhnSnU4R3NFR09WWkNqYlZVWG5fRDRnczRhdWxpZlktVlFHMkZNbEphSEUiLCJub3ciOjE3MDAwMDAwMDAsInRtYiI6IlU1WFVab3RzLVdtUVljUVdtc083NTFYazB5ZVZpOVhVS1dRMm1HejZBcWciLCJ0eXAiOiJjeXBoci5tZS9jeXBoci9rZXkvY3JlYXRlIn0sInNpZyI6InpFRUl1TURNM2E2R2VxZkFhc2hMM1dpeFNidS1MRmUxc0JzSEw5Tzk4MFpyRjVzQ0ttaXJuS2VhVDlpbmZzSEVKc1RCeDFjYUtLV1g3NVl3WThZRUp3Iiwia2V5Ijp7ImFsZyI6IkVTMjU2IiwicHViIjoiTGdNOHcwMEJFYkdkTmxidWd6UVlEYU11dnE5UHNKcFkzYks4Qjl5VHN4eTAxSndTS0l0ODRBNndoRXg4WlZxdEFvcVExeHJQQXpGd1BQYmZlY05fdlEiLCJ0bWIiOiJ4Z0p1OEdzRUdPVlpDamJWVVhuX0Q0Z3M0YXVsaWZZLVZRRzJGTWxKYUhFIn19",
    "eyJwYXkiOnsiYWxnIjoiRVMyNTYiLCJhcnJvdyI6IlNIQS0yNTY6M3p0LVprb2hvSWtBczZPM0RWNzNKSUcwVzhJVkxRcDdBeEpRS3daUmg2NCIsIm5vdyI6MTcwMDAwMDAwMCwidG1iIjoiVTVYVVpvdHMtV21RWWNRV21zTzc1MVhrMHllVmk5WFVLV1EybUd6NkFxZyIsInR5cCI6ImN5cGhyLm1lL2N5cGhyL2NvbW1pdC9jcmVhdGUifSwic2lnIjoiR2l2WDlGLUJtdDNTWkR4X0NEdElIbkktbzhOWWNWdnMwRnhiR1pNZGZmWkVZdU50Z0JLVkJKajhRYzVsbHA5NzhpOHVUM00ydkVCem8tQmRtZkF6RncifQ",
];

struct Tx {
    pay: Vec<u8>,
    sig: Vec<u8>,
    czd: coz::Czd,
    key: Option<cyphr::Key>,
}

/// `golden` signs `typ` (`key/create` or `key/delete`) over pool key `target`.
fn golden_tx(pool: &test_fixtures::Pool, typ: &str, target: &str, with_key: bool) -> Tx {
    let g = pool.get("golden").expect("golden");
    let t = pool.get(target).expect("target");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": g.alg,
        "id": t.compute_tmb_b64().expect("tmb"),
        "now": T,
        "tmb": g.compute_tmb_b64().expect("tmb"),
        "typ": typ,
    }))
    .expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(g.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&g.pub_key).expect("pub b64");
    let (sig, cad) = coz::sign_json(&pay, &g.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &g.alg).expect("czd");
    let key = with_key.then(|| {
        cyphr::Key::new(
            t.alg.clone(),
            t.compute_tmb().expect("tmb"),
            Base64UrlUnpadded::decode_vec(&t.pub_key).expect("pub b64"),
        )
        .expect("key binds its tmb")
        .with_first_seen(T)
    });
    Tx { pay, sig, czd, key }
}

/// Apply `tx` to `p` as one commit signed by `golden`, returning the commit's
/// wire blobs (the key sidecar embedded on the key-introducing coz).
fn commit_blobs(p: &mut Principal, pool: &test_fixtures::Pool, tx: &Tx) -> Vec<Vec<u8>> {
    let g = pool.get("golden").expect("golden");
    let prv = Base64UrlUnpadded::decode_vec(g.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&g.pub_key).expect("pub b64");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&tx.pay, &tx.sig, tx.czd.clone(), tx.key.clone())
        .expect("fixture tx applies on the base");
    scope
        .finalize_with_software(
            &SoftwareSigner::new(&g.alg, &prv, &pubb, &g.compute_tmb().expect("tmb")),
            T,
            "cyphr.me",
        )
        .expect("finalize");

    let entries = cyphr_storage::export_commits(p).expect("export");
    let last = entries.last().expect("a commit");
    let mut key_idx = 0;
    last.cozies
        .iter()
        .map(|v| {
            let mut coz = v.clone();
            let typ = coz["pay"]["typ"].as_str().unwrap_or("");
            if cyphr::parsed_coz::typ::is_key_introducing(typ) && key_idx < last.keys.len() {
                let k = &last.keys[key_idx];
                coz.as_object_mut().unwrap().insert(
                    "key".into(),
                    serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.tmb}),
                );
                key_idx += 1;
            }
            serde_json::to_vec(&coz).expect("coz")
        })
        .collect()
}

fn body(principal_id: &str, blobs: &[Vec<u8>]) -> String {
    serde_json::json!({
        "principal_id": principal_id,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

/// The fixture chain: commit 0 `golden`'s genesis, commit 1 `create key_a`
/// (D), commit 2 `delete key_a`, and a legitimate alternative commit 3
/// (`create key_b`), as push bodies, plus D's wire blob and the principal
/// id (its PG).
struct Chain {
    id: String,
    genesis_body: String,
    create_body: String,
    delete_body: String,
    fresh_body: String,
    d_blob: Vec<u8>,
}

fn build_chain(pool: &test_fixtures::Pool) -> Chain {
    let g = pool.get("golden").expect("golden");
    let genesis_key = cyphr::Key::new(
        g.alg.clone(),
        g.compute_tmb().expect("tmb"),
        Base64UrlUnpadded::decode_vec(&g.pub_key).expect("pub b64"),
    )
    .expect("key binds its tmb");
    let mut p = Principal::implicit(genesis_key).expect("implicit genesis");
    let id = p.pr_tagged().expect("PG");
    let genesis_blobs = test_fixtures::bundle::genesis_bundle(&mut p, g, &[], T).expect("genesis");

    let d = golden_tx(pool, "cyphr.me/cyphr/key/create", "key_a", true);
    let create_blobs = commit_blobs(&mut p, pool, &d);
    let d_blob = create_blobs[0].clone();

    let del = golden_tx(pool, "cyphr.me/cyphr/key/delete", "key_a", false);
    let delete_blobs = commit_blobs(&mut p, pool, &del);

    // Clones are independent (G0), so `p` is untouched by this commit.
    let mut fresh = p.clone();
    let fresh_tx = golden_tx(pool, "cyphr.me/cyphr/key/create", "key_b", true);
    let fresh_blobs = commit_blobs(&mut fresh, pool, &fresh_tx);

    Chain {
        genesis_body: body(&id, &genesis_blobs),
        create_body: body(&id, &create_blobs),
        delete_body: body(&id, &delete_blobs),
        fresh_body: body(&id, &fresh_blobs),
        d_blob,
        id,
    }
}

/// Backs SPEC 7.6: "For transactions, coz reuse by a particular principal is
/// prohibited and results in error `COZ_REUSE`. The first inclusion of a
/// transaction coz is considered authoritative." Scenario, end to end over
/// HTTP: after its genesis (commit 0), `golden` creates `key_a` (coz D,
/// commit 1) and deletes it (commit 2), so D is state-valid again; commit 3
/// re-includes D verbatim (the recorded bundle, whose first blob is asserted
/// equal to commit 1's D). The push must
/// be refused with a client-error status (422 or 409, never 2xx or 500)
/// whose message names `COZ_REUSE`; the stored chain must be exactly as it
/// was (same tip, same patch) and must stay writable: a legitimate commit 3
/// (`create key_b`) is then accepted, and the refused bundle is refused
/// again. Turns red if the push path bypasses the core check (replay
/// accepted), maps the error to a 500 or an untyped message, or persists the
/// bundle while refusing it. Mutants caught: engine skipping the reuse check
/// on load-then-apply, an error that leaves the blobs indexed, a generic
/// `InvalidInput` message. End to end: yes.
#[tokio::test]
async fn push_refuses_a_replayed_transaction_coz_and_keeps_the_chain() {
    let pool = load_pool();
    let chain = build_chain(&pool);
    let id = chain.id.clone();

    let replay_blobs: Vec<Vec<u8>> = REPLAY_BLOBS
        .iter()
        .map(|b| Base64UrlUnpadded::decode_vec(b).expect("recorded blob"))
        .collect();
    assert_eq!(
        replay_blobs[0], chain.d_blob,
        "premise: the recorded bundle re-includes commit 1's coz D verbatim"
    );
    let replay_body = body(&id, &replay_blobs);

    let (state, _dir) = keyless_server();
    let app = build_router(state);

    let (s0, b0) = post_json(app.clone(), "/push", chain.genesis_body.clone()).await;
    assert_eq!(s0, StatusCode::CREATED, "genesis push: {b0:?}");
    let (sc, bc) = post_json(app.clone(), "/push", chain.create_body.clone()).await;
    assert_eq!(sc, StatusCode::CREATED, "create push: {bc:?}");
    let (s1, b1) = post_json(app.clone(), "/push", chain.delete_body.clone()).await;
    assert_eq!(s1, StatusCode::CREATED, "delete push: {b1:?}");

    let tip_uri = format!("/tip?pr={id}");
    let patch_uri = format!("/patch?pr={id}");
    let (_, tip_before) = get_json(app.clone(), &tip_uri).await;
    let (_, patch_before) = get_json(app.clone(), &patch_uri).await;
    assert_eq!(envelope_payload(&tip_before)["commit_count"], 3);

    for attempt in 1..=2 {
        let (status, resp) = post_json(app.clone(), "/push", replay_body.clone()).await;
        assert!(
            status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::CONFLICT,
            "attempt {attempt}: a replayed coz must be a typed client error, got {status}: \
             {resp:?}"
        );
        let msg = envelope_payload(&resp)["error"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            msg.contains("coz_reuse") || msg.contains("coz reuse"),
            "attempt {attempt}: the refusal must name COZ_REUSE, got {msg:?}"
        );
    }

    let (_, tip_after) = get_json(app.clone(), &tip_uri).await;
    let (_, patch_after) = get_json(app.clone(), &patch_uri).await;
    assert_eq!(
        envelope_payload(&tip_before)["pr"],
        envelope_payload(&tip_after)["pr"]
    );
    assert_eq!(
        envelope_payload(&tip_before)["commit_count"],
        envelope_payload(&tip_after)["commit_count"],
        "a refused replay must not extend the chain"
    );
    assert_eq!(
        envelope_payload(&patch_before)["entries"],
        envelope_payload(&patch_after)["entries"],
        "a refused replay must not change the stored commits"
    );

    let (s2, b2) = post_json(app.clone(), "/push", chain.fresh_body.clone()).await;
    assert_eq!(
        s2,
        StatusCode::CREATED,
        "the chain must stay writable after a refused replay: {b2:?}"
    );
}
