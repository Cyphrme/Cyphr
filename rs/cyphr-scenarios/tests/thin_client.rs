//! A thin client end to end, against a real server over HTTP, with public
//! API only.
//!
//! The thin client holds one pinned `Root`, as if a witness had handed it
//! out of band, and nothing else. Its jobs:
//!
//! - (a) key K is in the principal's key set at the pinned root (sign-in);
//! - (b) a given commit is in the principal's history;
//! - (c) a newer head extends the pin.
//!
//! Freshness, whether the pinned root is the principal's current one, is a
//! witness's job and out of scope here: every check below is relative to
//! the pin. The commit's bundle is fetched from `/patch?pr&to=<index>`
//! (the entry at `index`), the way a client holding no chain asks for one
//! commit; the bundle carries everything the transaction root needs.

use std::net::SocketAddr;
use std::time::Duration;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::proof::{
    Anchor, Certificate, ProofError, Root, verify_extension, verify_key, verify_membership,
};
use cyphr::replay::WireBundle;
use cyphr_scenarios::actions::KeyRef;
use cyphr_scenarios::{Capability, Harness};

async fn get(
    h: &Harness,
    peer: SocketAddr,
    path: &str,
    query: &[(&str, &str)],
) -> reqwest::Response {
    h.http
        .get(format!("http://{peer}{path}"))
        .query(query)
        .send()
        .await
        .expect("request")
}

/// The `payload` of a 200 answer.
async fn payload(resp: reqwest::Response, what: &str) -> serde_json::Value {
    assert_eq!(resp.status(), 200, "{what}");
    let body: serde_json::Value = resp.json().await.expect("json");
    body["payload"].clone()
}

fn certificate_of(payload: &serde_json::Value, what: &str) -> Certificate {
    serde_json::from_value(payload["certificate"].clone())
        .unwrap_or_else(|e| panic!("{what}: not a certificate: {e}"))
}

fn thumbprint(b64: &str) -> coz::Thumbprint {
    coz::Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(b64).expect("base64url"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(thin-client): /key does not exist yet, and verify_membership takes a bundle"]
async fn thin_client_end_to_end() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::DataCommit,
    ])
    .await;
    let (laptop, phone) = (h.client("laptop"), h.client("phone"));
    let pr = h.ok(laptop.create_principal().await);
    h.ok(laptop.commit_data(&pr, "before").await);
    let es256 = h.ok(laptop.pair_device(&pr, &phone).await);
    let ed25519 = KeyRef(h.genesis_tmb(&pr).expect("genesis key"));
    // The phone's ES256 key retires the Ed25519 key: one rotation.
    h.ok(phone.remove_key(&pr, &ed25519).await);
    for i in 0..3 {
        h.ok(phone.commit_data(&pr, &format!("after{i}")).await);
    }
    h.ok(phone.push(&pr, &["p1"]).await)
        .accepted("the rotated chain");
    let peer = h.peer("p1").addr();
    let id = pr.0.as_str();

    // The pin: what a witness would have handed over. Taken from a pulled
    // record here only because the test has no witness.
    let entry = h.genesis_of(&pr).expect("genesis entry");
    let public = Base64UrlUnpadded::decode_vec(entry["pub_key"].as_str().expect("pub_key"))
        .expect("base64url");
    let alg = entry["alg"].as_str().expect("alg");
    let tmb = coz::compute_thumbprint_for_alg(alg, &public).expect("thumbprint");
    let genesis = cyphr::Key::new(alg.to_owned(), tmb, public).expect("genesis key");
    let mut record =
        cyphr_client::Record::new(pr.bare(), cyphr_client::Anchor::GenesisKey(genesis));
    let connector = cyphr_client::HttpConnector::connect(
        &format!("http://{peer}"),
        &cyphr_client::HttpOptions::new(Duration::from_secs(5)),
    )
    .expect("connector");
    cyphr_client::pull(
        &mut record,
        &[cyphr_client::PullPeer {
            name: "p1",
            connector: &connector,
        }],
    )
    .await;
    let n = record
        .principal()
        .expect("the record holds the chain")
        .commit_count() as u64;
    let root = record.principal().expect("chain").root_at(n).expect("root");
    let pin = || Anchor::pin(root.clone());
    assert!(n >= 6, "size {n}");

    let size = n.to_string();
    // (c) The owner commits more. The new head extends the pin; another
    // principal's head does not.
    for i in 0..2 {
        h.ok(phone.commit_data(&pr, &format!("more{i}")).await);
    }
    h.ok(phone.push(&pr, &["p1"]).await)
        .accepted("more commits");
    let resp = get(&h, peer, "/head", &[("pr", id)]).await;
    let head: Root = serde_json::from_value(payload(resp, "/head").await).expect("a Root");
    assert!(head.size > n, "the head moved on");
    let to = head.size.to_string();
    let resp = get(
        &h,
        peer,
        "/consistency",
        &[("pr", id), ("from", &size), ("to", &to)],
    )
    .await;
    let cert = certificate_of(&payload(resp, "/consistency").await, "/consistency");
    assert_eq!(
        verify_extension(&pin(), &cert, n, &head),
        Ok(()),
        "the new head"
    );

    let bob = h.client("bob");
    let other = h.ok(bob.create_principal().await);
    // As long as the owner's log, so the head is a real claim of the same
    // size and not merely one too short to follow the pin.
    for i in 1..head.size {
        h.ok(bob.commit_data(&other, &format!("bob{i}")).await);
    }
    h.ok(bob.push(&other, &["p1"]).await)
        .accepted("another principal");
    let resp = get(&h, peer, "/head", &[("pr", other.0.as_str())]).await;
    let theirs: Root =
        serde_json::from_value(payload(resp, "/head of another").await).expect("a Root");
    let r = verify_extension(&pin(), &cert, n, &theirs);
    assert!(
        matches!(r, Err(ProofError::Refuted(_))),
        "another principal's head: {r:?}"
    );

    // (a) The ES256 key is in the key set at the pin; the retired Ed25519
    // key is not.
    let (es, ed) = (thumbprint(&es256.0), thumbprint(&ed25519.0));
    let resp = get(
        &h,
        peer,
        "/key",
        &[("pr", id), ("tmb", &es256.0), ("size", &size)],
    )
    .await;
    let cert_es = certificate_of(&payload(resp, "/key for the ES256 key").await, "/key");
    assert_eq!(
        verify_key(&pin(), &cert_es, n, &es),
        Ok(()),
        "the ES256 key"
    );
    let r = verify_key(&pin(), &cert_es, n, &ed);
    assert!(
        matches!(r, Err(ProofError::Refuted(_))),
        "the retired key: {r:?}"
    );
    let resp = get(
        &h,
        peer,
        "/key",
        &[("pr", id), ("tmb", &ed25519.0), ("size", &size)],
    )
    .await;
    assert_ne!(
        resp.status(),
        200,
        "the server has no certificate for a retired key"
    );

    // (b) Commit 1 is in the history the pin vouches for. The thin client
    // fetches the commit's bundle, then the certificate, and checks them.
    let bundle_at = |index: u64| {
        let (h, id, i) = (&h, id, index.to_string());
        async move {
            let p = payload(
                get(h, peer, "/patch", &[("pr", id), ("to", &i)]).await,
                "/patch",
            )
            .await;
            let entry = &p["entries"][index as usize];
            assert_eq!(entry["sequence"], index, "the entry at {index}");
            // The entry is the commit's bundle with its metadata beside it.
            serde_json::from_value::<WireBundle>(entry.clone()).expect("a bundle")
        }
    };
    let (one, two) = (bundle_at(1).await, bundle_at(2).await);
    let resp = get(
        &h,
        peer,
        "/inclusion",
        &[("pr", id), ("size", &size), ("index", "1")],
    )
    .await;
    let cert = certificate_of(&payload(resp, "/inclusion").await, "/inclusion");
    assert_eq!(
        verify_membership(&pin(), &cert, n, 1, &one),
        Ok(()),
        "the right bundle"
    );
    let r = verify_membership(&pin(), &cert, n, 1, &two);
    assert!(
        matches!(r, Err(ProofError::Refuted(_))),
        "another commit's bundle: {r:?}"
    );

    // A certificate for a size the pin does not cover is a question, not
    // an accusation: size n + 1 is past what the pin vouches for.
    let past = (n + 1).to_string();
    let resp = get(
        &h,
        peer,
        "/inclusion",
        &[("pr", id), ("size", &past), ("index", "1")],
    )
    .await;
    let cert = certificate_of(
        &payload(resp, "/inclusion past the pin").await,
        "/inclusion",
    );
    let r = verify_membership(&pin(), &cert, n + 1, 1, &one);
    assert!(
        matches!(r, Err(ProofError::Question(_))),
        "a size the pin does not cover: {r:?}"
    );
}
