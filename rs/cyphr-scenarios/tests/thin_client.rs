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
//! the pin. The commit's bundle comes back from `/proof` beside the
//! certificate for a `member:` claim, and carries everything the
//! transaction root needs.

use std::net::SocketAddr;
use std::time::Duration;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::proof::{Anchor, Certificate, Claim, ProofError, Root, verify};
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
#[ignore = "RED(thin-client): /tip has no root and /proof does not exist yet"]
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
    // The one route every claim goes through.
    let proof = |size: String, claim: String| {
        let (h, id) = (&h, id);
        async move {
            get(
                h,
                peer,
                "/proof",
                &[("pr", id), ("size", &size), ("claim", &claim)],
            )
            .await
        }
    };
    let tip_root = |pr: String| {
        let h = &h;
        async move {
            let resp = get(h, peer, "/tip", &[("pr", &pr)]).await;
            let p = payload(resp, "/tip").await;
            serde_json::from_value::<Root>(p["root"].clone())
                .unwrap_or_else(|e| panic!("/tip has no root: {e}"))
        }
    };

    // (c) The owner commits more. The new head extends the pin; another
    // principal's head does not.
    for i in 0..2 {
        h.ok(phone.commit_data(&pr, &format!("more{i}")).await);
    }
    h.ok(phone.push(&pr, &["p1"]).await)
        .accepted("more commits");
    let head = tip_root(pr.0.clone()).await;
    assert!(head.size > n, "the head moved on");
    let resp = proof(head.size.to_string(), format!("extends:{n}")).await;
    let cert = certificate_of(&payload(resp, "/proof extends").await, "/proof extends");
    let extends = |head: &Root| Claim::Extends {
        from: n,
        head: head.pr.clone(),
    };
    assert_eq!(
        verify(&pin(), &cert, head.size, &extends(&head)),
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
    let theirs = tip_root(other.0.clone()).await;
    assert_eq!(theirs.size, head.size, "the same size");
    let r = verify(&pin(), &cert, theirs.size, &extends(&theirs));
    assert!(
        matches!(r, Err(ProofError::Refuted(_))),
        "another principal's head: {r:?}"
    );

    // (a) The ES256 key is in the key set at the pin; the retired Ed25519
    // key is not.
    let (es, ed) = (thumbprint(&es256.0), thumbprint(&ed25519.0));
    let resp = proof(size.clone(), format!("key:{}", es256.0)).await;
    let cert_es = certificate_of(&payload(resp, "/proof key").await, "/proof key");
    assert_eq!(
        verify(&pin(), &cert_es, n, &Claim::Key { tmb: es }),
        Ok(()),
        "the ES256 key"
    );
    let r = verify(&pin(), &cert_es, n, &Claim::Key { tmb: ed });
    assert!(
        matches!(r, Err(ProofError::Refuted(_))),
        "the retired key: {r:?}"
    );
    let resp = proof(size.clone(), format!("key:{}", ed25519.0)).await;
    assert_eq!(
        resp.status(),
        404,
        "the server has no certificate for a retired key"
    );

    // (b) Commit 1 is in the history the pin vouches for. The route returns
    // the commit's bundle beside the certificate; the thin client holds
    // nothing else.
    let member = |index: u64| {
        let size = size.clone();
        let proof = &proof;
        async move {
            let resp = proof(size, format!("member:{index}")).await;
            let p = payload(resp, "/proof member").await;
            let bundle = serde_json::from_value::<WireBundle>(p["bundle"].clone())
                .unwrap_or_else(|e| panic!("member {index}: not a bundle: {e}"));
            (certificate_of(&p, "/proof member"), bundle)
        }
    };
    let ((cert, one), (_, two)) = (member(1).await, member(2).await);
    let claim = |index: u64, commit: &WireBundle| Claim::Member {
        index,
        commit: commit.clone(),
    };
    assert_eq!(
        verify(&pin(), &cert, n, &claim(1, &one)),
        Ok(()),
        "the right bundle"
    );
    let r = verify(&pin(), &cert, n, &claim(1, &two));
    assert!(
        matches!(r, Err(ProofError::Refuted(_))),
        "another commit's bundle: {r:?}"
    );

    // A certificate for a size the pin does not cover is a question, not
    // an accusation: size n + 1 is past what the pin vouches for.
    let resp = proof((n + 1).to_string(), "member:1".to_owned()).await;
    let past = certificate_of(&payload(resp, "/proof past the pin").await, "/proof");
    let r = verify(&pin(), &past, n + 1, &claim(1, &one));
    assert!(
        matches!(r, Err(ProofError::Question(_))),
        "a size the pin does not cover: {r:?}"
    );
}
