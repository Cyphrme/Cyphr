//! A `/tip` answer given while the principal is in Error (SPEC 15.5): the
//! client reads the fork point and tied heads, verifies the server's
//! `held` statement, never takes it for a tip, and still reads the Active
//! shape.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::{
    HELD_REPORT_TYP, PatchFailure, PeerKey, TipAnswer, verify_authenticated_envelope,
    verify_held_envelope, verify_patch_body,
};
use serde_json::{Value, json};

fn b64(b: u8) -> String {
    Base64UrlUnpadded::encode_string(&[b; 32])
}

fn digest(b: u8) -> String {
    format!("SHA-256:{}", b64(b))
}

struct Authority {
    key: PeerKey,
    kp: coz::KeyPair,
}

fn authority() -> Authority {
    let kp = coz::Alg::Ed25519.generate_keypair();
    Authority {
        key: PeerKey {
            alg: kp.alg.name().to_string(),
            pub_key: kp.pub_bytes.clone(),
        },
        kp,
    }
}

fn error_payload() -> Value {
    json!({
        "state": "error",
        "principal_id": b64(7),
        "fork_point": { "height": 3, "pre": digest(1) },
        "heads": [
            { "commit_id": digest(8), "sequence": 4, "held_since": 1_700_000_100 },
            { "commit_id": digest(9), "sequence": 4, "held_since": null },
        ],
        "now": 1_700_000_500,
    })
}

fn held_envelope(a: &Authority, typ: &str) -> Value {
    let tmb = coz::compute_thumbprint_for_alg(a.kp.alg.name(), &a.kp.pub_bytes).expect("tmb");
    let pay = json!({
        "alg": a.kp.alg.name(),
        "now": 1_700_000_500,
        "tmb": tmb.to_b64(),
        "typ": typ,
        "pr": b64(7),
        "fork_point": { "height": 3, "pre": digest(1) },
        "heads": [
            { "commit_id": digest(8), "sequence": 4, "held_since": 1_700_000_100 },
            { "commit_id": digest(9), "sequence": 4, "held_since": null },
        ],
    });
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) =
        coz::sign_json(&bytes, a.kp.alg.name(), &a.kp.prv_bytes, &a.kp.pub_bytes).expect("sign");
    json!({
        "v": 1,
        "payload": error_payload(),
        "statement": { "kind": "signed",
            "coz": { "pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig) } },
    })
}

/// Backs the client reading the Error shape: the payload parses to the
/// fork point and both heads, with `held_since` as stated. Red if a head
/// or the fork point is dropped, or a malformed head is accepted.
#[test]
fn error_tip_answer_parses_to_fork_point_and_heads() {
    let body = json!({ "v": 1, "payload": error_payload(), "statement": { "kind": "unsigned" } });
    let TipAnswer::Error { fork_point, heads } = TipAnswer::parse(&body).expect("parses") else {
        panic!("state error reads as Error");
    };
    assert_eq!(fork_point.height, 3);
    assert_eq!(fork_point.pre.expect("pre").to_string(), digest(1));
    let got: Vec<_> = heads
        .iter()
        .map(|h| (h.commit_id.to_string(), h.sequence, h.held_since))
        .collect();
    assert_eq!(
        got,
        vec![(digest(8), 4, Some(1_700_000_100)), (digest(9), 4, None)]
    );

    let mut bad = body.clone();
    bad["payload"]["heads"][1]["commit_id"] = json!("not-a-digest");
    TipAnswer::parse(&bad).expect_err("a malformed head is refused, not skipped");
    let mut none = body;
    none["payload"]["heads"] = json!([]);
    TipAnswer::parse(&none).expect_err("Error with no head is refused");
}

/// Backs the Active shape still reading: the payload with a `commit_id`
/// and no `state` is `Active`. Red if the Error parse swallows it.
#[test]
fn active_tip_answer_still_parses() {
    let body = json!({
        "v": 1,
        "payload": { "principal_id": b64(7), "pr": digest(1), "sr": null, "ar": null,
            "cr": null, "commit_id": digest(9), "commit_count": 3, "last_updated": 5, "now": 6 },
        "statement": { "kind": "unsigned" },
    });
    assert_eq!(
        TipAnswer::parse(&body).expect("parses"),
        TipAnswer::Active {
            commit_id: digest(9).parse().expect("digest")
        }
    );
}

/// Backs verifying the held statement: genuine verifies and names the
/// heads; a wrong key, another principal, and a statement that is not a
/// held report are refused with the typed reason. Red if any is accepted.
#[test]
fn held_statement_verifies_and_refuses_forgeries() {
    let a = authority();
    let body = held_envelope(&a, HELD_REPORT_TYP);
    let id = format!("SHA-256:{}", b64(7));
    let report = verify_held_envelope(&body, &a.key, &id).expect("genuine verifies");
    assert_eq!(report.fork_point.height, 3);
    assert_eq!(report.heads.len(), 2);

    assert_eq!(
        verify_held_envelope(&body, &authority().key, &id).unwrap_err(),
        PatchFailure::EnvelopeUnsignedOrMisSigned
    );
    assert_eq!(
        verify_held_envelope(&body, &a.key, &format!("SHA-256:{}", b64(8))).unwrap_err(),
        PatchFailure::PrincipalMismatch
    );
    let tip_typed = held_envelope(&a, "cyphr-server/receipt/tip");
    assert_eq!(
        verify_held_envelope(&tip_typed, &a.key, &id).unwrap_err(),
        PatchFailure::MalformedReport
    );
}

/// Backs a held statement never being taken for a tip: the tip verifier
/// refuses it. Red if a held statement verifies as a canonical tip report.
#[test]
fn held_statement_is_never_a_tip_report() {
    let a = authority();
    let body = held_envelope(&a, HELD_REPORT_TYP);
    let id = format!("SHA-256:{}", b64(7));
    assert_eq!(
        verify_authenticated_envelope(&body, &a.key, &id).unwrap_err(),
        PatchFailure::MalformedReport
    );
}

fn entry(sequence: u64, id: u8) -> Value {
    json!({ "commit_id": digest(id), "sequence": sequence, "pr": digest(id + 100),
        "txs": [], "keys": [], "actions": [] })
}

/// Backs the client reading an Error patch (SPEC 15.7.1): `entries` is the
/// common chain followed by the branch the peer marks canonical, the chain
/// an Active peer would serve, and `fork` holds every branch. Red if the
/// branches are dropped, the canonical one is not appended, or an Error
/// patch with no canonical branch is accepted.
#[test]
fn error_patch_reads_as_the_canonical_chain_and_keeps_every_branch() {
    let body = |canonical: [bool; 2]| {
        json!({ "v": 1, "payload": {
            "principal_id": b64(7),
            "entries": [entry(0, 1), entry(1, 2)],
            "actions": [],
            "fork_point": { "height": 2, "pre": digest(102) },
            "branches": [
                { "head": digest(3), "canonical": canonical[0], "entries": [entry(2, 3)] },
                { "head": digest(4), "canonical": canonical[1], "entries": [entry(2, 4), entry(3, 5)] },
            ],
        }, "statement": { "kind": "unsigned" } })
    };
    let id = format!("SHA-256:{}", b64(7));
    let bytes = serde_json::to_vec(&body([false, true])).expect("body");
    let patch = verify_patch_body(&bytes, &id, None).expect("an Error patch reads");
    let seqs: Vec<u64> = patch.entries.iter().map(|e| e.sequence).collect();
    assert_eq!(
        seqs,
        vec![0, 1, 2, 3],
        "common chain, then the canonical branch"
    );
    let fork = patch.fork.expect("an Error patch carries its fork");
    assert_eq!(fork.fork_point.height, 2);
    assert_eq!(fork.branches.len(), 2, "every branch is kept");

    assert!(
        patch.held.is_none(),
        "unauthenticated reads carry no statement"
    );

    let none = serde_json::to_vec(&body([false, false])).expect("body");
    verify_patch_body(&none, &id, None).expect_err("no canonical branch is refused");

    let active = json!({ "v": 1, "payload": { "principal_id": b64(7),
        "entries": [entry(0, 1)], "actions": [] }, "statement": { "kind": "unsigned" } });
    let active = verify_patch_body(&serde_json::to_vec(&active).expect("body"), &id, None)
        .expect("Active reads");
    assert!(active.fork.is_none(), "an Active patch has no fork");
}
