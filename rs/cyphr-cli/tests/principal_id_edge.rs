//! The CLI edge takes a principal id in one spelling: the labelled
//! `ALG:digest` (CLOSE-DECISIONS D5 and Q1). A bare id is refused with an
//! error that shows the labelled form; no width is ever guessed.
//!
//! Property, for each algorithm a genesis key can use (ES256, ES384,
//! Ed25519: SHA-256, SHA-384, SHA-512 identities): the id's labelled
//! spelling round-trips through `cyphr::PrincipalGenesis`'s `Display` and
//! `FromStr`, `--identity=<labelled>` is accepted and names the same
//! principal as the one the store holds, and `--identity=<bare>` is refused.
//!
//! Red before ID: the CLI reads only the bare digest (`inspect` accepts
//! it) and refuses `SHA-256:<digest>` as bad base64.

mod common;

use common::{Ran, User};
use cyphr::PrincipalGenesis;

/// An implicit-genesis principal on a fresh key of `algo`, with its label
/// and bare digest. Setup is written to hold on both sides of ID: the
/// identity argument is tried labelled, then bare.
fn identity(user: &User, algo: &str, hash: &str) -> (String, String) {
    let tmb = user.setup(&["key", "generate", "--algo", algo])["tmb"]
        .as_str()
        .expect("tmb")
        .to_owned();
    let labelled = format!("{hash}:{tmb}");
    let upgraded = |id: &str| user.run(&["upgrade", &format!("--identity={id}")]).ok;
    assert!(
        upgraded(&labelled) || upgraded(&tmb),
        "setup: upgrade accepted neither spelling of the identity"
    );
    (labelled, tmb)
}

fn inspect(user: &User, id: &str) -> Ran {
    user.run(&["inspect", &format!("--identity={id}")])
}

#[test]
fn the_labelled_id_round_trips_and_is_accepted_for_every_hash() {
    for (algo, hash) in [
        ("ES256", "SHA-256"),
        ("ES384", "SHA-384"),
        ("Ed25519", "SHA-512"),
    ] {
        let user = User::new();
        let (labelled, _) = identity(&user, algo, hash);

        let pg: PrincipalGenesis = labelled
            .parse()
            .unwrap_or_else(|e| panic!("{algo}: {labelled} must parse: {e}"));
        assert_eq!(
            pg.to_string(),
            labelled,
            "{algo}: Display must print the id as given"
        );

        let ran = inspect(&user, &labelled);
        assert!(
            ran.ok,
            "{algo}: labelled id must be accepted: {}",
            ran.stderr
        );
        assert_eq!(ran.json()["commit_count"].as_u64(), Some(1), "{algo}");
    }
}

#[test]
fn a_bare_id_is_refused_and_the_error_shows_the_labelled_form() {
    for (algo, hash) in [
        ("ES256", "SHA-256"),
        ("ES384", "SHA-384"),
        ("Ed25519", "SHA-512"),
    ] {
        let user = User::new();
        let (_, bare) = identity(&user, algo, hash);

        let ran = inspect(&user, &bare);
        assert!(
            !ran.ok,
            "{algo}: a bare id must be refused, got {}",
            ran.stdout
        );
        assert!(
            ran.stderr.contains("ALG:digest"),
            "{algo}: the refusal must show the labelled form, got: {}",
            ran.stderr
        );
    }
}
