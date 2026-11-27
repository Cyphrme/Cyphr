//! A separated relying party completing a sign-in against a running server.
//!
//! The server plays only a peer: a mirror the relying party pulls the
//! principal's chain from. The relying party is pinned to the principal's
//! genesis key and decides from what it replayed. This demo makes a fresh
//! in-memory principal, publishes its genesis commit to the server, then:
//!
//! 1. the relying party pulls the chain from the server (pinned at the genesis key);
//! 2. it issues a challenge, the principal signs it, and the relying party verifies the login
//!    against the key set it replayed and opens a session;
//! 3. the session is re-decided from the view: it stands while the pull is within the bound.
//!
//! Usage: `relying_party --server http://127.0.0.1:8080 [--audience rp.example]`

use std::process::ExitCode;
use std::time::Duration;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::principal::system_clock;
use cyphr_net::{Anchor, HttpConnector, HttpOptions, PullPeer, RelyingParty, RpConfig};
use serde_json::json;

const USAGE: &str = "usage: relying_party --server <URL> [--audience <NAME>]\n\nSigns a fresh \
                     in-memory principal in to a relying party that pulls its chain from the \
                     server at <URL>, pinned at the principal's genesis key.";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let Some(server) = arg(&args, "--server") else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let audience = arg(&args, "--audience").unwrap_or_else(|| "rp.example".to_owned());
    match run(&server, &audience).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("sign-in failed: {why}");
            ExitCode::FAILURE
        },
    }
}

async fn run(server: &str, audience: &str) -> Result<(), String> {
    // The principal: one in-memory Ed25519 key, never stored.
    let keypair = coz::Alg::Ed25519.generate_keypair();
    let tmb = keypair
        .alg
        .compute_thumbprint(&keypair.pub_bytes)
        .ok_or("thumbprint")?;
    let now = system_clock();
    let genesis = cyphr::Key::new(
        keypair.alg.name().to_owned(),
        tmb.clone(),
        keypair.pub_bytes.clone(),
    )
    .map_err(|e| format!("genesis key: {e:?}"))?
    .with_first_seen(now);
    let signer = cyphr::signer::SoftwareSigner::new(
        keypair.alg.name(),
        &keypair.prv_bytes,
        &keypair.pub_bytes,
        &tmb,
    );
    let mut principal = cyphr::Principal::implicit(genesis.clone())
        .await
        .map_err(|e| format!("genesis: {e}"))?;
    principal
        .commit_genesis(&signer, &[], now, "cyphr.me")
        .await
        .map_err(|e| format!("genesis commit: {e}"))?;
    let pg: cyphr::PrincipalGenesis = format!("SHA-512:{}", tmb.to_b64())
        .parse()
        .map_err(|e| format!("pg: {e}"))?;

    publish(server, &pg, &principal).await?;

    let http = HttpConnector::connect(
        server.trim_end_matches('/'),
        &HttpOptions::new(Duration::from_secs(10)),
    )
    .map_err(|e| format!("server: {e}"))?;
    // The site's own challenge-signing key; this demo mints a throwaway one.
    let site = coz::Alg::Ed25519.generate_keypair();
    let config = RpConfig {
        audience: audience.to_owned(),
        issuer: std::sync::Arc::new(cyphr_net::login::SoftwareIssuer::new(
            site.alg.name(),
            &site.prv_bytes,
            &site.pub_bytes,
        )),
        pull_age_bound: Duration::from_secs(30),
        refresh_interval: Duration::from_secs(10),
        session_ttl: Duration::from_secs(cyphr_net::login::DEFAULT_SESSION_TTL_SECS.unsigned_abs()),
    };
    let mut rp = RelyingParty::new(&pg, Anchor::GenesisKey(genesis), config, system_clock);
    rp.refresh(&[PullPeer {
        name: server,
        connector: &http,
    }])
    .await;

    let challenge = rp.challenge().map_err(|e| e.to_string())?;
    let login = cyphr_net::login::sign_request(&signer, audience, &pg, now, Some(&challenge), None)
        .await
        .map_err(|e| e.to_string())?;

    let session = rp.sign_in(&login).map_err(|r| r.to_string())?;
    let trust = rp
        .check_session(&session.token)
        .map_err(|r| r.to_string())?;
    println!(
        "{}",
        json!({
            "principal": session.principal,
            "key": session.key.to_b64(),
            "session": session.token,
            "tip_commits": trust.tip.commits,
            "pull_age_secs": trust.pull_age.as_secs(),
            "principal_now_age_secs": trust.principal_now_age.map(|a| a.as_secs()),
        })
    );
    Ok(())
}

/// Push the principal's genesis commit to `server`, as any client would.
async fn publish(
    server: &str,
    pg: &cyphr::PrincipalGenesis,
    principal: &cyphr::Principal<cyphr::eml::MemoryStorage>,
) -> Result<(), String> {
    let commit = principal.commits().last().ok_or("no genesis commit")?;
    let mut txs = Vec::new();
    let mut keys = Vec::new();
    for cz in commit.iter_all_cozies() {
        let raw = serde_json::to_vec(cz.raw()).map_err(|e| e.to_string())?;
        txs.push(vec![Base64UrlUnpadded::encode_string(&raw)]);
        if let Some(key) = cz.new_key() {
            keys.push(json!({
                "alg": key.alg(),
                "pub": Base64UrlUnpadded::encode_string(key.pub_key()),
                "tmb": key.tmb().to_b64(),
            }));
        }
    }
    let body = json!({ "principal_id": pg.to_string(), "txs": txs, "keys": keys });
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?
        .post(format!("{}/push", server.trim_end_matches('/')))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("push: {e}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("push answered {status}: {text}"));
    }
    Ok(())
}
