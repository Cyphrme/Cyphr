//! A tip report cannot be rewritten in transit by default: the server's
//! upstream paths (witness sync from an authority, and gossip to peers)
//! refuse plain `http://` to a host that is not loopback, with a typed
//! error naming the one switch that allows it.

use std::sync::Arc;

use clap::Parser as _;
use cyphr_server::AppState;
use cyphr_server::config::{Cli, ConfigError, ServerConfig, ServerMode, resolve_config};
use cyphr_server::sync::{SyncFailure, SyncOutcome, sync_from_authority};

/// Resolve the operator's config: a real TOML file through the real flag
/// parser, as `cyphr-server serve` does.
fn resolve(toml: &str) -> Result<ServerConfig, ConfigError> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("server.toml");
    std::fs::write(&path, toml).expect("write config");
    let cli = Cli::try_parse_from([
        "cyphr-server",
        "--config",
        path.to_str().expect("utf-8 path"),
        "serve",
    ])
    .expect("cli");
    resolve_config(&cli)
}

/// Claim: an operator who points the server at a non-loopback `http://`
/// upstream (the witness authority, or a gossip peer) is refused at
/// startup with an error that names `allow_cleartext_upstream`; loopback
/// and `https://` need no switch; the switch allows the rest.
///
/// Turns red if: a non-loopback `http://` upstream resolves without the
/// switch; the refusal does not name the switch; or loopback, `https://`
/// or the switched config is refused.
/// End-to-end scenario: yes (TOML file through the flag parser and the
/// resolver the binary runs).
#[test]
fn config_refuses_cleartext_non_loopback_upstreams_without_the_switch() {
    let witness = |url: &str, extra: &str| {
        resolve(&format!(
            "mode = \"witness\"\nauthority_url = \"{url}\"\n{extra}"
        ))
    };
    let refused = witness("http://authority.example:3000", "").expect_err("cleartext refused");
    assert!(
        matches!(refused, ConfigError::CleartextUpstream { .. }),
        "{refused:?}"
    );
    assert!(
        refused.to_string().contains("allow_cleartext_upstream"),
        "the refusal names the switch: {refused}"
    );
    let gossip = resolve("[gossip]\npeers = [\"http://peer.example:3000\"]\n")
        .expect_err("a gossip peer is an upstream too");
    assert!(matches!(gossip, ConfigError::CleartextUpstream { .. }));

    witness("http://127.0.0.1:3000", "").expect("loopback is allowed");
    witness("http://localhost:3000", "").expect("localhost is allowed");
    witness("https://authority.example", "").expect("https is allowed");
    witness(
        "http://authority.example:3000",
        "allow_cleartext_upstream = true\n",
    )
    .expect("the switch allows it");
}

/// Claim: a server that never went through `resolve_config` (an embedder,
/// a test) is still refused at the sync itself: the witness fetches
/// nothing from a non-loopback `http://` authority, and reports the typed
/// `CleartextRefused` that names the switch.
///
/// Turns red if: the sync dials the cleartext authority, or reports the
/// refusal as an unreachable upstream.
/// End-to-end scenario: yes (a witness AppState syncing a principal).
#[tokio::test]
async fn sync_refuses_a_cleartext_non_loopback_authority() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: dir.path().join("data"),
        // TEST-NET-1 (RFC 5737): never routable, so a request that left
        // the refusal behind would hang or fail as unreachable.
        authority_url: Some("http://192.0.2.1:3000".into()),
        ..Default::default()
    };
    let state = Arc::new(AppState::new(config).expect("witness state"));
    match sync_from_authority(&state, "AAAA").await {
        SyncOutcome::Failed {
            reason: SyncFailure::CleartextRefused { host, switch },
        } => {
            assert_eq!(host, "192.0.2.1");
            assert_eq!(switch, "allow_cleartext_upstream");
        },
        other => panic!("expected the typed cleartext refusal, got {other:?}"),
    }
}
