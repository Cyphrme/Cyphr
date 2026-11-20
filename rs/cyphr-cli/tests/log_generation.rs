//! A local command writes the engine's durable commit log once, by the
//! engine's own append. A command that mutates a principal over that same
//! log leaves it one leaf ahead of the chain, and the next load throws the
//! log away and rebuilds it into a new generation: three keyspaces created
//! and three deleted, with an fsync each, on every commit.
//!
//! Generation bumps are the deterministic witness here: counting fsyncs in
//! a Rust test would mean tracing syscalls, and every regeneration is a
//! bump, so "no bump" is "no regeneration".

mod common;

use common::User;
use cyphr_blob_fjall::EmlLogs;
use cyphr_cli::commands::common::{get_principal_id, parse_principal_genesis};
use cyphr_storage::engine::LogFactory;

/// The log generation of `identity` in `user`'s store, read by the same
/// reader the engine uses, so a change to how generations are recorded
/// changes this value instead of emptying the check.
fn generation(user: &User, identity: &str) -> u64 {
    let path = user
        .store_uri()
        .strip_prefix("file:")
        .map(|p| std::path::Path::new(p).join("blobs"))
        .expect("file store uri");
    let db = fjall::Database::builder(path)
        .open()
        .expect("opening the store");
    let principal_id = get_principal_id(&parse_principal_genesis(identity).expect("identity"))
        .expect("principal id");
    EmlLogs::new(db)
        .expect("eml logs")
        .generation(&principal_id)
        .expect("reading the generation")
}

/// Behaviour: consecutive `data action` + `data commit` runs never
/// regenerate the principal's commit log.
#[test]
fn data_commits_leave_the_log_at_generation_zero() {
    let user = User::new();
    let id = user.new_identity();
    let (ident, signer) = (format!("--identity={id}"), format!("--signer={id}"));
    for n in 0..5 {
        user.setup(&["data", "action", &ident, &signer, &format!("--msg=m{n}")]);
        user.setup(&["data", "commit", &ident, &signer]);
    }
    assert_eq!(
        generation(&user, &id),
        0,
        "a CLI commit regenerated the log"
    );
}

/// Behaviour: a key change (`key add`, which also saves through the
/// engine) leaves the log at generation zero too.
#[test]
fn key_add_leaves_the_log_at_generation_zero() {
    let user = User::new();
    let id = user.new_identity();
    user.add_key(&id);
    let signer = format!("--signer={id}");
    let ident = format!("--identity={id}");
    user.setup(&["data", "action", &ident, &signer, "--msg=after"]);
    user.setup(&["data", "commit", &ident, &signer]);
    assert_eq!(generation(&user, &id), 0, "a CLI write regenerated the log");
}
