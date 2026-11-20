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
use fjall::{Database, KeyspaceCreateOptions};

/// The generation numbers recorded for every principal of `user`'s store;
/// an absent record is generation 0 and is not listed.
fn recorded_generations(user: &User) -> Vec<u64> {
    let path = user
        .store_uri()
        .strip_prefix("file:")
        .map(|p| std::path::Path::new(p).join("blobs"))
        .expect("file store uri");
    let db = Database::builder(path).open().expect("opening the store");
    let generations = db
        .keyspace("eml_generations", KeyspaceCreateOptions::default)
        .expect("generation keyspace");
    generations
        .iter()
        .map(|g| {
            let (_, v) = g.into_inner().expect("reading a generation record");
            u64::from_be_bytes(<[u8; 8]>::try_from(v.as_ref()).expect("a u64 record"))
        })
        .collect()
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
    assert!(
        recorded_generations(&user).iter().all(|g| *g == 0),
        "a CLI commit regenerated the log: {:?}",
        recorded_generations(&user)
    );
}

/// Behaviour: a key change (`key add`, which also saves through the
/// engine) leaves the log at generation zero too, and the history still
/// reads back whole afterwards.
#[test]
fn key_add_leaves_the_log_at_generation_zero() {
    let user = User::new();
    let id = user.new_identity();
    user.add_key(&id);
    let signer = format!("--signer={id}");
    let ident = format!("--identity={id}");
    user.setup(&["data", "action", &ident, &signer, "--msg=after"]);
    user.setup(&["data", "commit", &ident, &signer]);
    assert!(
        recorded_generations(&user).iter().all(|g| *g == 0),
        "a CLI write regenerated the log: {:?}",
        recorded_generations(&user)
    );
    // The store still serves the principal after those writes.
    user.setup(&["inspect", &ident]);
}
