//! `cyphr tx list` in its table form.

mod common;

use std::process::Command;

use common::User;

/// Claim: the table form of `tx list` names each coz by its kind in words
/// (the `typ` the JSON form prints), never as Rust `Debug` output.
/// Turns red if a row prints a struct literal such as `KeyCreate { id: .. }`.
/// End-to-end scenario: yes (a real identity with a second key).
#[test]
fn the_tx_list_table_names_kinds_in_words() {
    let user = User::new();
    let id = user.new_identity();
    user.add_key(&id);

    let out = Command::new(env!("CARGO_BIN_EXE_cyphr"))
        .arg("--keystore")
        .arg(user.keystore())
        .arg("--store")
        .arg(user.store_uri())
        .args([
            "--output",
            "table",
            "tx",
            "list",
            &format!("--identity={id}"),
        ])
        .output()
        .expect("running cyphr");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let table = String::from_utf8_lossy(&out.stdout);
    assert!(table.contains("key/create"), "kinds in words: {table}");
    assert!(
        !table.contains('{') && !table.contains("Thumbprint"),
        "no Rust Debug output: {table}"
    );
}
