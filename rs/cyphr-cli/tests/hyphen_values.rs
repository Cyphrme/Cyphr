//! A b64ut value may begin with `-` (it is in the alphabet); the CLI must
//! take it as a value, not read it as a flag.

mod common;

use common::User;

/// Generate keys until one thumbprint starts with `-` (1 in 64 each).
fn hyphen_key(u: &User) -> String {
    for _ in 0..2000 {
        let tmb = u.setup(&["key", "generate", "--algo", "Ed25519"])["tmb"]
            .as_str()
            .expect("tmb")
            .to_owned();
        if tmb.starts_with('-') {
            return tmb;
        }
    }
    panic!("no thumbprint starting with '-' in 2000 keys");
}

#[test]
fn init_keys_accepts_a_value_starting_with_hyphen() {
    let u = User::new();
    let h = hyphen_key(&u);
    let other = u.setup(&["key", "generate", "--algo", "Ed25519"])["tmb"]
        .as_str()
        .expect("tmb")
        .to_owned();
    let keys = format!("{h},{other}");
    let r = u.run(&["init", "--keys", &keys, "--genesis-commit"]);
    assert!(r.ok, "init with hyphen-leading key failed: {}", r.stderr);
}
