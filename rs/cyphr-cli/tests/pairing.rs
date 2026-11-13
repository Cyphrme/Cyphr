//! End to end: device pairing through the real `cyphr` binary. A new device
//! enrolls its own key and proves possession; an existing device accepts by
//! committing it. Spec rules are cited where a refusal rests on one.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{Ran, User};
use serde_json::Value;

/// `phone` signs a pairing request for `pr` into a file under `laptop`'s dir.
fn request(phone: &User, laptop: &User, pr: &str) -> (PathBuf, String) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let file = laptop
        .dir
        .path()
        .join(format!("request{}.json", N.fetch_add(1, Ordering::Relaxed)));
    let v = phone.setup(&[
        "key",
        "request",
        &format!("--identity={pr}"),
        &format!("--file={}", file.display()),
    ]);
    (file, v["tmb"].as_str().expect("tmb").to_owned())
}

fn accept(laptop: &User, pr: &str, file: &PathBuf, extra: &[&str]) -> Ran {
    let mut args = vec![
        "key".to_owned(),
        "accept".to_owned(),
        format!("--identity={pr}"),
        format!("--signer={pr}"),
        format!("--file={}", file.display()),
    ];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    laptop.run(&args)
}

fn holds(laptop: &User, pr: &str, tmb: &str) -> bool {
    laptop.setup(&["key", "list", &format!("--identity={pr}")])["active_keys"]
        .to_string()
        .contains(tmb)
}

fn edit(file: &PathBuf, f: impl FnOnce(&mut Value)) {
    let mut v: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(file, serde_json::to_string(&v).unwrap()).unwrap();
}

/// A device's own key, never exported: the request carries the public half
/// and the accepting device commits that key to the principal.
#[test]
fn pairing_enrolls_the_new_devices_own_key_without_exporting_it() {
    let laptop = User::new();
    let phone = User::new();
    let pr = laptop.new_identity();
    let before = laptop.commit_count(&pr);

    let (file, tmb) = request(&phone, &laptop, &pr);
    let text = std::fs::read_to_string(&file).unwrap();
    let keystore = std::fs::read_to_string(phone.keystore()).unwrap();
    let prv = serde_json::from_str::<Value>(&keystore).unwrap()[&tmb]["prv_key"]
        .as_str()
        .expect("the phone holds its private key")
        .to_owned();
    assert!(!prv.is_empty());
    assert!(
        !text.contains(&prv),
        "the request must not carry the private key"
    );
    assert!(!holds(&laptop, &pr, &tmb), "no key before accept");

    let r = accept(&laptop, &pr, &file, &[]);
    assert!(r.ok, "accept failed: {}", r.stderr);
    assert!(holds(&laptop, &pr, &tmb), "the phone's key is committed");
    assert_eq!(laptop.commit_count(&pr), before + 1);
}

/// A request whose proof of possession does not verify is refused and
/// commits nothing (SPEC 17.2: possession is shown by the key's own
/// signature).
#[test]
fn pairing_refuses_a_request_whose_proof_of_possession_fails() {
    let laptop = User::new();
    let phone = User::new();
    let pr = laptop.new_identity();
    let before = laptop.commit_count(&pr);

    // Signed pay altered after signing: the signature no longer verifies.
    let (file, tmb) = request(&phone, &laptop, &pr);
    edit(&file, |v| {
        let now = v["pay"]["now"].as_i64().unwrap();
        v["pay"]["now"] = Value::from(now + 1);
    });
    let r = accept(&laptop, &pr, &file, &[]);
    assert!(
        !r.ok && r.stderr.contains("no proof of possession"),
        "{}",
        r.stderr
    );

    // A key swapped in for the one the request names: not a proof of
    // possession of that key.
    let (file, _) = request(&phone, &laptop, &pr);
    let other = User::new();
    let (other_file, _) = request(&other, &laptop, &pr);
    let other_key = serde_json::from_slice::<Value>(&std::fs::read(&other_file).unwrap()).unwrap()
        ["key"]
        .clone();
    edit(&file, |v| v["key"] = other_key);
    let r = accept(&laptop, &pr, &file, &[]);
    assert!(!r.ok && r.stderr.contains("does not hash"), "{}", r.stderr);

    assert!(!holds(&laptop, &pr, &tmb));
    assert_eq!(
        laptop.commit_count(&pr),
        before,
        "a refused request commits nothing"
    );
}

/// SPEC 17.3: a bounded timestamp window refuses a stale request.
#[test]
fn pairing_refuses_a_stale_request() {
    let laptop = User::new();
    let phone = User::new();
    let pr = laptop.new_identity();
    let (file, tmb) = request(&phone, &laptop, &pr);
    std::thread::sleep(std::time::Duration::from_secs(3));

    let r = accept(&laptop, &pr, &file, &["--window=1"]);
    assert!(
        !r.ok && r.stderr.contains("stale or replayed"),
        "{}",
        r.stderr
    );
    assert!(!holds(&laptop, &pr, &tmb));
}

/// A request replayed after acceptance, inside the window, adds nothing: the
/// key is already active, so the protocol refuses a second `key/create`.
#[test]
fn pairing_refuses_a_replayed_request() {
    let laptop = User::new();
    let phone = User::new();
    let pr = laptop.new_identity();
    let (file, _) = request(&phone, &laptop, &pr);
    assert!(accept(&laptop, &pr, &file, &[]).ok);
    let after = laptop.commit_count(&pr);

    let r = accept(&laptop, &pr, &file, &[]);
    assert!(!r.ok, "a replayed request must be refused");
    assert_eq!(laptop.commit_count(&pr), after);
}

/// A request is for one principal: carried to another, it is refused.
#[test]
fn pairing_refuses_a_request_for_another_principal() {
    let laptop = User::new();
    let phone = User::new();
    let pr = laptop.new_identity();
    let (file, tmb) = request(
        &phone,
        &laptop,
        "SomeOtherPrincipalRootThatIsNotThisOne0000000",
    );
    let r = accept(&laptop, &pr, &file, &[]);
    assert!(!r.ok && r.stderr.contains("not `"), "{}", r.stderr);
    assert!(!holds(&laptop, &pr, &tmb));
}
