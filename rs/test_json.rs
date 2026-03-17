use serde_json::Value;
use std::fs;

fn main() {
    let json_str =
        fs::read_to_string("../tests/golden/edge_cases/action_after_key_add.json").unwrap();
    let val: Value = serde_json::from_str(&json_str).unwrap();
    let commits = val.get("commits").unwrap().as_array().unwrap();
    let commit = &commits[0];
    println!("Commit keys: {:?}", commit.get("keys"));
    println!(
        "Commit txs[0] key: {:?}",
        commit.get("txs").unwrap().as_array().unwrap()[0].get("key")
    );
}
