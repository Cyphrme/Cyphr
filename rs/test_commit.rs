use coz::{Czd, Thumbprint};
use cyphrpass::{HashAlg, Key, Principal, coz::ParsedCoz};
use serde_json::json;

fn main() {
    let key = Key {
        alg: "ES256".to_string(),
        tmb: Thumbprint::from_bytes(vec![0; 32]),
        pub_key: vec![0; 64], // not valid ES256, but...
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    };
    println!("Hello World");
}
