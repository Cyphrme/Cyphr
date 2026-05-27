#![no_main]

use coz::{CozJson, Czd, Pay, Thumbprint};
use cyphr::{Key, parsed_coz::verify_coz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try parsing data directly as CozJson
    if let Ok(coz_json) = serde_json::from_slice::<CozJson>(data) {
        // Try parsing Pay from pay
        let pay_json = serde_json::to_vec(&coz_json.pay).unwrap_or_default();
        if serde_json::from_slice::<Pay>(&pay_json).is_ok() {
            // Check if we can parse key
            let key = Key {
                alg: "ES256".to_string(),
                tmb: Thumbprint::from_bytes(vec![0; 32]),
                pub_key: vec![0; 65],
                first_seen: 0,
                last_used: None,
                revocation: None,
                tag: None,
            };
            let czd = Czd::from_bytes(vec![0; 32]);
            // Run verify_coz with dummy parameters
            let _ = verify_coz(&pay_json, &coz_json.sig, &key, czd, None);
        }
    }
});
