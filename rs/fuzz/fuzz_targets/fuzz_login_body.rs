#![no_main]

use cyphr_server::auth::login::{LOGIN_TYP_SUFFIX, parse_login};
use libfuzzer_sys::fuzz_target;

// Fuzzes the login-body parse the `login` handler runs on an
// unauthenticated request: `CozJson` deserialization followed by
// `parse_login` (schema and audience binding). The handler itself needs a
// full `AppState`; everything before its principal load is exactly these
// two calls.
fuzz_target!(|data: &[u8]| {
    let Ok(body) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(coz_json) = serde_json::from_str::<coz::CozJson>(body) else {
        return;
    };

    // Bind the audience to whatever the payload itself claims, so the
    // fuzzer reaches the field-extraction code behind the audience check
    // instead of dying at `AudienceMismatch` on every input.
    let audience = coz_json
        .pay
        .get("typ")
        .and_then(serde_json::Value::as_str)
        .and_then(|t| t.strip_suffix(LOGIN_TYP_SUFFIX))
        .unwrap_or("fuzz.example")
        .to_string();
    let _ = parse_login(coz_json, &audience);
});
