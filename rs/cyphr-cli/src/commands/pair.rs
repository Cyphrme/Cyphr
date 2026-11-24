//! Device pairing: a new device enrolls its own key and proves it holds it;
//! an existing device accepts by committing that key to the principal.
//!
//! Every device generates its own key, so no private key is ever exported
//! or copied. The request is a coz signed by the new key itself (a proof of
//! possession, SPEC 17.2: PoP "by signing a challenge message"), carrying
//! its public key so the accepting device can check it with nothing else.
//! The pairing `typ` is an application typ under the device's authority
//! (SPEC 7.3: the core protocol defines no behaviour for such a typ), so a
//! request can never be read as, or replayed as, a protocol transaction. In
//! the MVP the request travels out of band (a file or stdout).

use base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::Signer;
use indexmap::IndexMap;
use serde_json::Value;

use super::common::{
    current_timestamp, generate_key, load_principal_from_engine, parse_store,
    save_principal_to_engine, sign_pay,
};
use super::key::apply_key_create;
use crate::keystore::KeyBackend;
use crate::{Cli, Error, OutputFormat};

/// Noun and verb of the pairing request, after the authority (SPEC 7.2).
const PAIRING_ACT: &str = "pairing/create";

/// Seconds either side of the accepting device's clock a request's `now`
/// may sit. SPEC 17.3 requires a bounded timestamp window ("within +-N
/// seconds") and leaves N to the verifier; its 17.2 example is 60. Pairing
/// crosses a human-carried channel, so the default is wider.
pub const DEFAULT_WINDOW_SECS: u64 = 300;

fn pairing_typ(authority: &str) -> String {
    format!("{authority}/{PAIRING_ACT}")
}

/// `cyphr key request`: generate this device's own key and sign a pairing
/// request for `identity` with it.
pub fn request(
    cli: &Cli,
    identity: &str,
    algo: &str,
    tag: Option<&str>,
    file: Option<&std::path::Path>,
) -> crate::Result<()> {
    let mut keystore = super::common::open_backend(cli)?;
    let (tmb, _key) = generate_key(&mut keystore, algo, tag)?;
    let signer = keystore.signer(&tmb)?;
    let public = keystore.public(&tmb)?;

    let mut pay_map: IndexMap<String, Value> = IndexMap::new();
    pay_map.insert("alg".into(), Value::String(signer.alg().to_string()));
    pay_map.insert("now".into(), Value::Number(current_timestamp().into()));
    pay_map.insert("pg".into(), Value::String(identity.to_owned()));
    pay_map.insert("tmb".into(), Value::String(tmb.clone()));
    pay_map.insert("typ".into(), Value::String(pairing_typ(&cli.authority)));
    pay_map.sort_keys();
    let pay = serde_json::to_value(&pay_map)?;
    let (sig, _czd) = sign_pay(&signer, &serde_json::to_vec(&pay)?)?;
    let envelope = serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {
            "alg": public.alg,
            "pub": Base64UrlUnpadded::encode_string(&public.pub_key),
        },
    });

    match file {
        Some(path) => std::fs::write(path, serde_json::to_string_pretty(&envelope)?)?,
        None => println!("{}", serde_json::to_string_pretty(&envelope)?),
    }
    if file.is_some() {
        match cli.output {
            OutputFormat::Json => println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "tmb": tmb,
                    "alg": public.alg,
                    "identity": identity,
                }))?
            ),
            OutputFormat::Table => {
                println!("Pairing request signed by the new key");
                println!("  key: {tmb}");
                println!("  for: {identity}");
            },
        }
    }
    Ok(())
}

/// A pairing request whose proof of possession verified.
struct Verified {
    tmb: String,
    alg: String,
    pub_key: Vec<u8>,
}

/// Check a request against `identity` at time `now`; every refusal names
/// the rule it breaks.
fn verify_request(
    request: &Value,
    authority: &str,
    identity: &str,
    now: i64,
    window: u64,
) -> crate::Result<Verified> {
    let refuse = |why: String| Error::InvalidArgument(format!("pairing request refused: {why}"));
    let pay = request.get("pay").ok_or(Error::MissingField("pay"))?;
    let sig = decode(request, "sig")?;
    let key = request.get("key").ok_or(Error::MissingField("key"))?;
    let alg = key
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(Error::MissingField("key.alg"))?;
    let pub_key = decode(key, "pub")?;
    let text = |name: &'static str| {
        pay.get(name)
            .and_then(Value::as_str)
            .ok_or(Error::MissingField(name))
    };

    let typ = text("typ")?;
    if typ != pairing_typ(authority) {
        return Err(refuse(format!(
            "typ `{typ}` is not `{}`",
            pairing_typ(authority)
        )));
    }
    if text("pg")? != identity {
        return Err(refuse(format!(
            "it is for principal `{}`, not `{identity}`",
            text("pg")?
        )));
    }
    let tmb = text("tmb")?;
    // The disclosed key must be the one the request names, or the signature
    // check below would prove possession of some other key.
    if coz::compute_thumbprint_for_alg(alg, &pub_key).is_none_or(|t| t.to_b64() != tmb) {
        return Err(refuse("the disclosed key does not hash to `tmb`".into()));
    }
    if coz::verify_json(&serde_json::to_vec(pay)?, &sig, alg, &pub_key) != Some(true) {
        return Err(refuse(
            "the signature does not verify: no proof of possession".into(),
        ));
    }
    // SPEC 17.2/17.3: a timestamp window bounds replay of a signed request.
    let at = pay
        .get("now")
        .and_then(Value::as_i64)
        .ok_or(Error::MissingField("now"))?;
    if now.abs_diff(at) > window {
        return Err(refuse(format!(
            "`now` {at} is outside the +-{window}s window around {now} (stale or replayed)"
        )));
    }
    Ok(Verified {
        tmb: tmb.to_owned(),
        alg: alg.to_owned(),
        pub_key,
    })
}

fn decode(v: &Value, name: &'static str) -> crate::Result<Vec<u8>> {
    let s = v
        .get(name)
        .and_then(Value::as_str)
        .ok_or(Error::MissingField(name))?;
    Ok(Base64UrlUnpadded::decode_vec(s)?)
}

/// `cyphr key accept`: verify a pairing request and commit its key to
/// `identity` as a `key/create` signed by `signer_tmb`.
pub fn accept(
    cli: &Cli,
    identity: &str,
    signer_tmb: &str,
    file: &std::path::Path,
    window: u64,
) -> crate::Result<()> {
    let request: Value = serde_json::from_slice(&std::fs::read(file)?)?;
    let v = verify_request(
        &request,
        &cli.authority,
        identity,
        current_timestamp(),
        window,
    )?;

    let keystore = super::common::open_backend(cli)?;
    let store = parse_store(cli)?;
    let mut principal = load_principal_from_engine(&store, &keystore, identity)?;
    let key = cyphr::Key::from_pub_key(v.alg, v.pub_key)?.with_first_seen(current_timestamp());
    apply_key_create(
        &mut principal,
        &keystore,
        &v.tmb,
        &key,
        signer_tmb,
        &cli.authority,
    )?;
    save_principal_to_engine(&store, &keystore, &principal)?;

    match cli.output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "identity": identity,
                "added_key": v.tmb,
                "signed_by": signer_tmb,
            }))?
        ),
        OutputFormat::Table => {
            println!("Accepted pairing request");
            println!("  identity: {identity}");
            println!("  key: {}", v.tmb);
            println!("  signed by: {signer_tmb}");
        },
    }
    Ok(())
}
