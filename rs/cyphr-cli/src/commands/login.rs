//! `cyphr login`: sign in to a service (SPEC 17.2).
//!
//! The request is the one `cyphr_net::login` defines, signed through the
//! keystore's signer so the private key never leaves it. The command names
//! the audience it signed for and the peer it sent to, because a verifier's
//! verdict names its choice and a signer should see theirs.

use cyphr::PrincipalGenesis;
use cyphr_net::login::{self, LoginRequest};
use serde_json::json;

use super::common::{block_on, current_timestamp};
use crate::keystore::KeyBackend;
use crate::net::Peer;
use crate::{Cli, Error, OutputFormat};

/// The arguments of `cyphr login`.
pub struct Request<'a> {
    /// Principal Genesis, as the user spelled it.
    pub identity: &'a PrincipalGenesis,
    /// Thumbprint of the signing key.
    pub signer: &'a str,
    /// The service signed in to.
    pub audience: &'a str,
    /// A Cyphr server to post the login to; `None` prints the signed login
    /// (`--sign-only`).
    pub peer: Option<&'a str>,
    /// A file holding the service's signed challenge.
    pub challenge: Option<&'a std::path::Path>,
    /// The channel hash to commit to, base64url.
    pub channel_hash: Option<&'a str>,
}

/// Run `cyphr login`.
pub fn run(cli: &Cli, req: &Request<'_>) -> crate::Result<()> {
    let keystore = super::common::open_backend(cli)?;
    let signer = keystore.signer(req.signer)?;

    let challenge: Option<coz::CozJson> = req
        .challenge
        .map(|path| -> crate::Result<coz::CozJson> {
            let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
            // A server's answer wraps it as `payload.challenge`; accept the
            // bare Coz too.
            let coz = doc
                .get("payload")
                .and_then(|p| p.get("challenge"))
                .unwrap_or(&doc);
            Ok(serde_json::from_value(coz.clone())?)
        })
        .transpose()?;
    let channel = req
        .channel_hash
        .map(|h| {
            <base64ct::Base64UrlUnpadded as base64ct::Encoding>::decode_vec(h)
                .map_err(|_| Error::InvalidArgument("--channel-hash is not base64url".into()))
        })
        .transpose()?;

    let request: LoginRequest = block_on(login::sign_request(
        &signer,
        req.audience,
        req.identity,
        current_timestamp(),
        challenge.as_ref(),
        channel.as_deref(),
    ))?
    .map_err(|e| Error::Signing(e.to_string()))?;

    let out = match req.peer {
        Some(peer_url) => {
            let peer = Peer::new(peer_url, cli.peer_timeout_secs, cli.allow_cleartext)?;
            let token = block_on(peer.login(&request))??;
            json!({"identity": req.identity, "key": req.signer, "audience": req.audience,
                "peer": peer_url, "token": token})
        },
        None => json!({"identity": req.identity, "key": req.signer, "audience": req.audience,
            "login": request}),
    };
    match cli.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&out)?),
        OutputFormat::Table => match req.peer {
            Some(peer_url) => {
                println!("Signed in to {peer_url} as audience {}", req.audience);
                println!("  token: {}", out["token"].as_str().unwrap_or_default());
            },
            None => {
                println!("Signed a login for audience {}", req.audience);
                println!("{}", serde_json::to_string_pretty(&out["login"])?);
            },
        },
    }
    Ok(())
}
