//! Data commands: record a signed data action, include the data root in the
//! Principal Tree by a signed `ds/create`, and send an action to a peer.
//!
//! SPEC 4.8.1: a data action is recorded in the Data Tree (DT) and forms no
//! commit. SPEC 4.8.2: DR = MR(DT) enters PR only by a signed `ds/create`
//! whose `id` is the computed DR. How actions travel on the wire is open
//! with the spec author; actions travel as action-only bundles.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Value, json};

use super::common::{
    block_on, current_timestamp, get_principal_id, get_principal_id_from_principal,
    load_principal_from_engine, local_genesis, parse_principal_genesis, parse_store,
    save_principal_to_engine,
};
use crate::keystore::{JsonKeyStore, KeyStore, StoredKey};
use crate::net::Peer;
use crate::{Cli, DataCommands, Error, OutputFormat};

/// Run a data subcommand.
pub fn run(cli: &Cli, command: &DataCommands) -> crate::Result<()> {
    match command {
        DataCommands::Action {
            identity,
            signer,
            msg,
            now,
            sign_only,
        } => action(cli, identity, signer, msg, *now, *sign_only),
        DataCommands::Commit { identity, signer } => commit(cli, identity, signer),
        DataCommands::Submit {
            identity,
            peer,
            file,
        } => submit(cli, identity, peer, file),
    }
}

/// One signed coz: the pay as signed, its signature and digest.
pub(super) struct Signed {
    pay: Value,
    pay_bytes: Vec<u8>,
    sig: Vec<u8>,
    czd: coz::Czd,
}

impl Signed {
    /// The wire coz `{pay, sig}`.
    pub(super) fn wire(&self) -> Value {
        json!({"pay": self.pay, "sig": Base64UrlUnpadded::encode_string(&self.sig)})
    }
}

/// Sign `fields` plus the signer's `alg` and `tmb`, members sorted as the
/// core signs its own cozies.
pub(super) fn sign(key: &StoredKey, tmb: &str, mut fields: Value) -> crate::Result<Signed> {
    fields["alg"] = key.alg.clone().into();
    fields["tmb"] = tmb.into();
    if let Some(obj) = fields.as_object_mut() {
        obj.sort_keys();
    }
    let pay_bytes = serde_json::to_vec(&fields)?;
    let (sig, cad) = coz::sign_json(&pay_bytes, &key.alg, &key.prv_key, &key.pub_key)
        .ok_or_else(|| Error::Signing("sign_json failed".into()))?;
    let czd = coz::czd_for_alg(&cad, &sig, &key.alg)
        .ok_or_else(|| Error::Signing("czd_for_alg failed".into()))?;
    Ok(Signed {
        pay: fields,
        pay_bytes,
        sig,
        czd,
    })
}

fn emit(cli: &Cli, value: &Value, table: impl FnOnce()) -> crate::Result<()> {
    match cli.output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(value)?),
        OutputFormat::Table => table(),
    }
    Ok(())
}

/// `cyphr data action`: sign a data action; unless `sign_only`, record it in
/// the local DT and keep it in the store as an action-only bundle.
fn action(
    cli: &Cli,
    identity: &str,
    signer_tmb: &str,
    msg: &str,
    now: Option<i64>,
    sign_only: bool,
) -> crate::Result<()> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let key = keystore.get(signer_tmb)?;
    let now = now.unwrap_or_else(current_timestamp);
    let signed = sign(
        key,
        signer_tmb,
        json!({"msg": msg, "now": now, "typ": format!("{}/comment/create", cli.authority)}),
    )?;
    let czd = signed.czd.to_b64();

    if !sign_only {
        let store = parse_store(cli)?;
        let mut principal = load_principal_from_engine(&store, &keystore, identity)?;
        // An action is recorded against a committed principal, so the
        // genesis commit precedes the first action (as for any command).
        super::init::commit_genesis(&mut principal, &keystore, &[], &cli.authority)?;
        save_principal_to_engine(&store, &keystore, &principal)?;
        principal.verify_and_record_action(&signed.pay_bytes, &signed.sig, signed.czd.clone())?;

        let principal_id = get_principal_id_from_principal(&principal, &keystore)?;
        let genesis = local_genesis(&keystore, identity)?;
        let blob = serde_json::to_vec(&signed.wire())?;
        block_on(store.submit_commit(&principal_id, genesis, &[blob.as_slice()]))??;
    }

    let out = json!({"identity": identity, "czd": czd, "recorded": !sign_only,
        "coz": signed.wire()});
    emit(cli, &out, || {
        println!("Signed data action {czd}");
        println!("  recorded: {}", !sign_only);
    })
}

/// `cyphr data commit`: include DR = MR(DT) in PR by a signed `ds/create`,
/// finalized as one commit.
fn commit(cli: &Cli, identity: &str, signer_tmb: &str) -> crate::Result<()> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let key = keystore.get(signer_tmb)?;
    let store = parse_store(cli)?;
    let mut principal = load_principal_from_engine(&store, &keystore, identity)?;
    super::init::commit_genesis(&mut principal, &keystore, &[], &cli.authority)?;

    let now = current_timestamp();
    let mut scope = principal.begin_commit();
    let dr = scope.data_tree_id()?.ok_or_else(|| {
        Error::InvalidArgument("no data action is recorded; there is no DR to include".into())
    })?;
    let signed = sign(
        key,
        signer_tmb,
        json!({"id": dr, "now": now,
            "typ": format!("{}/{}", cli.authority, cyphr::parsed_coz::typ::DS_CREATE)}),
    )?;
    scope.verify_and_apply(&signed.pay_bytes, &signed.sig, signed.czd.clone(), None)?;
    let tmb = coz::Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(signer_tmb)?);
    let signer = cyphr::signer::SoftwareSigner::new(&key.alg, &key.prv_key, &key.pub_key, &tmb);
    block_on(scope.finalize_with_software(&signer, now, &cli.authority))??;
    save_principal_to_engine(&store, &keystore, &principal)?;

    let commit_id = cyphr_storage::export_commits(&principal)?
        .into_iter()
        .rfind(|l| !l.commit_id.is_empty())
        .map(|l| l.commit_id)
        .ok_or_else(|| Error::EmptyHistory(identity.to_owned()))?;
    let out = json!({"identity": identity, "dr": dr, "commit_id": commit_id});
    emit(cli, &out, || {
        println!("Included DR {dr} by ds/create");
        println!("  commit: {commit_id}");
    })
}

/// `cyphr data submit`: send one signed action (a coz file, as `data action
/// --sign-only` prints it) to a peer as an action-only bundle.
fn submit(cli: &Cli, identity: &str, peer_url: &str, file: &std::path::Path) -> crate::Result<()> {
    let coz: Value = serde_json::from_slice(&std::fs::read(file)?)?;
    // `data action` prints the whole answer; the coz is its `coz` member.
    let coz = coz.get("coz").unwrap_or(&coz);
    let blob = serde_json::to_vec(coz)?;
    let pg = parse_principal_genesis(identity)?;
    let wire = cyphr_storage::engine::bare_digest(&get_principal_id(&pg)?).to_owned();
    let peer = Peer::new(peer_url, cli.peer_timeout_secs, cli.allow_cleartext)?;
    let tip = block_on(async {
        peer.push_commit(&wire, &[blob]).await?;
        peer.tip_commit_id(&wire).await
    })??;
    let out = json!({"identity": identity, "peer": peer_url, "status": "accepted", "tip": tip});
    emit(cli, &out, || println!("Action accepted by {peer_url}"))
}
