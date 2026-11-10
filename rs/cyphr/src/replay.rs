//! Replay of stored commit bundles.
//!
//! A stored bundle is the cozies one push carried, in the order the
//! principal signed them: at most one commit's transactions plus any data
//! actions around them. Every consumer that rebuilds a principal from
//! stored or fetched bundles (the storage engine's ingest, rebuild and
//! load, a client following a peer) replays through [`replay_bundle`], so a
//! bundle means one thing on every path: one kind table decides what is a
//! transaction ([`typ::is_transaction`](crate::parsed_coz::typ::is_transaction)),
//! and one order rule decides how the bundle is applied.
//!
//! The order rule is the one every path used before it lived here: data
//! actions before the first transaction are recorded first, then every
//! transaction is applied inside one commit scope and the commit is
//! finalized, then the actions that followed the first transaction are
//! recorded. A bundle with no transaction forms no commit: its actions are
//! recorded in DT in `now` order, the lexical order of their digests
//! breaking ties (SPEC 4.8.1: actions "are not chained, and are recorded in
//! DT", "Ordered by `now`"; 3.7 step 2), whatever order they travelled in,
//! so a later `ds/create` includes them (4.8.2). Transaction grouping
//! (several cozies per transaction) is not decided here yet; each
//! transaction coz is its own transaction.

use coz::Czd;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;

use crate::error::Error;
use crate::key::Key;
use crate::parsed_coz::{CozHeader, compute_czd, typ};
use crate::principal::Principal;
use crate::state::{HashAlg, PrincipalRoot, hash_alg_from_str};
use crate::transaction_root::TransactionRoot;

/// Why a wire blob is not a stored coz.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    /// The blob is not a JSON object.
    #[error("blob is not JSON")]
    NotJson,
    /// The blob has no `pay`.
    #[error("no pay")]
    MissingPay,
    /// The blob has no `sig`, or it is not base64url.
    #[error("sig is missing or not base64url")]
    BadSig,
    /// The pay breaks a core rule checked before verification, with the
    /// kind verification would give it (a missing `alg` is
    /// [`Error::MalformedPayload`], as [`verify_coz`](crate::verify_coz)
    /// rules; an `alg` outside the algorithm table is [`Error::UnknownAlg`]).
    #[error("{0}")]
    Protocol(Error),
    /// The pay fails the core's header parse (`typ`, `tmb`, `now`).
    #[error("pay header: {0}")]
    Header(Error),
    /// A key-introducing coz's `key` sidecar lacks `alg`, `pub` or `tmb`,
    /// or one of them is not decodable.
    #[error("key sidecar is malformed")]
    KeyFields,
    /// The sidecar's key fails the core's key checks (a `tmb` that is not
    /// the thumbprint of `pub`).
    #[error("key sidecar: {0}")]
    Key(Error),
}

/// One coz of a stored bundle, decoded and canonicalized: the signed pay
/// bytes (keys sorted, the form the signature covers), the signature, its
/// digest, and the key it introduces, if any.
#[derive(Debug, Clone)]
pub struct StoredCoz {
    pay: Value,
    pay_json: Vec<u8>,
    sig: Vec<u8>,
    alg: String,
    hash_alg: HashAlg,
    czd: Czd,
    header: CozHeader,
    key: Option<Key>,
}

impl StoredCoz {
    /// A coz from its `pay`, signature bytes and the key it introduces.
    /// The key is kept only for a key-introducing `typ`; on any other coz a
    /// key is meaningless and is dropped.
    ///
    /// # Errors
    ///
    /// [`WireError::Header`] when the pay fails the core's header parse;
    /// [`WireError::Protocol`]: [`Error::MalformedPayload`] for a pay with
    /// no `alg`, [`Error::UnknownAlg`] for one the algorithm table does not
    /// hold.
    pub fn new(pay: &Value, sig: Vec<u8>, key: Option<Key>) -> Result<Self, WireError> {
        let mut pay = pay.clone();
        canonicalize(&mut pay);
        let header = CozHeader::parse(&pay).map_err(WireError::Header)?;
        let alg = pay
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(WireError::Protocol(Error::MalformedPayload))?
            .to_string();
        // A `Value` always serializes; `MalformedPayload` names the
        // impossible case without a panic.
        let pay_json =
            serde_json::to_vec(&pay).map_err(|_| WireError::Header(Error::MalformedPayload))?;
        let hash_alg = hash_alg_from_str(&alg).map_err(WireError::Protocol)?;
        // Every algorithm in the table has a coz digest; a `None` here is a
        // table row coz cannot compute, named rather than defaulted.
        let czd = compute_czd(&pay_json, &sig, &alg)
            .ok_or_else(|| WireError::Protocol(Error::UnsupportedAlgorithm(alg.clone())))?;
        let key = key.filter(|_| typ::is_key_introducing(&header.typ));
        Ok(Self {
            pay,
            pay_json,
            sig,
            alg,
            hash_alg,
            czd,
            header,
            key,
        })
    }

    /// A coz from its stored wire form, `{pay, sig, key?}` JSON with `sig`
    /// in base64url. The unsigned `key` sidecar is read only on a
    /// key-introducing coz; on any other coz it is never interpreted, so
    /// junk there cannot refuse a bundle whose signed content is valid.
    ///
    /// # Errors
    ///
    /// A [`WireError`] naming what is malformed.
    pub fn from_wire(blob: &[u8]) -> Result<Self, WireError> {
        let value: Value = serde_json::from_slice(blob).map_err(|_| WireError::NotJson)?;
        let pay = value.get("pay").ok_or(WireError::MissingPay)?;
        let sig = value
            .get("sig")
            .and_then(Value::as_str)
            .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
            .ok_or(WireError::BadSig)?;
        let introduces = pay
            .get("typ")
            .and_then(Value::as_str)
            .is_some_and(typ::is_key_introducing);
        let key = match value.get("key") {
            Some(sidecar) if introduces => Some(sidecar_key(sidecar)?),
            _ => None,
        };
        Self::new(pay, sig, key)
    }

    /// The canonical pay.
    #[must_use]
    pub fn pay(&self) -> &Value {
        &self.pay
    }

    /// The canonical pay bytes the signature covers.
    #[must_use]
    pub fn pay_json(&self) -> &[u8] {
        &self.pay_json
    }

    /// The signature bytes.
    #[must_use]
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }

    /// The pay's `alg`.
    #[must_use]
    pub fn alg(&self) -> &str {
        &self.alg
    }

    /// The hash algorithm of the pay's `alg`: the algorithm [`Self::czd`]
    /// is in.
    #[must_use]
    pub fn hash_alg(&self) -> HashAlg {
        self.hash_alg
    }

    /// The coz digest, in the pay's algorithm.
    #[must_use]
    pub fn czd(&self) -> &Czd {
        &self.czd
    }

    /// The pay's `typ`, `tmb` and `now`.
    #[must_use]
    pub fn header(&self) -> &CozHeader {
        &self.header
    }

    /// The key a key-introducing coz adds.
    #[must_use]
    pub fn key(&self) -> Option<&Key> {
        self.key.as_ref()
    }

    /// Whether this coz is a transaction (by the core kind table) rather
    /// than a data action.
    #[must_use]
    pub fn is_transaction(&self) -> bool {
        typ::is_transaction(&self.header.typ)
    }
}

/// A `key` sidecar `{alg, pub, tmb, now?, tag?}` as a [`Key`].
fn sidecar_key(sidecar: &Value) -> Result<Key, WireError> {
    let field = |name| sidecar.get(name).and_then(Value::as_str);
    let decode = |name| {
        field(name)
            .and_then(|v| Base64UrlUnpadded::decode_vec(v).ok())
            .ok_or(WireError::KeyFields)
    };
    let alg = field("alg").ok_or(WireError::KeyFields)?;
    let tmb = decode("tmb")?;
    let pub_key = decode("pub")?;
    Ok(Key::new(alg, coz::Thumbprint::from_bytes(tmb), pub_key)
        .map_err(WireError::Key)?
        .with_first_seen(sidecar.get("now").and_then(Value::as_i64).unwrap_or(0))
        .with_tag(field("tag").map(str::to_string)))
}

fn canonicalize(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.sort_keys();
            map.values_mut().for_each(canonicalize);
        },
        Value::Array(items) => items.iter_mut().for_each(canonicalize),
        _ => {},
    }
}

/// What one replayed bundle was: the digests of its cozies in signed
/// order, the TR of the commit it formed (none for an action-only bundle),
/// and the PR the principal held after it. Two bundles with equal
/// identities carry the same signed content and lead to the same state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleId {
    /// Every coz digest of the bundle, in signed order.
    pub czds: Vec<Czd>,
    /// The TR of the commit the bundle formed, if it formed one.
    pub tr: Option<TransactionRoot>,
    /// The principal's PR after the bundle.
    pub pr: PrincipalRoot,
}

/// A bundle the core refused, and where.
#[derive(Debug, thiserror::Error)]
#[error("coz {coz:?}: {source}")]
pub struct ReplayError {
    /// The index within the bundle of the coz refused; `None` when the
    /// refusal is the bundle's own (empty, or the commit fails to
    /// finalize).
    pub coz: Option<usize>,
    /// The core's refusal.
    #[source]
    pub source: Error,
}

/// Replay one stored bundle onto `principal` through the verifying commit
/// scope, by the order rule in the [module docs](self).
///
/// On error `principal` may hold the actions recorded before the refusal;
/// a caller that needs all-or-nothing replays onto a principal it can
/// discard.
///
/// # Errors
///
/// [`ReplayError`] with [`Error::EmptyCommit`] for an empty bundle, or the
/// core's refusal of a coz or of the commit.
pub fn replay_bundle<S: eml::Storage>(
    principal: &mut Principal<S>,
    cozies: &[StoredCoz],
) -> Result<BundleId, ReplayError> {
    let at = |i: usize| {
        move |source| ReplayError {
            coz: Some(i),
            source,
        }
    };
    let whole = |source| ReplayError { coz: None, source };
    if cozies.is_empty() {
        return Err(whole(Error::EmptyCommit));
    }
    let czds = cozies.iter().map(|c| c.czd.clone()).collect();
    let record = |principal: &mut Principal<S>, i: usize, c: &StoredCoz| {
        principal
            .verify_and_record_action(&c.pay_json, &c.sig, c.czd.clone())
            .map(|_| ())
            .map_err(at(i))
    };

    let Some(first_tx) = cozies.iter().position(StoredCoz::is_transaction) else {
        let mut order: Vec<(usize, &StoredCoz)> = cozies.iter().enumerate().collect();
        order.sort_by(|(_, a), (_, b)| {
            (a.header.now, a.czd.as_bytes()).cmp(&(b.header.now, b.czd.as_bytes()))
        });
        for (i, c) in order {
            record(principal, i, c)?;
        }
        return Ok(BundleId {
            czds,
            tr: None,
            pr: principal.pr().clone(),
        });
    };

    for (i, c) in cozies.iter().enumerate().take(first_tx) {
        record(principal, i, c)?;
    }
    let mut deferred = Vec::new();
    let mut scope = principal.begin_commit();
    for (i, c) in cozies.iter().enumerate().skip(first_tx) {
        if c.is_transaction() {
            scope
                .verify_and_apply(&c.pay_json, &c.sig, c.czd.clone(), c.key.clone())
                .map_err(at(i))?;
        } else {
            deferred.push((i, c));
        }
    }
    let tr = scope.finalize().map_err(whole)?.tr().clone();
    for (i, c) in deferred {
        record(principal, i, c)?;
    }
    Ok(BundleId {
        czds,
        tr: Some(tr),
        pr: principal.pr().clone(),
    })
}
