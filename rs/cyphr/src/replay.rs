//! Replay of stored commit bundles.
//!
//! A bundle is what one push carries, in the JSON wire form of SPEC 4.6.2:
//! `txs`, the commit's transactions, each an ordered array of cozies with
//! the commit transaction last; `keys`, the public keys the cozies of `txs`
//! introduce; and `actions`, data actions (SPEC 4.8.1, not transactions)
//! recorded before the transactions are applied. A bundle arrives one of two
//! ways, as a new submission ([`stage_bundle`], [`replay_bundle`]: the
//! storage engine's ingest) or as history already admitted somewhere
//! ([`replay_held`]: rebuild, load, a client following a peer), and both
//! apply it by the same rule below, so a bundle means one thing on every
//! path.
//!
//! The order rule: the bundle's actions are held first, then every
//! transaction is applied through [`CommitScope::apply_tx`] inside one
//! commit scope and the commit is finalized. Each transaction's cozies are
//! verified against the state the transaction meets and applied one by
//! one, so the transaction is one leaf of TR, `TX = MR(czd0, czd1?, ...)`
//! (SPEC 3.7.5), and all its cozies share one `typ` (4.1). Actions to be
//! recorded after a commit travel in a following action-only bundle. A
//! bundle with no transaction forms no commit: its actions are held in
//! DT (SPEC 4.8.1: actions "are not chained, and are recorded in DT",
//! "Ordered by `now`"; 3.7 step 2), whatever order they travelled in, so a
//! later `ds/create` includes them (4.8.2). Whether a held action counts
//! is read from the key timeline when DT is read, so an action means the
//! same in a bundle that forms a commit and in one that does not.
//!
//! [`CommitScope::apply_tx`]: crate::commit::CommitScope::apply_tx

use coz::Czd;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;

use crate::error::Error;
use crate::key::Key;
use crate::parsed_coz::{CozHeader, compute_czd, typ};
use crate::principal::{Arrival, Principal};
use crate::state::{HashAlg, PrincipalRoot, hash_alg_from_str};
use crate::transaction_root::TransactionRoot;

/// Why a wire blob or bundle is not a stored one.
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
    /// An entry of `keys` lacks `alg`, `pub` or `tmb`, or one of them is
    /// not decodable.
    #[error("key entry is malformed")]
    KeyFields,
    /// An entry of `keys` fails the core's key checks (a `tmb` that is not
    /// the thumbprint of `pub`).
    #[error("key entry: {0}")]
    Key(Error),
    /// A data action inside `txs`, or a transaction inside `actions`: SPEC
    /// 4.6.2 `txs` holds transactions only, and 4.8.1 actions are not
    /// transactions.
    #[error(
        "coz is in the wrong part of the bundle (a data action in txs or a transaction in actions)"
    )]
    Misplaced,
    /// A transaction of no coz (SPEC 4.1: one or more).
    #[error("a transaction holds no coz")]
    EmptyTransaction,
    /// A key-introducing coz names a key the bundle does not carry in
    /// `keys` (SPEC 4.6.2).
    #[error("a key-introducing coz names a key the bundle does not carry")]
    MissingKey,
}

/// One entry of a bundle's `keys` (SPEC 4.6.2, 5.2): the full public key a
/// key-introducing coz names by `tmb` only. Unsigned material, bound to the
/// signed pay by its thumbprint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyEntry {
    /// Algorithm identifier (e.g., "ES256").
    pub alg: String,
    /// Public key (base64url-encoded).
    #[serde(rename = "pub")]
    pub pub_key: String,
    /// Key thumbprint (base64url-encoded).
    pub tmb: String,
    /// Optional human-readable label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Optional creation timestamp (maps to [`Key::first_seen`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<i64>,
}

impl KeyEntry {
    /// The entry of `key`.
    #[must_use]
    pub fn of(key: &Key) -> Self {
        Self {
            alg: key.alg().to_owned(),
            pub_key: Base64UrlUnpadded::encode_string(key.pub_key()),
            tmb: key.tmb().to_b64(),
            tag: key.tag().map(str::to_owned),
            now: Some(key.first_seen()),
        }
    }

    /// The entry as a [`Key`]: the one place wire key material becomes a
    /// key, so the constructor's check that `tmb` is the thumbprint of
    /// `pub` holds on every path.
    ///
    /// # Errors
    ///
    /// [`WireError::KeyFields`] for undecodable fields, [`WireError::Key`]
    /// when the core refuses the key.
    pub fn to_key(&self) -> Result<Key, WireError> {
        let decode = |v: &str| Base64UrlUnpadded::decode_vec(v).map_err(|_| WireError::KeyFields);
        let tmb = decode(&self.tmb)?;
        let pub_key = decode(&self.pub_key)?;
        Ok(
            Key::new(self.alg.clone(), coz::Thumbprint::from_bytes(tmb), pub_key)
                .map_err(WireError::Key)?
                .with_first_seen(self.now.unwrap_or(0))
                .with_tag(self.tag.clone()),
        )
    }
}

/// One coz of a stored bundle, decoded and canonicalized: the signed pay
/// bytes (keys sorted, the form the signature covers), the signature and
/// its digest.
#[derive(Debug, Clone)]
pub struct StoredCoz {
    pay: Value,
    pay_json: Vec<u8>,
    sig: Vec<u8>,
    alg: String,
    hash_alg: HashAlg,
    czd: Czd,
    header: CozHeader,
}

impl StoredCoz {
    /// A coz from its `pay` and signature bytes.
    ///
    /// # Errors
    ///
    /// [`WireError::Header`] when the pay fails the core's header parse;
    /// [`WireError::Protocol`]: [`Error::MalformedPayload`] for a pay with
    /// no `alg`, [`Error::UnknownAlg`] for one the algorithm table does not
    /// hold.
    pub fn new(pay: &Value, sig: Vec<u8>) -> Result<Self, WireError> {
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
        Ok(Self {
            pay,
            pay_json,
            sig,
            alg,
            hash_alg,
            czd,
            header,
        })
    }

    /// A coz from its stored wire form, `{pay, sig}` JSON with `sig` in
    /// base64url. Key material is never read from a coz: it travels in the
    /// bundle's `keys` (SPEC 4.6.2).
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
        Self::new(pay, sig)
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

    /// Whether this coz is a transaction (by the core kind table) rather
    /// than a data action.
    #[must_use]
    pub fn is_transaction(&self) -> bool {
        typ::is_transaction(&self.header.typ)
    }

    /// The thumbprint a key-introducing coz names by its `id`; `None` for
    /// any other coz.
    fn introduces(&self) -> Option<&str> {
        typ::is_key_introducing(&self.header.typ)
            .then(|| self.pay.get("id").and_then(Value::as_str))
            .flatten()
    }
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

/// A bundle in its SPEC 4.6.2 wire form, the cozies still raw JSON bytes:
/// what a push sends, a patch entry serves and the storage engine keeps.
///
/// Serializes as `{"txs": [[coz, ...], ...], "keys": [...], "actions":
/// [coz, ...]}`, each coz a base64url string of its JSON (the transport
/// form a coz has on every route), `keys` and `actions` omitted when empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireBundle {
    /// Data actions recorded before the transactions.
    pub actions: Vec<Vec<u8>>,
    /// The commit's transactions, each its cozies in signed order, the
    /// commit transaction last.
    pub txs: Vec<Vec<Vec<u8>>>,
    /// The public keys the cozies of `txs` introduce.
    pub keys: Vec<KeyEntry>,
}

/// The JSON shape of [`WireBundle`].
#[derive(serde::Serialize, serde::Deserialize)]
struct WireBundleJson {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    txs: Vec<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    keys: Vec<KeyEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    actions: Vec<String>,
}

impl serde::Serialize for WireBundle {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encode = |b: &Vec<u8>| Base64UrlUnpadded::encode_string(b);
        WireBundleJson {
            txs: self
                .txs
                .iter()
                .map(|tx| tx.iter().map(encode).collect())
                .collect(),
            keys: self.keys.clone(),
            actions: self.actions.iter().map(encode).collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for WireBundle {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let json = WireBundleJson::deserialize(deserializer)?;
        let decode = |s: &String| {
            Base64UrlUnpadded::decode_vec(s)
                .map_err(|_| serde::de::Error::custom("coz is not base64url"))
        };
        Ok(Self {
            txs: json
                .txs
                .iter()
                .map(|tx| tx.iter().map(decode).collect())
                .collect::<Result<_, _>>()?,
            keys: json.keys,
            actions: json.actions.iter().map(decode).collect::<Result<_, _>>()?,
        })
    }
}

impl WireBundle {
    /// An action-only bundle.
    #[must_use]
    pub fn actions(actions: Vec<Vec<u8>>) -> Self {
        Self {
            actions,
            ..Self::default()
        }
    }

    /// The bundle of a finalized commit: its transactions as signed, the
    /// commit transaction last, and the keys they introduce.
    ///
    /// # Errors
    ///
    /// A coz that does not serialize (never, for a verified coz).
    pub fn of_commit(commit: &crate::commit::Commit) -> Result<Self, serde_json::Error> {
        Ok(Self {
            actions: Vec::new(),
            txs: commit
                .transactions()
                .iter()
                .map(|tx| tx.0.iter().map(|c| serde_json::to_vec(c.raw())).collect())
                .collect::<Result<_, _>>()?,
            keys: commit
                .iter_all_cozies()
                .filter_map(|c| c.new_key())
                .map(KeyEntry::of)
                .collect(),
        })
    }

    /// Whether the bundle carries no coz.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.txs.iter().all(Vec::is_empty)
    }

    /// Every coz of the bundle in bundle order: the actions, then each
    /// transaction's cozies. A [`ReplayError::coz`] indexes this order.
    pub fn cozies(&self) -> impl Iterator<Item = &[u8]> {
        self.actions
            .iter()
            .chain(self.txs.iter().flatten())
            .map(Vec::as_slice)
    }

    /// Apply `f` to every coz, keeping the shape (e.g. to canonicalize the
    /// bytes before they are stored).
    ///
    /// # Errors
    ///
    /// The first error `f` returns, with the coz's index in bundle order.
    pub fn try_map<E>(
        &self,
        mut f: impl FnMut(usize, &[u8]) -> Result<Vec<u8>, E>,
    ) -> Result<Self, E> {
        let mut i = 0;
        let mut next = |b: &Vec<u8>| {
            let out = f(i, b);
            i += 1;
            out
        };
        Ok(Self {
            actions: self
                .actions
                .iter()
                .map(&mut next)
                .collect::<Result<_, _>>()?,
            txs: self
                .txs
                .iter()
                .map(|tx| tx.iter().map(&mut next).collect())
                .collect::<Result<_, _>>()?,
            keys: self.keys.clone(),
        })
    }

    /// Decode every coz and key.
    ///
    /// # Errors
    ///
    /// The first malformed coz, with its index in bundle order; a
    /// malformed key entry (`coz: None`); a misplaced coz or an empty
    /// transaction.
    pub fn decode(&self) -> Result<Bundle, BundleWireError> {
        let at = |i| {
            move |error| BundleWireError {
                coz: Some(i),
                error,
            }
        };
        let mut i = 0;
        let mut coz = |blob: &Vec<u8>| {
            let out = StoredCoz::from_wire(blob).map_err(at(i));
            i += 1;
            out
        };
        let actions = self
            .actions
            .iter()
            .map(&mut coz)
            .collect::<Result<_, _>>()?;
        let txs = self
            .txs
            .iter()
            .map(|tx| tx.iter().map(&mut coz).collect())
            .collect::<Result<_, _>>()?;
        let keys = self
            .keys
            .iter()
            .map(KeyEntry::to_key)
            .collect::<Result<_, _>>()
            .map_err(|error| BundleWireError { coz: None, error })?;
        Bundle::new(actions, txs, keys)
    }
}

/// A [`WireError`] in a bundle, and where.
#[derive(Debug, thiserror::Error)]
#[error("coz {coz:?}: {error}")]
pub struct BundleWireError {
    /// The coz's index in bundle order ([`WireBundle::cozies`]); `None`
    /// for a key entry.
    pub coz: Option<usize>,
    /// What is malformed.
    #[source]
    pub error: WireError,
}

/// A decoded bundle: actions, transactions and keys (see the
/// [module docs](self)).
#[derive(Debug, Clone)]
pub struct Bundle {
    actions: Vec<StoredCoz>,
    txs: Vec<Vec<StoredCoz>>,
    keys: Vec<Key>,
}

impl Bundle {
    /// A bundle of `actions` recorded before the transactions `txs`, whose
    /// key-introducing cozies name keys of `keys`.
    ///
    /// # Errors
    ///
    /// [`WireError::Misplaced`] for a data action in `txs` or a
    /// transaction in `actions`; [`WireError::EmptyTransaction`] for a
    /// transaction of no coz.
    pub fn new(
        actions: Vec<StoredCoz>,
        txs: Vec<Vec<StoredCoz>>,
        keys: Vec<Key>,
    ) -> Result<Self, BundleWireError> {
        let misplaced = |i| BundleWireError {
            coz: Some(i),
            error: WireError::Misplaced,
        };
        if let Some(i) = actions.iter().position(StoredCoz::is_transaction) {
            return Err(misplaced(i));
        }
        let mut i = actions.len();
        for tx in &txs {
            if tx.is_empty() {
                return Err(BundleWireError {
                    coz: Some(i),
                    error: WireError::EmptyTransaction,
                });
            }
            if let Some(j) = tx.iter().position(|c| !c.is_transaction()) {
                return Err(misplaced(i + j));
            }
            i += tx.len();
        }
        Ok(Self { actions, txs, keys })
    }

    /// The commit id the bundle's transactions name in `alg`: its
    /// Transaction Root, `TR = MR(TX0?, ..., TXc)` with the commit
    /// transaction last (SPEC 3.7.5). A function of the bundle's own
    /// bytes, with no chain state: it names the commit whether or not the
    /// holder can replay it. `None` for a bundle of no transaction.
    #[must_use]
    pub fn commit_id(&self, alg: HashAlg) -> Option<crate::state::TaggedDigest> {
        let algs = [alg];
        let tx_id = |tx: &[StoredCoz]| {
            let czds: Vec<crate::state::TaggedCzd<'_>> = tx
                .iter()
                .map(|c| crate::state::TaggedCzd::new(c.czd(), c.hash_alg()))
                .collect();
            crate::transaction_root::compute_tx(&czds, &algs)
        };
        let (commit_tx, mutations) = self.txs.split_last()?;
        let mutations: Vec<_> = mutations
            .iter()
            .map(|tx| tx_id(tx))
            .collect::<Option<Vec<_>>>()?;
        let refs: Vec<&crate::multihash::MultihashDigest> = mutations.iter().collect();
        let tcr = crate::transaction_root::TransactionCommitRoot(tx_id(commit_tx)?);
        crate::transaction_root::compute_tr(&refs, &tcr, &algs)?
            .0
            .tagged(alg)
            .ok()
    }

    /// The actions recorded before the transactions.
    #[must_use]
    pub fn action_cozies(&self) -> &[StoredCoz] {
        &self.actions
    }

    /// The transactions, each its cozies in signed order.
    #[must_use]
    pub fn txs(&self) -> &[Vec<StoredCoz>] {
        &self.txs
    }

    /// Every coz in bundle order: the actions, then each transaction's.
    pub fn cozies(&self) -> impl DoubleEndedIterator<Item = &StoredCoz> {
        self.actions.iter().chain(self.txs.iter().flatten())
    }

    /// The signer of the commit the bundle forms: the closing
    /// `commit/create`'s, else the last coz's ([`commit_signer`]); `None`
    /// for a bundle of no coz.
    #[must_use]
    pub fn commit_signer(&self) -> Option<&coz::Thumbprint> {
        commit_signer(
            self.cozies()
                .map(|c| (c.header.typ.as_str(), &c.header.tmb)),
        )
    }

    /// Every key the bundle names, once each, in order of first mention:
    /// each coz's signer (`tmb`) and, for a key-introducing coz, the key it
    /// introduces (`id`). Read from the bundle's own bytes before any
    /// signature is checked, so it says what a revoke could bear on, never
    /// who authenticated.
    #[must_use]
    pub fn named_keys(&self) -> Vec<coz::Thumbprint> {
        let mut keys: Vec<coz::Thumbprint> = Vec::new();
        for coz in self.cozies() {
            let introduced = coz
                .introduces()
                .and_then(|id| Base64UrlUnpadded::decode_vec(id).ok())
                .map(coz::Thumbprint::from_bytes);
            for named in [Some(coz.header.tmb.clone()), introduced]
                .into_iter()
                .flatten()
            {
                if !keys.contains(&named) {
                    keys.push(named);
                }
            }
        }
        keys
    }

    /// The keys a genesis commit discloses, in wire order: each key a
    /// `key/create` before the first `principal/create` introduces (SPEC
    /// 5.1 steps 1-2, 5.3). `None` when the bundle has no
    /// `principal/create`, so it is no genesis commit; an empty list when
    /// no `key/create` precedes it.
    ///
    /// # Errors
    ///
    /// [`WireError::MissingKey`] when one of those `key/create` cozies names
    /// a key the bundle does not carry.
    pub fn genesis_keys(&self) -> Option<Result<Vec<&Key>, WireError>> {
        let all: Vec<&StoredCoz> = self.txs.iter().flatten().collect();
        let at = all
            .iter()
            .position(|c| typ::has_suffix(&c.header.typ, typ::PRINCIPAL_CREATE))?;
        Some(
            all[..at]
                .iter()
                .filter(|c| typ::has_suffix(&c.header.typ, typ::KEY_CREATE))
                .map(|c| self.introduced_key(c).ok_or(WireError::MissingKey))
                .collect(),
        )
    }

    /// The keys of the bundle a key-introducing coz names: exactly those
    /// whose thumbprint some coz of `txs` names by `id`.
    pub fn introduced_keys(&self) -> impl Iterator<Item = &Key> {
        self.txs
            .iter()
            .flatten()
            .filter_map(|c| self.introduced_key(c))
    }

    /// The key `coz` introduces: the entry of `keys` its `id` names.
    #[must_use]
    pub fn introduced_key(&self, coz: &StoredCoz) -> Option<&Key> {
        let id = coz.introduces()?;
        self.keys.iter().find(|k| k.tmb().to_b64() == id)
    }
}

/// The signer of the commit whose cozies, in signed order, are `cozies`
/// (each a `typ` and its signer): the closing `commit/create`'s, else the
/// last coz's. The one rule, whether the cozies are a bundle's or a stored
/// commit's.
pub fn commit_signer<'a, T>(cozies: impl DoubleEndedIterator<Item = (&'a str, T)>) -> Option<T> {
    let mut last = None;
    for (coz_typ, signer) in cozies.rev() {
        if typ::has_suffix(coz_typ, typ::COMMIT_CREATE) {
            return Some(signer);
        }
        if last.is_none() {
            last = Some(signer);
        }
    }
    last
}

/// What one replayed bundle was: the digests of its cozies in bundle
/// order, the TR of the commit it formed (none for an action-only bundle),
/// and the PR the principal held after it. Two bundles with equal
/// identities carry the same signed content and lead to the same state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleId {
    /// Every coz digest of the bundle, in bundle order.
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
    /// The index in bundle order ([`Bundle::cozies`]) of the coz refused;
    /// `None` when the refusal is the bundle's own (empty, or the commit
    /// fails to finalize) or a whole transaction's (its cozies do not
    /// share one `typ`).
    pub coz: Option<usize>,
    /// The core's refusal.
    #[source]
    pub source: Error,
}

/// A stored bundle verified onto a principal, with nothing written to its
/// commit log: phase one of [`replay_bundle`], for a caller that must make
/// the bundle durable elsewhere before the log (the storage engine records
/// it in the blob store first, its source of truth).
#[must_use = "a staged bundle that forms a commit writes nothing until .commit() is awaited"]
pub enum StagedBundle<'a, S: eml::Storage> {
    /// A bundle with no transaction: its actions are verified and held by
    /// [`StagedBundle::commit`], in memory, and there is nothing to write.
    Actions {
        /// The principal that will hold the actions.
        principal: &'a mut Principal<S>,
        /// The verified actions, not yet held.
        prepared: Vec<crate::action::Action>,
        /// The identity the bundle has.
        id: BundleId,
    },
    /// A bundle that forms a commit, staged: every coz is verified.
    Commit {
        /// The staged commit (boxed: it carries the principal's whole
        /// staged state).
        staged: Box<crate::commit::StagedCommit<'a, S>>,
        /// Every coz digest of the bundle, in bundle order.
        czds: Vec<Czd>,
    },
}

impl<S: eml::Storage> StagedBundle<'_, S> {
    /// The identity the bundle will have once committed.
    ///
    /// # Errors
    ///
    /// `MissingCommit` if a staged commit holds no commit (never, by
    /// construction).
    pub fn id(&self) -> Result<BundleId, ReplayError> {
        match self {
            Self::Actions { id, .. } => Ok(id.clone()),
            Self::Commit { staged, czds } => {
                let state = staged.state();
                let commit = state.commits().last().ok_or(ReplayError {
                    coz: None,
                    source: Error::MissingCommit,
                })?;
                Ok(BundleId {
                    czds: czds.clone(),
                    tr: Some(commit.tr().clone()),
                    pr: state.pr().clone(),
                })
            },
        }
    }

    /// Phase two: write the commit's log append (if the bundle forms one)
    /// and adopt the staged state.
    ///
    /// # Errors
    ///
    /// [`ReplayError`] with [`Error::Storage`] if the log write fails; the
    /// principal is then as it was before the commit.
    pub async fn commit(self) -> Result<BundleId, ReplayError> {
        let id = self.id()?;
        if let Self::Actions {
            principal,
            prepared,
            ..
        } = self
        {
            principal.hold_actions(prepared);
            return Ok(id);
        }
        if let Self::Commit { staged, .. } = self {
            staged
                .commit()
                .await
                .map_err(|source| ReplayError { coz: None, source })?;
        }
        Ok(id)
    }
}

/// Verify one new submission onto `principal` through the verifying commit
/// scope, by the order rule in the [module docs](self), and stage it: the
/// commit's log append is computed and nothing is written. Every coz is
/// verified before [`StagedBundle::commit`] writes, so a refused bundle
/// leaves no log leaf. Its actions are admitted only if their signers
/// authorize them (SPEC 6.5).
///
/// Nothing is held on `principal` until [`StagedBundle::commit`]: a
/// refused or dropped stage leaves it as it was, whichever refusal comes
/// between the stage and the commit.
///
/// # Errors
///
/// [`ReplayError`] with [`Error::EmptyCommit`] for an empty bundle,
/// [`Error::MixedTransactionTyp`] for a transaction whose cozies do not
/// share one `typ`, or the core's refusal of a coz or of the commit.
pub async fn stage_bundle<'a, S: eml::Storage>(
    principal: &'a mut Principal<S>,
    bundle: &Bundle,
) -> Result<StagedBundle<'a, S>, ReplayError> {
    stage(principal, bundle, Arrival::Submitted).await
}

async fn stage<'a, S: eml::Storage>(
    principal: &'a mut Principal<S>,
    bundle: &Bundle,
    arrival: Arrival,
) -> Result<StagedBundle<'a, S>, ReplayError> {
    let at = |i: usize| {
        move |source| ReplayError {
            coz: Some(i),
            source,
        }
    };
    let whole = |source| ReplayError { coz: None, source };
    let czds: Vec<Czd> = bundle.cozies().map(|c| c.czd.clone()).collect();
    if czds.is_empty() {
        return Err(whole(Error::EmptyCommit));
    }

    if bundle.txs.is_empty() {
        let mut prepared = Vec::with_capacity(bundle.actions.len());
        for (i, c) in bundle.actions.iter().enumerate() {
            let action = principal
                .prepare_action(&c.pay_json, &c.sig, c.czd.clone(), arrival)
                .map_err(at(i))?;
            prepared.extend(action);
        }
        let id = BundleId {
            czds,
            tr: None,
            pr: principal.pr().clone(),
        };
        return Ok(StagedBundle::Actions {
            principal,
            prepared,
            id,
        });
    }

    let mut scope = principal.begin_commit();
    for (i, c) in bundle.actions.iter().enumerate() {
        scope
            .hold_action(&c.pay_json, &c.sig, c.czd.clone(), arrival)
            .map_err(at(i))?;
    }
    let mut i = bundle.actions.len();
    for tx in &bundle.txs {
        // Every coz of a transaction is verified against the state the
        // transaction meets, then the transaction is applied as one TR
        // leaf; `apply_tx` refuses a mix of `typ`s before applying any.
        let verified = tx
            .iter()
            .enumerate()
            .map(|(j, c)| {
                scope
                    .verify(
                        &c.pay_json,
                        &c.sig,
                        c.czd.clone(),
                        bundle.introduced_key(c).cloned(),
                    )
                    .map_err(at(i + j))
            })
            .collect::<Result<Vec<_>, _>>()?;
        scope.apply_tx(verified).map_err(|source| ReplayError {
            // A refusal of the whole transaction names no single coz.
            coz: (tx.len() == 1).then_some(i),
            source,
        })?;
        i += tx.len();
    }
    let staged = scope.stage().await.map_err(whole)?;
    Ok(StagedBundle::Commit {
        staged: Box::new(staged),
        czds,
    })
}

/// Replay one new submission onto `principal`: [`stage_bundle`], then
/// [`StagedBundle::commit`]. Held history, already admitted elsewhere,
/// replays through [`replay_held`].
///
/// # Errors
///
/// As [`stage_bundle`] and [`StagedBundle::commit`].
pub async fn replay_bundle<S: eml::Storage>(
    principal: &mut Principal<S>,
    bundle: &Bundle,
) -> Result<BundleId, ReplayError> {
    stage_bundle(principal, bundle).await?.commit().await
}

/// [`replay_bundle`] for history already admitted somewhere (a store, a
/// peer, an export), not a new submission: every action is held once its
/// signature verifies under a key the principal has held, and whether it
/// counts is left to DT's read of the key timeline (SPEC 6.2: "actions
/// signed after it has been removed are ignored"), so replaying a history
/// gives the DT the principal that lived it had. An action by a key this
/// principal never held stays a refusal. A bundle that forms a commit
/// replays as [`replay_bundle`] does.
///
/// # Errors
///
/// As [`replay_bundle`], but no action is refused for its signer's inactivity.
pub async fn replay_held<S: eml::Storage>(
    principal: &mut Principal<S>,
    bundle: &Bundle,
) -> Result<BundleId, ReplayError> {
    stage(principal, bundle, Arrival::Held)
        .await?
        .commit()
        .await
}
