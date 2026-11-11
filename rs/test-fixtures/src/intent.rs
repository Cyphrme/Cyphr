//! Intent types and parsing.
//!
//! Intent files define test cases in human-editable TOML format.
//!
//! ## Canonical Format
//!
//! Transactions use `[[test.commit]]` + `[[test.commit.tx]]`.
//! Actions use `[[test.action]]`.
//! See `.sketches/2026-02-18-fixture-format-alignment.md` for design rationale.
//!
//! ## Numbered keys and repeated items
//!
//! Two shorthands keep large vectors readable; both are expanded when an
//! intent is loaded, so the generator only ever sees the long form:
//!
//! - A `principal` entry `"#a..#b"` stands for the numbered keys `#a` through `#b` inclusive (see
//!   [`crate::pool::NumberedKeys`]).
//! - A commit with `repeat = { from = 0, count = 255 }` repeats its `tx` list for each `n` in
//!   `from..from + count`, replacing `{n}` in every `target`. A target `nonce:<n>` is the nonce
//!   value of item `n`: the SHA-256 digest-shaped id whose bytes are `n` as big-endian `u16`
//!   followed by thirty `0xEE` bytes.

use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::Error;

/// A test intent file containing one or more test cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    /// Test cases defined in this file.
    #[serde(default)]
    pub test: Vec<TestIntent>,
}

/// A single test case intent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestIntent {
    /// Test name.
    pub name: String,
    /// Genesis key set (key names from pool).
    pub principal: Vec<String>,
    /// Setup modifiers (e.g., pre-revoke keys).
    #[serde(default)]
    pub setup: Option<SetupIntent>,
    /// Commit sequence. Each commit contains one or more cozies.
    #[serde(default)]
    pub commit: Vec<CommitIntent>,
    /// Action sequence (Level 4 data recording).
    #[serde(default)]
    pub action: Vec<ActionIntent>,
    /// The second principal, for a test about two (a merge).
    #[serde(default)]
    pub peer: Option<PeerIntent>,
    /// Override fields (for error tests).
    #[serde(default, rename = "override")]
    pub override_: Option<OverrideIntent>,
    /// Expected assertions.
    #[serde(default)]
    pub expected: Option<ExpectedAssertions>,
}

/// A single commit containing transactions.
/// Each transaction is a list of cozies (list-of-lists per SPEC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitIntent {
    /// Transactions within this commit.
    /// Each transaction is a list of cozies.
    #[serde(default)]
    pub tx: Vec<Vec<TxIntent>>,
}

/// A single coz within a commit.
///
/// Flat struct merging the old `PayIntent` + `CryptoIntent` fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxIntent {
    /// ParsedCoz type (e.g., "cyphr.me/key/create").
    pub typ: String,
    /// Timestamp.
    pub now: i64,
    /// Signer key name (from pool).
    pub signer: String,
    /// Target key name (for key/create, key/revoke): the pay `id` is its
    /// thumbprint.
    #[serde(default)]
    pub target: Option<String>,
    /// The pay `id` stated verbatim, for values no pool key's thumbprint
    /// can express (a nonce, an off-by-one width, a `principal/create` or
    /// `ds/create` naming a state it does not reach). Takes the place of
    /// `target` and of a derived `id`.
    #[serde(default)]
    pub id: Option<String>,
    /// `merge_from` of a `principal/merge` or `principal/merge-ack` (SPEC
    /// 11.5.1): PRs named by reference, `self:<n>` or `peer:<n>` for the
    /// PR that principal held after its `n`-th commit (`0` the genesis
    /// commit). The test's principal is `self`, its `peer` the other.
    #[serde(default)]
    pub merge_from: Option<Vec<String>>,
    /// `merge_to_pr` of a merge or merge-ack, by the same reference.
    #[serde(default)]
    pub merge_to_pr: Option<String>,
    /// Optional message.
    #[serde(default)]
    pub msg: Option<String>,
    /// Optional revocation timestamp.
    #[serde(default)]
    pub rvk: Option<i64>,
}

/// Setup modifiers for test.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetupIntent {
    /// A key of `principal` that is already revoked when the principal is
    /// created: genesis is given it carrying a revocation at `revoke_at`
    /// (SPEC 6.4: a revoked key is never trusted again; 7.7: genesis
    /// creates every key, its first included).
    #[serde(default)]
    pub revoke_key: Option<String>,
    /// Timestamp for the revocation.
    #[serde(default)]
    pub revoke_at: Option<i64>,
}

/// The second principal of a two-principal test: its genesis keys and
/// commits, generated after the test principal's (SPEC 11.5.1 merge), or
/// before them when `embedded` (SPEC 10.3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerIntent {
    /// Genesis key set (key names from pool).
    pub principal: Vec<String>,
    /// Commit sequence.
    #[serde(default)]
    pub commit: Vec<CommitIntent>,
    /// The peer is an embedded principal of the test principal: its chain
    /// comes first, and the verifier pins every PR it held to its tip, so
    /// a test-principal coz may name `id = "peer:<n>"` to embed it and be
    /// signed by a key of the peer.
    #[serde(default)]
    pub embedded: bool,
}

/// Override fields for error tests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverrideIntent {
    /// Override `tmb` field value (for UnknownKey tests).
    #[serde(default)]
    pub tmb: Option<String>,
    /// Override timestamp (for TimestampPast tests).
    #[serde(default)]
    pub now: Option<i64>,
    /// Force-inject a `pre` field onto actions (for [data-action-no-pre] tests).
    #[serde(default)]
    pub inject_pre: Option<bool>,
    /// Bypass the empty commit validation to force an empty commit generation (for
    /// [commit-one-or-more] tests).
    #[serde(default)]
    pub empty_commit: Option<bool>,
}

/// An action intent (Level 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionIntent {
    /// Action type (e.g., "cyphr.me/action").
    pub typ: String,
    /// Timestamp.
    pub now: i64,
    /// Signer key name (from pool).
    pub signer: String,
    /// Optional message content.
    #[serde(default)]
    pub msg: Option<String>,
    /// Optional payload ID (e.g. for witness/register/*).
    #[serde(default)]
    pub id: Option<String>,
}

/// Expected assertions after test execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExpectedAssertions {
    /// Expected key count.
    #[serde(default)]
    pub key_count: Option<usize>,
    /// Expected level.
    #[serde(default)]
    pub level: Option<u8>,
    /// Expected key root digest.
    #[serde(default)]
    pub kr: Option<String>,
    /// Expected auth root digest.
    #[serde(rename = "ar", default)]
    pub auth_root: Option<String>,
    /// Expected state root digest.
    #[serde(rename = "sr", default)]
    pub sr: Option<String>,
    /// Expected principal root digest.
    #[serde(default)]
    pub pr: Option<String>,
    /// Expected commit ID digest.
    #[serde(default)]
    pub tr: Option<String>,
    /// Expected error (for error tests).
    #[serde(default)]
    pub error: Option<String>,
    /// Expected `Principal::is_deleted()` (SPEC.md §11.1 `Deleted`).
    #[serde(default)]
    pub deleted: Option<bool>,
    /// Expected `Principal::is_frozen()` (SPEC.md §11.1 `Frozen`).
    #[serde(default)]
    pub frozen: Option<bool>,
    /// Expected `merge_status` of the test principal (the source) into its
    /// peer (the target): `None`, `Pending` or `Merged` (SPEC 11.5.1).
    #[serde(default)]
    pub merge_status: Option<String>,
}

impl Intent {
    /// Load an intent file from TOML and expand its shorthands.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::Read {
            path: path.display().to_string(),
            source: e,
        })?;
        Self::parse(&content, &path.display().to_string())
    }

    /// Parse TOML text, expanding the numbered-key and repeat shorthands
    /// to their long form. `origin` names the source in errors.
    fn parse(text: &str, origin: &str) -> Result<Self, Error> {
        let toml_err = |source| Error::TomlParse {
            path: origin.to_string(),
            source,
        };
        let mut doc: toml::Table = toml::from_str(text).map_err(toml_err)?;
        expand_repeats(&mut doc)?;
        let mut intent: Self = doc.try_into().map_err(toml_err)?;
        for test in &mut intent.test {
            test.principal = expand_principal(&test.name, &test.principal)?;
            let peer = test.peer.iter_mut().flat_map(|p| p.commit.iter_mut());
            for coz in test
                .commit
                .iter_mut()
                .chain(peer)
                .flat_map(|c| c.tx.iter_mut().flatten())
            {
                resolve_nonce(&test.name, coz)?;
            }
        }
        Ok(intent)
    }
}

impl FromStr for Intent {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s, "<string>")
    }
}

fn invalid(test: &str, why: String) -> Error {
    Error::InvalidIntent {
        message: format!("test '{test}': {why}"),
    }
}

/// Expand `"#a..#b"` entries (inclusive) to the numbered keys they name.
fn expand_principal(test: &str, names: &[String]) -> Result<Vec<String>, Error> {
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let Some((lo, hi)) = name.split_once("..") else {
            out.push(name.clone());
            continue;
        };
        let number = |s: &str| {
            s.strip_prefix('#')
                .and_then(|n| n.parse::<u32>().ok())
                .ok_or_else(|| invalid(test, format!("bad key range '{name}', want \"#a..#b\"")))
        };
        let (lo, hi) = (number(lo)?, number(hi)?);
        if lo > hi {
            return Err(invalid(test, format!("empty key range '{name}'")));
        }
        out.extend((lo..=hi).map(|n| format!("#{n}")));
    }
    Ok(out)
}

/// The nonce value of item `n`: SHA-256 digest-shaped, `n` as big-endian
/// `u16` then thirty `0xEE` bytes.
fn nonce_id(n: u32) -> Option<String> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let n = u16::try_from(n).ok()?;
    let mut raw = [0xEE_u8; 32];
    raw[..2].copy_from_slice(&n.to_be_bytes());
    Some(format!(
        "SHA-256:{}",
        Base64UrlUnpadded::encode_string(&raw)
    ))
}

/// Resolve a `nonce:<n>` target to the `id` it stands for.
fn resolve_nonce(test: &str, coz: &mut TxIntent) -> Result<(), Error> {
    let Some(item) = coz.target.as_deref().and_then(|t| t.strip_prefix("nonce:")) else {
        return Ok(());
    };
    let id = item
        .parse::<u32>()
        .ok()
        .and_then(nonce_id)
        .ok_or_else(|| invalid(test, format!("bad nonce item '{item}', want 0..=65535")))?;
    coz.target = None;
    coz.id = Some(id);
    Ok(())
}

/// Expand every commit's `repeat = { from, count }` in the raw document.
///
/// Done on the TOML tree, before typing, so the typed `CommitIntent` has no
/// shorthand-only field: the `tx` list is repeated for each item number and
/// `{n}` in every `target` becomes that number.
fn expand_repeats(doc: &mut toml::Table) -> Result<(), Error> {
    use toml::Value;

    let bad = |why: &str| Error::InvalidIntent {
        message: format!("commit repeat: {why}"),
    };
    let tests = doc.get_mut("test").and_then(Value::as_array_mut);
    let commits = tests
        .into_iter()
        .flatten()
        .filter_map(|t| t.get_mut("commit").and_then(Value::as_array_mut))
        .flatten();
    for commit in commits {
        let Some(table) = commit.as_table_mut() else {
            continue;
        };
        let Some(repeat) = table.remove("repeat") else {
            continue;
        };
        let field = |k: &str| {
            repeat
                .get(k)
                .and_then(Value::as_integer)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| bad("want repeat = { from = <u32>, count = <u32> }"))
        };
        let (from, count) = (field("from")?, field("count")?);
        let template = table
            .get("tx")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut txs = Vec::new();
        for n in from..from.saturating_add(count) {
            let mut round = template.clone();
            for coz in round
                .iter_mut()
                .filter_map(Value::as_array_mut)
                .flatten()
                .filter_map(Value::as_table_mut)
            {
                if let Some(Value::String(t)) = coz.get_mut("target") {
                    *t = t.replace("{n}", &n.to_string());
                }
            }
            txs.extend(round);
        }
        table.insert("tx".to_string(), Value::Array(txs));
    }
    Ok(())
}

impl TestIntent {
    /// Returns true if this test has commits (state-mutating cozies).
    pub fn has_commits(&self) -> bool {
        !self.commit.is_empty()
    }

    /// Returns true if this test has actions (Level 4 data recording).
    pub fn has_action(&self) -> bool {
        !self.action.is_empty()
    }

    /// Returns true if this is a genesis-only test (no commits or actions).
    pub fn is_genesis_only(&self) -> bool {
        self.commit.is_empty() && self.action.is_empty()
    }

    /// Returns true if this test has both commits and actions.
    pub fn has_tx_and_action(&self) -> bool {
        !self.commit.is_empty() && !self.action.is_empty()
    }

    /// Returns true if this test expects an error.
    pub fn is_error_test(&self) -> bool {
        self.expected.as_ref().is_some_and(|e| e.error.is_some())
    }
}
