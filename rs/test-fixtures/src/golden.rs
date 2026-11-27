//! Golden output types and generation.
//!
//! Golden files contain real Coz messages with hardcoded cryptographic values.
//!
//! ## Generation Flow
//!
//! ```text
//! Intent + Pool → Generator::generate() → Vec<Golden>
//! ```
//!
//! The generator:
//! 1. Creates a Principal from its genesis key and commits its genesis
//! 2. For each coz, captures `pre` from current state root
//! 3. Builds and signs the Coz message
//! 4. Applies the coz to the Principal
//! 5. Extracts final state digests (ks, as, sr, pr, commit_id)

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::StateDigest;
use cyphr_storage::{CommitEntry, KeyEntry};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::Error;
use crate::intent::{
    ActionIntent, CommitIntent, ExpectedAssertions, Intent, PeerIntent, SetupIntent, TestIntent,
    TxIntent,
};
use crate::pool::{Pool, PoolKey};

type CozSignerInfo = (String, Vec<u8>, Vec<u8>, String, i64);

/// `now` of a generated genesis commit for a test that states no time.
const GENESIS_NOW: i64 = 1_700_000_000;

/// A golden test case with real cryptographic values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Golden {
    /// Test name.
    pub name: String,
    /// Genesis key set (key names from pool).
    pub principal: Vec<String>,
    /// Setup modifiers (e.g., pre-revoke keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<GoldenSetup>,
    /// Full genesis key material (alg, pub, tmb) for storage import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_keys: Option<Vec<GoldenKey>>,
    /// Commit bundles in application order (one commit per line in JSONL).
    /// Each commit contains: cozies (cozies), ts, as, pr digests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commits: Option<Vec<CommitEntry>>,
    /// Coz digests (czd) parallel to all cozies across commits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digests: Option<Vec<String>>,
    /// The second principal of a two-principal test (a merge, SPEC
    /// 11.5.1); its commits replay after the test principal's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<GoldenPeer>,
    /// Expected state after execution.
    pub expected: GoldenExpected,
}

/// The second principal of a two-principal golden test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenPeer {
    /// Genesis key set (key names from pool).
    pub principal: Vec<String>,
    /// Commit bundles in application order.
    pub commits: Vec<CommitEntry>,
    /// The peer is an embedded principal of the test principal (SPEC
    /// 10.3): replay it first and pin every PR it held to its tip.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub embedded: bool,
}

/// Setup modifiers for golden test.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GoldenSetup {
    /// Key name to pre-revoke before test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_key: Option<String>,
    /// Timestamp for the revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_at: Option<i64>,
}

/// A Coz message with computed cryptographic values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenCoz {
    /// Pay object as RawValue to preserve exact signed bytes.
    /// This is critical: signatures are computed over these exact bytes.
    pub pay: Box<RawValue>,
    /// Signature (base64url).
    pub sig: String,
    /// Coz digest (base64url).
    pub czd: String,
    /// Embedded key (for key/create cozies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<GoldenKey>,
}

/// A key embedded in a golden Coz message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenKey {
    /// Algorithm.
    pub alg: String,
    /// Public key (base64url).
    #[serde(rename = "pub")]
    pub pub_key: String,
    /// Thumbprint (base64url).
    pub tmb: String,
}

/// Deserialize a field that may be a value, JSON `null`, or missing (the
/// last by `#[serde(default)]`): `null` reads as `Some(None)`, so a root
/// recorded as absent is distinct from a root the vector never mentions.
fn present_or_null<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// Expected state in golden output.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GoldenExpected {
    /// Expected key count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_count: Option<usize>,
    /// Expected level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    /// Expected key root digest (first variant). Outer `None` is a field
    /// the vector omits; inner `None` is JSON `null`, a root the principal
    /// does not have (a Dead principal has no KR, SPEC 3.7).
    #[serde(
        default,
        deserialize_with = "present_or_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub kr: Option<Option<String>>,
    /// Expected auth root digest (first variant); `null` when absent, as
    /// for `kr`.
    #[serde(
        rename = "ar",
        default,
        deserialize_with = "present_or_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_root: Option<Option<String>>,
    /// Expected principal root digest (first variant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr: Option<String>,
    /// Expected Commit Root digest (first variant), present once the
    /// principal has at least one checkpointed commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cr: Option<String>,
    /// Expected commit ID digest.
    #[serde(alias = "ts", default, skip_serializing_if = "Option::is_none")]
    pub tr: Option<String>,
    /// Expected State Root digest: root of the principal's StateTree
    /// (SPEC §3.7.2); promotes from AR when no Data Root is present,
    /// otherwise the tree root over AR and DR. `null` when absent (no keys
    /// and no data), as for `kr`.
    #[serde(
        default,
        deserialize_with = "present_or_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub sr: Option<Option<String>>,
    /// Expected data root digest (Level 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dr: Option<String>,
    /// Expected principal genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg: Option<String>,
    /// Expected error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Per-algorithm KR variants for multihash verification (SPEC §14).
    /// Key: algorithm name (e.g., "SHA-256"), Value: base64url digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multihash_kr: Option<std::collections::BTreeMap<String, String>>,
    /// Per-algorithm AR variants for multihash verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multihash_ar: Option<std::collections::BTreeMap<String, String>>,
    /// Per-algorithm PR variants for multihash verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multihash_pr: Option<std::collections::BTreeMap<String, String>>,
    /// Expected `Principal::is_deleted()` (SPEC.md §11.1 `Deleted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    /// Expected `Principal::is_frozen()` (SPEC.md §11.1 `Frozen`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frozen: Option<bool>,
    /// The TX of each transaction of the last commit, in order (SPEC
    /// 4.6.3 `txs_order`, TX = MR(czd0, czd1?, ...) in the first
    /// algorithm), stated when the commit holds a transaction of more than
    /// one coz: a single coz's TX is its czd, which `digests` already pins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txs_order: Option<Vec<String>>,
    /// Expected `merge_status` of the test principal (the source) into its
    /// peer (the target), SPEC 11.5.1: `None`, `Pending` or `Merged`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_status: Option<String>,
}

// ============================================================================
// Generator
// ============================================================================

/// Canonical name for a genesis-time protocol error, matching the
/// vocabulary test intents declare in their `expected.error` field (see
/// `error_name` in `rs/cyphr/tests/golden_fixtures.rs`, which independently
/// maintains the same mapping for the consumer side).
fn cyphr_error_name(e: &cyphr::error::Error) -> &'static str {
    use cyphr::error::Error;
    match e {
        Error::UnknownKey => "UnknownKey",
        Error::UnknownAlg => "UnknownAlg",
        Error::KeyRevoked => "KeyRevoked",
        Error::NoActiveKeys => "NoActiveKeys",
        Error::DuplicateKey => "DuplicateKey",
        Error::CozReuse => "CozReuse",
        Error::TimestampPast => "TimestampPast",
        Error::TimestampFuture => "TimestampFuture",
        Error::InvalidSignature => "InvalidSignature",
        Error::MalformedPayload => "MalformedPayload",
        Error::UnsupportedAlgorithm(_) => "UnsupportedAlgorithm",
        Error::AlreadyDeleted => "AlreadyDeleted",
        Error::AlreadyFrozen => "AlreadyFrozen",
        Error::NotFrozen => "NotFrozen",
        Error::EmbeddedErrored => "EmbeddedErrored",
        Error::DuplicateNonce => "DuplicateNonce",
        Error::UnknownNonce => "UnknownNonce",
        Error::GenesisIncomplete => "GenesisIncomplete",
        Error::MixedTransactionTyp => "MixedTransactionTyp",
        Error::LoneGroupedTransaction => "LoneGroupedTransaction",
        _ => "UnknownError",
    }
}

/// Generates golden test cases from intent definitions.
///
/// The generator transforms human-readable intent files into
/// golden JSON files containing real Coz messages with cryptographic
/// signatures. Uses `cyphr::Principal` to compute state digests.
#[derive(Debug)]
pub struct Generator<'a> {
    pool: &'a Pool,
    /// The PRs a merge reference resolves to while a commit is signed:
    /// the signing principal's after each of its commits (`self:<n>`), and
    /// the other principal's (`peer:<n>`).
    refs: std::cell::RefCell<MergeRefs>,
}

/// The PR histories merge references resolve against (see
/// [`crate::intent::TxIntent::merge_from`]).
#[derive(Debug, Default)]
struct MergeRefs {
    own: Vec<String>,
    other: Vec<String>,
}

/// The PR `principal` held after each of its commits, tagged.
fn pr_history(principal: &cyphr::Principal) -> Vec<String> {
    principal
        .commits()
        .filter_map(|c| c.pr().as_multihash().tagged_first().ok())
        .map(|t| t.to_string())
        .collect()
}

type SignResult = Result<(String, Vec<u8>, String, coz::Czd, Option<GoldenKey>), Error>;

impl<'a> Generator<'a> {
    /// Create a new generator with the given key pool.
    pub fn new(pool: &'a Pool) -> Self {
        Self {
            pool,
            refs: std::cell::RefCell::default(),
        }
    }

    /// The PR a merge reference (`self:<n>`, `peer:<n>`) names.
    fn resolve_ref(&self, reference: &str) -> Result<String, Error> {
        let bad = || Error::InvalidIntent {
            message: format!("merge reference '{reference}': want self:<n> or peer:<n>, n held"),
        };
        let (who, n) = reference.split_once(':').ok_or_else(bad)?;
        let n: usize = n.parse().map_err(|_| bad())?;
        let refs = self.refs.borrow();
        let history = match who {
            "self" => &refs.own,
            "peer" => &refs.other,
            _ => return Err(bad()),
        };
        history.get(n).cloned().ok_or_else(bad)
    }

    /// Format principal state as tagged digest string (alg:digest format).
    ///
    /// Delegates to `Principal::pr_tagged()`.
    fn format_pr_tagged(principal: &cyphr::Principal) -> Result<String, Error> {
        principal.pr_tagged().map_err(|e| Error::Generation {
            name: String::new(),
            reason: format!("pr_tagged failed: {}", e),
        })
    }

    /// Generate golden test cases from an intent file.
    ///
    /// Each test in the intent becomes a golden test case.
    pub async fn generate(&self, intent: &Intent) -> Result<Vec<Golden>, Error> {
        let mut goldens = Vec::with_capacity(intent.test.len());
        for test in &intent.test {
            goldens.push(self.generate_test(test).await?);
        }
        Ok(goldens)
    }

    /// Generate a single golden test case.
    pub async fn generate_test(&self, test: &TestIntent) -> Result<Golden, Error> {
        // Check if this is an error test expecting genesis-time failure
        let expected_error = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .cloned();

        // Create Principal from genesis keys
        let principal_result =
            self.create_principal(&test.principal, test.setup.as_ref(), &test.name);

        // Genesis-time errors (an unsupported algorithm, a revoked key)
        // are the vector when the test declares them.
        let mut principal = match principal_result.await {
            Ok(p) => p,
            Err(e) => return self.genesis_error_golden(test, expected_error, e),
        };
        if let Err(e) = self.commit_generated_genesis(test, &mut principal).await {
            // A misplaced `principal/create` is a defect of the intent; it
            // must not be emitted as a stub vector.
            if matches!(e, Error::InvalidIntent { .. }) {
                return Err(e);
            }
            return self.genesis_error_golden(test, expected_error, e);
        }
        if let (true, Some(declared)) = (test.is_genesis_only(), &expected_error) {
            return Err(Error::InvalidIntent {
                message: format!(
                    "test '{}': declares {declared}, but its genesis succeeds and it has nothing \
                     else to refuse",
                    test.name
                ),
            });
        }

        if let Some(peer) = &test.peer {
            return self.generate_pair(test, peer, principal).await;
        }

        // Dispatch based on test type
        if test.is_genesis_only() {
            self.generate_genesis_only(test, &principal)
        } else if test.has_tx_and_action() {
            // Combined: commits + actions
            self.generate_tx_and_action(test, &mut principal).await
        } else if test.has_action() {
            if test.action.len() > 1 {
                self.generate_multi_action(test, &mut principal)
            } else {
                self.generate_single_action(test, &mut principal)
            }
        } else if test.commit.len() > 1 {
            self.generate_multi_commit(test, &mut principal).await
        } else {
            self.generate_single_commit(test, &mut principal).await
        }
    }

    /// The vector of a test whose genesis fails with `e`: an error vector
    /// when the test declares that error -- checked against the error
    /// genesis actually raised, so a wrong declared expectation fails
    /// generation loudly instead of shipping a fixture that encodes it --
    /// and `e` itself otherwise.
    fn genesis_error_golden(
        &self,
        test: &TestIntent,
        declared: Option<String>,
        e: Error,
    ) -> Result<Golden, Error> {
        let Some(declared) = declared else {
            return Err(e);
        };
        if let Error::GenesisFailed { source, .. } = e {
            let actual = cyphr_error_name(&source);
            if declared != actual {
                return Err(Error::DeclaredErrorMismatch {
                    name: test.name.clone(),
                    declared,
                    actual,
                    source,
                });
            }
        }
        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys: None,
            commits: None,
            digests: None,
            peer: None,
            expected: GoldenExpected {
                error: Some(declared),
                ..Default::default()
            },
        })
    }

    /// Generate a two-principal test (a merge, SPEC 11.5.1): both
    /// principals commit their genesis, then the test principal's commits
    /// are signed, then the peer's, each resolving merge references
    /// against both PR histories so far. The vector states the
    /// `merge_status` of the test principal (source) into the peer
    /// (target).
    async fn generate_pair(
        &self,
        test: &TestIntent,
        peer: &PeerIntent,
        mut principal: cyphr::Principal,
    ) -> Result<Golden, Error> {
        let peer_test = TestIntent {
            name: format!("{} (peer)", test.name),
            principal: peer.principal.clone(),
            commit: peer.commit.clone(),
            ..TestIntent::default()
        };
        let mut other = self
            .create_principal(&peer.principal, None, &peer_test.name)
            .await?;
        self.commit_generated_genesis(&peer_test, &mut other)
            .await?;
        if peer.embedded {
            return self.generate_embedded(test, peer, principal, other).await;
        }

        self.refs.borrow_mut().other = pr_history(&other);
        for commit in &test.commit {
            let pre = Self::format_pr_tagged(&principal)?;
            self.sign_and_apply_commit(&test.name, commit, &mut principal, &pre)
                .await?;
        }
        self.refs.borrow_mut().other = pr_history(&principal);
        for commit in &peer.commit {
            let pre = Self::format_pr_tagged(&other)?;
            self.sign_and_apply_commit(&peer_test.name, commit, &mut other, &pre)
                .await?;
        }

        let status = format!("{:?}", cyphr::merge_status(&principal, &other));
        let mut expected = self.build_expected_from_principal(&principal, test.expected.as_ref());
        if let Some(declared) = test.expected.as_ref().and_then(|e| e.merge_status.as_ref())
            && *declared != status
        {
            return Err(Error::InvalidIntent {
                message: format!(
                    "test '{}': declares merge_status {declared}, the chains give {status}",
                    test.name
                ),
            });
        }
        expected.merge_status = Some(status);
        let (commits, digests) = Self::export_principal_commits(&principal)?;
        let (peer_commits, _) = Self::export_principal_commits(&other)?;
        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: None,
            genesis_keys: self.build_genesis_keys(&test.principal).ok(),
            commits: Some(commits),
            digests: Some(digests),
            peer: Some(GoldenPeer {
                principal: peer.principal.clone(),
                commits: peer_commits,
                embedded: false,
            }),
            expected,
        })
    }

    /// Generate a test whose peer is embedded in the test principal (SPEC
    /// 10.3): the peer's commits are signed first, every PR it held is
    /// pinned on the test principal to the peer's tip, then the test
    /// principal's commits are signed, a `peer:<n>` id naming the peer.
    async fn generate_embedded(
        &self,
        test: &TestIntent,
        peer: &PeerIntent,
        mut principal: cyphr::Principal,
        mut other: cyphr::Principal,
    ) -> Result<Golden, Error> {
        let peer_name = format!("{} (peer)", test.name);
        for commit in &peer.commit {
            let pre = Self::format_pr_tagged(&other)?;
            self.sign_and_apply_commit(&peer_name, commit, &mut other, &pre)
                .await?;
        }
        let held = pr_history(&other);
        for pr in &held {
            let tip = cyphr::Tip::new(&other, 0);
            principal
                .reveal_embedded(pr, cyphr::Tracking::Pin(Box::new(tip)))
                .map_err(|e| Error::Generation {
                    name: test.name.clone(),
                    reason: format!("pin peer PR {pr}: {e}"),
                })?;
        }
        self.refs.borrow_mut().other = held;
        for commit in &test.commit {
            let pre = Self::format_pr_tagged(&principal)?;
            self.sign_and_apply_commit(&test.name, commit, &mut principal, &pre)
                .await?;
        }
        let expected = self.build_expected_from_principal(&principal, test.expected.as_ref());
        let (commits, digests) = Self::export_principal_commits(&principal)?;
        let (peer_commits, _) = Self::export_principal_commits(&other)?;
        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: None,
            genesis_keys: self.build_genesis_keys(&test.principal).ok(),
            commits: Some(commits),
            digests: Some(digests),
            peer: Some(GoldenPeer {
                principal: peer.principal.clone(),
                commits: peer_commits,
                embedded: true,
            }),
            expected,
        })
    }

    /// Convert SetupIntent to GoldenSetup for output.
    fn setup_to_golden(setup: &Option<SetupIntent>) -> Option<GoldenSetup> {
        setup.as_ref().map(|s| GoldenSetup {
            revoke_key: s.revoke_key.clone(),
            revoke_at: s.revoke_at,
        })
    }

    /// Commit the genesis a test's intent does not state itself (SPEC 5.1,
    /// 5.2, 5.3): the first listed key, the genesis key, creates itself and
    /// every further listed key, signs the `principal/create` and the
    /// `commit/create`.
    ///
    /// Every commit chain begins with a genesis commit, so a test that
    /// commits gets one first, and a principal of more than one key
    /// (Level 3+) exists only through one. A single-key principal that
    /// never commits stays at Level 1/2 and has none. An intent states its
    /// own genesis by carrying the `principal/create` in its first commit
    /// (to pin a genesis rule), and then lists only its genesis key: every
    /// further key enters by a `key/create` the intent states. A
    /// `principal/create` in any later commit would need a commit before
    /// the genesis, which does not exist. The exception is an error test
    /// whose last commit holds the `principal/create`: that is a repeat of
    /// the genesis generated here, dated one second before it.
    async fn commit_generated_genesis(
        &self,
        test: &TestIntent,
        principal: &mut cyphr::Principal,
    ) -> Result<(), Error> {
        let invalid = |why: &str| Error::InvalidIntent {
            message: format!("test '{}': {why}", test.name),
        };
        let creates = |c: &CommitIntent| {
            c.tx.iter()
                .flatten()
                .any(|t| t.typ.ends_with(cyphr::parsed_coz::typ::PRINCIPAL_CREATE))
        };
        // An error test whose last commit holds the `principal/create` is a
        // repeat of the genesis generated here, which `failing_commit`
        // signs and the core refuses (SPEC 7.6: DUPLICATE).
        let declares_error = test.expected.as_ref().is_some_and(|e| e.error.is_some());
        let repeats_genesis = |i: usize| declares_error && i + 1 == test.commit.len();
        let mut repeat = false;
        match test.commit.iter().position(creates) {
            Some(i) if repeats_genesis(i) && (i > 0 || test.principal.len() > 1) => repeat = true,
            Some(0) if test.principal.len() > 1 => {
                return Err(invalid(
                    "an intent stating its own genesis lists only the genesis key",
                ));
            },
            Some(0) => return Ok(()),
            Some(_) => {
                return Err(invalid(
                    "principal/create must be in the first commit (SPEC 5.1)",
                ));
            },
            None if test.commit.is_empty() && test.principal.len() < 2 => return Ok(()),
            None => {},
        }
        // Every later coz keeps a `now` at or after the genesis's.
        let now = test
            .commit
            .iter()
            .flat_map(|c| c.tx.iter().flatten().map(|t| t.now))
            .chain(test.action.iter().map(|a| a.now))
            .min()
            .unwrap_or(GENESIS_NOW)
            // A repeat dated with the genesis would be the genesis's own coz
            // again and be refused as `CozReuse` before its own defect.
            - i64::from(repeat);
        let genesis = test
            .principal
            .first()
            .ok_or_else(|| invalid("no genesis key"))?;
        let signer = self.resolve_key(genesis)?.software_signer()?;
        let others = test.principal[1..]
            .iter()
            .map(|name| self.genesis_key(name, test.setup.as_ref(), &test.name))
            .collect::<Result<Vec<_>, _>>()?;
        principal
            .commit_genesis(&signer, &others, now, "cyphr.me")
            .await
            .map_err(|source| Error::GenesisFailed {
                name: test.name.clone(),
                source,
            })?;
        Ok(())
    }

    /// Sign the cozies of an error test's last commit and apply them
    /// transaction by transaction until one is refused; return its
    /// transactions through the refused one. The refusal is what the vector
    /// pins, so cozies after it are never reached: a coz refused at
    /// verification ends its transaction there, a transaction refused whole
    /// (its cozies do not share one `typ`, SPEC 4.1) is returned whole. A
    /// one-coz commit returns that coz (a refusal the test declares may come
    /// at finalize or replay instead).
    fn failing_commit(
        &self,
        test: &TestIntent,
        commit: &CommitIntent,
        principal: &mut cyphr::Principal,
        pre: &str,
    ) -> Result<Vec<Vec<GoldenCoz>>, Error> {
        self.refs.borrow_mut().own = pr_history(principal);
        let mut scope = principal.begin_commit();
        let mut txs = Vec::new();
        let mut first = true;
        for group in &commit.tx {
            let mut cozies = Vec::new();
            let mut verified = Vec::new();
            let mut refused = false;
            for tx in group {
                let tx = match test.override_.as_ref().and_then(|o| o.now) {
                    Some(now) if first => TxIntent { now, ..tx.clone() },
                    _ => tx.clone(),
                };
                first = false;
                let own_pr =
                    Self::derived_id(&scope, &tx.typ, pre).map_err(|e| Error::Generation {
                        name: test.name.clone(),
                        reason: format!("{} id: {e}", tx.typ),
                    })?;
                let (coz, sig, czd) = self.build_golden_coz(&tx, &test.name, Some(&own_pr))?;
                // A key the core cannot hold (an unsupported algorithm) is
                // itself the refusal the vector pins.
                let new_key = match (&coz.key, &tx.target) {
                    (Some(_), Some(target)) => {
                        match self.pool_key_to_cyphr_key(target, &test.name) {
                            Ok(key) => Some(key),
                            Err(_) => {
                                cozies.push(coz);
                                refused = true;
                                break;
                            },
                        }
                    },
                    _ => None,
                };
                let pay = coz.pay.get().as_bytes().to_vec();
                cozies.push(coz);
                match scope.verify(&pay, &sig, czd, new_key) {
                    Ok(v) => verified.push(v),
                    Err(_) => {
                        refused = true;
                        break;
                    },
                }
            }
            refused = refused || scope.apply_tx(verified).is_err();
            txs.push(cozies);
            if refused {
                break;
            }
        }
        Ok(txs)
    }

    /// The `id` a coz of kind `typ` names when the intent states none: a
    /// `principal/create` names the future SR (SPEC 5.1 step 3), a
    /// `ds/create` MR over the actions recorded (SPEC 4.8.2), and the lifecycle
    /// transactions the PR `pre` before the commit.
    fn derived_id(
        scope: &cyphr::CommitScope<'_>,
        typ: &str,
        pre: &str,
    ) -> cyphr::error::Result<String> {
        use cyphr::parsed_coz::typ::{DS_CREATE, PRINCIPAL_CREATE, has_suffix};

        if has_suffix(typ, PRINCIPAL_CREATE) {
            scope.genesis_id()
        } else if has_suffix(typ, DS_CREATE) {
            Ok(scope.data_tree_id()?.unwrap_or_else(|| pre.to_string()))
        } else {
            Ok(pre.to_string())
        }
    }

    /// Build genesis_keys from pool key names.
    fn build_genesis_keys(&self, key_names: &[String]) -> Result<Vec<GoldenKey>, Error> {
        key_names
            .iter()
            .map(|name| {
                let pool_key = self.resolve_key(name)?;
                Ok(GoldenKey {
                    alg: pool_key.alg.clone(),
                    pub_key: pool_key.pub_key.clone(),
                    tmb: pool_key.compute_tmb_b64()?,
                })
            })
            .collect()
    }

    /// Export commits from Principal using cyphr-storage export logic.
    /// Returns commits as Vec<CommitEntry> and digests as Vec<String>.
    ///
    /// Each CommitEntry contains:
    /// - cozies: array of cozies in commit (with pay, sig, key? fields)
    /// - tr: Commit ID digest (base64url)
    /// - as: Auth State digest (base64url)
    /// - sr: State Root digest (base64url)
    /// - pr: Principal State digest (base64url)
    ///
    /// Actions travel in the export itself, each on its own line where it
    /// was recorded; their digests follow the cozies' here.
    fn export_principal_commits(
        principal: &cyphr::Principal,
    ) -> Result<(Vec<CommitEntry>, Vec<String>), Error> {
        use cyphr_storage::export_commits;

        let commits = export_commits(principal).map_err(|e| Error::Generation {
            name: String::new(),
            reason: format!("export_commits failed: {}", e),
        })?;

        // Compute digests from cozies and actions
        let mut digests = Vec::new();
        for cz in principal.iter_all_cozies() {
            digests.push(cz.czd().to_b64());
        }

        for action in principal.actions() {
            digests.push(action.czd().to_b64());
        }

        Ok((commits, digests))
    }

    /// The commit entry of an error test's failing transactions: each coz
    /// `{pay, sig}`, grouped as signed, with the keys they introduce at
    /// commit level. Its state digests are placeholders, as the commit never
    /// formed.
    fn cozies_to_commit_entry(txs: &[Vec<GoldenCoz>]) -> Result<CommitEntry, Error> {
        let mut keys = Vec::new();
        let mut entry_txs = Vec::with_capacity(txs.len());
        for tx in txs {
            let mut cozies = Vec::with_capacity(tx.len());
            for coz in tx {
                cozies.push(Self::coz_value(coz)?);
                keys.extend(coz.key.as_ref().map(|k| KeyEntry {
                    alg: k.alg.clone(),
                    pub_key: k.pub_key.clone(),
                    tmb: k.tmb.clone(),
                    tag: None,
                    now: None,
                }));
            }
            entry_txs.push(cozies);
        }
        Ok(CommitEntry {
            txs: entry_txs,
            keys,
            ..CommitEntry::default()
        })
    }

    /// The action-only entry of an error test's refused data action.
    fn action_to_entry(coz: &GoldenCoz) -> Result<CommitEntry, Error> {
        Ok(CommitEntry {
            actions: vec![Self::coz_value(coz)?],
            ..CommitEntry::default()
        })
    }

    /// A golden coz as its `{pay, sig}` wire value.
    fn coz_value(coz: &GoldenCoz) -> Result<Value, Error> {
        let pay: Value = serde_json::from_str(coz.pay.get()).map_err(|e| Error::Generation {
            name: String::new(),
            reason: format!("failing coz pay is not JSON: {e}"),
        })?;
        Ok(serde_json::json!({ "pay": pay, "sig": coz.sig }))
    }

    /// Create a Principal from its genesis key, the first of `key_names`
    /// (SPEC 5.1 step 1). Every further key enters by `key/create`: the
    /// generated genesis commit's, or the intent's own.
    async fn create_principal(
        &self,
        key_names: &[String],
        setup: Option<&SetupIntent>,
        test_name: &str,
    ) -> Result<cyphr::Principal, Error> {
        let genesis = key_names.first().ok_or_else(|| Error::InvalidIntent {
            message: format!("test '{}': principal requires at least one key", test_name),
        })?;
        let key = self.genesis_key(genesis, setup, test_name)?;
        cyphr::Principal::implicit(key)
            .await
            .map_err(|source| Error::GenesisFailed {
                name: test_name.to_string(),
                source,
            })
    }

    /// A key genesis is given: the pool key `name`, carrying a revocation
    /// when `setup` names it revoked at genesis.
    fn genesis_key(
        &self,
        name: &str,
        setup: Option<&SetupIntent>,
        test_name: &str,
    ) -> Result<cyphr::Key, Error> {
        let key = self.pool_key_to_cyphr_key(name, test_name)?;
        Ok(match setup {
            Some(s) if s.revoke_key.as_deref() == Some(name) => {
                key.with_revocation(cyphr::key::Revocation {
                    rvk: s.revoke_at.unwrap_or(0),
                    by: None,
                })
            },
            _ => key,
        })
    }

    /// Convert a pool key name to a cyphr::Key.
    fn pool_key_to_cyphr_key(&self, name: &str, test_name: &str) -> Result<cyphr::Key, Error> {
        let pool_key = self.resolve_key(name)?;
        let tmb = pool_key.compute_tmb()?;
        let pub_bytes = Base64UrlUnpadded::decode_vec(&pool_key.pub_key).map_err(|e| {
            Error::PoolValidation {
                message: format!("key '{}': invalid pub base64: {}", name, e),
            }
        })?;

        // The constructor refuses an unknown alg or a tmb that is not the
        // pub's thumbprint; surface that as the test's genesis failure so a
        // declared `expected.error` is still checked against it.
        let key = cyphr::Key::new(pool_key.alg.clone(), tmb, pub_bytes).map_err(|source| {
            Error::GenesisFailed {
                name: test_name.to_string(),
                source,
            }
        })?;
        Ok(key.with_tag(pool_key.tag.clone()))
    }

    /// Build a `CozSignerInfo` (alg, prv, pub, tmb_b64, now) for `name`, for
    /// use as a candidate signer of a commit's terminal `commit/create` coz.
    fn signer_info_for(&self, name: &str, now: i64) -> Result<CozSignerInfo, Error> {
        let key = self.resolve_key(name)?;
        let tmb_b64 = key.compute_tmb_b64()?;
        let prv_b64 = key.prv.as_ref().ok_or_else(|| Error::MissingPrivateKey {
            name: key.name.clone(),
        })?;
        let prv_bytes =
            Base64UrlUnpadded::decode_vec(prv_b64).map_err(|e| Error::PoolValidation {
                message: format!("key '{}': invalid prv base64: {}", name, e),
            })?;
        let pub_bytes =
            Base64UrlUnpadded::decode_vec(&key.pub_key).map_err(|e| Error::PoolValidation {
                message: format!("key '{}': invalid pub base64: {}", name, e),
            })?;
        Ok((key.alg.clone(), prv_bytes, pub_bytes, tmb_b64, now))
    }

    /// Choose which candidate should sign a commit's terminal `commit/create`
    /// coz: the commit's first coz signer, unless that signer's key was
    /// itself retired by a later mutation in the same commit (e.g. a
    /// `key/replace` or self-revoke of the commit's own first signer) — in
    /// which case the most-recently-introduced new key (guaranteed active)
    /// is used instead. Falls back to the first signer if no later key was
    /// introduced, unchanged from previous behavior.
    fn choose_commit_signer(
        scope: &cyphr::CommitScope<'_>,
        first_coz_signer: Option<CozSignerInfo>,
        last_new_key_signer: Option<CozSignerInfo>,
    ) -> Option<CozSignerInfo> {
        let first_still_active = first_coz_signer
            .as_ref()
            .is_some_and(|(_, _, _, tmb_b64, _)| {
                Base64UrlUnpadded::decode_vec(tmb_b64)
                    .ok()
                    .map(coz::Thumbprint::from_bytes)
                    .is_some_and(|tmb| scope.is_key_active(&tmb))
            });

        if first_still_active {
            first_coz_signer
        } else {
            last_new_key_signer.or(first_coz_signer)
        }
    }

    /// Sign and apply every transaction of `commit_intent` to a
    /// freshly-opened `CommitScope` on `principal`, each as one transaction
    /// (its cozies verified against the state it meets, then applied
    /// together, SPEC 4.1, 4.6.2), then finalize with the terminal
    /// `commit/create` (Arrow) cozy per `choose_commit_signer`.
    ///
    /// `pre` is the Principal Root captured before this commit began (used
    /// only for a `principal/create` cozy's `id` field).
    ///
    /// Returns the base64 czd of each applied cozy, in application order.
    async fn sign_and_apply_commit(
        &self,
        test_name: &str,
        commit_intent: &CommitIntent,
        principal: &mut cyphr::Principal,
        pre: &str,
    ) -> Result<Vec<String>, Error> {
        self.refs.borrow_mut().own = pr_history(principal);
        let mut scope = principal.begin_commit();
        let mut first_coz_signer: Option<CozSignerInfo> = None;
        let mut last_new_key_signer: Option<CozSignerInfo> = None;
        let mut czds = Vec::new();
        let mut latest_now = i64::MIN;

        for tx_group in &commit_intent.tx {
            let mut verified = Vec::with_capacity(tx_group.len());
            for tx_cz in tx_group {
                let signer = self.resolve_key(&tx_cz.signer)?;
                let signer_tmb = signer.compute_tmb_b64()?;
                let prv_b64 = signer
                    .prv
                    .as_ref()
                    .ok_or_else(|| Error::MissingPrivateKey {
                        name: signer.name.clone(),
                    })?;
                let prv_bytes =
                    Base64UrlUnpadded::decode_vec(prv_b64).map_err(|e| Error::Generation {
                        name: test_name.to_string(),
                        reason: format!("invalid prv base64: {}", e),
                    })?;
                let pub_bytes = Base64UrlUnpadded::decode_vec(&signer.pub_key).map_err(|e| {
                    Error::Generation {
                        name: test_name.to_string(),
                        reason: format!("invalid pub base64: {}", e),
                    }
                })?;

                // Build pay value for this cozy. The derived `id` matters
                // only to the kinds whose `id` names a state (see
                // `derived_id`); other cozy types ignore it.
                let own_pr =
                    Self::derived_id(&scope, &tx_cz.typ, pre).map_err(|e| Error::Generation {
                        name: test_name.to_string(),
                        reason: format!("{} id: {e}", tx_cz.typ),
                    })?;
                let pay_value =
                    self.build_pay_value(tx_cz, &signer.alg, &signer_tmb, Some(&own_pr))?;
                let pay_vec = serde_json::to_vec(&pay_value).map_err(|e| Error::Generation {
                    name: test_name.to_string(),
                    reason: e.to_string(),
                })?;

                let (sig_bytes, cad) =
                    coz::sign_json(&pay_vec, &signer.alg, &prv_bytes, &pub_bytes).unwrap();
                let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer.alg).unwrap();

                let new_key = if (tx_cz.typ.ends_with("key/create")
                    || tx_cz.typ.ends_with("key/replace"))
                    && let Some(target_name) = tx_cz.target.as_ref()
                {
                    // The new key is only a fallback-signer candidate (see
                    // choose_commit_signer) if the pool holds its private half;
                    // a public-only pool key (simulating an externally-held key)
                    // simply can't ever sign, so leave last_new_key_signer unset.
                    match self.signer_info_for(target_name, tx_cz.now) {
                        Ok(info) => last_new_key_signer = Some(info),
                        Err(Error::MissingPrivateKey { .. }) => {},
                        Err(e) => return Err(e),
                    }
                    Some(self.pool_key_to_cyphr_key(target_name, test_name)?)
                } else {
                    None
                };

                verified.push(
                    scope
                        .verify(&pay_vec, &sig_bytes, czd.clone(), new_key)
                        .map_err(|e| Error::Generation {
                            name: test_name.to_string(),
                            reason: format!("failed to verify cozy: {}", e),
                        })?,
                );

                czds.push(czd.to_b64());
                latest_now = latest_now.max(tx_cz.now);

                if first_coz_signer.is_none() {
                    first_coz_signer = Some((
                        signer.alg.clone(),
                        prv_bytes,
                        pub_bytes,
                        signer_tmb,
                        tx_cz.now,
                    ));
                }
            }
            scope.apply_tx(verified).map_err(|e| Error::Generation {
                name: test_name.to_string(),
                reason: format!("failed to apply transaction: {}", e),
            })?;
        }

        // Finalize the commit scope using the first signer's credentials, unless that
        // signer's key was itself retired within this commit (see choose_commit_signer).
        let (alg, prv, pub_k, tmb_str, coz_now) =
            Self::choose_commit_signer(&scope, first_coz_signer, last_new_key_signer).ok_or_else(
                || Error::InvalidIntent {
                    message: format!("test '{}': no cozies applied", test_name),
                },
            )?;
        let tmb = coz::Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(&tmb_str).unwrap());
        scope
            .finalize_with_software(
                &cyphr::signer::SoftwareSigner::new(&alg, &prv, &pub_k, &tmb),
                // The commit/create comes last, so no earlier than any coz
                // of the commit (SPEC 14.1).
                coz_now.max(latest_now),
                "cyphr.me",
            )
            .await
            .map_err(|e| Error::Generation {
                name: test_name.to_string(),
                reason: format!("failed to finalize commit: {}", e),
            })?;

        Ok(czds)
    }

    /// Generate a single-commit golden test case.
    async fn generate_single_commit(
        &self,
        test: &TestIntent,
        principal: &mut cyphr::Principal,
    ) -> Result<Golden, Error> {
        let is_empty_commit = test
            .override_
            .as_ref()
            .is_some_and(|o| o.empty_commit.unwrap_or(false));

        if is_empty_commit {
            let expected = self.build_expected_from_principal(principal, test.expected.as_ref());
            let genesis_keys = self.build_genesis_keys(&test.principal).ok();
            let (mut commits, digests) = Self::export_principal_commits(principal)?;

            commits.push(crate::CommitEntry::default());

            return Ok(Golden {
                name: test.name.clone(),
                principal: test.principal.clone(),
                setup: Self::setup_to_golden(&test.setup),
                genesis_keys,
                commits: Some(commits),
                digests: Some(digests),
                peer: None,
                expected,
            });
        }

        if test
            .commit
            .first()
            .and_then(|c| c.tx.first())
            .and_then(|t| t.first())
            .is_none()
        {
            return Err(Error::InvalidIntent {
                message: format!(
                    "test '{}': single-commit test requires at least one coz",
                    test.name
                ),
            });
        }

        // Check if this is an error test
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        // Capture the current PR (used only for principal/create's `id` field).
        let current_pr = Self::format_pr_tagged(principal)?;

        // override.now (TimestampPast tests) applies to the failing commit's
        // first coz; see failing_commit.
        let commit_intent = test.commit.first().ok_or_else(|| Error::InvalidIntent {
            message: format!(
                "test '{}': single-commit test requires at least one commit",
                test.name
            ),
        })?;
        let regroup = test
            .override_
            .as_ref()
            .is_some_and(|o| o.regroup.unwrap_or(false));
        let mut regrouped = None;
        let failing = if is_error_test && regroup {
            regrouped = Some(
                self.regrouped_commit(&test.name, commit_intent, principal, &current_pr)
                    .await?,
            );
            Vec::new()
        } else if is_error_test {
            // Error tests: sign manually — CommitScope would reject invalid payloads.
            // We need valid signatures over intentionally bad data.
            self.failing_commit(test, commit_intent, principal, &current_pr)?
        } else {
            self.sign_and_apply_commit(&test.name, commit_intent, principal, &current_pr)
                .await?;
            Vec::new()
        };

        // Build expected with computed state digests (or error)
        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        // For error tests, the failing cozies were not committed - add them
        let (mut commits, mut digests) = Self::export_principal_commits(principal)?;
        if let Some((entry, czds)) = regrouped {
            commits.push(entry);
            digests.extend(czds);
        } else if is_error_test {
            commits.push(Self::cozies_to_commit_entry(&failing)?);
            digests.extend(failing.iter().flatten().map(|c| c.czd.clone()));
        }

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            peer: None,
            expected,
        })
    }

    /// A finalized commit emitted regrouped: the intent's cozies are signed
    /// and finalized as separate transactions on a fork (so the commit
    /// transaction and arrow are real), then every mutation coz is moved into
    /// one transaction, the commit transaction last. The principal itself is
    /// left at its state before the commit, as for any error vector.
    async fn regrouped_commit(
        &self,
        test_name: &str,
        commit: &CommitIntent,
        principal: &cyphr::Principal,
        pre: &str,
    ) -> Result<(CommitEntry, Vec<String>), Error> {
        let split = CommitIntent {
            tx: commit
                .tx
                .iter()
                .flatten()
                .map(|c| vec![c.clone()])
                .collect(),
        };
        let mut forked = principal.fork().await.map_err(|e| Error::Generation {
            name: test_name.to_string(),
            reason: format!("fork failed: {e}"),
        })?;
        self.sign_and_apply_commit(test_name, &split, &mut forked, pre)
            .await?;
        let (mut commits, _) = Self::export_principal_commits(&forked)?;
        let mut entry = commits.pop().ok_or_else(|| Error::Generation {
            name: test_name.to_string(),
            reason: "regroup: the finalized commit did not export".to_string(),
        })?;
        let closing = entry.txs.pop().ok_or_else(|| Error::Generation {
            name: test_name.to_string(),
            reason: "regroup: the commit has no transactions".to_string(),
        })?;
        let group: Vec<Value> = entry.txs.drain(..).flatten().collect();
        entry.txs = vec![group, closing];
        let czds = forked
            .commits()
            .last()
            .map(|c| {
                c.transactions()
                    .iter()
                    .flat_map(|tx| tx.0.iter().map(|cz| cz.czd().to_b64()))
                    .collect()
            })
            .unwrap_or_default();
        Ok((entry, czds))
    }

    /// Generate a multi-commit golden test case.
    async fn generate_multi_commit(
        &self,
        test: &TestIntent,
        principal: &mut cyphr::Principal,
    ) -> Result<Golden, Error> {
        let mut failing = Vec::new();

        // Check if this is an error test (applies to last commit)
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        let commit_count = test.commit.len();
        for (i, commit) in test.commit.iter().enumerate() {
            let is_last_commit = i == commit_count - 1;
            if commit.tx.first().and_then(|t| t.first()).is_none() {
                return Err(Error::InvalidIntent {
                    message: format!("test '{}': commit {} has no cozies", test.name, i + 1),
                });
            }

            // Capture pre before this commit (alg:digest format)
            let pre = Self::format_pr_tagged(principal)?;

            if is_last_commit && is_error_test {
                // Error tests: sign last commit manually
                failing = self
                    .failing_commit(test, commit, principal, &pre)
                    .map_err(|e| Error::Generation {
                        name: test.name.clone(),
                        reason: format!("commit {}: {}", i + 1, e),
                    })?;
            } else {
                // Happy path: apply all cozies in all transactions of the commit
                self.sign_and_apply_commit(&test.name, commit, principal, &pre)
                    .await?;
            }
        }

        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        // For error tests, we need to combine exported entries with the failing entry
        let (mut commits, mut digests) = Self::export_principal_commits(principal)?;
        if is_error_test {
            // The last commit was not applied - add its failing cozies
            commits.push(Self::cozies_to_commit_entry(&failing)?);
            digests.extend(failing.iter().flatten().map(|c| c.czd.clone()));
        }

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            peer: None,
            expected,
        })
    }

    /// Generate a genesis-only test case (no cozies or actions of its own).
    fn generate_genesis_only(
        &self,
        test: &TestIntent,
        principal: &cyphr::Principal,
    ) -> Result<Golden, Error> {
        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Genesis-only: the generated genesis commit, if any (Level 3+).
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();
        let (commits, digests) = Self::export_principal_commits(principal)?;

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            peer: None,
            expected,
        })
    }

    /// Generate a combined commit + action test case.
    ///
    /// Commits and actions are merged into one timeline and applied in
    /// chronological order (by each event's first `now` timestamp), matching
    /// the order in the exported golden fixture.
    async fn generate_tx_and_action(
        &self,
        test: &TestIntent,
        principal: &mut cyphr::Principal,
    ) -> Result<Golden, Error> {
        enum TimelineEvent<'a> {
            Commit(&'a CommitIntent),
            Action(&'a ActionIntent),
        }

        impl TimelineEvent<'_> {
            fn timestamp(&self) -> i64 {
                match self {
                    TimelineEvent::Commit(c) => {
                        c.tx.first()
                            .and_then(|t| t.first())
                            .map(|cz| cz.now)
                            .unwrap_or(0)
                    },
                    TimelineEvent::Action(a) => a.now,
                }
            }
        }

        let mut timeline = Vec::new();
        for commit in &test.commit {
            timeline.push(TimelineEvent::Commit(commit));
        }
        for action in &test.action {
            timeline.push(TimelineEvent::Action(action));
        }
        // Stable sort to maintain relative order if timestamps are identical
        timeline.sort_by_key(|event| event.timestamp());

        let mut digests = Vec::new();
        let mut action_entries = Vec::new();
        let mut failing = Vec::new();
        // An error test pins the refusal of its last event: a data action,
        // or a commit (signed coz by coz until one is refused).
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();
        let events = timeline.len();

        for (i, event) in timeline.into_iter().enumerate() {
            if let (true, true, TimelineEvent::Action(action_intent)) =
                (is_error_test, i + 1 == events, &event)
            {
                let (coz, _, czd) = self.build_action_coz(action_intent, None, &test.name)?;
                digests.push(czd.to_b64());
                action_entries.push(Self::action_to_entry(&coz)?);
                continue;
            }
            if let (true, true, TimelineEvent::Commit(commit_intent)) =
                (is_error_test, i + 1 == events, &event)
            {
                let pre = Self::format_pr_tagged(principal)?;
                failing = self.failing_commit(test, commit_intent, principal, &pre)?;
                continue;
            }
            match event {
                TimelineEvent::Commit(commit_intent) => {
                    // Apply all cozies in all transactions of the commit
                    let pre = Self::format_pr_tagged(principal)?;
                    let czds = self
                        .sign_and_apply_commit(&test.name, commit_intent, principal, &pre)
                        .await?;
                    digests.extend(czds);
                },
                TimelineEvent::Action(action_intent) => {
                    let action_pre = if test
                        .override_
                        .as_ref()
                        .and_then(|o| o.inject_pre)
                        .unwrap_or(false)
                    {
                        Some(Self::format_pr_tagged(principal)?)
                    } else {
                        None
                    };
                    let action_pre_ref = action_pre.as_deref();

                    let (_, action_sig_bytes, action_czd) =
                        self.build_action_coz(action_intent, action_pre_ref, &test.name)?;

                    // Apply action to principal
                    self.apply_action_to_principal(
                        principal,
                        action_intent,
                        action_pre_ref,
                        &action_sig_bytes,
                        action_czd.clone(),
                        &test.name,
                    )?;

                    digests.push(action_czd.to_b64());
                },
            }
        }

        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests using storage export logic
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        let mut commits =
            cyphr_storage::export_commits(principal).map_err(|e| Error::Generation {
                name: test.name.clone(),
                reason: format!("export_commits failed: {}", e),
            })?;

        // The refused action of an error test, which the export lacks.
        commits.extend(action_entries);
        if !failing.is_empty() {
            digests.extend(failing.iter().flatten().map(|c| c.czd.clone()));
            commits.push(Self::cozies_to_commit_entry(&failing)?);
        }

        // The export's order: every commit, then the actions, which hold
        // no chain position (SPEC 4.8.1); the refused event of an error
        // test last.

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            peer: None,
            expected,
        })
    }

    /// Generate a single-action test case (Level 4).
    fn generate_single_action(
        &self,
        test: &TestIntent,
        principal: &mut cyphr::Principal,
    ) -> Result<Golden, Error> {
        let action_intent = test.action.first().ok_or_else(|| Error::InvalidIntent {
            message: format!(
                "test '{}': single-action test requires [[action]]",
                test.name
            ),
        })?;

        let action_pre = if test
            .override_
            .as_ref()
            .and_then(|o| o.inject_pre)
            .unwrap_or(false)
        {
            Some(Self::format_pr_tagged(principal)?)
        } else {
            None
        };
        let action_pre_ref = action_pre.as_deref();

        let (action_coz, sig_bytes, czd) =
            self.build_action_coz(action_intent, action_pre_ref, &test.name)?;

        // Check if this is an error test
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        if !is_error_test {
            // Apply action to principal
            self.apply_action_to_principal(
                principal,
                action_intent,
                action_pre_ref,
                &sig_bytes,
                czd,
                &test.name,
            )?;
        }

        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        // For error tests, the action was not applied - add it manually
        let (mut commits, mut digests) = Self::export_principal_commits(principal)?;
        if is_error_test {
            commits.push(Self::action_to_entry(&action_coz)?);
            digests.push(action_coz.czd.clone());
        }

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            peer: None,
            expected,
        })
    }

    /// Generate a multi-action test case (Level 4).
    fn generate_multi_action(
        &self,
        test: &TestIntent,
        principal: &mut cyphr::Principal,
    ) -> Result<Golden, Error> {
        let mut action_sequence = Vec::with_capacity(test.action.len());

        // Check if this is an error test (applies to last action)
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        let action_count = test.action.len();
        for (i, action_intent) in test.action.iter().enumerate() {
            let is_last_action = i == action_count - 1;

            let action_pre = if is_last_action
                && is_error_test
                && test
                    .override_
                    .as_ref()
                    .and_then(|o| o.inject_pre)
                    .unwrap_or(false)
            {
                Some(Self::format_pr_tagged(principal)?)
            } else {
                None
            };
            let action_pre_ref = action_pre.as_deref();

            let (action_coz, sig_bytes, czd) = self
                .build_action_coz(action_intent, action_pre_ref, &test.name)
                .map_err(|e| Error::Generation {
                    name: test.name.clone(),
                    reason: format!("action {}: {}", i + 1, e),
                })?;

            // Apply action (skip last action for error tests)
            if !(is_last_action && is_error_test) {
                self.apply_action_to_principal(
                    principal,
                    action_intent,
                    action_pre_ref,
                    &sig_bytes,
                    czd,
                    &test.name,
                )
                .map_err(|e| Error::Generation {
                    name: test.name.clone(),
                    reason: format!("action {}: {}", i + 1, e),
                })?;
            }

            action_sequence.push(action_coz);
        }

        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        // For error tests, we need to combine exported entries with the failing entry
        let (mut commits, mut digests) = Self::export_principal_commits(principal)?;
        if is_error_test && !action_sequence.is_empty() {
            // The last action was not applied - add it from action_sequence
            let failing_coz = action_sequence.last().unwrap();
            commits.push(Self::action_to_entry(failing_coz)?);
            digests.push(failing_coz.czd.clone());
        }

        // A repeated submission of an applied action (SPEC 7.6: ignored, no
        // state change) leaves no trace in the principal's state, so the
        // export above omits it. Emit it so consumers replay the repeat and
        // the expected roots pin that it changed nothing.
        if !is_error_test {
            let mut seen = std::collections::HashSet::new();
            for coz in &action_sequence {
                if !seen.insert(coz.czd.clone()) {
                    commits.push(Self::action_to_entry(coz)?);
                    digests.push(coz.czd.clone());
                }
            }
        }

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            peer: None,
            expected,
        })
    }

    /// Build the pay JSON for an action (canonical field order).
    ///
    /// Shared by `build_action_coz` (for golden output) and
    /// `apply_action_to_principal` (for verification), ensuring
    /// identical bytes in both paths.
    fn build_action_pay_json(
        &self,
        action: &ActionIntent,
        pre: Option<&str>,
        test_name: &str,
    ) -> Result<Vec<u8>, Error> {
        let signer = self.resolve_key(&action.signer)?;
        let signer_tmb = signer.compute_tmb_b64()?;

        let mut pay_map: IndexMap<String, Value> = IndexMap::new();
        pay_map.insert("alg".to_string(), Value::String(signer.alg.clone()));
        if let Some(ref id) = action.id {
            pay_map.insert("id".to_string(), Value::String(id.clone()));
        }
        if let Some(ref msg) = action.msg {
            pay_map.insert("msg".to_string(), Value::String(msg.clone()));
        }
        pay_map.insert("now".to_string(), Value::Number(action.now.into()));

        // [data-action-no-pre] injection override
        if let Some(pre_val) = pre {
            pay_map.insert("pre".to_string(), Value::String(pre_val.to_string()));
        }

        pay_map.insert("tmb".to_string(), Value::String(signer_tmb));
        pay_map.insert("typ".to_string(), Value::String(action.typ.clone()));

        serde_json::to_vec(&pay_map).map_err(|e| Error::Generation {
            name: test_name.to_string(),
            reason: format!("failed to serialize action pay: {}", e),
        })
    }

    /// Build a GoldenCoz for an action.
    fn build_action_coz(
        &self,
        action: &ActionIntent,
        pre: Option<&str>,
        test_name: &str,
    ) -> Result<(GoldenCoz, Vec<u8>, coz::Czd), Error> {
        let pay_json = self.build_action_pay_json(action, pre, test_name)?;

        // Resolve signer for signing
        let signer = self.resolve_key(&action.signer)?;

        // Get private and public key bytes
        let prv = signer
            .prv
            .as_ref()
            .ok_or_else(|| Error::MissingPrivateKey {
                name: signer.name.clone(),
            })?;
        let prv_bytes = Base64UrlUnpadded::decode_vec(prv).map_err(|e| Error::Generation {
            name: test_name.to_string(),
            reason: format!("invalid prv base64: {}", e),
        })?;
        let pub_bytes =
            Base64UrlUnpadded::decode_vec(&signer.pub_key).map_err(|e| Error::Generation {
                name: test_name.to_string(),
                reason: format!("invalid pub base64: {}", e),
            })?;

        // Sign using coz
        let (sig_bytes, cad) = coz::sign_json(&pay_json, &signer.alg, &prv_bytes, &pub_bytes)
            .ok_or_else(|| Error::UnsupportedAlgorithm {
                alg: signer.alg.clone(),
            })?;

        // Compute czd = H(cad || sig)
        let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer.alg).ok_or_else(|| {
            Error::UnsupportedAlgorithm {
                alg: signer.alg.clone(),
            }
        })?;

        let sig_b64 = Base64UrlUnpadded::encode_string(&sig_bytes);
        let czd_b64 = Base64UrlUnpadded::encode_string(czd.as_bytes());

        let coz = GoldenCoz {
            // CRITICAL: Use pay_json bytes directly - these are the exact bytes that were signed
            pay: RawValue::from_string(
                String::from_utf8(pay_json).expect("pay_json is valid UTF-8"),
            )
            .unwrap(),
            sig: sig_b64,
            czd: czd_b64,
            key: None,
        };

        Ok((coz, sig_bytes, czd))
    }

    /// Apply an action to a principal.
    fn apply_action_to_principal(
        &self,
        principal: &mut cyphr::Principal,
        action: &ActionIntent,
        pre: Option<&str>,
        sig_bytes: &[u8],
        czd: coz::Czd,
        test_name: &str,
    ) -> Result<(), Error> {
        let pay_json = self.build_action_pay_json(action, pre, test_name)?;

        principal
            .verify_and_record_action(&pay_json, sig_bytes, czd)
            .map_err(|e| Error::Generation {
                name: test_name.to_string(),
                reason: format!("failed to apply action: {}", e),
            })?;

        Ok(())
    }

    /// Build a GoldenCoz from a coz intent.
    ///
    /// Returns the GoldenCoz plus raw sig bytes and czd for applying to Principal.
    fn build_golden_coz(
        &self,
        cz: &TxIntent,
        test_name: &str,
        current_pr: Option<&str>,
    ) -> Result<(GoldenCoz, Vec<u8>, coz::Czd), Error> {
        // Resolve signer
        let signer = self.resolve_key(&cz.signer)?;

        // Build pay JSON with derived fields
        let pay_json =
            self.build_pay_json(cz, &signer.alg, &signer.compute_tmb_b64()?, current_pr)?;

        // Sign the message
        let (sig_b64, sig_bytes, czd_b64, czd, embedded_key) =
            self.sign_pay(&pay_json, signer, cz, test_name)?;

        let coz = GoldenCoz {
            pay: serde_json::from_slice(&pay_json).map_err(|e| Error::Generation {
                name: test_name.to_string(),
                reason: format!("invalid pay JSON: {}", e),
            })?,
            sig: sig_b64,
            czd: czd_b64,
            key: embedded_key,
        };

        Ok((coz, sig_bytes, czd))
    }

    /// Build the pay fields as a serde_json::Value (object).
    ///
    /// Returns the pay without `commit` field — CommitScope injects that.
    /// Per Coz spec, standard fields appear in canonical (alphabetic) order.
    ///
    /// `current_pr` is the Principal Root immediately before this cozy — it
    /// no longer appears on the wire as a `pre` field (only the closing
    /// `commit/create`'s `arrow` carries chain data), but `principal/create`
    /// still needs it to derive its `id` field (SPEC §5.1 step 3: `id` equals
    /// the future SR, which — absent a CR at this pre-commit point — is the
    /// same value as the current PR), since `principal/create` doesn't
    /// mutate state, only freezes PG.
    fn build_pay_value(
        &self,
        cz: &TxIntent,
        alg: &str,
        tmb: &str,
        current_pr: Option<&str>,
    ) -> Result<Value, Error> {
        let mut fields: IndexMap<String, Value> = IndexMap::new();

        // Standard fields in canonical order
        fields.insert("alg".to_string(), Value::String(alg.to_string()));

        // Canonical (alphabetic) order: `arrow` sorts right after `alg`.
        if let Some(arrow) = &cz.arrow {
            fields.insert("arrow".to_string(), Value::String(arrow.clone()));
        }

        // id field handling depends on coz type. principal/create and the
        // three lifecycle transactions (principal/delete, freeze/create,
        // freeze/delete) all target the signer's own PR rather than a
        // distinct key (SPEC §5.1, §11.4, §14.9).
        let targets_own_pr = cz.typ.contains("principal/create")
            || cz.typ.contains("principal/delete")
            || cz.typ.contains("freeze/create")
            || cz.typ.contains("freeze/delete")
            || cz.typ.contains("ds/create");
        if let Some(id) = &cz.id {
            // A stated `id`, for values no pool key's thumbprint can
            // express (e.g. a nonce of an off-by-one width, or a
            // `ds/create` naming a DR over actions this principal lacks).
            let id = match id.strip_prefix("peer:") {
                Some(_) => self.resolve_ref(id)?,
                None => id.clone(),
            };
            fields.insert("id".to_string(), Value::String(id));
        } else if targets_own_pr {
            let pr_val = current_pr.ok_or_else(|| Error::Generation {
                name: "build_pay_value".to_string(),
                reason: "this coz type requires its derived id".to_string(),
            })?;
            fields.insert("id".to_string(), Value::String(pr_val.to_string()));
        } else if let Some(target_name) = &cz.target {
            // For key/create etc, id is the target key thumbprint
            let target = self.resolve_key(target_name)?;
            let target_tmb = target.compute_tmb_b64()?;
            fields.insert("id".to_string(), Value::String(target_tmb));
        }

        // A merge's claim (SPEC 11.5.1), by reference.
        if let Some(from) = &cz.merge_from {
            let from = from
                .iter()
                .map(|r| self.resolve_ref(r).map(Value::String))
                .collect::<Result<Vec<_>, _>>()?;
            fields.insert("merge_from".to_string(), Value::Array(from));
        }
        if let Some(to) = &cz.merge_to_pr {
            fields.insert(
                "merge_to_pr".to_string(),
                Value::String(self.resolve_ref(to)?),
            );
        }

        // msg if present
        if let Some(msg) = &cz.msg {
            fields.insert("msg".to_string(), Value::String(msg.clone()));
        }

        // now (timestamp)
        fields.insert("now".to_string(), Value::Number(cz.now.into()));

        // rvk if present
        if let Some(rvk) = cz.rvk {
            fields.insert("rvk".to_string(), Value::Number(rvk.into()));
        }

        // tmb (signer thumbprint)
        fields.insert("tmb".to_string(), Value::String(tmb.to_string()));

        // typ (coz/action type)
        fields.insert("typ".to_string(), Value::String(cz.typ.clone()));

        serde_json::to_value(&fields).map_err(|e| Error::Signing {
            message: format!("failed to build pay value: {}", e),
        })
    }

    /// Build the pay JSON with correct field ordering.
    ///
    /// Per Coz spec, standard fields appear in canonical order.
    /// Thin wrapper over build_pay_value for paths that need raw bytes.
    fn build_pay_json(
        &self,
        cz: &TxIntent,
        alg: &str,
        tmb: &str,
        current_pr: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        let value = self.build_pay_value(cz, alg, tmb, current_pr)?;
        serde_json::to_vec(&value).map_err(|e| Error::Signing {
            message: format!("failed to serialize pay: {}", e),
        })
    }

    /// Sign the pay JSON and compute czd.
    ///
    /// Returns (sig_b64, sig_bytes, czd_b64, czd, embedded_key).
    fn sign_pay(
        &self,
        pay_json: &[u8],
        signer: &PoolKey,
        cz: &TxIntent,
        test_name: &str,
    ) -> SignResult {
        // Get private key bytes
        let prv_b64 = signer
            .prv
            .as_ref()
            .ok_or_else(|| Error::MissingPrivateKey {
                name: signer.name.clone(),
            })?;

        let prv_bytes = Base64UrlUnpadded::decode_vec(prv_b64).map_err(|e| Error::Generation {
            name: test_name.to_string(),
            reason: format!("invalid prv base64: {}", e),
        })?;

        let pub_bytes =
            Base64UrlUnpadded::decode_vec(&signer.pub_key).map_err(|e| Error::Generation {
                name: test_name.to_string(),
                reason: format!("invalid pub base64: {}", e),
            })?;

        // Sign using coz
        let (sig_bytes, cad) = coz::sign_json(pay_json, &signer.alg, &prv_bytes, &pub_bytes)
            .ok_or_else(|| Error::UnsupportedAlgorithm {
                alg: signer.alg.clone(),
            })?;

        // Compute czd = H(cad || sig)
        let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer.alg).ok_or_else(|| {
            Error::UnsupportedAlgorithm {
                alg: signer.alg.clone(),
            }
        })?;

        let sig_b64 = Base64UrlUnpadded::encode_string(&sig_bytes);
        let czd_b64 = Base64UrlUnpadded::encode_string(czd.as_bytes());

        // The key a key-introducing coz names, for the commit's `keys`
        // (SPEC 4.6.2); no other coz carries key material.
        let embedded_key = if let Some(target_name) = cz
            .target
            .as_ref()
            .filter(|_| cyphr::parsed_coz::typ::is_key_introducing(&cz.typ))
        {
            let target = self.resolve_key(target_name)?;
            Some(GoldenKey {
                alg: target.alg.clone(),
                pub_key: target.pub_key.clone(),
                tmb: target.compute_tmb_b64()?,
            })
        } else {
            None
        };

        Ok((sig_b64, sig_bytes, czd_b64, czd, embedded_key))
    }

    /// Resolve a key reference to a pool key.
    fn resolve_key(&self, name: &str) -> Result<&PoolKey, Error> {
        self.pool.get(name).ok_or_else(|| Error::KeyRef {
            name: name.to_string(),
        })
    }

    fn build_expected_from_principal(
        &self,
        principal: &cyphr::Principal,
        intent_expected: Option<&ExpectedAssertions>,
    ) -> GoldenExpected {
        // Get lexicographically first algorithm for deterministic ordering
        let first_alg = principal
            .active_algs()
            .first()
            .copied()
            .expect("Principal must have at least one active algorithm");

        // Compute state digests with algorithm prefix (alg:digest format).
        // KR and AR are absent for a Dead principal (SPEC 3.7).
        let kr = principal.key_root().map(|ks_state| {
            ks_state
                .get(first_alg)
                .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
                .unwrap_or_default()
        });
        let auth_root = principal.auth_root().map(|a| {
            a.get(first_alg)
                .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
                .unwrap_or_default()
        });
        let pr_val = principal
            .pr()
            .get(first_alg)
            .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
            .unwrap_or_default();
        let tr = principal.current_tr().and_then(|cid| {
            cid.get(first_alg)
                .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
        });
        let sr = principal.sr().map(|sr_val| {
            sr_val
                .get(first_alg)
                .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
                .unwrap_or_default()
        });
        let cr = principal.cr().and_then(|cr_val| {
            cr_val
                .get(first_alg)
                .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
        });
        let dr = principal
            .data_root()
            .and_then(|d| d.0.get(first_alg).map(Base64UrlUnpadded::encode_string));
        let pg = principal
            .pg()
            .and_then(|pg_val| pg_val.get(first_alg))
            .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
            .unwrap_or_default();
        let level = principal.level() as u8;
        let key_count = principal.active_key_count();
        let txs_order = principal
            .commits()
            .last()
            .filter(|c| c.transactions().iter().any(|tx| tx.0.len() > 1))
            .map(|c| {
                c.transactions()
                    .iter()
                    .filter_map(|tx| tx.id(&[first_alg]))
                    .filter_map(|id| id.get(first_alg).map(|d| (first_alg, d.to_vec())))
                    .map(|(alg, d)| format!("{alg}:{}", Base64UrlUnpadded::encode_string(&d)))
                    .collect()
            });

        // Build multihash variants if multiple algorithms active
        let active_algs = principal.active_algs();
        let (multihash_kr, multihash_ar, multihash_pr) = if active_algs.len() > 1 {
            let ks_map: std::collections::BTreeMap<String, String> = active_algs
                .iter()
                .filter_map(|alg| {
                    principal
                        .key_root()
                        .and_then(|k| k.get(*alg))
                        .map(|d| (alg.to_string(), Base64UrlUnpadded::encode_string(d)))
                })
                .collect();
            let as_map: std::collections::BTreeMap<String, String> = active_algs
                .iter()
                .filter_map(|alg| {
                    principal
                        .auth_root()
                        .and_then(|a| a.get(*alg))
                        .map(|d| (alg.to_string(), Base64UrlUnpadded::encode_string(d)))
                })
                .collect();
            let pr_map: std::collections::BTreeMap<String, String> = active_algs
                .iter()
                .filter_map(|alg| {
                    principal
                        .pr()
                        .get(*alg)
                        .map(|d| (alg.to_string(), Base64UrlUnpadded::encode_string(d)))
                })
                .collect();
            (Some(ks_map), Some(as_map), Some(pr_map))
        } else {
            (None, None, None)
        };

        // Use intent overrides if present, otherwise use computed values
        match intent_expected {
            Some(e) => GoldenExpected {
                key_count: e.key_count.or(Some(key_count)),
                level: e.level.or(Some(level)),
                kr: e.kr.clone().map(Some).or(Some(kr)),
                auth_root: e.auth_root.clone().map(Some).or(Some(auth_root)),
                pr: e.pr.clone().or(Some(pr_val)),
                cr: cr.clone(),
                tr: e.tr.clone().or(tr),
                sr: e.sr.clone().map(Some).or(Some(sr)),
                dr: dr.clone(),
                pg: Some(pg.clone()),
                error: e.error.clone(),
                multihash_kr: multihash_kr.clone(),
                multihash_ar: multihash_ar.clone(),
                multihash_pr: multihash_pr.clone(),
                deleted: e.deleted.or(Some(principal.is_deleted())),
                frozen: e.frozen.or(Some(principal.is_frozen())),
                txs_order: txs_order.clone(),
                merge_status: None,
            },
            None => GoldenExpected {
                key_count: Some(key_count),
                level: Some(level),
                kr: Some(kr),
                auth_root: Some(auth_root),
                pr: Some(pr_val),
                cr: cr.clone(),
                tr,
                sr: Some(sr),
                dr,
                pg: Some(pg),
                error: None,
                multihash_kr,
                multihash_ar,
                multihash_pr,
                deleted: Some(principal.is_deleted()),
                frozen: Some(principal.is_frozen()),
                txs_order,
                merge_status: None,
            },
        }
    }
}

/// Generate golden test cases from an intent file.
///
/// This is the main entry point for golden generation.
///
/// # Example
///
/// ```ignore
/// let pool = Pool::load(Path::new("tests/keys/pool.toml"))?;
/// let intent = Intent::load(Path::new("tests/intents/genesis.toml"))?;
/// let goldens = generate(&intent, &pool).await?;
/// ```
pub async fn generate(intent: &Intent, pool: &Pool) -> Result<Vec<Golden>, Error> {
    Generator::new(pool).generate(intent).await
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    const SINGLE_STEP_INTENT: &str = r#"
[[test]]
name = "key_add_golden_to_alice"
principal = ["golden"]

[[test.commit]]
tx = [
  [{typ = "cyphr.me/cyphr/key/create", now = 1700000000, signer = "golden", target = "alice"}]
]

[test.expected]
key_count = 2
level = 3
"#;

    /// Backs: the corpus generator's commit root (CR) equals an independent recomputation, so a
    /// golden vector cannot encode a wrong root. Unit: generator internals are not reachable
    /// through the golden runner, which only consumes finished fixtures.
    #[tokio::test]
    async fn test_generate_single_commit() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool");
        let intent = crate::Intent::from_str(SINGLE_STEP_INTENT).expect("failed to parse intent");

        let goldens = generate(&intent, &pool).await.expect("generation failed");

        assert_eq!(goldens.len(), 1);
        let golden = &goldens[0];
        assert_eq!(golden.name, "key_add_golden_to_alice");

        // Verify we have commits and digests
        let commits = golden.commits.as_ref().expect("missing commits");
        let digests = golden.digests.as_ref().expect("missing digests");
        // The generated genesis commit (self key/create, principal/create,
        // commit/create) precedes the intent's commit.
        assert_eq!(
            commits.len(),
            2,
            "single-step should have genesis + 1 commit"
        );
        assert_eq!(
            digests.len(),
            5,
            "single-step should have 5 digests (genesis 3, mutation + commit)"
        );

        // Verify commit has correct structure
        let commit = &commits[1];
        assert_eq!(
            commit.txs.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![1, 1],
            "commit should have 2 one-coz transactions (mutation + commit)"
        );
        let cz = &commit.txs[0][0];
        let pay = cz.get("pay").expect("cz missing pay");
        assert_eq!(pay["alg"], "ES256");
        assert_eq!(pay["typ"], "cyphr.me/cyphr/key/create");
        assert_eq!(pay["now"], 1700000000);
        assert!(
            pay.get("pre").is_none(),
            "mutation cozies must not carry a pre field — only commit/create's arrow does"
        );

        let cz2 = &commit.txs[1][0];
        let pay2 = cz2.get("pay").expect("commit/create missing pay");
        assert_eq!(pay2["typ"], "cyphr.me/cyphr/commit/create");
        assert!(
            pay2.get("arrow").is_some(),
            "arrow should be populated on commit coz"
        );

        // Verify sig and keys are populated
        assert!(cz.get("sig").is_some(), "cz should have sig");
        let key = commit
            .keys
            .first()
            .expect("commit should include tracked key");
        assert_eq!(key.alg, "ES256");
        assert_eq!(key.tmb.to_string().len(), 43); // approximate thumbprint check
        assert!(!digests[0].is_empty(), "czd should be populated");

        // Verify expected state was computed
        assert_eq!(golden.expected.key_count, Some(2));
        assert_eq!(golden.expected.level, Some(3));
        assert!(golden.expected.kr.is_some(), "ks should be computed");
        assert!(golden.expected.auth_root.is_some(), "as should be computed");
        assert!(golden.expected.pr.is_some(), "pr should be computed");
        assert!(golden.expected.pg.is_some(), "pg should be computed");
        assert!(golden.expected.sr.is_some(), "sr should be computed");
        assert!(
            golden.expected.cr.is_some(),
            "cr should be computed once a commit has been finalized"
        );

        // Round trip: independently reconstruct a principal from the same
        // intent/pool data and confirm its own recomputed cr matches
        // golden.expected.cr byte-for-byte, as an independent check on top
        // of golden_fixtures.rs's corpus-driven cr equality assertion.
        let generator = Generator::new(&pool);
        let mut principal2 = generator
            .create_principal(&intent.test[0].principal, None, &intent.test[0].name)
            .await
            .expect("failed to reconstruct principal");
        generator
            .commit_generated_genesis(&intent.test[0], &mut principal2)
            .await
            .expect("failed to commit the genesis");
        generator
            .generate_single_commit(&intent.test[0], &mut principal2)
            .await
            .expect("failed to regenerate golden");
        let first_alg2 = principal2
            .active_algs()
            .first()
            .copied()
            .expect("principal must have at least one active algorithm");
        let recomputed_cr = principal2.cr().and_then(|cr_val| {
            cr_val
                .get(first_alg2)
                .map(|d| format!("{}:{}", first_alg2, Base64UrlUnpadded::encode_string(d)))
        });
        assert_eq!(
            recomputed_cr, golden.expected.cr,
            "independently recomputed cr must match golden.expected.cr"
        );
    }

    /// Backs: an intent declaring the genesis error the protocol really raises generates a fixture.
    /// Unit: the generator is build-time tooling with no CLI/HTTP surface.
    #[tokio::test]
    async fn test_declared_genesis_error_matching_actual_succeeds() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool");

        // "unsupported_key" (RS256) genuinely fails genesis with UnknownAlg.
        let intent_str = r#"
[[test]]
name = "unsupported_algorithm_fails"
principal = ["unsupported_key"]

[test.expected]
error = "UnknownAlg"
"#;

        let intent = crate::Intent::from_str(intent_str).expect("failed to parse intent");
        let goldens = generate(&intent, &pool)
            .await
            .expect("declared error matches actual");

        assert_eq!(goldens[0].expected.error.as_deref(), Some("UnknownAlg"));
    }

    /// Backs: the generator refuses a fixture whose declared error differs from the actual one (F45
    /// drift), so the corpus cannot encode a wrong error name. Unit: build-time tooling with no
    /// end-to-end surface.
    #[tokio::test]
    async fn test_declared_genesis_error_mismatch_fails_loudly() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool");

        // "unsupported_key" (RS256) genuinely fails genesis with UnknownAlg,
        // not UnsupportedAlgorithm -- this mirrors the exact drift F45
        // describes (tests/intents/errors.toml once declared
        // "UnsupportedAlgorithm" for this same case). The generator must
        // reject the wrong declared string rather than shipping a fixture
        // that silently encodes it.
        let intent_str = r#"
[[test]]
name = "unsupported_algorithm_fails"
principal = ["unsupported_key"]

[test.expected]
error = "UnsupportedAlgorithm"
"#;

        let intent = crate::Intent::from_str(intent_str).expect("failed to parse intent");
        let result = generate(&intent, &pool).await;

        let err = result.expect_err(
            "generation must fail loudly when the declared error doesn't match the actual one",
        );
        assert!(
            matches!(err, Error::DeclaredErrorMismatch { .. }),
            "expected DeclaredErrorMismatch, got {:?}",
            err
        );
        let msg = err.to_string();
        assert!(msg.contains("UnsupportedAlgorithm"), "{}", msg);
        assert!(msg.contains("UnknownAlg"), "{}", msg);
    }
}
