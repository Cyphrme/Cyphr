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
//! 1. Creates a Principal from genesis keys (auto-promotion per spec)
//! 2. For each coz, captures `pre` from current state root
//! 3. Builds and signs the Coz message
//! 4. Applies the coz to the Principal
//! 5. Extracts final state digests (ks, as, sr, ps, commit_id)

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphrpass_storage::{CommitEntry, KeyEntry};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::Error;
use crate::intent::{ActionIntent, ExpectedAssertions, Intent, SetupIntent, TestIntent, TxIntent};
use crate::pool::{Pool, PoolKey};

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
    /// Each commit contains: cozies (cozies), ts, as, ps digests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commits: Option<Vec<CommitEntry>>,
    /// Coz digests (czd) parallel to all cozies across commits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digests: Option<Vec<String>>,
    /// Expected state after execution.
    pub expected: GoldenExpected,
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

/// Expected state in golden output.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GoldenExpected {
    /// Expected key count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_count: Option<usize>,
    /// Expected level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    /// Expected key root digest (first variant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kr: Option<String>,
    /// Expected auth root digest (first variant).
    #[serde(rename = "ar", default, skip_serializing_if = "Option::is_none")]
    pub auth_root: Option<String>,
    /// Expected principal root digest (first variant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr: Option<String>,
    /// Expected commit ID digest.
    #[serde(alias = "ts", default, skip_serializing_if = "Option::is_none")]
    pub tr: Option<String>,
    /// Expected state root digest: MR(AR, DR?).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sr: Option<String>,
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
}

// ============================================================================
// Generator
// ============================================================================

/// Generates golden test cases from intent definitions.
///
/// The generator transforms human-readable intent files into
/// golden JSON files containing real Coz messages with cryptographic
/// signatures. Uses `cyphrpass::Principal` to compute state digests.
#[derive(Debug)]
pub struct Generator<'a> {
    pool: &'a Pool,
}

type SignResult = Result<(String, Vec<u8>, String, coz::Czd, Option<GoldenKey>), Error>;

impl<'a> Generator<'a> {
    /// Create a new generator with the given key pool.
    pub fn new(pool: &'a Pool) -> Self {
        Self { pool }
    }

    /// Format principal state as tagged digest string (alg:digest format).
    ///
    /// Delegates to Principal::pr_tagged() — the canonical `pre` format.
    fn format_pr_tagged(principal: &cyphrpass::Principal) -> Result<String, Error> {
        principal.pr_tagged().map_err(|e| Error::Generation {
            name: String::new(),
            reason: format!("pr_tagged failed: {}", e),
        })
    }

    /// Generate golden test cases from an intent file.
    ///
    /// Each test in the intent becomes a golden test case.
    pub fn generate(&self, intent: &Intent) -> Result<Vec<Golden>, Error> {
        intent
            .test
            .iter()
            .map(|test| self.generate_test(test))
            .collect()
    }

    /// Generate a single golden test case.
    pub fn generate_test(&self, test: &TestIntent) -> Result<Golden, Error> {
        // Check if this is an error test expecting genesis-time failure
        let expected_error = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .cloned();

        // Create Principal from genesis keys
        let principal_result = self.create_principal(&test.principal, &test.name);

        // Handle genesis-time errors (e.g., UnsupportedAlgorithm)
        let mut principal = match principal_result {
            Ok(p) => p,
            Err(e) => {
                // If we expected an error and got one during genesis, generate error golden
                if expected_error.is_some() {
                    return Ok(Golden {
                        name: test.name.clone(),
                        principal: test.principal.clone(),
                        setup: None,
                        genesis_keys: None,
                        commits: None,
                        digests: None,
                        expected: GoldenExpected {
                            error: expected_error,
                            ..Default::default()
                        },
                    });
                }
                // Otherwise, propagate the error
                return Err(e);
            },
        };

        // Apply setup modifiers
        if let Some(ref setup) = test.setup {
            self.apply_setup(&mut principal, setup, &test.name)?;
        }

        // Dispatch based on test type
        if test.is_genesis_only() {
            self.generate_genesis_only(test, &principal)
        } else if test.has_tx_and_action() {
            // Combined: commits + actions
            self.generate_tx_and_action(test, &mut principal)
        } else if test.has_action() {
            if test.action.len() > 1 {
                self.generate_multi_action(test, &mut principal)
            } else {
                self.generate_single_action(test, &mut principal)
            }
        } else if test.commit.len() > 1 {
            self.generate_multi_commit(test, &mut principal)
        } else {
            self.generate_single_commit(test, &mut principal)
        }
    }

    /// Apply setup modifiers to a principal (e.g., pre-revoke keys).
    fn apply_setup(
        &self,
        principal: &mut cyphrpass::Principal,
        setup: &SetupIntent,
        _test_name: &str,
    ) -> Result<(), Error> {
        if let Some(ref key_name) = setup.revoke_key {
            let rvk_time = setup.revoke_at.unwrap_or(0);
            let pool_key = self.resolve_key(key_name)?;
            let tmb = pool_key.compute_tmb()?;

            // Pre-revoke the key (moves from active to revoked set)
            principal.pre_revoke_key(&tmb, rvk_time);
        }
        Ok(())
    }

    /// Convert SetupIntent to GoldenSetup for output.
    fn setup_to_golden(setup: &Option<SetupIntent>) -> Option<GoldenSetup> {
        setup.as_ref().map(|s| GoldenSetup {
            revoke_key: s.revoke_key.clone(),
            revoke_at: s.revoke_at,
        })
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

    /// Export commits from Principal using cyphrpass-storage export logic.
    /// Returns commits as Vec<CommitEntry> and digests as Vec<String>.
    ///
    /// Each CommitEntry contains:
    /// - cozies: array of cozies in commit (with pay, sig, key? fields)
    /// - tr: Commit ID digest (base64url)
    /// - as: Auth State digest (base64url)
    /// - sr: State Root digest (base64url)
    /// - pr: Principal State digest (base64url)
    ///
    /// Actions are exported as single-cz pseudo-commits at the end, with
    /// the current state digests at the time of action application.
    fn export_principal_commits(
        principal: &cyphrpass::Principal,
    ) -> Result<(Vec<CommitEntry>, Vec<String>), Error> {
        use cyphrpass_storage::export_commits;

        let mut commits = export_commits(principal).map_err(|e| Error::Generation {
            name: String::new(),
            reason: format!("export_commits failed: {}", e),
        })?;

        // Compute digests from cozies and actions
        let mut digests = Vec::new();
        for cz in principal.iter_all_cozies() {
            digests.push(cz.czd().to_b64());
        }

        // Export actions as pseudo-commits
        // Each action gets its own single-cz commit entry
        // Actions use the state from the last finalized commit
        let last_commit = principal.commits().last();
        for action in principal.actions() {
            digests.push(action.czd().to_b64());

            // Serialize action's CozJson
            let raw = serde_json::to_value(action.raw()).map_err(|e| Error::Generation {
                name: String::new(),
                reason: format!("action serialization failed: {}", e),
            })?;

            // Create pseudo-commit with current state
            // (actions don't change key state, only add data state)
            // Use last commit's tr if available, else we have no tr (genesis-only)
            let tr = last_commit
                .map(|c| {
                    use coz::base64ct::{Base64UrlUnpadded, Encoding};
                    c.tr()
                        .0
                        .first_variant()
                        .map(Base64UrlUnpadded::encode_string)
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            let auth_root = principal
                .auth_root()
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            let sr = principal
                .sr()
                .map(|s| {
                    s.as_multihash()
                        .first_variant()
                        .map(Base64UrlUnpadded::encode_string)
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            let pr_ = principal
                .pr()
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();

            commits.push(CommitEntry::new(vec![raw], vec![], tr, auth_root, sr, pr_));
        }

        Ok((commits, digests))
    }

    /// Convert a GoldenCoz to a CommitEntry for error tests.
    /// Used for error tests where the failing entry is not in Principal.
    /// Wraps the single failing coz as a commit with placeholder state digests.
    ///
    /// Note: For error tests, the state digests are meaningless since the
    /// coz failed validation. We use empty strings as placeholders.
    fn coz_to_commit_entry(coz: &GoldenCoz) -> CommitEntry {
        // Build JSON object for the failing coz (no embedded key)
        let tx_json = serde_json::json!({
            "pay": serde_json::from_str::<Value>(coz.pay.get()).expect("valid pay JSON"),
            "sig": coz.sig,
        });

        // Move key to commit-level keys[] if present
        let keys = coz
            .key
            .as_ref()
            .map(|k| {
                vec![KeyEntry {
                    alg: k.alg.clone(),
                    pub_key: k.pub_key.clone(),
                    tmb: k.tmb.clone(),
                    tag: None,
                    now: None,
                }]
            })
            .unwrap_or_default();

        // Wrap as a single-coz commit with placeholder state digests
        CommitEntry::new(
            vec![tx_json],
            keys,
            String::new(), // commit_id placeholder for error tests
            String::new(), // as placeholder for error tests
            String::new(), // sr placeholder for error tests
            String::new(), // ps placeholder for error tests
        )
    }

    /// Create a Principal from genesis key names.
    ///
    /// Uses auto-promotion rules per spec:
    /// - 1 key → implicit genesis (Level 1/2)
    /// - >1 keys → explicit genesis (Level 3+)
    fn create_principal(
        &self,
        key_names: &[String],
        test_name: &str,
    ) -> Result<cyphrpass::Principal, Error> {
        if key_names.is_empty() {
            return Err(Error::InvalidIntent {
                message: format!("test '{}': principal requires at least one key", test_name),
            });
        }

        // Convert pool keys to cyphrpass keys
        let keys: Vec<cyphrpass::Key> = key_names
            .iter()
            .map(|name| self.pool_key_to_cyphrpass_key(name))
            .collect::<Result<Vec<_>, _>>()?;

        // Auto-promotion: 1 key = implicit, >1 = explicit
        if keys.len() == 1 {
            cyphrpass::Principal::implicit(keys.into_iter().next().unwrap()).map_err(|e| {
                Error::Generation {
                    name: test_name.to_string(),
                    reason: format!("failed to create implicit principal: {}", e),
                }
            })
        } else {
            cyphrpass::Principal::explicit(keys).map_err(|e| Error::Generation {
                name: test_name.to_string(),
                reason: format!("failed to create explicit principal: {}", e),
            })
        }
    }

    /// Convert a pool key name to a cyphrpass::Key.
    fn pool_key_to_cyphrpass_key(&self, name: &str) -> Result<cyphrpass::Key, Error> {
        let pool_key = self.resolve_key(name)?;
        let tmb = pool_key.compute_tmb()?;
        let pub_bytes = Base64UrlUnpadded::decode_vec(&pool_key.pub_key).map_err(|e| {
            Error::PoolValidation {
                message: format!("key '{}': invalid pub base64: {}", name, e),
            }
        })?;

        Ok(cyphrpass::Key {
            alg: pool_key.alg.clone(),
            tmb,
            pub_key: pub_bytes,
            first_seen: 0,
            last_used: None,
            revocation: None,
            tag: pool_key.tag.clone(),
        })
    }

    /// Generate a single-commit golden test case.
    fn generate_single_commit(
        &self,
        test: &TestIntent,
        principal: &mut cyphrpass::Principal,
    ) -> Result<Golden, Error> {
        let cz = test
            .commit
            .first()
            .and_then(|c| c.tx.first())
            .and_then(|t| t.first())
            .ok_or_else(|| Error::InvalidIntent {
                message: format!(
                    "test '{}': single-commit test requires at least one coz",
                    test.name
                ),
            })?;

        // Check if this is an error test
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        // Capture pre (principal state before coz) in alg:digest format
        // Use override.pre if specified (for InvalidPrior tests)
        let computed_pre;
        let pre: &str =
            if let Some(override_pre) = test.override_.as_ref().and_then(|o| o.pre.as_deref()) {
                override_pre
            } else {
                computed_pre = Self::format_pr_tagged(principal)?;
                &computed_pre
            };

        // Resolve signer for pay construction
        let signer = self.resolve_key(&cz.signer)?;
        let signer_tmb = signer.compute_tmb_b64()?;

        // Build the pay Value (without commit field)
        let pay_value = self.build_pay_value(cz, &signer.alg, &signer_tmb, Some(pre))?;

        let coz = if is_error_test {
            // Error tests: sign manually — CommitScope would reject invalid payloads
            // (e.g., wrong pre). We need valid signatures over intentionally bad data.
            let (coz, _sig_bytes, _czd) = self.build_golden_coz(cz, &test.name, Some(pre))?;
            coz
        } else {
            // Happy path: use CommitScope::finalize_with_commit
            // This handles mutation → CS computation → commit injection → signing atomically.
            let new_key = if let Some(target_name) = &cz.target {
                Some(self.pool_key_to_cyphrpass_key(target_name)?)
            } else {
                None
            };

            let prv_b64 = signer
                .prv
                .as_ref()
                .ok_or_else(|| Error::MissingPrivateKey {
                    name: signer.name.clone(),
                })?;
            let prv_bytes =
                Base64UrlUnpadded::decode_vec(prv_b64).map_err(|e| Error::Generation {
                    name: test.name.clone(),
                    reason: format!("invalid prv base64: {}", e),
                })?;
            let pub_bytes =
                Base64UrlUnpadded::decode_vec(&signer.pub_key).map_err(|e| Error::Generation {
                    name: test.name.clone(),
                    reason: format!("invalid pub base64: {}", e),
                })?;

            let commit = self.apply_and_finalize(
                principal,
                pay_value,
                &signer.alg,
                &prv_bytes,
                &pub_bytes,
                &signer_tmb,
                new_key,
                cz.now,
            )?;

            // Extract GoldenCoz from the finalized commit (the first tx is the mutation)
            let vtx = &commit.iter_all_cozies().next().unwrap();
            self.commit_vtx_to_golden_coz(vtx, cz)?
        };

        // Build expected with computed state digests (or error)
        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        // For error tests, the coz was not applied - add it manually
        let (mut commits, mut digests) = Self::export_principal_commits(principal)?;
        if is_error_test {
            commits.push(Self::coz_to_commit_entry(&coz));
            digests.push(coz.czd.clone());
        }

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            expected,
        })
    }

    /// Generate a multi-commit golden test case.
    fn generate_multi_commit(
        &self,
        test: &TestIntent,
        principal: &mut cyphrpass::Principal,
    ) -> Result<Golden, Error> {
        let mut coz_sequence = Vec::with_capacity(test.commit.len());

        // Check if this is an error test (applies to last commit)
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        let commit_count = test.commit.len();
        for (i, commit) in test.commit.iter().enumerate() {
            let is_last_commit = i == commit_count - 1;
            let cz =
                commit
                    .tx
                    .first()
                    .and_then(|t| t.first())
                    .ok_or_else(|| Error::InvalidIntent {
                        message: format!("test '{}': commit {} has no cozies", test.name, i + 1),
                    })?;

            // Capture pre before this commit (alg:digest format)
            let pre = Self::format_pr_tagged(principal)?;

            // Resolve signer
            let signer = self.resolve_key(&cz.signer)?;
            let signer_tmb = signer.compute_tmb_b64()?;

            let coz = if is_last_commit && is_error_test {
                // Error tests: sign last commit manually
                let (coz, _sig_bytes, _czd) = self
                    .build_golden_coz(cz, &test.name, Some(&pre))
                    .map_err(|e| Error::Generation {
                        name: test.name.clone(),
                        reason: format!("commit {}: {}", i + 1, e),
                    })?;
                coz
            } else {
                // Happy path: use CommitScope::finalize_with_commit
                let new_key = if let Some(target_name) = &cz.target {
                    Some(self.pool_key_to_cyphrpass_key(target_name)?)
                } else {
                    None
                };

                let prv_b64 = signer
                    .prv
                    .as_ref()
                    .ok_or_else(|| Error::MissingPrivateKey {
                        name: signer.name.clone(),
                    })?;
                let prv_bytes =
                    Base64UrlUnpadded::decode_vec(prv_b64).map_err(|e| Error::Generation {
                        name: test.name.clone(),
                        reason: format!("commit {}: invalid prv base64: {}", i + 1, e),
                    })?;
                let pub_bytes = Base64UrlUnpadded::decode_vec(&signer.pub_key).map_err(|e| {
                    Error::Generation {
                        name: test.name.clone(),
                        reason: format!("commit {}: invalid pub base64: {}", i + 1, e),
                    }
                })?;

                let pay_value = self.build_pay_value(cz, &signer.alg, &signer_tmb, Some(&pre))?;

                let commit_ref = self
                    .apply_and_finalize(
                        principal,
                        pay_value,
                        &signer.alg,
                        &prv_bytes,
                        &pub_bytes,
                        &signer_tmb,
                        new_key,
                        cz.now,
                    )
                    .map_err(|e| Error::Generation {
                        name: test.name.clone(),
                        reason: format!("commit {}: {}", i + 1, e),
                    })?;

                let vtx = &commit_ref.iter_all_cozies().next().unwrap();
                self.commit_vtx_to_golden_coz(vtx, cz)?
            };

            coz_sequence.push(coz);
        }

        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        // For error tests, we need to combine exported entries with the failing entry
        let (mut commits, mut digests) = Self::export_principal_commits(principal)?;
        if is_error_test && !coz_sequence.is_empty() {
            // The last step was not applied - add it from coz_sequence
            let failing_coz = coz_sequence.last().unwrap();
            commits.push(Self::coz_to_commit_entry(failing_coz));
            digests.push(failing_coz.czd.clone());
        }

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            expected,
        })
    }

    /// Generate a genesis-only test case (no cozies or actions).
    fn generate_genesis_only(
        &self,
        test: &TestIntent,
        principal: &cyphrpass::Principal,
    ) -> Result<Golden, Error> {
        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Genesis-only: no entries or digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(vec![]),
            digests: Some(vec![]),
            expected,
        })
    }

    /// Generate a combined commit + action test case.
    ///
    /// The commit cozies are applied first, then the actions.
    fn generate_tx_and_action(
        &self,
        test: &TestIntent,
        principal: &mut cyphrpass::Principal,
    ) -> Result<Golden, Error> {
        // First, apply the commit coz
        let cz = test
            .commit
            .first()
            .and_then(|c| c.tx.first())
            .and_then(|t| t.first())
            .ok_or_else(|| Error::InvalidIntent {
                message: format!(
                    "test '{}': cz+action test requires at least one coz",
                    test.name
                ),
            })?;

        // Capture pre (principal state before coz) in alg:digest format
        let pre = Self::format_pr_tagged(principal)?;

        // Resolve signer and build pay
        let signer = self.resolve_key(&cz.signer)?;
        let signer_tmb = signer.compute_tmb_b64()?;
        let pay_value = self.build_pay_value(cz, &signer.alg, &signer_tmb, Some(&pre))?;

        let new_key = if let Some(target_name) = &cz.target {
            Some(self.pool_key_to_cyphrpass_key(target_name)?)
        } else {
            None
        };

        let prv_b64 = signer
            .prv
            .as_ref()
            .ok_or_else(|| Error::MissingPrivateKey {
                name: signer.name.clone(),
            })?;
        let prv_bytes = Base64UrlUnpadded::decode_vec(prv_b64).map_err(|e| Error::Generation {
            name: test.name.clone(),
            reason: format!("invalid prv base64: {}", e),
        })?;
        let pub_bytes =
            Base64UrlUnpadded::decode_vec(&signer.pub_key).map_err(|e| Error::Generation {
                name: test.name.clone(),
                reason: format!("invalid pub base64: {}", e),
            })?;

        // Use apply_and_finalize for the coz
        self.apply_and_finalize(
            principal,
            pay_value,
            &signer.alg,
            &prv_bytes,
            &pub_bytes,
            &signer_tmb,
            new_key,
            cz.now,
        )?;

        // Now apply the action
        let action_intent = test.action.first().ok_or_else(|| Error::InvalidIntent {
            message: format!("test '{}': cz+action test requires [[action]]", test.name),
        })?;

        let (_, action_sig_bytes, action_czd) = self.build_action_coz(action_intent, &test.name)?;

        // Apply action to principal
        self.apply_action_to_principal(
            principal,
            action_intent,
            &action_sig_bytes,
            action_czd,
            &test.name,
        )?;

        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests using storage export logic
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();
        let (commits, digests) = Self::export_principal_commits(principal)?;

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            expected,
        })
    }

    /// Generate a single-action test case (Level 4).
    fn generate_single_action(
        &self,
        test: &TestIntent,
        principal: &mut cyphrpass::Principal,
    ) -> Result<Golden, Error> {
        let action_intent = test.action.first().ok_or_else(|| Error::InvalidIntent {
            message: format!(
                "test '{}': single-action test requires [[action]]",
                test.name
            ),
        })?;

        let (action_coz, sig_bytes, czd) = self.build_action_coz(action_intent, &test.name)?;

        // Check if this is an error test
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        if !is_error_test {
            // Apply action to principal
            self.apply_action_to_principal(principal, action_intent, &sig_bytes, czd, &test.name)?;
        }

        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        // For error tests, the action was not applied - add it manually
        let (mut commits, mut digests) = Self::export_principal_commits(principal)?;
        if is_error_test {
            commits.push(Self::coz_to_commit_entry(&action_coz));
            digests.push(action_coz.czd.clone());
        }

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
            expected,
        })
    }

    /// Generate a multi-action test case (Level 4).
    fn generate_multi_action(
        &self,
        test: &TestIntent,
        principal: &mut cyphrpass::Principal,
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

            let (action_coz, sig_bytes, czd) = self
                .build_action_coz(action_intent, &test.name)
                .map_err(|e| Error::Generation {
                    name: test.name.clone(),
                    reason: format!("action {}: {}", i + 1, e),
                })?;

            // Apply action (skip last action for error tests)
            if !(is_last_action && is_error_test) {
                self.apply_action_to_principal(
                    principal,
                    action_intent,
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
            commits.push(Self::coz_to_commit_entry(failing_coz));
            digests.push(failing_coz.czd.clone());
        }

        Ok(Golden {
            name: test.name.clone(),
            principal: test.principal.clone(),
            setup: Self::setup_to_golden(&test.setup),
            genesis_keys,
            commits: Some(commits),
            digests: Some(digests),
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
        test_name: &str,
    ) -> Result<Vec<u8>, Error> {
        let signer = self.resolve_key(&action.signer)?;
        let signer_tmb = signer.compute_tmb_b64()?;

        let mut pay_map: IndexMap<String, Value> = IndexMap::new();
        pay_map.insert("alg".to_string(), Value::String(signer.alg.clone()));
        if let Some(ref msg) = action.msg {
            pay_map.insert("msg".to_string(), Value::String(msg.clone()));
        }
        pay_map.insert("now".to_string(), Value::Number(action.now.into()));
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
        test_name: &str,
    ) -> Result<(GoldenCoz, Vec<u8>, coz::Czd), Error> {
        let pay_json = self.build_action_pay_json(action, test_name)?;

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
        principal: &mut cyphrpass::Principal,
        action: &ActionIntent,
        sig_bytes: &[u8],
        czd: coz::Czd,
        test_name: &str,
    ) -> Result<(), Error> {
        let pay_json = self.build_action_pay_json(action, test_name)?;

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
        pre: Option<&str>,
    ) -> Result<(GoldenCoz, Vec<u8>, coz::Czd), Error> {
        // Resolve signer key
        let signer = self.resolve_key(&cz.signer)?;
        let signer_tmb = signer.compute_tmb_b64()?;

        // Build pay JSON with derived fields (including pre)
        let pay_json = self.build_pay_json(cz, &signer.alg, &signer_tmb, pre)?;

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
    fn build_pay_value(
        &self,
        cz: &TxIntent,
        alg: &str,
        tmb: &str,
        pre: Option<&str>,
    ) -> Result<Value, Error> {
        let mut fields: IndexMap<String, Value> = IndexMap::new();

        // Standard fields in canonical order
        fields.insert("alg".to_string(), Value::String(alg.to_string()));

        // id field handling depends on coz type
        let is_principal_create = cz.typ.contains("principal/create");
        if is_principal_create {
            // For principal/create, id is the current PS (SPEC §5.1: "id: Final PS = PR").
            // pre is the PS-tagged value, which equals PS at this point since
            // principal/create doesn't mutate state — it only freezes PR.
            let ps_val = pre.ok_or_else(|| Error::Generation {
                name: "build_pay_value".to_string(),
                reason: "principal/create requires pre (PS) for id field".to_string(),
            })?;
            fields.insert("id".to_string(), Value::String(ps_val.to_string()));
        } else if let Some(target_name) = &cz.target {
            // For key/create etc, id is the target key thumbprint
            let target = self.resolve_key(target_name)?;
            let target_tmb = target.compute_tmb_b64()?;
            fields.insert("id".to_string(), Value::String(target_tmb));
        }

        // msg if present
        if let Some(msg) = &cz.msg {
            fields.insert("msg".to_string(), Value::String(msg.clone()));
        }

        // now (timestamp)
        fields.insert("now".to_string(), Value::Number(cz.now.into()));

        // pre (prior auth state) - only for cozies, not genesis
        if let Some(pre_val) = pre {
            fields.insert("pre".to_string(), Value::String(pre_val.to_string()));
        }

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
        pre: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        let value = self.build_pay_value(cz, alg, tmb, pre)?;
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

        // Build embedded key for key/create operations
        let embedded_key = if let Some(target_name) = &cz.target {
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

    /// Extract a GoldenCoz from a VerifiedCoz (produced by CommitScope).
    ///
    /// Used after `finalize_with_commit()` to convert the Commit's coz
    /// into the golden fixture format.
    fn commit_vtx_to_golden_coz(
        &self,
        vtx: &cyphrpass::parsed_coz::VerifiedCoz,
        cz: &TxIntent,
    ) -> Result<GoldenCoz, Error> {
        let raw = vtx.raw();
        let sig_b64 = Base64UrlUnpadded::encode_string(&raw.sig);
        let czd_b64 = Base64UrlUnpadded::encode_string(vtx.czd().as_bytes());

        // Build embedded key for key/create operations
        let embedded_key = if let Some(target_name) = &cz.target {
            let target = self.resolve_key(target_name)?;
            Some(GoldenKey {
                alg: target.alg.clone(),
                pub_key: target.pub_key.clone(),
                tmb: target.compute_tmb_b64()?,
            })
        } else {
            None
        };

        // Convert Value to Box<RawValue> for bit-perfect preservation in GoldenCoz
        let pay_str = serde_json::to_string(&raw.pay).map_err(|e| Error::Generation {
            name: cz.signer.clone(),
            reason: format!("failed to serialize pay from commit: {}", e),
        })?;
        let pay_raw: Box<RawValue> =
            RawValue::from_string(pay_str).map_err(|e| Error::Generation {
                name: cz.signer.clone(),
                reason: format!("failed to create RawValue: {}", e),
            })?;

        Ok(GoldenCoz {
            pay: pay_raw,
            sig: sig_b64,
            czd: czd_b64,
            key: embedded_key,
        })
    }

    /// Resolve a key reference to a pool key.
    fn resolve_key(&self, name: &str) -> Result<&PoolKey, Error> {
        self.pool.get(name).ok_or_else(|| Error::KeyRef {
            name: name.to_string(),
        })
    }

    /// Build expected assertions from principal state and intent overrides.

    fn apply_and_finalize(
        &self,
        principal: &mut cyphrpass::Principal,
        pay_value: serde_json::Value,
        signer_alg: &str,
        prv_bytes: &[u8],
        pub_bytes: &[u8],
        signer_tmb: &str,
        new_key: Option<cyphrpass::key::Key>,
        now: i64,
    ) -> Result<cyphrpass::Commit, Error> {
        let pay_vec = serde_json::to_vec(&pay_value).map_err(|e| Error::Generation {
            name: "unknown".into(),
            reason: e.to_string(),
        })?;
        let (sig_bytes, cad) = coz::sign_json(&pay_vec, signer_alg, prv_bytes, pub_bytes).unwrap();
        let czd = coz::czd_for_alg(&cad, &sig_bytes, signer_alg).unwrap();
        let mut scope = principal.begin_commit();
        scope
            .verify_and_apply(&pay_vec, &sig_bytes, czd, new_key)
            .map_err(|e| Error::Generation {
                name: "unknown".into(),
                reason: e.to_string(),
            })?;
        let tmb = coz::Thumbprint::from_bytes(
            coz::base64ct::Base64UrlUnpadded::decode_vec(signer_tmb).unwrap(),
        );
        let commit_ref = scope
            .finalize_with_arrow(signer_alg, prv_bytes, pub_bytes, &tmb, now)
            .map_err(|e| Error::Generation {
                name: "unknown".into(),
                reason: e.to_string(),
            })?;
        Ok(commit_ref.clone())
    }

    fn build_expected_from_principal(
        &self,
        principal: &cyphrpass::Principal,
        intent_expected: Option<&ExpectedAssertions>,
    ) -> GoldenExpected {
        // Get lexicographically first algorithm for deterministic ordering
        let first_alg = principal
            .active_algs()
            .first()
            .copied()
            .expect("Principal must have at least one active algorithm");

        // Compute state digests with algorithm prefix (alg:digest format)
        let kr = {
            let ks_state = principal.key_root();
            ks_state
                .get(first_alg)
                .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
                .unwrap_or_default()
        };
        let auth_root = principal
            .auth_root()
            .get(first_alg)
            .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
            .unwrap_or_default();
        let pr_val = principal
            .pr()
            .get(first_alg)
            .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
            .unwrap_or_default();
        let tr = principal.current_tr().and_then(|cid| {
            cid.get(first_alg)
                .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
        });
        let sr = principal.sr().and_then(|sr_val| {
            sr_val
                .get(first_alg)
                .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
        });
        let dr = principal.data_root().map(|d| d.0.to_b64());
        let pg = principal
            .pg()
            .and_then(|pg_val| pg_val.get(first_alg))
            .map(|d| format!("{}:{}", first_alg, Base64UrlUnpadded::encode_string(d)))
            .unwrap_or_default();
        let level = principal.level() as u8;
        let key_count = principal.active_key_count();

        // Build multihash variants if multiple algorithms active
        let active_algs = principal.active_algs();
        let (multihash_kr, multihash_ar, multihash_pr) = if active_algs.len() > 1 {
            let ks_map: std::collections::BTreeMap<String, String> = active_algs
                .iter()
                .filter_map(|alg| {
                    principal
                        .key_root()
                        .get(*alg)
                        .map(|d| (alg.to_string(), Base64UrlUnpadded::encode_string(d)))
                })
                .collect();
            let as_map: std::collections::BTreeMap<String, String> = active_algs
                .iter()
                .filter_map(|alg| {
                    principal
                        .auth_root()
                        .get(*alg)
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
                kr: e.kr.clone().or(Some(kr)),
                auth_root: e.auth_root.clone().or(Some(auth_root)),
                pr: e.pr.clone().or(Some(pr_val)),
                tr: e.tr.clone().or(tr),
                sr: e.sr.clone().or(sr),
                dr: dr.clone(),
                pg: Some(pg.clone()),
                error: e.error.clone(),
                multihash_kr: multihash_kr.clone(),
                multihash_ar: multihash_ar.clone(),
                multihash_pr: multihash_pr.clone(),
            },
            None => GoldenExpected {
                key_count: Some(key_count),
                level: Some(level),
                kr: Some(kr),
                auth_root: Some(auth_root),
                pr: Some(pr_val),
                tr,
                sr,
                dr,
                pg: Some(pg),
                error: None,
                multihash_kr,
                multihash_ar,
                multihash_pr,
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
/// let goldens = generate(&intent, &pool)?;
/// ```
pub fn generate(intent: &Intent, pool: &Pool) -> Result<Vec<Golden>, Error> {
    Generator::new(pool).generate(intent)
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
[[test.commit.cz]]
typ = "cyphr.me/key/create"
now = 1700000000
signer = "golden"
target = "alice"

[test.expected]
key_count = 2
level = 3
"#;

    #[test]
    fn test_generate_single_commit() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool");
        let intent = crate::Intent::from_str(SINGLE_STEP_INTENT).expect("failed to parse intent");

        let goldens = generate(&intent, &pool).expect("generation failed");

        assert_eq!(goldens.len(), 1);
        let golden = &goldens[0];
        assert_eq!(golden.name, "key_add_golden_to_alice");

        // Verify we have commits and digests
        let commits = golden.commits.as_ref().expect("missing commits");
        let digests = golden.digests.as_ref().expect("missing digests");
        assert_eq!(commits.len(), 1, "single-step should have 1 commit");
        assert_eq!(digests.len(), 1, "single-step should have 1 digest");

        // Verify commit has correct structure
        let commit = &commits[0];
        assert_eq!(commit.cozies.len(), 1, "commit should have 1 cz");
        let cz = &commit.cozies[0];
        let pay = cz.get("pay").expect("cz missing pay");
        assert_eq!(pay["alg"], "ES256");
        assert_eq!(pay["typ"], "cyphr.me/key/create");
        assert_eq!(pay["now"], 1700000000);
        assert!(pay.get("pre").is_some(), "pre should be populated");

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
    }

    #[test]
    fn test_missing_signer_key() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool");

        let intent_str = r#"
[[test]]
name = "bad_signer"
principal = ["golden"]

[[test.commit]]
[[test.commit.cz]]
typ = "cyphr.me/key/create"
now = 1700000000
signer = "nonexistent_key"
target = "alice"
"#;

        let intent = crate::Intent::from_str(intent_str).expect("failed to parse intent");
        let result = generate(&intent, &pool);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("nonexistent_key"));
    }

    #[test]
    fn test_genesis_state_computation() {
        // Test that genesis produces correct state (all promoted)
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool");

        // Just create a principal, no coz
        let intent_str = r#"
[[test]]
name = "genesis_only"
principal = ["golden"]

[[test.commit]]
[[test.commit.cz]]
typ = "cyphr.me/key/create"
now = 1700000000
signer = "golden"
target = "alice"
"#;

        let intent = crate::Intent::from_str(intent_str).expect("failed to parse intent");
        let goldens = generate(&intent, &pool).expect("generation failed");

        let golden = &goldens[0];

        // For single-key implicit genesis, PR = PS = AS = KS = tmb
        // After adding alice, we should have 2 keys
        assert_eq!(golden.expected.key_count, Some(2));

        // All state digests should be non-empty
        assert!(golden.expected.pg.is_some());
        assert!(golden.expected.pr.is_some());
        assert!(golden.expected.kr.is_some());
        assert!(golden.expected.auth_root.is_some());
    }
}
