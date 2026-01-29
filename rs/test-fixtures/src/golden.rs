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
//! 2. For each transaction, captures `pre` from current auth_state
//! 3. Builds and signs the Coz message
//! 4. Applies the transaction to the Principal
//! 5. Extracts final state digests (ks, as, ps, ts)

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphrpass_storage::CommitEntry;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::Error;
use crate::intent::{
    ActionIntent, CryptoIntent, ExpectedAssertions, Intent, PayIntent, SetupIntent, TestIntent,
};
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
    /// Each commit contains: txs (transactions), ts, as, ps digests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commits: Option<Vec<CommitEntry>>,
    /// Coz digests (czd) parallel to all transactions across commits.
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
    /// Embedded key (for key/create transactions).
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
    /// Expected key state digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ks: Option<String>,
    /// Expected auth state digest.
    #[serde(rename = "as", default, skip_serializing_if = "Option::is_none")]
    pub auth_state: Option<String>,
    /// Expected principal state digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    /// Expected transaction state digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    /// Expected data state digest (Level 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ds: Option<String>,
    /// Expected principal root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr: Option<String>,
    /// Expected error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
            // Combined: transaction + action
            self.generate_tx_and_action(test, &mut principal)
        } else if test.has_action() {
            if test.is_multi_action() {
                self.generate_multi_action(test, &mut principal)
            } else {
                self.generate_single_action(test, &mut principal)
            }
        } else if test.is_multi_step() {
            self.generate_multi_step(test, &mut principal)
        } else {
            self.generate_single_step(test, &mut principal)
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
    /// - txs: array of transactions in commit (with pay, sig, key? fields)
    /// - ts: Transaction State digest (base64url)
    /// - as: Auth State digest (base64url)
    /// - ps: Principal State digest (base64url)
    ///
    /// Actions are exported as single-tx pseudo-commits at the end, with
    /// the current state digests at the time of action application.
    fn export_principal_commits(
        principal: &cyphrpass::Principal,
    ) -> (Vec<CommitEntry>, Vec<String>) {
        use cyphrpass_storage::export_commits;

        let mut commits = export_commits(principal);

        // Compute digests from transactions and actions
        let mut digests = Vec::new();
        for tx in principal.transactions() {
            digests.push(tx.czd().to_b64());
        }

        // Export actions as pseudo-commits
        // Each action gets its own single-tx commit entry
        // Actions use the state from the last finalized commit
        let last_commit = principal.commits().last();
        for action in principal.actions() {
            digests.push(action.czd().to_b64());

            // Serialize action's CozJson
            let raw =
                serde_json::to_value(action.raw()).expect("CozJson serialization cannot fail");

            // Create pseudo-commit with current state
            // (actions don't change key state, only add data state)
            // Use last commit's ts if available, else we have no ts (genesis-only)
            let ts = last_commit
                .map(|c| {
                    use coz::base64ct::{Base64UrlUnpadded, Encoding};
                    c.ts()
                        .as_multihash()
                        .variants()
                        .values()
                        .next()
                        .map(|b| Base64UrlUnpadded::encode_string(b))
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            let auth_state = principal
                .auth_state()
                .as_multihash()
                .variants()
                .values()
                .next()
                .map(|b| Base64UrlUnpadded::encode_string(b))
                .unwrap_or_default();
            let ps = principal
                .ps()
                .as_multihash()
                .variants()
                .values()
                .next()
                .map(|b| Base64UrlUnpadded::encode_string(b))
                .unwrap_or_default();

            commits.push(CommitEntry::new(vec![raw], ts, auth_state, ps));
        }

        (commits, digests)
    }

    /// Convert a GoldenCoz to a CommitEntry for error tests.
    /// Used for error tests where the failing entry is not in Principal.
    /// Wraps the single failing transaction as a commit with placeholder state digests.
    ///
    /// Note: For error tests, the state digests are meaningless since the
    /// transaction failed validation. We use empty strings as placeholders.
    fn coz_to_commit_entry(coz: &GoldenCoz) -> CommitEntry {
        // Build JSON object for the failing transaction
        let mut tx_json = serde_json::json!({
            "pay": serde_json::from_str::<Value>(coz.pay.get()).expect("valid pay JSON"),
            "sig": coz.sig,
        });

        if let Some(ref key) = coz.key {
            tx_json.as_object_mut().unwrap().insert(
                "key".to_string(),
                serde_json::json!({
                    "alg": key.alg,
                    "pub": key.pub_key,
                    "tmb": key.tmb
                }),
            );
        }

        // Wrap as a single-transaction commit with placeholder state digests
        CommitEntry::new(
            vec![tx_json],
            String::new(), // ts placeholder for error tests
            String::new(), // as placeholder for error tests
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

    /// Generate a single-step golden test case.
    fn generate_single_step(
        &self,
        test: &TestIntent,
        principal: &mut cyphrpass::Principal,
    ) -> Result<Golden, Error> {
        let pay_intent = test.pay.as_ref().ok_or_else(|| Error::InvalidIntent {
            message: format!(
                "test '{}': single-step test requires [pay] section",
                test.name
            ),
        })?;

        let crypto_intent = test.crypto.as_ref().ok_or_else(|| Error::InvalidIntent {
            message: format!(
                "test '{}': single-step test requires [crypto] section",
                test.name
            ),
        })?;

        // Capture pre (auth state before transaction)
        // Use override.pre if specified (for InvalidPrior tests)
        let computed_pre;
        let pre: &str =
            if let Some(override_pre) = test.override_.as_ref().and_then(|o| o.pre.as_deref()) {
                override_pre
            } else {
                computed_pre = {
                    principal
                        .auth_state()
                        .as_multihash()
                        .variants()
                        .values()
                        .next()
                        .map(|b| Base64UrlUnpadded::encode_string(b))
                        .unwrap_or_default()
                };
                &computed_pre
            };

        // Build and sign coz message
        let (coz, sig_bytes, czd) =
            self.build_golden_coz(pay_intent, crypto_intent, &test.name, Some(pre))?;

        // Check if this is an error test
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        if !is_error_test {
            // Apply transaction to principal to get final state
            self.apply_transaction_to_principal(
                principal,
                pay_intent,
                crypto_intent,
                &coz,
                &sig_bytes,
                czd,
                &test.name,
            )?;
        }

        // Build expected with computed state digests (or error)
        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        // For error tests, the transaction was not applied - add it manually
        let (mut commits, mut digests) = Self::export_principal_commits(principal);
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

    /// Generate a multi-step golden test case.
    fn generate_multi_step(
        &self,
        test: &TestIntent,
        principal: &mut cyphrpass::Principal,
    ) -> Result<Golden, Error> {
        let mut coz_sequence = Vec::with_capacity(test.step.len());

        // Check if this is an error test (applies to last step)
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        let step_count = test.step.len();
        for (i, step) in test.step.iter().enumerate() {
            let is_last_step = i == step_count - 1;

            // Capture pre before this step
            let pre = principal
                .auth_state()
                .as_multihash()
                .variants()
                .values()
                .next()
                .map(|b| Base64UrlUnpadded::encode_string(b))
                .unwrap_or_default();

            let (coz, sig_bytes, czd) = self
                .build_golden_coz(&step.pay, &step.crypto, &test.name, Some(&pre))
                .map_err(|e| Error::Generation {
                    name: test.name.clone(),
                    reason: format!("step {}: {}", i + 1, e),
                })?;

            // Apply transaction (skip last step for error tests)
            if !(is_last_step && is_error_test) {
                self.apply_transaction_to_principal(
                    principal,
                    &step.pay,
                    &step.crypto,
                    &coz,
                    &sig_bytes,
                    czd,
                    &test.name,
                )
                .map_err(|e| Error::Generation {
                    name: test.name.clone(),
                    reason: format!("step {}: {}", i + 1, e),
                })?;
            }

            coz_sequence.push(coz);
        }

        let expected = self.build_expected_from_principal(principal, test.expected.as_ref());

        // Build genesis_keys, entries, and digests
        let genesis_keys = self.build_genesis_keys(&test.principal).ok();

        // For error tests, we need to combine exported entries with the failing entry
        let (mut commits, mut digests) = Self::export_principal_commits(principal);
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

    /// Generate a genesis-only test case (no transactions or actions).
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

    /// Generate a combined transaction + action test case.
    ///
    /// This handles tests with both `pay` (transaction) and `action` fields.
    /// The transaction is applied first, then the action.
    fn generate_tx_and_action(
        &self,
        test: &TestIntent,
        principal: &mut cyphrpass::Principal,
    ) -> Result<Golden, Error> {
        // First, apply the transaction (reuse single_step logic)
        let pay_intent = test.pay.as_ref().ok_or_else(|| Error::InvalidIntent {
            message: format!(
                "test '{}': tx+action test requires [pay] section",
                test.name
            ),
        })?;

        let crypto_intent = test.crypto.as_ref().ok_or_else(|| Error::InvalidIntent {
            message: format!(
                "test '{}': tx+action test requires [crypto] section",
                test.name
            ),
        })?;

        // Capture pre (auth state before transaction)
        let pre = principal
            .auth_state()
            .as_multihash()
            .variants()
            .values()
            .next()
            .map(|b| Base64UrlUnpadded::encode_string(b))
            .unwrap_or_default();

        // Build and sign transaction coz message
        let (tx_coz, tx_sig_bytes, tx_czd) =
            self.build_golden_coz(pay_intent, crypto_intent, &test.name, Some(&pre))?;

        // Apply transaction to principal
        self.apply_transaction_to_principal(
            principal,
            pay_intent,
            crypto_intent,
            &tx_coz,
            &tx_sig_bytes,
            tx_czd,
            &test.name,
        )?;

        // Now apply the action
        let action_intent = test.action.as_ref().ok_or_else(|| Error::InvalidIntent {
            message: format!(
                "test '{}': tx+action test requires [action] section",
                test.name
            ),
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
        let (commits, digests) = Self::export_principal_commits(principal);

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
        let action_intent = test.action.as_ref().ok_or_else(|| Error::InvalidIntent {
            message: format!(
                "test '{}': single-action test requires [action] section",
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
        let (mut commits, mut digests) = Self::export_principal_commits(principal);
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
        let mut action_sequence = Vec::with_capacity(test.action_step.len());

        // Check if this is an error test (applies to last action)
        let is_error_test = test
            .expected
            .as_ref()
            .and_then(|e| e.error.as_ref())
            .is_some();

        let action_count = test.action_step.len();
        for (i, action_intent) in test.action_step.iter().enumerate() {
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
        let (mut commits, mut digests) = Self::export_principal_commits(principal);
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

    /// Build a GoldenCoz for an action.
    fn build_action_coz(
        &self,
        action: &ActionIntent,
        test_name: &str,
    ) -> Result<(GoldenCoz, Vec<u8>, coz::Czd), Error> {
        // Resolve signer key
        let signer = self.resolve_key(&action.signer)?;
        let signer_tmb = signer.compute_tmb_b64()?;

        // Build pay JSON for action (canonical order)
        let mut pay_map: IndexMap<String, Value> = IndexMap::new();
        pay_map.insert("alg".to_string(), Value::String(signer.alg.clone()));
        if let Some(ref msg) = action.msg {
            pay_map.insert("msg".to_string(), Value::String(msg.clone()));
        }
        pay_map.insert("now".to_string(), Value::Number(action.now.into()));
        pay_map.insert("tmb".to_string(), Value::String(signer_tmb));
        pay_map.insert("typ".to_string(), Value::String(action.typ.clone()));

        let pay_json = serde_json::to_vec(&pay_map).map_err(|e| Error::Generation {
            name: test_name.to_string(),
            reason: format!("failed to serialize action pay: {}", e),
        })?;

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
        // Rebuild pay JSON (same as build_action_coz)
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

        let pay_json = serde_json::to_vec(&pay_map).map_err(|e| Error::Generation {
            name: test_name.to_string(),
            reason: format!("failed to serialize action pay: {}", e),
        })?;

        principal
            .verify_and_record_action(&pay_json, sig_bytes, czd)
            .map_err(|e| Error::Generation {
                name: test_name.to_string(),
                reason: format!("failed to apply action: {}", e),
            })?;

        Ok(())
    }

    /// Build a GoldenCoz from pay and crypto intents.
    ///
    /// Returns the GoldenCoz plus raw sig bytes and czd for applying to Principal.
    fn build_golden_coz(
        &self,
        pay: &PayIntent,
        crypto: &CryptoIntent,
        test_name: &str,
        pre: Option<&str>,
    ) -> Result<(GoldenCoz, Vec<u8>, coz::Czd), Error> {
        // Resolve signer key
        let signer = self.resolve_key(&crypto.signer)?;
        let signer_tmb = signer.compute_tmb_b64()?;

        // Build pay JSON with derived fields (including pre)
        let pay_json = self.build_pay_json(pay, &signer.alg, &signer_tmb, crypto, pre)?;

        // Sign the message
        let (sig_b64, sig_bytes, czd_b64, czd, embedded_key) =
            self.sign_pay(&pay_json, signer, crypto, test_name)?;

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

    /// Build the pay JSON with correct field ordering.
    ///
    /// Per Coz spec, standard fields appear in canonical order.
    fn build_pay_json(
        &self,
        pay: &PayIntent,
        alg: &str,
        tmb: &str,
        crypto: &CryptoIntent,
        pre: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        let mut fields: IndexMap<String, Value> = IndexMap::new();

        // Standard fields in canonical order
        fields.insert("alg".to_string(), Value::String(alg.to_string()));

        // id field for key/create (target key thumbprint)
        if let Some(target_name) = &crypto.target {
            let target = self.resolve_key(target_name)?;
            let target_tmb = target.compute_tmb_b64()?;
            fields.insert("id".to_string(), Value::String(target_tmb));
        }

        // msg if present
        if let Some(msg) = &pay.msg {
            fields.insert("msg".to_string(), Value::String(msg.clone()));
        }

        // now (timestamp)
        fields.insert("now".to_string(), Value::Number(pay.now.into()));

        // pre (prior auth state) - only for transactions, not genesis
        if let Some(pre_val) = pre {
            fields.insert("pre".to_string(), Value::String(pre_val.to_string()));
        }

        // rvk if present
        if let Some(rvk) = pay.rvk {
            fields.insert("rvk".to_string(), Value::Number(rvk.into()));
        }

        // tmb (signer thumbprint)
        fields.insert("tmb".to_string(), Value::String(tmb.to_string()));

        // typ (transaction/action type)
        fields.insert("typ".to_string(), Value::String(pay.typ.clone()));

        // Serialize with preserved order
        serde_json::to_vec(&fields).map_err(|e| Error::Signing {
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
        crypto: &CryptoIntent,
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
        let embedded_key = if let Some(target_name) = &crypto.target {
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

    /// Apply a transaction to the principal.
    #[allow(clippy::too_many_arguments)]
    fn apply_transaction_to_principal(
        &self,
        principal: &mut cyphrpass::Principal,
        _pay: &PayIntent,
        crypto: &CryptoIntent,
        coz: &GoldenCoz,
        sig_bytes: &[u8],
        czd: coz::Czd,
        test_name: &str,
    ) -> Result<(), Error> {
        // Get new key for key/create operations
        let new_key = if let Some(target_name) = &crypto.target {
            Some(self.pool_key_to_cyphrpass_key(target_name)?)
        } else {
            None
        };

        // Serialize pay back to JSON for verify_and_apply
        let pay_json = serde_json::to_vec(&coz.pay).map_err(|e| Error::Generation {
            name: test_name.to_string(),
            reason: format!("failed to serialize pay: {}", e),
        })?;

        // Apply transaction - this updates principal state
        principal
            .verify_and_apply_transaction(&pay_json, sig_bytes, czd, new_key)
            .map_err(|e| Error::Generation {
                name: test_name.to_string(),
                reason: format!("transaction application failed: {}", e),
            })?;

        Ok(())
    }

    /// Resolve a key reference to a pool key.
    fn resolve_key(&self, name: &str) -> Result<&PoolKey, Error> {
        self.pool.get(name).ok_or_else(|| Error::KeyRef {
            name: name.to_string(),
        })
    }

    /// Build expected assertions from principal state and intent overrides.
    fn build_expected_from_principal(
        &self,
        principal: &cyphrpass::Principal,
        intent_expected: Option<&ExpectedAssertions>,
    ) -> GoldenExpected {
        // Compute state digests from principal
        let ks = {
            let ks_state = principal.key_state();
            ks_state
                .get(principal.hash_alg())
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default()
        };
        let auth_state = principal
            .auth_state()
            .as_multihash()
            .variants()
            .values()
            .next()
            .map(|b| Base64UrlUnpadded::encode_string(b))
            .unwrap_or_default();
        let ps = principal
            .ps()
            .as_multihash()
            .variants()
            .values()
            .next()
            .map(|b| Base64UrlUnpadded::encode_string(b))
            .unwrap_or_default();
        let ts = principal.transactions().last().and({
            // Get TS if there are transactions
            // Note: Principal doesn't expose ts() directly, compute from transactions
            // For now, we'll leave ts as None and rely on the fact that
            // AS = H(KS, TS) when TS exists
            None::<String>
        });
        let ds = principal.data_state().map(|d| d.0.to_b64());
        let pr = principal
            .pr()
            .as_multihash()
            .variants()
            .values()
            .next()
            .map(|b| Base64UrlUnpadded::encode_string(b))
            .unwrap_or_default();
        let level = principal.level() as u8;
        let key_count = principal.active_key_count();

        // Use intent overrides if present, otherwise use computed values
        match intent_expected {
            Some(e) => GoldenExpected {
                key_count: e.key_count.or(Some(key_count)),
                level: e.level.or(Some(level)),
                ks: e.ks.clone().or(Some(ks)),
                auth_state: e.auth_state.clone().or(Some(auth_state)),
                ps: e.ps.clone().or(Some(ps)),
                ts: e.ts.clone().or(ts),
                ds: ds.clone(),
                pr: Some(pr.clone()),
                error: e.error.clone(),
            },
            None => GoldenExpected {
                key_count: Some(key_count),
                level: Some(level),
                ks: Some(ks),
                auth_state: Some(auth_state),
                ps: Some(ps),
                ts,
                ds,
                pr: Some(pr),
                error: None,
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

[test.pay]
typ = "cyphr.me/key/create"
now = 1700000000

[test.crypto]
signer = "golden"
target = "alice"

[test.expected]
key_count = 2
level = 3
"#;

    #[test]
    fn test_generate_single_step() {
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
        assert_eq!(commit.txs.len(), 1, "commit should have 1 tx");
        let tx = &commit.txs[0];
        let pay = tx.get("pay").expect("tx missing pay");
        assert_eq!(pay["alg"], "ES256");
        assert_eq!(pay["typ"], "cyphr.me/key/create");
        assert_eq!(pay["now"], 1700000000);
        assert!(pay.get("pre").is_some(), "pre should be populated");

        // Verify sig and key are populated
        assert!(tx.get("sig").is_some(), "tx should have sig");
        let key = tx.get("key").expect("key/create tx should include key");
        assert_eq!(key["alg"], "ES256");
        assert!(key.get("tmb").is_some(), "key should have tmb");

        // Verify czd digest is populated
        assert!(!digests[0].is_empty(), "czd should be populated");

        // Verify expected state was computed
        assert_eq!(golden.expected.key_count, Some(2));
        assert_eq!(golden.expected.level, Some(3));
        assert!(golden.expected.ks.is_some(), "ks should be computed");
        assert!(
            golden.expected.auth_state.is_some(),
            "as should be computed"
        );
        assert!(golden.expected.ps.is_some(), "ps should be computed");
        assert!(golden.expected.pr.is_some(), "pr should be computed");
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

[test.pay]
typ = "cyphr.me/key/create"
now = 1700000000

[test.crypto]
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

        // Just create a principal, no transaction
        let intent_str = r#"
[[test]]
name = "genesis_only"
principal = ["golden"]

[test.pay]
typ = "cyphr.me/key/create"
now = 1700000000

[test.crypto]
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
        assert!(golden.expected.pr.is_some());
        assert!(golden.expected.ps.is_some());
        assert!(golden.expected.ks.is_some());
        assert!(golden.expected.auth_state.is_some());
    }
}
