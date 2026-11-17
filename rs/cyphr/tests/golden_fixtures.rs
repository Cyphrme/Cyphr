//! Integration tests consuming golden fixtures from tests/golden/.
//!
//! Each test loads a golden JSON file, creates a Principal from the
//! genesis keys, applies Coz message(s), and verifies expected state.

use std::fs;
use std::path::PathBuf;

use cyphr::key::Key;
use cyphr::{Principal, StateDigest};
use test_fixtures::{Golden, GoldenExpected, GoldenPeer, Pool, PoolKey};

// ============================================================================
// Test helpers
// ============================================================================

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("should have rs/ parent")
        .parent()
        .expect("should have repo root parent")
        .join("tests")
}

fn golden_dir() -> PathBuf {
    tests_dir().join("golden")
}

/// Parse hash algorithm name from string (e.g., "SHA-256" -> HashAlg::Sha256).
fn parse_hash_alg(s: &str) -> Option<coz::HashAlg> {
    match s {
        "SHA-256" => Some(coz::HashAlg::Sha256),
        "SHA-384" => Some(coz::HashAlg::Sha384),
        "SHA-512" => Some(coz::HashAlg::Sha512),
        _ => None,
    }
}

/// Parse algorithm-prefixed digest string (e.g., "SHA-256:abc123..." -> ("SHA-256", "abc123...")).
fn parse_alg_digest(s: &str) -> Option<(String, String)> {
    let (alg, digest) = s.split_once(':')?;

    Some((alg.to_string(), digest.to_string()))
}

fn load_pool() -> Pool {
    let path = tests_dir().join("keys").join("pool.toml");
    Pool::load(&path).expect("failed to load pool.toml")
}

/// Convert a pool key to a domain key. An unsupported algorithm or key
/// material the checked `Key` constructor refuses is the genesis error the
/// vector may declare.
fn try_pool_key_to_domain(pk: &PoolKey) -> Result<Key, cyphr::error::Error> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let unsupported = || cyphr::error::Error::UnsupportedAlgorithm(pk.alg.clone());
    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).map_err(|_| unsupported())?;
    let tmb = pk.compute_tmb().map_err(|_| unsupported())?;

    Key::new(pk.alg.clone(), tmb, pub_bytes)
}

fn error_name(e: &cyphr::error::Error) -> &'static str {
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
        Error::StateMismatch => "StateMismatch",
        Error::MixedTransactionTyp => "MixedTransactionTyp",
        Error::EmptyCommit => "EmptyCommit",
        Error::EmptyMultihash => "EmptyMultihash",
        _ => "UnknownError",
    }
}

fn verify_expected(principal: &Principal, expected: &GoldenExpected, test_name: &str) {
    // SPEC 3.7.5 / 4.6.3 `txs_order`: the TX of each transaction of the
    // last commit, TX = MR(czd0, czd1?, ...), in the stated algorithm.
    if let Some(order) = &expected.txs_order {
        let commit = principal
            .commits()
            .last()
            .unwrap_or_else(|| panic!("{test_name}: txs_order but no commit"));
        let actual: Vec<String> = commit
            .transactions()
            .iter()
            .zip(order)
            .map(|(tx, stated)| {
                let (alg, _) = parse_alg_digest(stated).expect("tagged TX");
                let alg = parse_hash_alg(&alg).expect("TX algorithm");
                let id = tx.id(&[alg]).expect("TX");
                cyphr::state::TaggedDigest::new(alg, id.get(alg).expect("variant").to_vec())
                    .expect("tagged")
                    .to_string()
            })
            .collect();
        assert_eq!(
            commit.transactions().len(),
            order.len(),
            "{test_name}: txs_order length"
        );
        assert_eq!(&actual, order, "{test_name}: txs_order mismatch");
    }

    if let Some(count) = expected.key_count {
        assert_eq!(
            principal.active_key_count(),
            count,
            "{}: key_count mismatch",
            test_name
        );
    }

    if let Some(level) = expected.level {
        assert_eq!(
            principal.level() as u8,
            level,
            "{}: level mismatch",
            test_name
        );
    }

    if let Some(deleted) = expected.deleted {
        assert_eq!(
            principal.is_deleted(),
            deleted,
            "{}: deleted mismatch",
            test_name
        );
    }

    if let Some(frozen) = expected.frozen {
        assert_eq!(
            principal.is_frozen(),
            frozen,
            "{}: frozen mismatch",
            test_name
        );
    }

    // `null` in the vector is a root the principal must not have (a Dead
    // principal has no KR or AR, SPEC 3.7); a string is compared by digest.
    match &expected.kr {
        Some(Some(ks)) => {
            let (alg, expected_digest) = parse_alg_digest(ks).unwrap_or_else(|| {
                panic!("{}: invalid ks format (expected alg:digest)", test_name)
            });
            let hash_alg = parse_hash_alg(&alg)
                .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
            let actual_ks = principal
                .key_root()
                .and_then(|k| k.get(hash_alg))
                .map(|b| {
                    use coz::base64ct::{Base64UrlUnpadded, Encoding};
                    Base64UrlUnpadded::encode_string(b)
                })
                .unwrap_or_default();
            assert_eq!(actual_ks, expected_digest, "{}: ks mismatch", test_name);
        },
        Some(None) => assert!(
            principal.key_root().is_none(),
            "{}: expected no KR",
            test_name
        ),
        None => {},
    }

    match &expected.auth_root {
        Some(Some(auth_root)) => {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let (alg, expected_digest) = parse_alg_digest(auth_root).unwrap_or_else(|| {
                panic!("{}: invalid as format (expected alg:digest)", test_name)
            });
            let hash_alg = parse_hash_alg(&alg)
                .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
            let actual_as = principal
                .auth_root()
                .and_then(|a| a.get(hash_alg))
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            assert_eq!(actual_as, expected_digest, "{}: as mismatch", test_name);
        },
        Some(None) => assert!(
            principal.auth_root().is_none(),
            "{}: expected no AR",
            test_name
        ),
        None => {},
    }

    if let Some(ref pr) = expected.pr {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        // Parse alg:digest format
        let (alg, expected_digest) = parse_alg_digest(pr)
            .unwrap_or_else(|| panic!("{}: invalid pr format (expected alg:digest)", test_name));
        let hash_alg = parse_hash_alg(&alg)
            .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
        let actual_pr = principal
            .pr()
            .get(hash_alg)
            .map(Base64UrlUnpadded::encode_string)
            .unwrap_or_default();
        assert_eq!(actual_pr, expected_digest, "{}: pr mismatch", test_name);
    }

    if let Some(ref cr) = expected.cr {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        // Parse alg:digest format
        let (alg, expected_digest) = parse_alg_digest(cr)
            .unwrap_or_else(|| panic!("{}: invalid cr format (expected alg:digest)", test_name));
        let hash_alg = parse_hash_alg(&alg)
            .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
        let actual_cr = principal
            .cr()
            .and_then(|cr_val| cr_val.get(hash_alg))
            .map(Base64UrlUnpadded::encode_string)
            .unwrap_or_default();
        assert_eq!(actual_cr, expected_digest, "{}: cr mismatch", test_name);
    }

    match &expected.sr {
        Some(Some(sr)) => {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let (alg, expected_digest) = parse_alg_digest(sr).unwrap_or_else(|| {
                panic!("{}: invalid sr format (expected alg:digest)", test_name)
            });
            let hash_alg = parse_hash_alg(&alg)
                .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
            let actual_sr = principal
                .sr()
                .and_then(|sr_val| sr_val.get(hash_alg))
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            assert_eq!(actual_sr, expected_digest, "{}: sr mismatch", test_name);
        },
        Some(None) => assert!(principal.sr().is_none(), "{}: expected no SR", test_name),
        None => {},
    }

    if let Some(ref pg) = expected.pg {
        // Skip empty PG or non-prefixed format (implicit genesis uses raw thumbprint)
        if !pg.is_empty()
            && let Some((alg, expected_digest)) = parse_alg_digest(pg)
        {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let hash_alg = parse_hash_alg(&alg)
                .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
            let actual_pg = principal
                .pg()
                .and_then(|pg_val| pg_val.get(hash_alg))
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            assert_eq!(actual_pg, expected_digest, "{}: pg mismatch", test_name);
        }
        // If no ':' in pg, it's a raw thumbprint format - skip alg:digest verification
    }

    if let Some(ref ds) = expected.dr {
        let principal_ds = principal
            .data_root()
            .and_then(|d| d.0.first_variant().ok())
            .map(|bytes| {
                use coz::base64ct::{Base64UrlUnpadded, Encoding};
                Base64UrlUnpadded::encode_string(bytes)
            })
            .unwrap_or_else(|| "<no ds>".to_string());
        assert_eq!(principal_ds, *ds, "{}: ds mismatch", test_name);
    }

    // Verify per-algorithm multihash variants (SPEC §14 cross-implementation parity)
    if let Some(ref mh_ks) = expected.multihash_kr {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        for (alg_name, expected_digest) in mh_ks {
            let hash_alg = parse_hash_alg(alg_name)
                .unwrap_or_else(|| panic!("{}: invalid hash algorithm {}", test_name, alg_name));
            let actual = principal
                .key_root()
                .and_then(|k| k.get(hash_alg))
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            assert_eq!(
                actual, *expected_digest,
                "{}: multihash_ks[{}] mismatch",
                test_name, alg_name
            );
        }
    }

    if let Some(ref mh_as) = expected.multihash_ar {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        for (alg_name, expected_digest) in mh_as {
            let hash_alg = parse_hash_alg(alg_name)
                .unwrap_or_else(|| panic!("{}: invalid hash algorithm {}", test_name, alg_name));
            let actual = principal
                .auth_root()
                .and_then(|a| a.get(hash_alg))
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            assert_eq!(
                actual, *expected_digest,
                "{}: multihash_as[{}] mismatch",
                test_name, alg_name
            );
        }
    }

    if let Some(ref mh_pr) = expected.multihash_pr {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        for (alg_name, expected_digest) in mh_pr {
            let hash_alg = parse_hash_alg(alg_name)
                .unwrap_or_else(|| panic!("{}: invalid hash algorithm {}", test_name, alg_name));
            let actual = principal
                .pr()
                .get(hash_alg)
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            assert_eq!(
                actual, *expected_digest,
                "{}: multihash_pr[{}] mismatch",
                test_name, alg_name
            );
        }
    }
}

/// Resolve formal constraint tags (e.g., "[no-revoke-non-self]") to native error codes.
///
/// Allows TOML tests to use constraint tags from the machine spec directly.
/// If the input is not a bracketed tag, it passes through unchanged.
fn resolve_constraint_tag(expected: &str) -> &str {
    match expected {
        // Transactions
        "[create-uniqueness]" => "DuplicateKey",
        "[no-unauthorized-transaction]" => "UnknownKey",
        "[revoke-self-signed]" => "MalformedPayload",
        "[no-revoke-non-self]" => "MalformedPayload",
        // What a Dead principal answers: its revoked key signs nothing.
        "[no-self-revoke-recovery]" => "KeyRevoked",
        // Structural constraints
        "[commit-one-or-more]" => "EmptyCommit",
        "[no-empty-mr]" => "EmptyMultihash",
        // Authentication
        "[verification-timestamp-order]" => "TimestampPast",
        // Principal Lifecycle
        "[no-level-1-recovery]" => "KeyRevoked",
        "[dead-terminal]" => "KeyRevoked",
        // Rust cyphr library conflates UnknownSigner and UnknownTarget into UnknownKey
        "UnknownSigner" => "UnknownKey",
        // Pass through if not a constraint tag
        other => other,
    }
}

async fn run_golden_test(fixture_path: &PathBuf, pool: &Pool) {
    let content = fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {}", fixture_path, e));
    let fixture: Golden = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {:?}: {}", fixture_path, e));

    // Check if this is an error test
    let expected_error = fixture
        .expected
        .error
        .as_deref()
        .map(resolve_constraint_tag);

    // Resolve genesis keys from pool (fallibly for unsupported algorithms)
    let pool_keys: Vec<&PoolKey> = fixture
        .principal
        .iter()
        .map(|name| {
            pool.pool
                .key
                .iter()
                .find(|k| k.name == *name)
                .unwrap_or_else(|| panic!("{}: key '{}' not found in pool", fixture.name, name))
        })
        .collect();

    // Try to convert pool keys to domain keys (may fail for unsupported
    // algs). A key `setup.revoke_key` names reaches genesis already revoked.
    let revoked_at = |pk: &PoolKey| {
        fixture
            .setup
            .as_ref()
            .filter(|s| s.revoke_key.as_deref() == Some(pk.name.as_str()))
            .map(|s| cyphr::key::Revocation {
                rvk: s.revoke_at.unwrap_or(0),
                by: None,
            })
    };
    let genesis_keys: Result<Vec<Key>, cyphr::error::Error> = pool_keys
        .iter()
        .map(|pk| {
            let key = try_pool_key_to_domain(pk)?;
            Ok(match revoked_at(pk) {
                Some(r) => key.with_revocation(r),
                None => key,
            })
        })
        .collect();

    // Handle genesis-time errors (e.g., unsupported algorithm)
    let genesis_keys = match genesis_keys {
        Ok(keys) => keys,
        Err(e) => {
            // Genesis failed (e.g. unsupported algorithm)
            if let Some(expected) = expected_error
                && expected == error_name(&e)
            {
                println!("  ✓ {} (expected error: {})", fixture.name, expected);
                return;
            }
            panic!(
                "{}: genesis failed with {:?}, but expected error was {:?}",
                fixture.name, e, expected_error
            );
        },
    };

    // A vector with no genesis key at all (`[no-empty-mr]`): there is no
    // principal to replay, so the proposition is the one the constraint
    // states, a state digest computed from zero children. Built from the
    // core's own key tree over no members.
    if genesis_keys.is_empty() {
        let sha256 = [coz::HashAlg::Sha256];
        let root = cyphr::semantic_tree::KeyTree::build_tree(&[], &sha256)
            .and_then(|kt| kt.root(&sha256).map(|_| ()));
        match (root, expected_error) {
            (Err(e), Some(expected)) if error_name(&e) == expected => {
                println!("  ✓ {} (expected error: {})", fixture.name, expected);
                return;
            },
            (got, _) => panic!(
                "{}: an empty key tree gave {got:?}, expected {expected_error:?}",
                fixture.name
            ),
        }
    }

    // A principal is its genesis key, the first listed; every further key
    // enters by a `key/create` the vector's commits carry (SPEC 5.1).
    let genesis_key = genesis_keys
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{}: no genesis key", fixture.name));
    let principal_res = Principal::implicit(genesis_key).await;

    let mut principal = match principal_res {
        Ok(p) => p,
        Err(e) => {
            let err_str = error_name(&e);
            if let Some(expected) = expected_error
                && expected == err_str
            {
                println!("  ✓ {} (expected error: {})", fixture.name, expected);
                return;
            }
            panic!(
                "{}: genesis failed with {:?}, but expected error was {:?}",
                fixture.name, e, expected_error
            );
        },
    };

    // ========================================================================
    // Replay each line through the core's one replay entry point, the path
    // every consumer of a stored or fetched bundle takes: actions first,
    // then each transaction of `txs` as one transaction (SPEC 4.6.2).
    // ========================================================================
    // An embedded peer (SPEC 10.3) is replayed first, and every PR it held
    // is pinned on the test principal to the peer's tip.
    if let Some(peer) = fixture.peer.as_ref().filter(|p| p.embedded) {
        let other = replay_peer(pool, peer, &fixture.name).await;
        for commit in other.commits() {
            let pr = commit.pr().as_multihash().tagged_first().expect("PR");
            let tip = cyphr::Tip::new(&other, 0);
            principal
                .reveal_embedded(&pr.to_string(), cyphr::Tracking::Pin(Box::new(tip)))
                .expect("pin peer");
        }
    }

    if let Some(commits) = &fixture.commits {
        // What the vector's bundles carry, to hold the replay to: no action
        // may be ignored or lost on the way into DT, whichever way it fails.
        let mut carried: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
        for (ci, commit) in commits.iter().enumerate() {
            // The lines are held history, judged as a replay is; an error
            // vector's last line is the submission it pins, judged as
            // admission is.
            let submitted = expected_error.is_some() && ci + 1 == commits.len();
            let replayed = match commit.bundle().map(|b| b.decode()) {
                Ok(Ok(bundle)) if submitted => {
                    cyphr::replay::replay_bundle(&mut principal, &bundle)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.source)
                },
                Ok(Ok(bundle)) => {
                    carried.extend(
                        bundle
                            .action_cozies()
                            .iter()
                            .map(|c| c.czd().as_bytes().to_vec()),
                    );
                    cyphr::replay::replay_held(&mut principal, &bundle)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.source)
                },
                Ok(Err(e)) => Err(match e.error {
                    cyphr::replay::WireError::Protocol(p)
                    | cyphr::replay::WireError::Header(p)
                    | cyphr::replay::WireError::Key(p) => p,
                    other => panic!("{}: line {} is malformed: {other}", fixture.name, ci + 1),
                }),
                Err(e) => panic!("{}: line {} does not serialize: {e}", fixture.name, ci + 1),
            };
            if let Err(e) = replayed {
                match expected_error {
                    Some(expected) => {
                        assert_eq!(
                            error_name(&e),
                            expected,
                            "{}: wrong error at line {}: {e:?}",
                            fixture.name,
                            ci + 1
                        );
                        println!("  ✓ {} (expected error: {})", fixture.name, expected);
                        return;
                    },
                    None => panic!("{}: line {} failed: {e:?}", fixture.name, ci + 1),
                }
            }
        }

        // All commits processed — check for unexpected success on error test
        if let Some(expected) = expected_error {
            panic!(
                "{}: expected error '{}' but all commits succeeded",
                fixture.name, expected
            );
        }

        // A two-principal vector: replay the peer the same way, then the
        // merge status of the test principal (source) into it (SPEC 11.5.1).
        if let Some(peer) = fixture.peer.as_ref().filter(|p| !p.embedded) {
            let other = replay_peer(pool, peer, &fixture.name).await;
            let status = format!("{:?}", cyphr::merge_status(&principal, &other));
            assert_eq!(
                Some(status.as_str()),
                fixture.expected.merge_status.as_deref(),
                "{}: merge_status mismatch",
                fixture.name
            );
        }

        // Actions move no root of their own (SPEC 4.8.1), so a dropped one
        // is invisible to the expected roots below: count them.
        assert_eq!(
            principal.action_count(),
            carried.len(),
            "{}: DT holds a different number of actions than the vector carries",
            fixture.name
        );

        // Verify expected state
        verify_expected(&principal, &fixture.expected, &fixture.name);
        println!("  ✓ {}", fixture.name);
        return;
    }

    // No commits - check for genesis-only test
    panic!(
        "{}: fixture has no commits array - regenerate with fixture-gen",
        fixture.name
    );
}

/// The second principal of a two-principal vector, replayed through the
/// same entry point as the first.
async fn replay_peer(pool: &Pool, peer: &GoldenPeer, name: &str) -> Principal {
    let first = pool
        .get(&peer.principal[0])
        .unwrap_or_else(|| panic!("{name}: peer key not in pool"));
    let mut other = Principal::implicit(try_pool_key_to_domain(first).expect("peer genesis key"))
        .await
        .expect("peer genesis");
    for (ci, commit) in peer.commits.iter().enumerate() {
        let bundle = commit
            .bundle()
            .expect("peer line")
            .decode()
            .expect("peer bundle");
        cyphr::replay::replay_bundle(&mut other, &bundle)
            .await
            .unwrap_or_else(|e| panic!("{name}: peer line {} failed: {e}", ci + 1));
    }
    other
}

async fn run_golden_dir(subdir: &str) {
    let pool = load_pool();
    let dir = golden_dir().join(subdir);

    if !dir.exists() {
        println!("Skipping {} (not found)", subdir);
        return;
    }

    let mut count = 0;
    for entry in fs::read_dir(&dir).expect("failed to read dir") {
        let path = entry.expect("failed to read entry").path();
        if path.extension().is_some_and(|ext| ext == "json") {
            run_golden_test(&path, &pool).await;
            count += 1;
        }
    }
    println!("Ran {} test(s) from {}/", count, subdir);
}

// ============================================================================
// Tests - one per category
// ============================================================================

#[tokio::test]
async fn test_golden_mutations() {
    run_golden_dir("mutations").await;
}

#[tokio::test]
async fn test_golden_multi_key() {
    run_golden_dir("multi_key").await;
}

#[tokio::test]
async fn test_golden_algorithm_diversity() {
    run_golden_dir("algorithm_diversity").await;
}

#[tokio::test]
async fn test_golden_edge_cases() {
    run_golden_dir("edge_cases").await;
}

#[tokio::test]
async fn test_golden_actions() {
    run_golden_dir("actions").await;
}

#[tokio::test]
async fn test_golden_state_computation() {
    run_golden_dir("state_computation").await;
}

// @docket: rv-timestamp-monotone :: scripts/docket-run rv-timestamp-monotone
// @docket: rv-key-set :: scripts/docket-run rv-key-set
// @docket: rv-alg-support :: scripts/docket-run rv-alg-support
#[tokio::test]
async fn test_golden_errors() {
    run_golden_dir("errors").await;
}

#[tokio::test]
async fn test_golden_lifecycle() {
    run_golden_dir("lifecycle").await;
}

#[tokio::test]
async fn test_golden_witness() {
    run_golden_dir("witness").await;
}

/// Structural-constraint vectors (`[commit-one-or-more]`,
/// `[no-empty-mr]`): the vectors `constraint_coverage.md` names as TESTED.
/// Their expected errors are constraint tags, mapped to `Error` variants by
/// [`resolve_constraint_tag`].
#[tokio::test]
async fn test_golden_structural_constraints() {
    run_golden_dir("structural_constraints").await;
}

/// Key-authentication vectors (SPEC 6.4): a revoked key is never re-added.
#[tokio::test]
async fn test_golden_key_auth() {
    run_golden_dir("key_auth").await;
}

/// Transaction grouping vectors (SPEC 3.7.5, 4, 4.1, 4.6.2): the SPEC 4
/// example as one two-coz transaction pins its TX (`txs_order`) and TR,
/// the same pair as two transactions pins another TR, and a transaction
/// mixing `typ`s is refused with `MixedTransactionTyp`. Red if a replay
/// applies each coz as its own transaction or accepts the mix.
#[tokio::test]
async fn test_golden_transaction_grouping() {
    run_golden_dir("transaction_grouping").await;
}

/// Merge vectors (SPEC 11.5.1): a merge alone is pending, an ack alone is
/// no merge, the two with equal fields are merged, and an ack naming
/// another `merge_from` leaves the merge pending.
#[tokio::test]
async fn test_golden_merge() {
    run_golden_dir("merge").await;
}

/// Embedding vectors (SPEC 10.3, 10.5): a principal embeds another's PR in
/// its KT and a key the embedded principal authorizes at its tip signs
/// for it, including a key added after the embedded PR. Red if the
/// embedded member's key is refused or the resulting roots drift.
#[tokio::test]
async fn test_golden_embedding() {
    run_golden_dir("embedding").await;
}
