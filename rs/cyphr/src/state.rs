//! State computation and digest types.
//!
//! Implements SPEC §7 state calculation semantics.

// Only the test-support oracle `compute_pr` uses it at module level.
#[cfg(any(test, feature = "test-utils"))]
use std::collections::BTreeMap;

use coz::Czd;
// `Thumbprint` is only referenced by test-support-only oracle functions
// (compute_kr, derive_auth_state) and unit tests below.
#[cfg(test)]
use coz::Thumbprint;

use crate::multihash::MultihashDigest;

// ============================================================================
// State Digest Trait
// ============================================================================

/// Trait implemented by all state newtype wrappers to retrieve their MultihashDigest.
pub trait StateDigest {
    /// Retrieve the multihash digest.
    fn as_multihash(&self) -> &MultihashDigest;

    /// Get the digest for a specific algorithm variant.
    fn get(&self, alg: HashAlg) -> Option<&[u8]> {
        self.as_multihash().get(alg)
    }
}

// ============================================================================
// State newtypes
// ============================================================================

/// Key State (KS) - SPEC §7.2
///
/// Digest of active key thumbprints.
/// Single key with no nonce: KS = tmb (implicit promotion).
///
/// Now holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyRoot(pub crate::multihash::MultihashDigest);

impl StateDigest for KeyRoot {
    fn as_multihash(&self) -> &crate::multihash::MultihashDigest {
        &self.0
    }
}

/// Auth State (AS) — SPEC §8.4
///
/// Authentication state: `AS = MR(KS, RS?)` or promoted if only KS.
///
/// Holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthRoot(pub MultihashDigest);

impl StateDigest for AuthRoot {
    fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }
}

/// State Root (SR) — SPEC §3.7.2
///
/// Principal state tree root: `SR = MR(AR, DR?, embedding?)`.
/// SR excludes commit information (CR is a sibling of SR in PR, not a child).
/// If DR is None and no embedding, SR = AR (implicit promotion).
///
/// Holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StateRoot(pub MultihashDigest);

impl StateDigest for StateRoot {
    fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }
}

/// Data State (DS) - SPEC §7.4
///
/// State of user actions (Level 4+).
///
/// Holds a [`MultihashDigest`] with one variant per active hash algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataRoot(pub MultihashDigest);

impl StateDigest for DataRoot {
    fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }
}

/// Principal Root (PR) — SPEC §3.7.1
///
/// Current top-level state: `PR = MR(SR, CR?)`.
/// When no CR exists (Levels 1-3), PR = SR (implicit promotion).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrincipalRoot(pub MultihashDigest);

impl StateDigest for PrincipalRoot {
    fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }
}

/// Principal Genesis (PG) - SPEC §3.7.1
///
/// The first PR ever computed. Permanent, never changes.
///
/// The digest is private, so no caller outside this crate can hold a
/// genesis with no variants: each constructor refuses one, and `Display`
/// never prints an empty string. Neither of these builds one:
///
/// ```compile_fail,E0423
/// use cyphr::{MultihashDigest, PrincipalGenesis};
/// let _ = PrincipalGenesis(MultihashDigest::default());
/// ```
///
/// ```compile_fail,E0616
/// use cyphr::{PrincipalGenesis, state::HashAlg};
/// let pg = PrincipalGenesis::from_digest(HashAlg::Sha256, vec![0u8; 32]).unwrap();
/// let _ = &pg.0;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrincipalGenesis(MultihashDigest);

impl PrincipalGenesis {
    /// A PG from a digest `bytes` taken under `alg`, the hash that produced
    /// it. A genesis digest's width follows its genesis key's algorithm
    /// (an Ed25519 identity is 64 bytes, SHA-512), so the caller names the
    /// hash; the width alone would read a SHA-512 digest as something else.
    ///
    /// # Errors
    ///
    /// `DigestLengthMismatch` if `bytes` is not `alg`'s digest width —
    /// reachable from untrusted input such as a CLI-supplied identity.
    pub fn from_digest(alg: HashAlg, bytes: Vec<u8>) -> crate::error::Result<Self> {
        Ok(Self(MultihashDigest::from_single(alg, bytes)?))
    }

    /// A PG from a digest holding one variant per algorithm, as a
    /// principal with a mixed-algorithm keyset has.
    ///
    /// # Errors
    ///
    /// `EmptyMultihash` if `digest` has no variants.
    pub fn from_multihash(digest: MultihashDigest) -> crate::error::Result<Self> {
        if digest.is_empty() {
            return Err(crate::error::Error::EmptyMultihash);
        }
        Ok(Self(digest))
    }

    /// Create PG from the initial PR (at genesis).
    ///
    /// # Errors
    ///
    /// `EmptyMultihash` if `pr` has no variants.
    pub fn from_initial(pr: &PrincipalRoot) -> crate::error::Result<Self> {
        Self::from_multihash(pr.0.clone())
    }
}

impl PrincipalGenesis {
    /// The digest of the spelling [`Display`](std::fmt::Display) prints,
    /// without its label: the form the signed statements a server issues
    /// carry for `pg` (their `alg` aligns it, SPEC 2.2.3). Output only; an
    /// input is never read in this spelling.
    #[must_use]
    pub fn wire_digest(&self) -> String {
        let text = self.to_string();
        text.split_once(':')
            .map_or(text.clone(), |(_, digest)| digest.to_owned())
    }

    /// Whether `digest`, a statement's unlabelled `pg`, is the digest of
    /// one of this genesis's variants. The label is not read: the claim is
    /// a statement field aligned by its `alg`, not an id.
    #[must_use]
    pub fn names_wire_digest(&self, digest: &str) -> bool {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        self.0
            .variants()
            .values()
            .any(|bytes| Base64UrlUnpadded::encode_string(bytes) == digest)
    }
}

impl serde::Serialize for PrincipalGenesis {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for PrincipalGenesis {
    /// The labelled spelling only, parsed by [`FromStr`](std::str::FromStr):
    /// every edge that deserializes an id refuses a bare one the same way.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for PrincipalGenesis {
    type Err = crate::error::Error;

    /// The one parser of a principal id: the labelled spelling
    /// `ALG:digest`, one variant. A string with no `:` is refused before
    /// any decoding, because core cannot know which algorithm a bare
    /// digest came from; every other failure is [`TaggedDigest`]'s.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains(':') {
            return Err(crate::error::Error::MalformedDigest(
                "unlabelled principal id: expected ALG:digest, for example SHA-256:<base64url>",
            ));
        }
        let tagged: TaggedDigest = s.parse()?;
        Self::from_digest(tagged.alg(), tagged.as_bytes().to_vec())
    }
}

impl std::fmt::Display for PrincipalGenesis {
    /// The one canonical spelling: a single `ALG:digest`. A value holding
    /// several variants prints the first in the digest's own order, so the
    /// spelling is deterministic; equality across spellings is
    /// [`MultihashDigest::matches`], not string comparison.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        // The first variant in the digest's own order, the order
        // `active_algs` names an id's algorithm by, so a printed id is the
        // id the engine keys the principal under.
        match self.0.variants().iter().next() {
            Some((alg, digest)) => {
                write!(f, "{alg}:{}", Base64UrlUnpadded::encode_string(digest))
            },
            None => Ok(()),
        }
    }
}

impl StateDigest for PrincipalGenesis {
    fn as_multihash(&self) -> &MultihashDigest {
        &self.0
    }
}

// ============================================================================
// The algorithm table
// ============================================================================

// Coz owns the algorithms: a signing algorithm's name and hash
// (`coz::Alg`), a hash algorithm's name (`HashAlg`'s `Display`), digest
// size and hashing. Cyphr adds only which hash algorithms it supports and
// their EML ids (`crate::commit_root::hash_alg_to_u64`); everything else
// is looked up here rather than re-tabulated.
pub use coz::HashAlg;

/// Every hash algorithm Cyphr supports, keyed by its Coz name (e.g.
/// `SHA-256`) through [`hash_alg_named`]. `hash_alg_to_u64` matches
/// exhaustively on `HashAlg`, so an algorithm Coz adds fails to compile
/// there until it is given an EML id and a row here.
pub const HASH_ALGS: [HashAlg; 3] = [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512];

/// The supported hash algorithm whose Coz name is `name` (e.g. `SHA-256`).
///
/// # Errors
///
/// `UnsupportedAlgorithm` if no supported hash algorithm has that name.
pub fn hash_alg_named(name: &str) -> crate::error::Result<HashAlg> {
    HASH_ALGS
        .into_iter()
        .find(|alg| alg.to_string() == name)
        .ok_or_else(|| crate::error::Error::UnsupportedAlgorithm(name.to_string()))
}

// ============================================================================
// Tagged Digest (algorithm-prefixed digest with parse-time validation)
// ============================================================================

/// A cryptographic digest with explicit algorithm tag.
///
/// Format: `<alg>:<digest>` (e.g., `SHA-256:U5XUZots-WmQ...`)
///
/// Validated during parsing - invalid algorithm/length combinations fail early.
/// This implements "Parse, Don't Validate" - once constructed, the digest is
/// guaranteed to have the correct length for its algorithm.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TaggedDigest {
    alg: HashAlg,
    digest: Vec<u8>,
}

impl TaggedDigest {
    /// Construct a tagged digest from an algorithm and raw digest bytes.
    ///
    /// # Errors
    ///
    /// Returns `DigestLengthMismatch` if `digest`'s length doesn't match
    /// `alg`'s expected output size.
    pub fn new(alg: HashAlg, digest: Vec<u8>) -> crate::error::Result<Self> {
        let expected = Self::expected_len(alg);
        if digest.len() != expected {
            return Err(crate::error::Error::DigestLengthMismatch {
                alg,
                expected,
                actual: digest.len(),
            });
        }
        Ok(Self { alg, digest })
    }

    /// Returns the hash algorithm of this digest.
    #[must_use]
    pub fn alg(&self) -> HashAlg {
        self.alg
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.digest
    }

    /// Returns the expected digest length in bytes for a given algorithm.
    #[must_use]
    pub const fn expected_len(alg: HashAlg) -> usize {
        alg.digest_size()
    }
}

impl std::str::FromStr for TaggedDigest {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (alg_str, digest_b64) =
            s.split_once(':')
                .ok_or(crate::error::Error::MalformedDigest(
                    "missing ':' separator",
                ))?;

        let alg = hash_alg_named(alg_str)?;

        // Decode base64 into a buffer sized for the expected algorithm output
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        let expected = Self::expected_len(alg);

        // Allocate buffer for max possible digest (SHA-512 = 64 bytes)
        let mut buf = [0u8; 64];
        let decoded = Base64UrlUnpadded::decode(digest_b64, &mut buf)
            .map_err(|_| crate::error::Error::MalformedDigest("invalid base64"))?;

        // Validate length matches algorithm
        if decoded.len() != expected {
            return Err(crate::error::Error::DigestLengthMismatch {
                alg,
                expected,
                actual: decoded.len(),
            });
        }

        Ok(Self {
            alg,
            digest: decoded.to_vec(),
        })
    }
}

impl std::fmt::Display for TaggedDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        write!(
            f,
            "{}:{}",
            self.alg,
            Base64UrlUnpadded::encode_string(&self.digest)
        )
    }
}

impl serde::Serialize for TaggedDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for TaggedDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The hash algorithm of the signing algorithm named `alg` (e.g. `ES256`),
/// by Coz's algorithm table.
///
/// # Errors
///
/// Returns `UnknownAlg` if the client's signing algorithm is not one this
/// implementation recognizes or supports — a client-facing protocol
/// question, distinct from `UnsupportedAlgorithm`'s internal algorithm-ID
/// bookkeeping.
pub fn hash_alg_from_str(alg: &str) -> crate::error::Result<HashAlg> {
    coz::Alg::from_str(alg)
        .map(coz::Alg::hash_alg)
        .ok_or(crate::error::Error::UnknownAlg)
}

/// Derive the set of hash algorithms from a keyset (SPEC §14).
///
/// For each active key, its algorithm's hash algorithm, deduplicated and
/// sorted for deterministic ordering. A [`crate::Key`] holds only a
/// supported algorithm, so no key is dropped for an unknown one.
///
/// # Example
///
/// ```ignore
/// use cyphr::state::derive_hash_algs;
/// // ES256 key -> [Sha256]
/// // ES256 + ES384 keys -> [Sha256, Sha384]
/// ```
pub fn derive_hash_algs(keys: &[&crate::Key]) -> Vec<HashAlg> {
    use std::collections::BTreeSet;

    let algs: BTreeSet<HashAlg> = keys
        .iter()
        .filter(|k| k.is_active())
        .map(|k| k.hash_alg())
        .collect();

    algs.into_iter().collect()
}

// ============================================================================
// Core state computation algorithm (SPEC §7.1)
// ============================================================================

/// Compute `H(sort(components...))` returning raw bytes.
///
/// Same as [`hash_sorted_concat`] but returns raw bytes for MultihashDigest construction.
pub(crate) fn hash_sorted_concat_bytes(alg: HashAlg, components: &[&[u8]]) -> Vec<u8> {
    #[cfg(any(test, feature = "test-utils"))]
    crate::probe::hashed();
    // Sort lexicographically
    let mut sorted: Vec<&[u8]> = components.to_vec();
    sorted.sort();

    let mut concat = Vec::new();
    for c in sorted {
        concat.extend_from_slice(c);
    }
    alg.hash_bytes(&concat)
}

/// Compute `H(components...)` in array order (no sort).
///
/// Used where the order is defined, not sorted (SPEC §3.7): CommitID, where
/// coz order is significant (SPEC §8.5), and the Arrow (SPEC §4.2).
pub(crate) fn hash_concat_bytes(alg: HashAlg, components: &[&[u8]]) -> Vec<u8> {
    #[cfg(any(test, feature = "test-utils"))]
    crate::probe::hashed();
    let mut concat = Vec::new();
    for c in components {
        concat.extend_from_slice(c);
    }
    alg.hash_bytes(&concat)
}

/// Hash raw bytes using the specified algorithm (SPEC §14.2 conversion).
///
/// Used when converting a czd from one algorithm to another.
pub(crate) fn hash_bytes(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    #[cfg(any(test, feature = "test-utils"))]
    crate::probe::hashed();
    alg.hash_bytes(data)
}

// ============================================================================
// State computation functions
// ============================================================================

/// Compute Key State (SPEC §7.2).
///
/// - Single key, no nonce: KS = tmb (implicit promotion to single-variant multihash)
/// - Otherwise: KS = H(sort(tmb₀, tmb₁, nonce?, ...)) for each algorithm
///
/// The `algs` slice specifies which hash algorithms to include in the multihash.
/// For single-algorithm keysets, pass a single-element slice.
///
/// This is an independent oracle over the same formula
/// [`crate::semantic_tree::KeyTree`] (a `polydigest::EpochTree`, k=256, one
/// leaf per active key thumbprint, lexically sorted) computes structurally,
/// so the two independently-written implementations can be cross-checked
/// against each other. The two agree byte-for-byte for single-hash-algorithm
/// keysets; for mixed-hash-algorithm keysets `KeyTree` additionally converts
/// each non-native thumbprint to its target algorithm's canonical digest
/// (the same `hash_bytes` conversion [`compute_dr`] applies to czd content)
/// before folding, which this function does not do — see
/// `semantic_tree`'s `oracle_kr_*` differential tests for the exact,
/// predicted divergence. `Principal`'s actual KR is produced by the tree
/// itself, never by this function.
///
/// # Errors
///
/// Returns `NoActiveKeys` if `algs` is empty.
#[cfg(test)]
pub(crate) fn compute_kr(
    thumbprints: &[&Thumbprint],
    nonce: Option<&[u8]>,
    algs: &[HashAlg],
) -> crate::error::Result<KeyRoot> {
    use std::collections::BTreeMap;

    use crate::multihash::MultihashDigest;

    if algs.is_empty() {
        return Err(crate::error::Error::NoActiveKeys);
    }

    // Implicit promotion: single key, no nonce
    // The thumbprint becomes the single-variant multihash
    if thumbprints.len() == 1 && nonce.is_none() {
        // Use the first algorithm for the promoted thumbprint
        let alg = algs[0];
        return Ok(KeyRoot(MultihashDigest::from_single(
            alg,
            thumbprints[0].as_bytes().to_vec(),
        )?));
    }

    // Collect components
    let mut components: Vec<&[u8]> = thumbprints.iter().map(|t| t.as_bytes()).collect();
    if let Some(n) = nonce {
        components.push(n);
    }

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    Ok(KeyRoot(MultihashDigest::new(variants)?))
}

/// A czd tagged with its source hash algorithm.
///
/// Used for cross-algorithm state computation where czds from different
/// signing algorithms need to be converted to a common hash algorithm.
#[derive(Debug, Clone)]
pub struct TaggedCzd<'a> {
    /// The raw czd bytes.
    pub czd: &'a Czd,
    /// Hash algorithm that produced this czd (from signing key).
    pub alg: HashAlg,
}

impl<'a> TaggedCzd<'a> {
    /// Create a new tagged czd.
    pub fn new(czd: &'a Czd, alg: HashAlg) -> Self {
        Self { czd, alg }
    }

    /// Convert this czd to target algorithm.
    ///
    /// If source and target algorithms match, returns the raw bytes.
    /// Otherwise, re-hashes the czd bytes with the target algorithm.
    pub fn convert_to(&self, target: HashAlg) -> Vec<u8> {
        if self.alg == target {
            // Same algorithm: use raw bytes
            self.czd.as_bytes().to_vec()
        } else {
            // Different algorithm: re-hash (SPEC §14.2 conversion)
            hash_bytes(target, self.czd.as_bytes())
        }
    }
}

/// Compute Auth Root — SPEC §3.7.
///
/// `AR = MR(KR, RR?, embedding?)` — authentication state derived from keyset.
///
/// - Only KR, no nonce/embedding: AR = KR (implicit promotion)
/// - Otherwise: AR = H(sort(KR, RR?, nonce?, embedding?))
///
/// `embedding` is reserved for future use; pass `None`.
///
/// This is an independent oracle over the same formula
/// [`crate::semantic_tree::AuthTree`] (a `polydigest::EpochTree`, k=2, cell
/// 0 = KT's root, cell 1 = RT's root) computes structurally, so the two
/// independently-written implementations can be cross-checked against each
/// other. RT is never implemented today, so `AuthTree`'s cell 1 is always
/// absent and it always promotes from KT alone — the two agree
/// byte-for-byte unconditionally. `Principal`'s actual AR is produced by
/// the tree itself, never by this function.
///
/// # Errors
///
/// Returns `EmptyMultihash` if the KeyRoot contains no variants.
#[cfg(test)]
pub(crate) fn compute_ar(
    ks: &KeyRoot,
    // rs: Option<&RuleRoot>,  // Level 5, not yet implemented
    nonce: Option<&[u8]>,
    embedding: Option<&[u8]>,
    algs: &[HashAlg],
) -> crate::error::Result<AuthRoot> {
    // Implicit promotion: only KR, no nonce, no embedding
    if nonce.is_none() && embedding.is_none() {
        return Ok(AuthRoot(ks.0.clone()));
    }

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let kr_bytes = ks.0.get_or_err(alg)?;

        // Collect non-nil components
        let mut components: Vec<&[u8]> = vec![kr_bytes];
        // TODO: Level 5 — add RR component here when RuleRoot is implemented
        if let Some(n) = nonce {
            components.push(n);
        }
        if let Some(e) = embedding {
            components.push(e);
        }

        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    Ok(AuthRoot(MultihashDigest::new(variants)?))
}

/// Compute State Root — SPEC §3.7.2.
///
/// `SR = MR(AR, DR?, embedding?)` — principal state tree root.
///
/// - If ds is None and no embedding: SR promotes from AR
/// - Otherwise: SR = H(sort(AR, DR?, embedding?)) for each algorithm
///
/// `embedding` is reserved for future use; pass `None`.
///
/// This is an independent oracle over the same formula
/// [`crate::semantic_tree::StateTree`] (a `polydigest::EpochTree`, k=2, cell
/// 0 = AR-node's root, cell 1 = DR) computes structurally, so the two
/// independently-written implementations can be cross-checked against each
/// other. They agree byte-for-byte whenever `ds` is absent (promotion, the
/// common case). When `ds` is present, this function sorts `AR`/`DR`
/// lexically before concatenating, while `StateTree` concatenates them
/// positionally (`AR ∥ DR`, its fixed cell order) — the two diverge exactly
/// when `DR`'s bytes lexically precede `AR`'s; see `semantic_tree`'s
/// `oracle_ar_sr_*` differential tests for the predicted-divergence proof.
/// `Principal`'s actual SR is produced by the tree itself, never by this
/// function.
///
/// # Errors
///
/// Returns `EmptyMultihash` if AuthRoot contains no variants.
#[cfg(test)]
pub(crate) fn compute_sr(
    auth_root: &AuthRoot,
    ds: Option<&DataRoot>,
    embedding: Option<&[u8]>,
    algs: &[HashAlg],
) -> crate::error::Result<StateRoot> {
    // Implicit promotion: no DS, no embedding → SR = AR
    if ds.is_none() && embedding.is_none() {
        return Ok(StateRoot(auth_root.0.clone()));
    }

    // Compute hash for each algorithm variant
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let ar_bytes = auth_root.0.get_or_err(alg)?;

        let mut components: Vec<&[u8]> = vec![ar_bytes];
        if let Some(d) = ds {
            components.push(d.0.get_or_err(alg)?);
        }
        if let Some(e) = embedding {
            components.push(e);
        }
        let digest = hash_sorted_concat_bytes(alg, &components);
        variants.insert(alg, digest.into_boxed_slice());
    }

    Ok(StateRoot(MultihashDigest::new(variants)?))
}

/// Compute Data State (SPEC §7.4).
///
/// - No actions, no nonce: DS = None
/// - Single action, no nonce: DS = czd (implicit promotion)
/// - Otherwise: DS = H(sort(czd₀, czd₁, nonce?, ...))
///
/// Each component is converted to every target algorithm from the
/// algorithm it is in (an action's signing key's, a nonce's label), never
/// from one guessed from its width.
pub fn compute_dr(
    actions: &[&crate::action::Action],
    nonce: Option<&TaggedDigest>,
    algs: &[HashAlg],
) -> crate::error::Result<Option<DataRoot>> {
    use std::collections::BTreeMap;

    use crate::multihash::MultihashDigest;

    if actions.is_empty() && nonce.is_none() {
        return Ok(None);
    }

    // Implicit promotion: single action, no nonce.
    // Convert the action's single-algorithm czd to all target algorithms.
    if actions.len() == 1 && nonce.is_none() {
        let tagged = TaggedCzd::new(actions[0].czd(), actions[0].hash_alg());
        let mut variants = BTreeMap::new();
        for &target_alg in algs {
            let converted = tagged.convert_to(target_alg);
            variants.insert(target_alg, converted.into_boxed_slice());
        }
        let mh = MultihashDigest::new(variants)?;
        return Ok(Some(DataRoot(mh)));
    }

    // Sort components: actions by now then czd, non-actions by digest bytes
    struct DrComponent<'a> {
        bytes: &'a [u8],
        alg: HashAlg,
        now: i64,
    }

    let mut components = Vec::new();
    for a in actions {
        components.push(DrComponent {
            bytes: a.czd().as_bytes(),
            alg: a.hash_alg(),
            now: a.now(),
        });
    }
    if let Some(n) = nonce {
        components.push(DrComponent {
            bytes: n.as_bytes(),
            alg: n.alg(),
            now: i64::MAX,
        });
    }
    components.sort_by(|a, b| match a.now.cmp(&b.now) {
        std::cmp::Ordering::Equal => a.bytes.cmp(b.bytes),
        other => other,
    });

    let mut variants = BTreeMap::new();
    for &alg in algs {
        // Convert components to the target algorithm
        let mut converted_components = Vec::new();
        for comp in &components {
            if comp.alg == alg {
                converted_components.push(comp.bytes.to_vec());
            } else {
                converted_components.push(hash_bytes(alg, comp.bytes));
            }
        }

        let refs: Vec<&[u8]> = converted_components.iter().map(|v| v.as_slice()).collect();
        let bytes = hash_concat_bytes(alg, &refs);
        variants.insert(alg, digest_into_boxed_slice(bytes));
    }

    let mh = MultihashDigest::new(variants)?;
    Ok(Some(DataRoot(mh)))
}

fn digest_into_boxed_slice(v: Vec<u8>) -> Box<[u8]> {
    v.into_boxed_slice()
}

/// Compute Principal Root — SPEC §3.7.1.
///
/// `PR = MR(SR, CR?)` — top-level state.
/// If CR is None (Levels 1-3), PR = SR (implicit promotion).
///
/// This is an independent oracle over the same formula the real
/// `PrincipalTree` (a `polydigest::EpochTree`, k=2, cell 0 = SR, cell 1 = CR)
/// computes structurally: positional (never lexically sorted) concatenation,
/// matching the tree's fixed cell order, so the two independently-written
/// implementations can be cross-checked against each other (see
/// `cyphr-storage/tests/e2e.rs`'s multihash-coherence recomputation).
/// `Principal`'s actual PR is produced by the tree itself
/// (`EpochTree::root(alg_id)`), never by this function.
///
/// # Errors
///
/// Returns `EmptyMultihash` if the StateRoot contains no variants.
#[cfg(any(test, feature = "test-utils"))]
pub fn compute_pr(
    state_root: &StateRoot,
    cr: Option<&crate::commit_root::CommitRoot>,
    algs: &[HashAlg],
) -> crate::error::Result<PrincipalRoot> {
    // Implicit promotion: only SR, no CR
    let Some(cr) = cr else {
        return Ok(PrincipalRoot(state_root.0.clone()));
    };

    // Compute hash for each algorithm variant: H(SR || CR), array order (no
    // sort) — matches the tree's fixed cell order (SR at cell 0, CR at cell 1).
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let sr_bytes = state_root.0.get_or_err(alg)?;
        let cr_bytes = cr.0.get_or_err(alg)?;
        let digest = hash_concat_bytes(alg, &[sr_bytes, cr_bytes]);
        variants.insert(alg, digest.into_boxed_slice());
    }

    Ok(PrincipalRoot(MultihashDigest::new(variants)?))
}

// ============================================================================
// Composite derivation helpers
// ============================================================================

/// Compute KR → AR → SR from a set of thumbprints and an optional DataRoot,
/// chaining the three oracle functions above.
///
/// An oracle-of-oracles: the differential-test counterpart of
/// [`crate::semantic_tree::derive_state_roots`], which is what every
/// production call site actually uses. No production code calls this
/// function anymore — it exists purely so oracle tests can get the full
/// KR/AR/SR chain from the old formulas in one call, mirroring
/// `derive_state_roots`'s exact signature.
#[cfg(test)]
pub(crate) fn derive_auth_state(
    thumbprints: &[&Thumbprint],
    dr: Option<&DataRoot>,
    algs: &[HashAlg],
) -> crate::error::Result<(KeyRoot, AuthRoot, StateRoot)> {
    let kr = compute_kr(thumbprints, None, algs)?;
    let ar = compute_ar(&kr, None, None, algs)?;
    let sr = compute_sr(&ar, dr, None, algs)?;
    Ok((kr, ar, sr))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// F46 regression: a digest of the wrong width for its algorithm is
    /// refused with `DigestLengthMismatch`, not a panic; a 64-byte SHA-512
    /// genesis is read as SHA-512. A unit test because the CLI reaches
    /// this constructor only after it has picked the algorithm itself.
    #[test]
    fn principal_genesis_from_digest_follows_its_algorithm() {
        let result = PrincipalGenesis::from_digest(HashAlg::Sha256, vec![0xAA; 31]);
        assert!(matches!(
            result,
            Err(crate::error::Error::DigestLengthMismatch {
                alg: HashAlg::Sha256,
                expected: 32,
                actual: 31,
            })
        ));
        let pg = PrincipalGenesis::from_digest(HashAlg::Sha512, vec![0xAA; 64]).unwrap();
        assert_eq!(pg.0.algorithms().collect::<Vec<_>>(), [HashAlg::Sha512]);
    }

    #[test]
    fn cross_algorithm_promotion_dr() {
        let czd = Czd::from_bytes(vec![10; 32]); // SHA-256 size
        let active_algs = [HashAlg::Sha256, HashAlg::Sha384];
        let action = crate::action::Action::new(
            "cyphr.me/comment/create".to_string(),
            Thumbprint::from_bytes(vec![1; 32]),
            1000,
            czd.clone(),
            HashAlg::Sha256,
            coz::CozJson {
                pay: serde_json::Value::Null,
                sig: vec![],
            },
        );

        // 1. DR promotion test
        let dr = compute_dr(&[&action], None, &active_algs).unwrap().unwrap();
        assert!(dr.0.contains(HashAlg::Sha256));
        assert!(dr.0.contains(HashAlg::Sha384));

        let dr_sha256 = dr.0.get(HashAlg::Sha256).unwrap();
        let dr_sha384 = dr.0.get(HashAlg::Sha384).unwrap();

        assert_eq!(dr_sha256, czd.as_bytes());
        // For Sha384, it should be the converted (re-hashed) version
        assert_eq!(
            dr_sha384,
            hash_bytes(HashAlg::Sha384, czd.as_bytes()).as_slice()
        );
    }

    // ========================================================================
    // TaggedDigest tests
    // ========================================================================

    #[test]
    fn tagged_digest_missing_separator() {
        let input = "SHA-256U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let result: Result<super::TaggedDigest, _> = input.parse();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::error::Error::MalformedDigest(_)),
            "expected MalformedDigest, got {:?}",
            err
        );
    }

    #[test]
    fn tagged_digest_unknown_algorithm() {
        let input = "SHA-999:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let result: Result<super::TaggedDigest, _> = input.parse();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, crate::error::Error::UnsupportedAlgorithm(_)),
            "expected UnsupportedAlgorithm, got {:?}",
            err
        );
    }

    #[test]
    fn tagged_digest_length_mismatch() {
        // SHA-256 expects 32 bytes, but this is only 16 bytes
        // 16 bytes = 22 chars base64url (AAAAAAAAAAAAAAAAAAAAAA)
        let input = "SHA-256:AAAAAAAAAAAAAAAAAAAAAA";
        let result: Result<super::TaggedDigest, _> = input.parse();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::DigestLengthMismatch {
                    alg: super::HashAlg::Sha256,
                    expected: 32,
                    actual: 16,
                }
            ),
            "expected DigestLengthMismatch, got {:?}",
            err
        );
    }
}
