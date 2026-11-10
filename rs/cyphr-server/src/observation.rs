//! The durable, server-local global key death-set (SPEC.md §6.4).
//!
//! A witness that accepts a self-signed naked `key/revoke` coz records the
//! revoked key's thumbprint *here*, deliberately not on any principal's chain
//! and not in the rebuildable index:
//!
//! - A naked revoke mutates no PR (SPEC §6.4): the principal's chain is untouched, so the chain is
//!   the wrong home.
//! - The index is a derived projection a reindex rebuilds from blobs (root `AGENTS.md` I1): a death
//!   record kept there would be silently wiped by the next reindex, which is exactly the durability
//!   the acceptance suite pins against.
//!
//! So this is independent, durable, server-local truth: its own fjall
//! database, opened beside the blob store and the index, keyed by the revoked
//! key's thumbprint ALONE. Death is global by thumbprint -- one slot per key,
//! no principal scoping -- so the key is refused for every capability and
//! every principal that holds it.

use std::path::Path;

use coz::Thumbprint;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};

/// Keyspace and key under which a dedicated fjall store records its format
/// version, as decimal text.
const META_KEYSPACE: &str = "meta";
const VERSION_KEY: &str = "format-version";

/// The format version of the death set and the admission spent set. A store
/// with no recorded version predates versions and is v1 (same layout).
pub(crate) const STORE_FORMAT_VERSION: u32 = 1;

/// Why a store's recorded format version could not be accepted.
#[derive(Debug)]
pub(crate) enum StampError {
    /// fjall failed reading or writing the record.
    Backend(String),
    /// The record is not a decimal number.
    NotANumber(String),
    /// The store states a version this build does not read.
    Unsupported { found: u64 },
}

/// Check the format version recorded in `db`'s meta keyspace, stamping
/// [`STORE_FORMAT_VERSION`] when none is recorded (a store from before
/// versions is v1). Called on open, before any data keyspace is read, so a
/// store this build cannot interpret is never mis-decoded.
pub(crate) fn check_store_version(db: &Database) -> Result<(), StampError> {
    let backend = |e: fjall::Error| StampError::Backend(e.to_string());
    let meta = db
        .keyspace(META_KEYSPACE, KeyspaceCreateOptions::default)
        .map_err(backend)?;
    match meta.get(VERSION_KEY).map_err(backend)? {
        Some(raw) => {
            let text = String::from_utf8_lossy(&raw);
            let found: u64 = text
                .trim()
                .parse()
                .map_err(|_| StampError::NotANumber(text.into_owned()))?;
            if found == u64::from(STORE_FORMAT_VERSION) {
                Ok(())
            } else {
                Err(StampError::Unsupported { found })
            }
        },
        None => {
            meta.insert(VERSION_KEY, STORE_FORMAT_VERSION.to_string())
                .map_err(backend)?;
            db.persist(PersistMode::SyncAll).map_err(backend)
        },
    }
}

/// Failures from the death-set store. A store failure is server
/// infrastructure breaking, never a client error.
#[derive(Debug, thiserror::Error)]
pub enum ObservationError {
    /// The underlying fjall store failed.
    #[error("death-set store backend: {0}")]
    Backend(String),
    /// A `spawn_blocking` task failed to join.
    #[error("death-set store task join: {0}")]
    Join(String),
    /// Serializing a death record failed.
    #[error("death-set serialize: {0}")]
    Serialize(String),
    /// The store records a format version this build does not read. Nothing
    /// was read from it: a mis-decoded death set would un-revoke keys.
    #[error("death set format version {found} is not the supported {supported}")]
    UnsupportedVersion { found: u64, supported: u32 },
    /// The death set already holds the operator's ceiling of keys
    /// (`[limits] max_dead_keys`): a refusal of the new record, not a fault.
    #[error("death set is full ({ceiling} keys)")]
    Full { ceiling: u64 },
}

impl From<StampError> for ObservationError {
    fn from(e: StampError) -> Self {
        match e {
            StampError::Backend(m) => Self::Backend(m),
            StampError::NotANumber(t) => {
                Self::Backend(format!("recorded format version is not a number: {t:?}"))
            },
            StampError::Unsupported { found } => Self::UnsupportedVersion {
                found,
                supported: STORE_FORMAT_VERSION,
            },
        }
    }
}

fn backend(e: fjall::Error) -> ObservationError {
    ObservationError::Backend(e.to_string())
}

/// A durable server-local set of naked-revoked (dead) keys, backed by a
/// dedicated fjall database and keyed by thumbprint.
pub struct ObservationStore {
    /// The backing database. Held so the keyspace outlives it, and used to
    /// force a synchronous journal fsync after a death is recorded (fjall's
    /// per-insert durability is only `PersistMode::Buffer`).
    db: Database,
    dead_keys: Keyspace,
    /// How many keys the death set holds, guarded so the ceiling check and
    /// the insert are one step.
    dead_count: std::sync::Arc<std::sync::Mutex<u64>>,
    /// The most keys the death set may hold ([`Self::with_ceiling`]).
    ceiling: u64,
}

impl ObservationStore {
    /// Open or create the death-set store at `path`, owning a dedicated
    /// database (separate from the blob store and the index, so its failure
    /// domain is independent of theirs and a reindex cannot wipe it).
    pub fn open(path: &Path) -> Result<Self, ObservationError> {
        let db = Database::builder(path).open().map_err(backend)?;
        check_store_version(&db)?;
        let dead_keys = db
            .keyspace("observations", KeyspaceCreateOptions::default)
            .map_err(backend)?;
        let mut count = 0u64;
        for entry in dead_keys.iter() {
            entry.key().map_err(backend)?;
            count += 1;
        }
        Ok(Self {
            db,
            dead_keys,
            dead_count: std::sync::Arc::new(std::sync::Mutex::new(count)),
            ceiling: u64::MAX,
        })
    }

    /// Bound the death set to `ceiling` keys for [`Self::record`]. A naked
    /// revoke needs no prior knowledge of its key (a Level 1 key signs
    /// nothing a peer could have seen, SPEC 6.4), so revokes of unseen keys
    /// are bounded by this operator quota; past it [`Self::record`] is
    /// refused [`ObservationError::Full`] and stores nothing, while
    /// [`Self::record_seen`] still records a key the server holds.
    #[must_use]
    pub fn with_ceiling(mut self, ceiling: u64) -> Self {
        self.ceiling = ceiling;
        self
    }

    /// Record `tmb` as dead, retaining `coz` (the revoke as received) as the
    /// value so the claim can be surfaced later.
    ///
    /// Keyed on the thumbprint alone, so it is idempotent by construction: a
    /// re-revoke of an already-dead key is a no-op (see the short-circuit
    /// below) and changes nothing observable.
    ///
    /// The insert is followed by a synchronous journal fsync
    /// (`PersistMode::SyncAll`) before returning: fjall's default per-insert
    /// durability is only `PersistMode::Buffer`, which leaves the write in OS
    /// buffers, so a crash before the next flush could lose a death record the
    /// caller was already told was recorded. Fsyncing here makes the `recorded`
    /// acknowledgement honest under a power loss, at the cost of one fsync per
    /// *first* revoke of a key -- acceptable for a rare security event.
    ///
    /// A key already dead short-circuits to a read-only `contains_key` before
    /// touching the write path: since a re-revoke changes nothing observable
    /// (the key was already refused everywhere), the redundant insert and its
    /// fsync would only be amplification for whoever calls this -- a revoke is
    /// idempotent and pre-signed replays are accepted, so a cheap repeated
    /// POST would otherwise force one synchronous disk fsync each time.
    ///
    /// Past the ceiling ([`Self::with_ceiling`]) a new key is refused
    /// [`ObservationError::Full`]; [`Self::record_seen`] records past it.
    pub async fn record(
        &self,
        tmb: &Thumbprint,
        coz: serde_json::Value,
    ) -> Result<(), ObservationError> {
        self.insert(tmb, coz, true).await
    }

    /// [`Self::record`] for a key the caller has established the server has
    /// seen (one a stored principal holds), recorded even past the ceiling:
    /// the ceiling bounds revokes of keys nobody here holds, and must never
    /// deny the revoke of a key real principals hold (SPEC 6.4).
    pub async fn record_seen(
        &self,
        tmb: &Thumbprint,
        coz: serde_json::Value,
    ) -> Result<(), ObservationError> {
        self.insert(tmb, coz, false).await
    }

    async fn insert(
        &self,
        tmb: &Thumbprint,
        coz: serde_json::Value,
        bounded: bool,
    ) -> Result<(), ObservationError> {
        let key = tmb.as_bytes().to_vec();
        let value =
            serde_json::to_vec(&coz).map_err(|e| ObservationError::Serialize(e.to_string()))?;
        let dead_keys = self.dead_keys.clone();
        let db = self.db.clone();
        let (dead_count, ceiling) = (self.dead_count.clone(), self.ceiling);
        tokio::task::spawn_blocking(move || {
            if dead_keys.contains_key(&key).map_err(backend)? {
                return Ok(());
            }
            let mut count = dead_count.lock().unwrap_or_else(|p| p.into_inner());
            if bounded && *count >= ceiling {
                return Err(ObservationError::Full { ceiling });
            }
            dead_keys.insert(key, value).map_err(backend)?;
            db.persist(PersistMode::SyncAll).map_err(backend)?;
            *count += 1;
            Ok(())
        })
        .await
        .map_err(|e| ObservationError::Join(e.to_string()))?
    }

    /// Whether `coz` introduces a dead key: a `key/create` or `key/replace`
    /// whose `pay.id` names a thumbprint in the death set (SPEC §6.4), so a
    /// revoked key cannot be re-added to any principal. A coz of another
    /// type, or one with no decodable `pay.id`, introduces nothing here and
    /// is left to the engine's own validation.
    ///
    /// Like the signer fence, this reads an unverified, client-declared
    /// field and is compliant only because its outcome is pure refusal.
    pub async fn introduces_dead_key(
        &self,
        coz: &serde_json::Value,
    ) -> Result<bool, ObservationError> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let pay = &coz["pay"];
        if !cyphr::parsed_coz::typ::is_key_introducing(pay["typ"].as_str().unwrap_or("")) {
            return Ok(false);
        }
        let Some(Ok(id)) = pay["id"].as_str().map(Base64UrlUnpadded::decode_vec) else {
            return Ok(false);
        };
        self.is_dead(&Thumbprint::from_bytes(id)).await
    }

    /// The revoke envelope recorded for `tmb`, as it was received, or
    /// `None` when the key is not dead. Served by `GET /revoked` so a peer's
    /// readers can verify the death themselves.
    pub async fn revoke_of(
        &self,
        tmb: &Thumbprint,
    ) -> Result<Option<serde_json::Value>, ObservationError> {
        let key = tmb.as_bytes().to_vec();
        let dead_keys = self.dead_keys.clone();
        let stored = tokio::task::spawn_blocking(move || dead_keys.get(&key).map_err(backend))
            .await
            .map_err(|e| ObservationError::Join(e.to_string()))??;
        stored
            .map(|raw| {
                serde_json::from_slice(&raw).map_err(|e| ObservationError::Serialize(e.to_string()))
            })
            .transpose()
    }

    /// Whether `tmb` is dead (carries a naked-revoke record). A true here
    /// refuses the key for every capability, even though it may still be
    /// active on-chain.
    pub async fn is_dead(&self, tmb: &Thumbprint) -> Result<bool, ObservationError> {
        let key = tmb.as_bytes().to_vec();
        let dead_keys = self.dead_keys.clone();
        tokio::task::spawn_blocking(move || dead_keys.contains_key(&key).map_err(backend))
            .await
            .map_err(|e| ObservationError::Join(e.to_string()))?
    }
}
