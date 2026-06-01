//! SQLite-backed [`Indexer`] implementation.

use cyphr::state::TaggedDigest;
use cyphr_storage::blob::Blake3Hash;
use cyphr_storage::index::{
    CommitRef, EntityRef, EntityType, IndexableCommit, IndexableCoz, Indexer, IndexerError,
    PrincipalSummary, PublicKeyInfo, TipState,
};

/// Production-grade indexer backed by SQLite.
pub struct SqliteIndexer {
    tx: tokio::sync::mpsc::Sender<ActorMessage>,
}

enum ActorMessage {
    IndexCommit {
        commit: IndexableCommit,
        respond_to: tokio::sync::oneshot::Sender<Result<(), IndexerError>>,
    },
    GetTip {
        principal_id: String,
        respond_to: tokio::sync::oneshot::Sender<Result<Option<TipState>, IndexerError>>,
    },
    GetCommitChain {
        principal_id: String,
        from: Option<u64>,
        to: Option<u64>,
        respond_to: tokio::sync::oneshot::Sender<Result<Vec<CommitRef>, IndexerError>>,
    },
    ResolveDigest {
        digest: TaggedDigest,
        respond_to: tokio::sync::oneshot::Sender<Result<Option<EntityRef>, IndexerError>>,
    },
    ListPrincipals {
        respond_to: tokio::sync::oneshot::Sender<Result<Vec<PrincipalSummary>, IndexerError>>,
    },
    Clear {
        respond_to: tokio::sync::oneshot::Sender<Result<(), IndexerError>>,
    },
    IsBlobIndexed {
        hash: Blake3Hash,
        respond_to: tokio::sync::oneshot::Sender<Result<bool, IndexerError>>,
    },
    GetKey {
        thumbprint: String,
        respond_to: tokio::sync::oneshot::Sender<Result<Option<PublicKeyInfo>, IndexerError>>,
    },
}

impl SqliteIndexer {
    /// Open a persistent SQLite database at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self, IndexerError> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| IndexerError::Backend(format!("failed to open sqlite database: {e}")))?;
        Self::from_connection(conn)
    }

    /// Create an in-memory SQLite database.
    pub fn memory() -> Result<Self, IndexerError> {
        let conn = rusqlite::Connection::open_in_memory().map_err(|e| {
            IndexerError::Backend(format!("failed to open memory sqlite database: {e}"))
        })?;
        Self::from_connection(conn)
    }

    /// Create an indexer from a connection and start the background actor loop.
    pub fn from_connection(conn: rusqlite::Connection) -> Result<Self, IndexerError> {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -8000;
            PRAGMA foreign_keys = OFF;
            PRAGMA busy_timeout = 5000;
        ",
        )
        .map_err(|e| IndexerError::Backend(e.to_string()))?;

        // Initialize schema
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS cozies (
                blob_hash     TEXT NOT NULL,
                czd           TEXT NOT NULL,
                principal_id  TEXT NOT NULL,
                typ           TEXT NOT NULL,
                tmb           TEXT NOT NULL,
                alg           TEXT NOT NULL,
                now           INTEGER NOT NULL,
                commit_seq    INTEGER,
                payload       TEXT,
                PRIMARY KEY (czd)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS commits (
                principal_id  TEXT NOT NULL,
                sequence      INTEGER NOT NULL,
                commit_czd    TEXT NOT NULL,
                pre           TEXT,
                pr            TEXT NOT NULL,
                sr            TEXT NOT NULL,
                ar            TEXT NOT NULL,
                blob_hashes   TEXT NOT NULL,
                created_at    INTEGER NOT NULL,
                PRIMARY KEY (principal_id, sequence)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS digests (
                digest        TEXT PRIMARY KEY,
                blob_hash     TEXT NOT NULL,
                entity_type   TEXT NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS public_keys (
                thumbprint    TEXT PRIMARY KEY,
                algorithm     TEXT NOT NULL,
                principal_id  TEXT NOT NULL,
                public_key    TEXT NOT NULL,
                introduced_at INTEGER NOT NULL,
                revoked_at    INTEGER
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS tips (
                principal_id  TEXT PRIMARY KEY,
                pr            TEXT NOT NULL,
                sr            TEXT NOT NULL,
                ar            TEXT NOT NULL,
                commit_czd    TEXT NOT NULL,
                commit_count  INTEGER NOT NULL,
                last_updated  INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS principals (
                principal_id  TEXT PRIMARY KEY,
                pr            TEXT NOT NULL,
                commit_count  INTEGER NOT NULL,
                created       INTEGER NOT NULL,
                last_updated  INTEGER NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_cozies_typ       ON cozies(typ);
            CREATE INDEX IF NOT EXISTS idx_cozies_tmb       ON cozies(tmb);
            CREATE INDEX IF NOT EXISTS idx_cozies_now       ON cozies(now);
            CREATE INDEX IF NOT EXISTS idx_cozies_principal ON cozies(principal_id);
            CREATE INDEX IF NOT EXISTS idx_cozies_blob      ON cozies(blob_hash);
            CREATE INDEX IF NOT EXISTS idx_cozies_commit    ON cozies(principal_id, commit_seq);

            CREATE INDEX IF NOT EXISTS idx_commits_czd      ON commits(commit_czd);
            CREATE INDEX IF NOT EXISTS idx_commits_time     ON commits(created_at);

            CREATE INDEX IF NOT EXISTS idx_digests_blob     ON digests(blob_hash);

            CREATE INDEX IF NOT EXISTS idx_keys_principal   ON public_keys(principal_id);

            INSERT OR IGNORE INTO schema_version (version) VALUES (1);
        ",
        )
        .map_err(|e| IndexerError::Backend(format!("failed to initialize schema: {e}")))?;

        let (tx, rx) = tokio::sync::mpsc::channel(100);
        std::thread::spawn(move || {
            run_actor(conn, rx);
        });

        Ok(Self { tx })
    }
}

fn map_sqlite_err(e: rusqlite::Error) -> IndexerError {
    match e {
        rusqlite::Error::QueryReturnedNoRows => {
            IndexerError::NotFound("query returned no rows".to_string())
        },
        other => IndexerError::Backend(other.to_string()),
    }
}

fn run_actor(mut conn: rusqlite::Connection, mut rx: tokio::sync::mpsc::Receiver<ActorMessage>) {
    while let Some(msg) = rx.blocking_recv() {
        match msg {
            ActorMessage::IndexCommit { commit, respond_to } => {
                let res = db_index_commit(&mut conn, &commit);
                let _ = respond_to.send(res);
            },
            ActorMessage::GetTip {
                principal_id,
                respond_to,
            } => {
                let res = db_get_tip(&conn, &principal_id);
                let _ = respond_to.send(res);
            },
            ActorMessage::GetCommitChain {
                principal_id,
                from,
                to,
                respond_to,
            } => {
                let res = db_get_commit_chain(&conn, &principal_id, from, to);
                let _ = respond_to.send(res);
            },
            ActorMessage::ResolveDigest { digest, respond_to } => {
                let res = db_resolve_digest(&conn, &digest);
                let _ = respond_to.send(res);
            },
            ActorMessage::ListPrincipals { respond_to } => {
                let res = db_list_principals(&conn);
                let _ = respond_to.send(res);
            },
            ActorMessage::Clear { respond_to } => {
                let res = db_clear(&mut conn);
                let _ = respond_to.send(res);
            },
            ActorMessage::IsBlobIndexed { hash, respond_to } => {
                let res = db_is_blob_indexed(&conn, &hash);
                let _ = respond_to.send(res);
            },
            ActorMessage::GetKey {
                thumbprint,
                respond_to,
            } => {
                let res = db_get_key(&conn, &thumbprint);
                let _ = respond_to.send(res);
            },
        }
    }
}

fn db_index_commit(
    conn: &mut rusqlite::Connection,
    commit: &IndexableCommit,
) -> Result<(), IndexerError> {
    let first_blob_hash = commit
        .blob_hashes
        .first()
        .cloned()
        .ok_or_else(|| IndexerError::Consistency("commit has no blob hashes".into()))?
        .to_string();

    let mut run = |conn: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // 1. Insert cozies
        for coz in &commit.cozies {
            tx.execute(
                "INSERT OR IGNORE INTO cozies (blob_hash, czd, principal_id, typ, tmb, alg, now, \
                 commit_seq, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    coz.blob_hash.to_string(),
                    coz.czd,
                    commit.principal_id,
                    coz.typ,
                    coz.tmb,
                    coz.alg,
                    coz.now,
                    commit.sequence,
                    coz.payload,
                ],
            )?;

            // 2. Insert digests for cozies (as TRANSACTION or ACTION)
            let entity_type = if coz.typ.starts_with("cyphr/action") || coz.typ.contains("/action")
            {
                "action"
            } else {
                "transaction"
            };
            tx.execute(
                "INSERT OR IGNORE INTO digests (digest, blob_hash, entity_type) VALUES (?1, ?2, \
                 ?3)",
                rusqlite::params![coz.czd, coz.blob_hash.to_string(), entity_type,],
            )?;
        }

        // 3. Insert commit chain entry
        let primary_cid = commit.commit_ids.first().cloned().unwrap_or_default();
        let primary_pr = commit.prs.first().cloned().unwrap_or_default();
        let primary_sr = commit.srs.first().cloned().unwrap_or_default();
        let primary_ar = commit.ars.first().cloned().unwrap_or_default();
        let blob_hashes_json = serde_json::to_string(&commit.blob_hashes).unwrap_or_default();

        tx.execute(
            "INSERT OR IGNORE INTO commits (principal_id, sequence, commit_czd, pre, pr, sr, ar, \
             blob_hashes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                commit.principal_id,
                commit.sequence,
                primary_cid,
                commit.pre,
                primary_pr,
                primary_sr,
                primary_ar,
                blob_hashes_json,
                commit.timestamp,
            ],
        )?;

        // 4. Index all MHMR digest variants
        for cid in &commit.commit_ids {
            tx.execute(
                "INSERT OR IGNORE INTO digests (digest, blob_hash, entity_type) VALUES (?1, ?2, \
                 'commit')",
                rusqlite::params![cid, first_blob_hash],
            )?;
        }

        for pr in &commit.prs {
            tx.execute(
                "INSERT OR IGNORE INTO digests (digest, blob_hash, entity_type) VALUES (?1, ?2, \
                 'commit')",
                rusqlite::params![pr, first_blob_hash],
            )?;
        }

        for sr in &commit.srs {
            tx.execute(
                "INSERT OR IGNORE INTO digests (digest, blob_hash, entity_type) VALUES (?1, ?2, \
                 'commit')",
                rusqlite::params![sr, first_blob_hash],
            )?;
        }

        for ar in &commit.ars {
            tx.execute(
                "INSERT OR IGNORE INTO digests (digest, blob_hash, entity_type) VALUES (?1, ?2, \
                 'commit')",
                rusqlite::params![ar, first_blob_hash],
            )?;
        }

        // 5. Index public keys
        for key in &commit.keys {
            tx.execute(
                "INSERT OR IGNORE INTO public_keys (thumbprint, algorithm, principal_id, \
                 public_key, introduced_at, revoked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                rusqlite::params![
                    key.thumbprint,
                    key.algorithm,
                    commit.principal_id,
                    key.public_key,
                    commit.sequence,
                ],
            )?;
        }

        // Check if any key-revocations were in this commit, and update `revoked_at`
        for coz in &commit.cozies {
            if coz.typ.contains("/key/revoke") {
                if let Some(payload_str) = &coz.payload {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload_str) {
                        if let Some(rev) = v.get("rev").and_then(|r| r.as_str()) {
                            tx.execute(
                                "UPDATE public_keys SET revoked_at = ?1 WHERE thumbprint = ?2 AND \
                                 revoked_at IS NULL",
                                rusqlite::params![commit.sequence, rev],
                            )?;
                        }
                    }
                }
            }
        }

        // 6. Update materialized views: tips and principals
        let commit_count: u64 = tx.query_row(
            "SELECT COUNT(*) FROM commits WHERE principal_id = ?1",
            rusqlite::params![commit.principal_id],
            |row| row.get(0),
        )?;

        let created_at: i64 = tx.query_row(
            "SELECT MIN(created_at) FROM commits WHERE principal_id = ?1",
            rusqlite::params![commit.principal_id],
            |row| row.get(0),
        )?;

        tx.execute(
            "INSERT OR REPLACE INTO tips (principal_id, pr, sr, ar, commit_czd, commit_count, \
             last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                commit.principal_id,
                primary_pr,
                primary_sr,
                primary_ar,
                primary_cid,
                commit_count,
                commit.timestamp,
            ],
        )?;

        tx.execute(
            "INSERT OR REPLACE INTO principals (principal_id, pr, commit_count, created, \
             last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                commit.principal_id,
                primary_pr,
                commit_count,
                created_at,
                commit.timestamp,
            ],
        )?;

        tx.commit()?;
        Ok(())
    };
    run(conn).map_err(map_sqlite_err)
}

fn db_get_tip(
    conn: &rusqlite::Connection,
    principal_id: &str,
) -> Result<Option<TipState>, IndexerError> {
    let mut run = || -> Result<Option<TipState>, rusqlite::Error> {
        let mut stmt = conn.prepare(
            "SELECT pr, sr, ar, commit_czd, commit_count, last_updated FROM tips WHERE \
             principal_id = ?1",
        )?;

        let mut rows = stmt.query(rusqlite::params![principal_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(TipState {
                principal_id: principal_id.to_string(),
                pr: row.get(0)?,
                sr: row.get(1)?,
                ar: row.get(2)?,
                commit_id: row.get(3)?,
                commit_count: row.get(4)?,
                last_updated: row.get(5)?,
            }))
        } else {
            Ok(None)
        }
    };
    run().map_err(map_sqlite_err)
}

fn db_get_commit_chain(
    conn: &rusqlite::Connection,
    principal_id: &str,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<Vec<CommitRef>, IndexerError> {
    let run = || -> Result<Vec<CommitRef>, IndexerError> {
        let from_seq = from.unwrap_or(0) as i64;
        let to_seq = to.map(|t| t as i64).unwrap_or(i64::MAX);

        let mut stmt = conn
            .prepare(
                "SELECT commit_czd, sequence, pre, pr, sr, ar, blob_hashes
             FROM commits
             WHERE principal_id = ?1 AND sequence >= ?2 AND sequence <= ?3
             ORDER BY sequence",
            )
            .map_err(map_sqlite_err)?;

        let rows = stmt
            .query_map(rusqlite::params![principal_id, from_seq, to_seq], |row| {
                let commit_czd: String = row.get(0)?;
                let sequence: u64 = row.get(1)?;
                let pre: Option<String> = row.get(2)?;
                let pr: String = row.get(3)?;
                let sr: String = row.get(4)?;
                let ar: String = row.get(5)?;
                let blob_hashes_str: String = row.get(6)?;

                Ok((commit_czd, sequence, pre, pr, sr, ar, blob_hashes_str))
            })
            .map_err(map_sqlite_err)?;

        let mut chain = Vec::new();
        for row_res in rows {
            let (commit_czd, sequence, pre, pr, sr, ar, blob_hashes_str) =
                row_res.map_err(map_sqlite_err)?;
            let blob_hashes: Vec<Blake3Hash> = serde_json::from_str(&blob_hashes_str)
                .map_err(|e| IndexerError::Backend(e.to_string()))?;

            chain.push(CommitRef {
                commit_id: commit_czd,
                sequence,
                pre,
                pr,
                sr,
                ar,
                blob_hashes,
            });
        }

        Ok(chain)
    };
    run()
}

fn db_resolve_digest(
    conn: &rusqlite::Connection,
    digest: &TaggedDigest,
) -> Result<Option<EntityRef>, IndexerError> {
    let run = || -> Result<Option<EntityRef>, IndexerError> {
        let digest_str = digest.to_string();
        let mut stmt = conn
            .prepare("SELECT blob_hash, entity_type FROM digests WHERE digest = ?1")
            .map_err(map_sqlite_err)?;

        let mut rows = stmt
            .query(rusqlite::params![digest_str])
            .map_err(map_sqlite_err)?;
        if let Some(row) = rows.next().map_err(map_sqlite_err)? {
            let hash_str: String = row.get(0).map_err(map_sqlite_err)?;
            let blob_hash = hash_str
                .parse::<Blake3Hash>()
                .map_err(|e| IndexerError::Backend(e.to_string()))?;
            let entity_type_str: String = row.get(1).map_err(map_sqlite_err)?;
            let entity_type = match entity_type_str.as_str() {
                "commit" => EntityType::Commit,
                "transaction" => EntityType::Transaction,
                _ => EntityType::Action,
            };
            Ok(Some(EntityRef {
                digest: digest_str,
                blob_hash,
                entity_type,
            }))
        } else {
            Ok(None)
        }
    };
    run()
}

fn db_list_principals(conn: &rusqlite::Connection) -> Result<Vec<PrincipalSummary>, IndexerError> {
    let run = || -> Result<Vec<PrincipalSummary>, rusqlite::Error> {
        let mut stmt = conn.prepare(
            "SELECT principal_id, pr, commit_count, created, last_updated FROM principals",
        )?;

        let rows = stmt.query_map(rusqlite::params![], |row| {
            Ok(PrincipalSummary {
                principal_id: row.get(0)?,
                pr: row.get(1)?,
                commit_count: row.get(2)?,
                created: row.get(3)?,
                last_updated: row.get(4)?,
            })
        })?;

        let mut res = Vec::new();
        for r in rows {
            res.push(r?);
        }
        Ok(res)
    };
    run().map_err(map_sqlite_err)
}

fn db_clear(conn: &mut rusqlite::Connection) -> Result<(), IndexerError> {
    let run = |conn: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM cozies", rusqlite::params![])?;
        tx.execute("DELETE FROM commits", rusqlite::params![])?;
        tx.execute("DELETE FROM digests", rusqlite::params![])?;
        tx.execute("DELETE FROM public_keys", rusqlite::params![])?;
        tx.execute("DELETE FROM tips", rusqlite::params![])?;
        tx.execute("DELETE FROM principals", rusqlite::params![])?;
        tx.commit()?;
        Ok(())
    };
    run(conn).map_err(map_sqlite_err)
}

fn db_is_blob_indexed(
    conn: &rusqlite::Connection,
    hash: &Blake3Hash,
) -> Result<bool, IndexerError> {
    let run = || -> Result<bool, rusqlite::Error> {
        let hash_str = hash.to_string();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM cozies WHERE blob_hash = ?1",
            rusqlite::params![hash_str],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    };
    run().map_err(map_sqlite_err)
}

fn db_get_key(
    conn: &rusqlite::Connection,
    thumbprint: &str,
) -> Result<Option<PublicKeyInfo>, IndexerError> {
    let run = || -> Result<Option<PublicKeyInfo>, rusqlite::Error> {
        let mut stmt = conn.prepare(
            "SELECT thumbprint, algorithm, public_key FROM public_keys WHERE thumbprint = ?1",
        )?;

        let mut rows = stmt.query(rusqlite::params![thumbprint])?;
        if let Some(row) = rows.next()? {
            Ok(Some(PublicKeyInfo {
                thumbprint: row.get(0)?,
                algorithm: row.get(1)?,
                public_key: row.get(2)?,
            }))
        } else {
            Ok(None)
        }
    };
    run().map_err(map_sqlite_err)
}

impl Indexer for SqliteIndexer {
    fn index_commit(
        &self,
        commit: &IndexableCommit,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let commit = commit.clone();
        let tx = self.tx.clone();
        async move {
            let (respond_to, rx) = tokio::sync::oneshot::channel();
            tx.send(ActorMessage::IndexCommit { commit, respond_to })
                .await
                .map_err(|e| IndexerError::Backend(format!("actor channel closed: {e}")))?;
            rx.await
                .map_err(|e| IndexerError::Backend(format!("actor response channel closed: {e}")))?
        }
    }

    fn get_tip(
        &self,
        principal_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<TipState>, IndexerError>> + Send {
        let principal_id = principal_id.to_string();
        let tx = self.tx.clone();
        async move {
            let (respond_to, rx) = tokio::sync::oneshot::channel();
            tx.send(ActorMessage::GetTip {
                principal_id,
                respond_to,
            })
            .await
            .map_err(|e| IndexerError::Backend(format!("actor channel closed: {e}")))?;
            rx.await
                .map_err(|e| IndexerError::Backend(format!("actor response channel closed: {e}")))?
        }
    }

    fn get_commit_chain(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> impl std::future::Future<Output = Result<Vec<CommitRef>, IndexerError>> + Send {
        let principal_id = principal_id.to_string();
        let tx = self.tx.clone();
        async move {
            let (respond_to, rx) = tokio::sync::oneshot::channel();
            tx.send(ActorMessage::GetCommitChain {
                principal_id,
                from,
                to,
                respond_to,
            })
            .await
            .map_err(|e| IndexerError::Backend(format!("actor channel closed: {e}")))?;
            rx.await
                .map_err(|e| IndexerError::Backend(format!("actor response channel closed: {e}")))?
        }
    }

    fn resolve_digest(
        &self,
        digest: &TaggedDigest,
    ) -> impl std::future::Future<Output = Result<Option<EntityRef>, IndexerError>> + Send {
        let digest = digest.clone();
        let tx = self.tx.clone();
        async move {
            let (respond_to, rx) = tokio::sync::oneshot::channel();
            tx.send(ActorMessage::ResolveDigest { digest, respond_to })
                .await
                .map_err(|e| IndexerError::Backend(format!("actor channel closed: {e}")))?;
            rx.await
                .map_err(|e| IndexerError::Backend(format!("actor response channel closed: {e}")))?
        }
    }

    fn list_principals(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PrincipalSummary>, IndexerError>> + Send {
        let tx = self.tx.clone();
        async move {
            let (respond_to, rx) = tokio::sync::oneshot::channel();
            tx.send(ActorMessage::ListPrincipals { respond_to })
                .await
                .map_err(|e| IndexerError::Backend(format!("actor channel closed: {e}")))?;
            rx.await
                .map_err(|e| IndexerError::Backend(format!("actor response channel closed: {e}")))?
        }
    }

    fn clear(&self) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send {
        let tx = self.tx.clone();
        async move {
            let (respond_to, rx) = tokio::sync::oneshot::channel();
            tx.send(ActorMessage::Clear { respond_to })
                .await
                .map_err(|e| IndexerError::Backend(format!("actor channel closed: {e}")))?;
            rx.await
                .map_err(|e| IndexerError::Backend(format!("actor response channel closed: {e}")))?
        }
    }

    fn is_blob_indexed(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, IndexerError>> + Send {
        let hash = *hash;
        let tx = self.tx.clone();
        async move {
            let (respond_to, rx) = tokio::sync::oneshot::channel();
            tx.send(ActorMessage::IsBlobIndexed { hash, respond_to })
                .await
                .map_err(|e| IndexerError::Backend(format!("actor channel closed: {e}")))?;
            rx.await
                .map_err(|e| IndexerError::Backend(format!("actor response channel closed: {e}")))?
        }
    }

    fn get_key(
        &self,
        thumbprint: &str,
    ) -> impl std::future::Future<Output = Result<Option<PublicKeyInfo>, IndexerError>> + Send {
        let thumbprint = thumbprint.to_string();
        let tx = self.tx.clone();
        async move {
            let (respond_to, rx) = tokio::sync::oneshot::channel();
            tx.send(ActorMessage::GetKey {
                thumbprint,
                respond_to,
            })
            .await
            .map_err(|e| IndexerError::Backend(format!("actor channel closed: {e}")))?;
            rx.await
                .map_err(|e| IndexerError::Backend(format!("actor response channel closed: {e}")))?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commit(principal_id: &str, seq: u64, timestamp: i64) -> IndexableCommit {
        let blob_data = format!("{principal_id}-commit-{seq}");
        let blob_hash = Blake3Hash::from_bytes(*blake3::hash(blob_data.as_bytes()).as_bytes());

        IndexableCommit {
            principal_id: principal_id.to_string(),
            commit_ids: vec![format!("SHA-256:commit-{principal_id}-{seq}")],
            sequence: seq,
            pre: None,
            prs: vec![format!("SHA-256:pr-{principal_id}-{seq}")],
            srs: vec![format!("SHA-256:sr-{principal_id}-{seq}")],
            ars: vec![format!("SHA-256:ar-{principal_id}-{seq}")],
            blob_hashes: vec![blob_hash],
            cozies: vec![IndexableCoz {
                blob_hash,
                czd: format!("SHA-256:cozy-czd-{principal_id}-{seq}"),
                typ: "cyphr/key/create".to_string(),
                tmb: "thumbprint".to_string(),
                alg: "ED25519".to_string(),
                now: timestamp,
                payload: None,
            }],
            timestamp,
            keys: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_sqlite_indexer() {
        let indexer = SqliteIndexer::memory().expect("open memory db");
        let commit = make_commit("alice", 0, 1000);

        indexer.index_commit(&commit).await.expect("index");

        let tip = indexer
            .get_tip("alice")
            .await
            .expect("get_tip")
            .expect("has tip");
        assert_eq!(tip.principal_id, "alice");
        assert_eq!(tip.pr, "SHA-256:pr-alice-0");
        assert_eq!(tip.sr, "SHA-256:sr-alice-0");
        assert_eq!(tip.ar, "SHA-256:ar-alice-0");
        assert_eq!(tip.commit_id, "SHA-256:commit-alice-0");
        assert_eq!(tip.commit_count, 1);
        assert_eq!(tip.last_updated, 1000);

        let chain = indexer
            .get_commit_chain("alice", None, None)
            .await
            .expect("chain");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].commit_id, "SHA-256:commit-alice-0");

        let is_indexed = indexer
            .is_blob_indexed(&commit.blob_hashes[0])
            .await
            .expect("is_indexed");
        assert!(is_indexed);

        // Test clear
        indexer.clear().await.expect("clear");
        let tip_after = indexer.get_tip("alice").await.expect("get_tip");
        assert!(tip_after.is_none());
    }
}
