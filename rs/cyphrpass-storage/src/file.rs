//! File-based storage backend using JSONL format.
//!
//! Stores each principal's entries in a separate `.jsonl` file,
//! with one signed Coz message per line.

use crate::{Entry, EntryError, QueryOpts, Store};
use cyphrpass::state::PrincipalRoot;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// File-based storage backend.
///
/// Stores each principal's entries in a JSONL file named `<pr_b64>.jsonl`
/// within the configured base directory.
///
/// # Example
///
/// ```no_run
/// use cyphrpass_storage::FileStore;
///
/// let store = FileStore::new("/var/data/cyphrpass");
/// ```
pub struct FileStore {
    base_dir: PathBuf,
}

impl FileStore {
    /// Create a new file store with the given base directory.
    ///
    /// The directory will be created if it doesn't exist.
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    /// Get the file path for a principal's entry log.
    fn path_for(&self, pr: &PrincipalRoot) -> PathBuf {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        let filename = format!(
            "{}.jsonl",
            Base64UrlUnpadded::encode_string(pr.as_cad().as_bytes())
        );
        self.base_dir.join(filename)
    }

    /// Ensure the base directory exists.
    fn ensure_dir(&self) -> Result<(), FileStoreError> {
        if !self.base_dir.exists() {
            fs::create_dir_all(&self.base_dir).map_err(FileStoreError::Io)?;
        }
        Ok(())
    }
}

impl Store for FileStore {
    type Error = FileStoreError;

    fn append_entry(&self, pr: &PrincipalRoot, entry: &Entry) -> Result<(), Self::Error> {
        self.ensure_dir()?;
        let path = self.path_for(pr);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(FileStoreError::Io)?;

        // Write the original JSON bytes (no re-serialization)
        writeln!(file, "{}", entry.raw_json()).map_err(FileStoreError::Io)?;

        Ok(())
    }

    fn get_entries(&self, pr: &PrincipalRoot) -> Result<Vec<Entry>, Self::Error> {
        let path = self.path_for(pr);

        if !path.exists() {
            return Ok(vec![]);
        }

        let file = File::open(&path).map_err(FileStoreError::Io)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line.map_err(FileStoreError::Io)?;
            if line.trim().is_empty() {
                continue;
            }

            // CRITICAL: Use from_json to preserve original bytes for czd computation
            let entry = Entry::from_json(line).map_err(|e| FileStoreError::Entry {
                line: line_num + 1,
                source: e,
            })?;

            entries.push(entry);
        }

        Ok(entries)
    }

    fn get_entries_range(
        &self,
        pr: &PrincipalRoot,
        opts: &QueryOpts,
    ) -> Result<Vec<Entry>, Self::Error> {
        let mut entries = self.get_entries(pr)?;

        // Apply time filters
        if let Some(after) = opts.after {
            entries.retain(|e| e.now > after);
        }
        if let Some(before) = opts.before {
            entries.retain(|e| e.now < before);
        }

        // Apply limit
        if let Some(limit) = opts.limit {
            entries.truncate(limit);
        }

        Ok(entries)
    }

    fn exists(&self, pr: &PrincipalRoot) -> Result<bool, Self::Error> {
        Ok(self.path_for(pr).exists())
    }
}

/// Errors from the file-based storage backend.
#[derive(Debug, thiserror::Error)]
pub enum FileStoreError {
    /// I/O error reading or writing files.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Error parsing a line in the JSONL file.
    #[error("failed to parse line {line}: {source}")]
    ParseLine {
        line: usize,
        #[source]
        source: serde_json::Error,
    },

    /// Error extracting entry data.
    #[error("invalid entry at line {line}: {source}")]
    Entry {
        line: usize,
        #[source]
        source: EntryError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_store(test_name: &str) -> (FileStore, PathBuf) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = temp_dir().join(format!(
            "cyphrpass_test_{}_{}_{}",
            std::process::id(),
            test_name,
            nanos
        ));
        (FileStore::new(&dir), dir)
    }

    #[test]
    fn test_exists_empty() {
        let (store, dir) = temp_store("exists_empty");
        let pr = PrincipalRoot::from_bytes(vec![1, 2, 3, 4]);

        assert!(!store.exists(&pr).unwrap());

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_append_and_get() {
        let (store, dir) = temp_store("append_and_get");
        let pr = PrincipalRoot::from_bytes(vec![1, 2, 3, 4]);

        let entry = Entry::from_json(
            r#"{"pay":{"now":1234567890,"typ":"test/action"},"sig":"test"}"#.to_string(),
        )
        .unwrap();

        store.append_entry(&pr, &entry).unwrap();
        assert!(store.exists(&pr).unwrap());

        let entries = store.get_entries(&pr).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].now, 1234567890);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_get_entries_range() {
        let (store, dir) = temp_store("entries_range");
        let pr = PrincipalRoot::from_bytes(vec![1, 2, 3, 4]);

        // Add entries with different timestamps: 100, 200, 300, 400, 500
        for i in 1..=5 {
            let json = format!(
                r#"{{"pay":{{"now":{},"typ":"test"}},"sig":"test"}}"#,
                i * 100
            );
            let entry = Entry::from_json(json).unwrap();
            store.append_entry(&pr, &entry).unwrap();
        }

        // Filter by time range: after 150, before 450
        // Entries: 100, 200, 300, 400, 500
        // after 150 -> now > 150 -> 200, 300, 400, 500
        // before 450 -> now < 450 -> 200, 300, 400
        // Result: 3 entries (200, 300, 400)
        let opts = QueryOpts {
            after: Some(150),
            before: Some(450),
            limit: None,
        };
        let entries = store.get_entries_range(&pr, &opts).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].now, 200);
        assert_eq!(entries[1].now, 300);
        assert_eq!(entries[2].now, 400);

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }
}
