#![no_main]

use cyphr_storage::{
    blob::{BlobStore, MemoryBlobStore},
    engine::StorageEngine,
    index::MemoryIndexer,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(_) => return,
    };

    let mut chunks = Vec::new();
    let mut rest = data;
    while rest.len() >= 2 {
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        rest = &rest[2..];
        if rest.len() < len {
            chunks.push(rest);
            break;
        }
        let (chunk, remaining) = rest.split_at(len);
        chunks.push(chunk);
        rest = remaining;
    }

    if chunks.is_empty() {
        return;
    }

    rt.block_on(async {
        let blob_store = MemoryBlobStore::new();
        let indexer = MemoryIndexer::new();
        let engine = StorageEngine::new(blob_store, indexer);

        for chunk in chunks {
            if let Ok(mut handle) = engine.blob_store().open_write().await {
                if tokio::io::AsyncWriteExt::write_all(&mut handle, chunk)
                    .await
                    .is_ok()
                {
                    let _ = engine.blob_store().close(handle).await;
                }
            }
        }

        // Run reindex recovery - should not panic
        let _ = engine.reindex(&[], true).await;
    });
});
