#![no_main]

use std::sync::OnceLock;

use cyphr_storage::blob::{BlobStore, MemoryBlobStore};
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::MemoryIndexer;
use libfuzzer_sys::fuzz_target;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn get_runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build runtime")
    })
}

fuzz_target!(|data: &[u8]| {
    let rt = get_runtime();

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
            let write_chunk = || async {
                let mut handle = engine.blob_store().open_write().await.ok()?;
                tokio::io::AsyncWriteExt::write_all(&mut handle, chunk)
                    .await
                    .ok()?;
                engine.blob_store().close(handle).await.ok()?;
                Some(())
            };
            let _ = write_chunk().await;
        }

        // Run reindex recovery - should not panic
        let _ = engine.reindex(&[], true).await;
    });
});
