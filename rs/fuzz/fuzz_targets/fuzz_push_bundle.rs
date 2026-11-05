#![no_main]

use std::sync::OnceLock;

use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::{StorageEngine, genesis_principal_id};
use cyphr_storage::index::MemoryIndexer;
use libfuzzer_sys::fuzz_target;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build runtime")
    })
}

/// Splits the input into u16-length-prefixed chunks: one chunk per blob of
/// the pushed commit bundle.
fn split_bundle(mut rest: &[u8]) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
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
    chunks
}

// Fuzzes the push path's bundle handling: `submit_commit` over arbitrary
// raw blobs on an empty engine. The principal id is derived from the
// bundle's own genesis (as a legitimate client would), so inputs get past
// the id-binding check into blob parsing and chain verification.
fuzz_target!(|data: &[u8]| {
    let blobs = split_bundle(data);
    if blobs.is_empty() {
        return;
    }
    runtime().block_on(async {
        let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        let principal_id = match engine.resolve_genesis("fuzz", &blobs).await {
            Ok(genesis) => genesis_principal_id(&genesis).unwrap_or_else(|_| "fuzz".into()),
            Err(_) => "fuzz".into(),
        };
        let _ = engine.submit_commit(&principal_id, None, &blobs).await;
    });
});
