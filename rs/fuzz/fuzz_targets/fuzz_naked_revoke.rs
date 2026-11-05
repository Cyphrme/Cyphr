#![no_main]

use std::sync::OnceLock;

use cyphr_server::revoke::{NakedRevokeEnvelope, interpret};
use cyphr_storage::index::MemoryIndexer;
use libfuzzer_sys::fuzz_target;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to build runtime")
    })
}

// Fuzzes the naked-revoke envelope: the request body is deserialized to
// `NakedRevokeEnvelope` and handed to `interpret` (payload shape, `typ`,
// `rvk`, size bound, key/thumbprint binding, signature).
fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = serde_json::from_slice::<NakedRevokeEnvelope>(data) else {
        return;
    };
    let indexer = MemoryIndexer::new();
    let _ = runtime().block_on(interpret(&envelope, &indexer));
});
