//! Witness mode state synchronization client (`docs/specs/witness-mode.md`).
//!
//! Fetches state deltas (`GET /patch`) from a configured upstream authority node,
//! validates every commit signature and root in memory using storage engine rules
//! before persisting, and rejects unverified deltas without partial application.

use std::sync::Arc;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;
use tracing::{error, warn};

use crate::AppState;
use crate::error::AppError;

/// Sync state for `principal_id` from upstream authority URL if in Witness mode.
pub async fn sync_from_authority(
    state: &Arc<AppState>,
    principal_id: &str,
) -> Result<(), AppError> {
    if state.config.mode != crate::config::ServerMode::Witness {
        return Ok(());
    }

    let Some(authority_url) = &state.config.authority_url else {
        return Ok(());
    };

    let principal_lock = {
        let mut map = state.sync_locks.lock().await;
        map.entry(principal_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = principal_lock.lock().await;

    let base_url = authority_url.trim_end_matches('/');

    let from_seq = state
        .engine
        .get_tip(principal_id)
        .await
        .map_err(AppError::engine)?
        .map(|t| t.commit_count)
        .unwrap_or(0);

    let patch_url = format!("{base_url}/patch?pr={principal_id}&from={from_seq}");

    let res = match state
        .http_client
        .get(&patch_url)
        .header("accept", "application/json")
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            error!(
                principal = %principal_id,
                error = %err,
                "witness sync HTTP request failed"
            );
            return Ok(());
        },
    };

    if !res.status().is_success() {
        warn!(
            principal = %principal_id,
            status = %res.status(),
            "witness sync upstream non-success status"
        );
        return Ok(());
    }

    let body: Value = match res.json().await {
        Ok(v) => v,
        Err(err) => {
            warn!(
                principal = %principal_id,
                error = %err,
                "witness sync payload decode failed"
            );
            return Ok(());
        },
    };

    let entries = match body
        .get("payload")
        .and_then(|p| p.get("entries"))
        .and_then(|e| e.as_array())
    {
        Some(e) => e,
        None => return Ok(()),
    };

    for entry in entries {
        let seq = entry.get("sequence").and_then(|s| s.as_u64()).unwrap_or(0);
        if seq < from_seq {
            continue;
        }

        let blob_strs = match entry.get("blobs").and_then(|b| b.as_array()) {
            Some(b) => b,
            None => continue,
        };

        let mut raw_blobs = Vec::with_capacity(blob_strs.len());
        let mut decode_error = false;
        for b_val in blob_strs {
            let Some(b_str) = b_val.as_str() else {
                decode_error = true;
                break;
            };
            let Ok(decoded) = Base64UrlUnpadded::decode_vec(b_str) else {
                decode_error = true;
                break;
            };
            raw_blobs.push(decoded);
        }

        if decode_error || raw_blobs.is_empty() {
            warn!(principal_id = %principal_id, "patch entry blob decode failed");
            break;
        }

        let blob_refs: Vec<&[u8]> = raw_blobs.iter().map(|b| b.as_slice()).collect();

        // Submit commit to storage engine which verifies commit signatures & roots in memory
        // before persisting. If validation fails, break immediately without applying unverified
        // state.
        if let Err(err) = state
            .engine
            .submit_commit(principal_id, None, &blob_refs)
            .await
        {
            warn!(
                principal_id = %principal_id,
                error = %err,
                "witness node rejected unverifiable delta from authority"
            );
            break;
        }
    }

    Ok(())
}
