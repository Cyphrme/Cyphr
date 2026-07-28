//! Best-effort background push fanout client (SPEC §13.5).
//!
//! When a commit is accepted on the authority node (`POST /push`), authority
//! spawns a non-blocking background task to push the commit payload to all
//! active registered witnesses for that principal.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::Serialize;
use tracing::warn;

use crate::AppState;

/// Status tracking for fanout delivery to a specific witness.
#[derive(Debug, Clone, Serialize)]
pub struct DeliveryStatus {
    /// Witness ID or registered URL.
    pub witness_id: String,
    /// Target URL for fanout delivery.
    pub url: String,
    /// Delivery status: `"delivered"`, `"failed"`, `"abandoned"`, `"unreachable"`, or `"pending"`.
    pub status: String,
    /// Unix timestamp of the most recent attempt.
    pub last_attempt: i64,
    /// Number of delivery attempts.
    pub attempts: u32,
    /// Error message from the last failed attempt, if any.
    pub last_error: Option<String>,
}

/// In-memory store for tracking fanout delivery status across principals and witnesses.
#[derive(Debug, Default)]
pub struct FanoutTracker {
    statuses: RwLock<HashMap<String, HashMap<String, DeliveryStatus>>>,
}

impl FanoutTracker {
    /// Construct a new `FanoutTracker`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a delivery attempt outcome for a principal's witness.
    pub fn record_status(
        &self,
        principal_id: &str,
        witness_id: &str,
        status: &str,
        error: Option<String>,
        now: i64,
    ) {
        let mut map = self.statuses.write().unwrap_or_else(|e| e.into_inner());
        let principal_map = map.entry(principal_id.to_string()).or_default();
        let entry = principal_map
            .entry(witness_id.to_string())
            .or_insert_with(|| DeliveryStatus {
                witness_id: witness_id.to_string(),
                url: witness_id.to_string(),
                status: status.to_string(),
                last_attempt: now,
                attempts: 0,
                last_error: None,
            });
        entry.status = status.to_string();
        entry.last_attempt = now;
        entry.attempts += 1;
        entry.last_error = error;
    }

    /// Retrieve tracked deliveries for `principal_id`, populating missing active witnesses.
    pub fn get_deliveries(
        &self,
        principal_id: &str,
        active_witnesses: &[String],
    ) -> Vec<DeliveryStatus> {
        let map = self.statuses.read().unwrap_or_else(|e| e.into_inner());
        let mut result = Vec::new();
        if let Some(principal_map) = map.get(principal_id) {
            for status in principal_map.values() {
                result.push(status.clone());
            }
        }
        for witness_id in active_witnesses {
            if !result
                .iter()
                .any(|d| &d.witness_id == witness_id || &d.url == witness_id)
            {
                result.push(DeliveryStatus {
                    witness_id: witness_id.clone(),
                    url: witness_id.clone(),
                    status: "pending".to_string(),
                    last_attempt: 0,
                    attempts: 0,
                    last_error: None,
                });
            }
        }
        result
    }
}

/// Spawn a non-blocking background task to fan out a commit payload to all registered witnesses.
pub fn spawn_fanout(state: Arc<AppState>, principal_id: String, blobs: Vec<String>) {
    let (active_witnesses, _) = state.registration.get_witnesses(&principal_id);
    if active_witnesses.is_empty() {
        return;
    }

    tokio::spawn(async move {
        let push_req = crate::routes::PushRequest {
            principal_id: principal_id.clone(),
            blobs,
        };

        for witness_id in active_witnesses {
            let target_url =
                if witness_id.starts_with("http://") || witness_id.starts_with("https://") {
                    format!("{}/push", witness_id.trim_end_matches('/'))
                } else {
                    format!("http://{}/push", witness_id.trim_end_matches('/'))
                };

            let now = crate::auth::server_now();
            let res = tokio::time::timeout(
                std::time::Duration::from_millis(150),
                state
                    .http_client
                    .post(&target_url)
                    .header("content-type", "application/json")
                    .header("x-cyphr-fanout", "true")
                    .header("x-witness-push", "true")
                    .json(&push_req)
                    .send(),
            )
            .await;

            match res {
                Ok(Ok(response)) if response.status().is_success() => {
                    state
                        .fanout
                        .record_status(&principal_id, &witness_id, "delivered", None, now);
                },
                Ok(Ok(response)) => {
                    let status_code = response.status();
                    warn!(
                        principal = %principal_id,
                        witness = %witness_id,
                        status = %status_code,
                        "fanout delivery attempt failed with non-success status"
                    );
                    state.fanout.record_status(
                        &principal_id,
                        &witness_id,
                        "failed",
                        Some(format!("HTTP {status_code}")),
                        now,
                    );
                },
                Ok(Err(err)) => {
                    warn!(
                        principal = %principal_id,
                        witness = %witness_id,
                        error = %err,
                        "fanout delivery attempt failed"
                    );
                    state.fanout.record_status(
                        &principal_id,
                        &witness_id,
                        "failed",
                        Some(err.to_string()),
                        now,
                    );
                },
                Err(_) => {
                    warn!(
                        principal = %principal_id,
                        witness = %witness_id,
                        "fanout delivery attempt timed out"
                    );
                    state.fanout.record_status(
                        &principal_id,
                        &witness_id,
                        "failed",
                        Some("timeout".to_string()),
                        now,
                    );
                },
            }
        }
    });
}
