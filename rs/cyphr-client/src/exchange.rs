//! Bundle exchange: carrying verified history between clients with no peer.
//!
//! A [`ExchangeBundle`] is a file's worth of what a peer would serve about one
//! principal: its chain or chains (a chain per branch the exporter holds),
//! and the naked revokes it holds. [`BundleConnector`] serves one chain as
//! a [`Connector`], so an import is the ordinary [`pull`](crate::pull)
//! step against a "client that serves it": nothing in a bundle is believed
//! except by the replay and signature checks every peer's answer passes.
//!
//! The bundle holds principal-signed objects only (commits, the other
//! branch, naked revokes), never a statement of the exporter's: the
//! exporter is a mirror, as any peer is (GOSSIP-MIN section 2).

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::connector::{ChannelBinding, ConnectError, Connector, Request};
use crate::sync::{ForkFinding, Record};

/// Bundle file version this build writes and reads. Version 2 drops the
/// chain position (`after`) from action bundles (SPEC 4.8.1).
pub const BUNDLE_VERSION: u64 = 2;

/// Why a bundle file was refused.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// The file is not JSON of the bundle shape.
    #[error("not a bundle file: {0}")]
    Malformed(String),
    /// The file states a version this build does not read.
    #[error("bundle version {found} is not the supported {supported}")]
    UnsupportedVersion {
        /// The stated version.
        found: u64,
        /// The one version this build reads.
        supported: u64,
    },
}

/// One bundle of data actions (SPEC 4.8.1): not chained, so it holds no
/// place among the commits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleActions {
    /// The signed actions, base64url.
    pub blobs: Vec<String>,
}

/// One chain from genesis: a branch of the principal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BundleChain {
    /// The commits, oldest first.
    pub commits: Vec<WireBundle>,
    /// The action-only bundles.
    #[serde(default)]
    pub actions: Vec<BundleActions>,
}

/// Everything one client carries to another about one principal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExchangeBundle {
    /// The file version.
    pub v: u64,
    /// The principal's id as the exporter knew it.
    pub principal_id: String,
    /// The chains: the record's own first, then one per fork it holds.
    pub chains: Vec<BundleChain>,
    /// Naked-revoke envelopes (`{pay, sig, key}`), unverified on read.
    #[serde(default)]
    pub revoked: Vec<Value>,
}

impl ExchangeBundle {
    /// The bundle of `record`: its chain, the other branch of each of
    /// `forks`, and `revoked` envelopes.
    #[must_use]
    pub fn export(record: &Record, forks: &[ForkFinding], revoked: Vec<Value>) -> Self {
        let mut own = BundleChain::default();
        for bundle in record.bundles_since(0) {
            if bundle.txs.is_empty() && !bundle.actions.is_empty() {
                own.actions.push(BundleActions {
                    blobs: bundle
                        .actions
                        .iter()
                        .map(|b| Base64UrlUnpadded::encode_string(b))
                        .collect(),
                });
            } else {
                own.commits.push(bundle.clone());
            }
        }
        let mut chains = vec![own.clone()];
        for fork in forks {
            // The other branch is the shared prefix plus the rival. Actions
            // belong to no branch, so it carries them all.
            let mut chain = BundleChain {
                commits: own.commits.iter().take(fork.height).cloned().collect(),
                actions: own.actions.clone(),
            };
            chain.commits.push(fork.rival.clone());
            chains.push(chain);
        }
        Self {
            v: BUNDLE_VERSION,
            principal_id: record.principal_id().to_owned(),
            chains,
            revoked,
        }
    }

    /// Read a bundle file.
    ///
    /// # Errors
    ///
    /// [`BundleError::UnsupportedVersion`] for a version this build does
    /// not read (checked before anything else is interpreted);
    /// [`BundleError::Malformed`] otherwise.
    pub fn parse(bytes: &[u8]) -> Result<Self, BundleError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| BundleError::Malformed(e.to_string()))?;
        let found = value
            .get("v")
            .and_then(Value::as_u64)
            .ok_or_else(|| BundleError::Malformed("v missing or not an integer".into()))?;
        if found != BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion {
                found,
                supported: BUNDLE_VERSION,
            });
        }
        serde_json::from_value(value).map_err(|e| BundleError::Malformed(e.to_string()))
    }

    /// One serving [`Connector`] per chain, each carrying every revoke.
    #[must_use]
    pub fn connectors(&self) -> Vec<BundleConnector> {
        self.chains
            .iter()
            .map(|chain| BundleConnector {
                chain: chain.clone(),
                revoked: self.revoked.clone(),
            })
            .collect()
    }
}

/// A bundle chain served as a peer would serve it.
pub struct BundleConnector {
    chain: BundleChain,
    revoked: Vec<Value>,
}

fn envelope(payload: &Value) -> Result<Vec<u8>, ConnectError> {
    serde_json::to_vec(&json!({"v": 1, "payload": payload}))
        .map_err(|e| ConnectError::Unreachable(e.to_string()))
}

impl Connector for BundleConnector {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let route = request.target.split('?').next().unwrap_or_default();
        match route {
            // The head names no commit id: the exporter's id is a claim the
            // verifier would not trust, so the pull reads the chain itself.
            "/branches" => {
                let heads = match self.chain.commits.len().checked_sub(1) {
                    Some(sequence) => {
                        json!([{"tip": "-", "sequence": sequence, "canonical": true}])
                    },
                    None => json!([]),
                };
                envelope(&json!({"branches": heads}))
            },
            // A file has no "from": the whole chain answers every request.
            "/patch" if request.target.contains("&from=") => Err(ConnectError::NonSuccess(404)),
            "/patch" => {
                let entries: Vec<Value> = self
                    .chain
                    .commits
                    .iter()
                    .enumerate()
                    .map(|(i, bundle)| {
                        let mut entry = serde_json::to_value(bundle).unwrap_or_default();
                        entry["sequence"] = i.into();
                        entry
                    })
                    .collect();
                let actions: Vec<Value> = self
                    .chain
                    .actions
                    .iter()
                    .map(|a| json!({"blobs": a.blobs}))
                    .collect();
                envelope(&json!({"entries": entries, "actions": actions}))
            },
            "/revoked" => envelope(&json!({"revoked": self.revoked})),
            _ => Err(ConnectError::NonSuccess(404)),
        }
    }
}
