use crate::parsed_coz::VerifiedCoz;

/// A sequence of one or more related mutation cozies.
/// In Cyphr, mutation cozies MUST be grouped by transaction.
#[derive(Debug, Clone)]
pub struct Transaction(pub Vec<VerifiedCoz>);

impl Transaction {
    /// Returns true if this transaction contains a commit finalizer cozy.
    pub fn is_commit(&self) -> bool {
        self.0.iter().any(|cz| cz.arrow().is_some())
    }
}
