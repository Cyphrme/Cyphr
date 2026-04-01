use crate::parsed_coz::VerifiedCoz;

/// A sequence of one or more related mutation cozies.
/// In Cyphrpass, mutation cozies MUST be grouped by transaction.
#[derive(Debug, Clone)]
pub struct Transaction(pub Vec<VerifiedCoz>);

/// The commit transaction is a specialized sequence of cozies containing the finality marker.
/// The commit transaction MUST be the exact last transaction in the commit.
#[derive(Debug, Clone)]
pub struct CommitTransaction(pub Vec<VerifiedCoz>);
