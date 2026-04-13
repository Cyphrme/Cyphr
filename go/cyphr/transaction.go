package cyphr

// Transaction is a sequence of related mutation cozies.
// In Cyphr, mutation cozies MUST be grouped by transaction.
type Transaction []*ParsedCoz

// CommitTransaction is a specialized sequence of cozies containing the finality marker.
// The commit transaction MUST be the exact last transaction in the commit.
type CommitTransaction []*ParsedCoz
