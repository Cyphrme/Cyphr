package cyphrpass

import (
	"encoding/json"

	"github.com/cyphrme/coz"
)

// Commit is a finalized, atomic bundle of transactions.
//
// Per SPEC §4.2.1:
//   - Commit ID = MR(sort(czd₀, czd₁, ...)) for transactions in this commit only
//   - The last transaction has `commit: true` in its payload
//   - `pre` of first transaction references previous commit's CS (or PR for genesis)
//
// A Commit is immutable once finalized.
type Commit struct {
	// transactions are the verified transactions in this commit.
	transactions []*Transaction
	// commitID is the Commit ID: Merkle root of transaction czds.
	commitID *CommitID
	// cs is the Commit State at the end of this commit.
	cs CommitState
	// as is the Auth State at the end of this commit.
	as AuthState
	// ps is the Principal State at the end of this commit.
	ps PrincipalState
	// raw stores the original raw JSON for each transaction (for storage round-trips).
	raw []json.RawMessage
}

// NewCommit creates a finalized commit from transactions and computed states.
// Panics if transactions is empty.
func NewCommit(txs []*Transaction, commitID *CommitID, cs CommitState, as AuthState, ps PrincipalState) *Commit {
	if len(txs) == 0 {
		panic("Commit must contain at least one transaction")
	}
	return &Commit{
		transactions: txs,
		commitID:     commitID,
		cs:           cs,
		as:           as,
		ps:           ps,
	}
}

// Transactions returns the transactions in this commit.
func (c *Commit) Transactions() []*Transaction {
	return c.transactions
}

// CommitID returns the Commit ID (Merkle root of this commit's czds).
func (c *Commit) CommitID() *CommitID {
	return c.commitID
}

// CS returns the Commit State at the end of this commit.
func (c *Commit) CS() CommitState {
	return c.cs
}

// AS returns the Auth State at the end of this commit.
func (c *Commit) AS() AuthState {
	return c.as
}

// PS returns the Principal State at the end of this commit.
func (c *Commit) PS() PrincipalState {
	return c.ps
}

// Len returns the number of transactions in this commit.
func (c *Commit) Len() int {
	return len(c.transactions)
}

// IsEmpty returns true if the commit has no transactions (invalid state).
func (c *Commit) IsEmpty() bool {
	return len(c.transactions) == 0
}

// Raw returns the raw JSON messages for storage round-trips.
func (c *Commit) Raw() []json.RawMessage {
	return c.raw
}

// SetRaw sets the raw JSON messages for storage round-trips.
func (c *Commit) SetRaw(raw []json.RawMessage) {
	c.raw = raw
}

// PendingCommit is a commit being built but not yet finalized.
//
// Transactions are added until the final transaction with `commit: true` is
// received, at which point Finalize() converts it to an immutable Commit.
//
// Per SPEC §4.2.1, state during a pending commit is "transitory" and cannot
// be referenced by external transactions until finalized.
type PendingCommit struct {
	// transactions are the accumulated transactions (not yet finalized).
	transactions []*Transaction
	// raw stores the original raw JSON for each transaction.
	raw []json.RawMessage
	// hashAlg is the hash algorithm for state computation.
	hashAlg HashAlg
}

// NewPendingCommit creates a new empty pending commit.
func NewPendingCommit(hashAlg HashAlg) *PendingCommit {
	return &PendingCommit{
		transactions: make([]*Transaction, 0),
		raw:          make([]json.RawMessage, 0),
		hashAlg:      hashAlg,
	}
}

// Push adds a transaction to the pending commit.
func (p *PendingCommit) Push(tx *Transaction) {
	p.transactions = append(p.transactions, tx)
	if tx.Raw != nil {
		p.raw = append(p.raw, tx.Raw)
	}
}

// Transactions returns the current list of pending transactions.
func (p *PendingCommit) Transactions() []*Transaction {
	return p.transactions
}

// IsEmpty returns true if no transactions have been added.
func (p *PendingCommit) IsEmpty() bool {
	return len(p.transactions) == 0
}

// Len returns the number of pending transactions.
func (p *PendingCommit) Len() int {
	return len(p.transactions)
}

// ComputeCommitID computes the Commit ID for the current pending transactions.
// Returns nil if no transactions have been added.
func (p *PendingCommit) ComputeCommitID() (*CommitID, error) {
	if len(p.transactions) == 0 {
		return nil, nil
	}
	czds := make([]coz.B64, len(p.transactions))
	for i, tx := range p.transactions {
		czds[i] = tx.Czd
	}
	return ComputeCommitID(czds, nil, []HashAlg{p.hashAlg})
}

// Finalize converts the pending commit to an immutable Commit.
//
// Arguments:
//   - as: The computed Auth State after all transactions
//   - cs: The computed Commit State (binds AS to this commit's ID)
//   - ps: The computed Principal State after all transactions
//
// Returns nil if no transactions exist.
func (p *PendingCommit) Finalize(as AuthState, cs CommitState, ps PrincipalState) (*Commit, error) {
	if len(p.transactions) == 0 {
		return nil, ErrEmptyCommit
	}

	// Compute Commit ID from all transaction czds
	cid, err := p.ComputeCommitID()
	if err != nil {
		return nil, err
	}

	commit := NewCommit(p.transactions, cid, cs, as, ps)
	commit.SetRaw(p.raw)
	return commit, nil
}

// IntoTransactions consumes the pending commit and returns the transactions.
// Use for rollback or when abandoning a pending commit.
func (p *PendingCommit) IntoTransactions() []*Transaction {
	txs := p.transactions
	p.transactions = nil
	p.raw = nil
	return txs
}
