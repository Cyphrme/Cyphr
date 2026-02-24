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

// newCommit creates a finalized commit from transactions and computed states.
// Returns ErrEmptyCommit if transactions is empty.
func newCommit(txs []*Transaction, commitID *CommitID, cs CommitState, as AuthState, ps PrincipalState) (*Commit, error) {
	if len(txs) == 0 {
		return nil, ErrEmptyCommit
	}
	return &Commit{
		transactions: txs,
		commitID:     commitID,
		cs:           cs,
		as:           as,
		ps:           ps,
	}, nil
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

// setRaw sets the raw JSON messages for storage round-trips.
func (c *Commit) setRaw(raw []json.RawMessage) {
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
	if tx.raw != nil {
		p.raw = append(p.raw, tx.raw)
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

	commit, err := newCommit(p.transactions, cid, cs, as, ps)
	if err != nil {
		return nil, err
	}
	commit.setRaw(p.raw)
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

// CommitBatch manages the lifecycle of a multi-transaction commit.
//
// Following the database/sql Tx pattern:
//
//	batch := principal.BeginCommit()
//	batch.Apply(vtx1)    // eagerly mutates principal
//	batch.Apply(vtx2)    // second tx sees tx1's mutations
//	commit := batch.Finalize()  // recomputes state, produces Commit
//
// For single-transaction commits, use [Principal.ApplyTransaction] instead.
//
// Unlike Rust's CommitScope, Go has no borrow checker, so intermediate state
// IS observable between Apply() and Finalize(). This matches the database/sql
// convention: between Begin() and Commit(), the caller is responsible for
// not reading stale data.
type CommitBatch struct {
	principal *Principal
	pending   *PendingCommit
}

// Apply applies a verified transaction to this commit batch.
//
// The principal's state is eagerly mutated (key set, timestamps, etc.)
// so that subsequent transactions within the same batch can see prior
// mutations (e.g., tx₂ signed by a key added in tx₁).
//
// State recomputation (KS, AS, CS, PS) is deferred to [CommitBatch.Finalize].
func (b *CommitBatch) Apply(vt *VerifiedTx) error {
	if err := b.principal.applyTransactionInternal(vt.tx, vt.newKey); err != nil {
		return err
	}
	b.pending.Push(vt.tx)
	return nil
}

// VerifyAndApply verifies a Coz message and applies the resulting transaction.
//
// This is a convenience method for the storage import path, combining
// [Principal.VerifyTransaction] and [CommitBatch.Apply].
func (b *CommitBatch) VerifyAndApply(cz *coz.Coz, newKey *coz.Key) error {
	vt, err := b.principal.VerifyTransaction(cz, newKey)
	if err != nil {
		return err
	}
	return b.Apply(vt)
}

// Finalize completes the commit batch, recomputing all state digests and
// producing an immutable [Commit].
//
// Returns ErrEmptyCommit if no transactions were applied.
func (b *CommitBatch) Finalize() (*Commit, error) {
	return b.principal.finalizeCommit(b.pending)
}

// Len returns the number of transactions applied so far.
func (b *CommitBatch) Len() int {
	return b.pending.Len()
}

// IsEmpty returns true if no transactions have been applied.
func (b *CommitBatch) IsEmpty() bool {
	return b.pending.IsEmpty()
}
