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
	// sr is the State Root at the end of this commit.
	sr StateRoot
	// as is the Auth State at the end of this commit.
	ar AuthRoot
	// ps is the Principal State at the end of this commit.
	pr PrincipalRoot
	// raw stores the original raw JSON for each transaction (for storage round-trips).
	raw []json.RawMessage
}

// newCommit creates a finalized commit from transactions and computed states.
// Returns ErrEmptyCommit if transactions is empty.
func newCommit(txs []*Transaction, commitID *CommitID, sr StateRoot, ar AuthRoot, pr PrincipalRoot) (*Commit, error) {
	if len(txs) == 0 {
		return nil, ErrEmptyCommit
	}
	return &Commit{
		transactions: txs,
		commitID:     commitID,
		sr:           sr,
		ar:           ar,
		pr:           pr,
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

// SR returns the State Root at the end of this commit.
func (c *Commit) SR() StateRoot {
	return c.sr
}

// AS returns the Auth State at the end of this commit.
func (c *Commit) AR() AuthRoot {
	return c.ar
}

// PS returns the Principal State at the end of this commit.
func (c *Commit) PR() PrincipalRoot {
	return c.pr
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
func (p *PendingCommit) Finalize(ar AuthRoot, sr StateRoot, pr PrincipalRoot) (*Commit, error) {
	if len(p.transactions) == 0 {
		return nil, ErrEmptyCommit
	}

	// Compute Commit ID from all transaction czds
	cid, err := p.ComputeCommitID()
	if err != nil {
		return nil, err
	}

	commit, err := newCommit(p.transactions, cid, sr, ar, pr)
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

// FinalizeWithCommit signs the last transaction with commit:<CS> and finalizes.
//
// This is the creation-path API (Option A). It:
//  1. Applies the last tx mutation from the pay fields
//  2. Computes CS = MR(AS', DS') from post-mutation state
//  3. Injects "commit":<CS> into the pay
//  4. Signs the complete pay via the provided coz.Key
//  5. Computes czd and creates the final transaction
//  6. Pushes to pending and calls finalizeCommit
//
// The pay must be a map[string]any with all fields except "commit".
// The signerKey must include private key material for signing.
func (b *CommitBatch) FinalizeWithCommit(
	pay map[string]any,
	signerKey *coz.Key,
	newKey *coz.Key,
) (*Commit, error) {
	// 1. Parse pay into TransactionPay to determine mutation kind
	payBytes, err := json.Marshal(pay)
	if err != nil {
		return nil, ErrMalformedPayload
	}

	var txPay TransactionPay
	if err := json.Unmarshal(payBytes, &txPay); err != nil {
		return nil, ErrMalformedPayload
	}

	// Create preliminary tx with placeholder czd to apply mutation
	placeholderCzd := coz.B64(make([]byte, 32))
	tx, err := ParseTransaction(&txPay, placeholderCzd)
	if err != nil {
		return nil, err
	}

	// Apply mutation eagerly (newKey is *coz.Key, matching internal API)
	if err := b.principal.applyTransactionInternal(tx, newKey); err != nil {
		return nil, err
	}

	// 2. Compute CS post-mutation
	thumbprints := make([]coz.B64, len(b.principal.auth.Keys))
	for i, k := range b.principal.auth.Keys {
		thumbprints[i] = k.Tmb
	}
	kr, err := ComputeKR(thumbprints, nil, b.principal.activeAlgs)
	if err != nil {
		return nil, err
	}
	ar, err := ComputeAR(kr, nil, nil, b.principal.activeAlgs)
	if err != nil {
		return nil, err
	}
	sr, err := ComputeSR(ar, b.principal.dr, nil, b.principal.activeAlgs)
	if err != nil {
		return nil, err
	}

	// 3. Inject commit:<SR> into pay
	pay["commit"] = sr.Tagged()

	// 4. Serialize and sign
	payBytes, err = json.Marshal(pay)
	if err != nil {
		return nil, ErrMalformedPayload
	}

	digest, err := coz.Hash(signerKey.Alg.Hash(), payBytes)
	if err != nil {
		return nil, ErrMalformedPayload
	}

	sig, err := signerKey.Sign(digest)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	// 5. Compute czd via coz metadata
	signedCoz := &coz.Coz{
		Pay: payBytes,
		Sig: sig,
	}
	if err := signedCoz.Meta(); err != nil {
		return nil, ErrMalformedPayload
	}

	// 6. Parse the real transaction (with commit field and real czd)
	txPay.Commit = sr.Tagged()
	realTx, err := ParseTransaction(&txPay, signedCoz.Czd)
	if err != nil {
		return nil, err
	}

	// Store raw bytes for bit-perfect export
	rawEntry, err := buildRawEntry(signedCoz, newKey)
	if err != nil {
		return nil, ErrMalformedPayload
	}
	realTx.raw = rawEntry

	// 7. Replace the placeholder tx in principal.auth.Transactions
	lastIdx := len(b.principal.auth.Transactions) - 1
	b.principal.auth.Transactions[lastIdx] = realTx

	// 8. Push to pending and finalize
	b.pending.Push(realTx)
	return b.principal.finalizeCommit(b.pending)
}
