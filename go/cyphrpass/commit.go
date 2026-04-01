package cyphrpass

import (
	"encoding/json"

	"github.com/cyphrme/coz"
)

// Commit is a finalized, atomic bundle of cozies.
//
// Per SPEC §4.2.1:
//   - Commit ID = MR(sort(czd₀, czd₁, ...)) for cozies in this commit only
//   - The last coz has `commit: true` in its payload
//   - `pre` of first coz references previous commit's CS (or PR for genesis)
//
// A Commit is immutable once finalized.
type Commit struct {
	transactions []Transaction
	commitTx     CommitTransaction
	commitID     *CommitID
	// sr is the State Root at the end of this commit.
	sr StateRoot
	// as is the Auth State at the end of this commit.
	ar AuthRoot
	// ps is the Principal State at the end of this commit.
	pr PrincipalRoot
	// raw stores the original raw JSON for each coz (for storage round-trips).
	raw []json.RawMessage
}

// newCommit creates a finalized commit from cozies and computed states.
// Returns ErrEmptyCommit if cozies is empty.
func newCommit(transactions []Transaction, commitTx CommitTransaction, commitID *CommitID, sr StateRoot, ar AuthRoot, pr PrincipalRoot) (*Commit, error) {
	if len(transactions) == 0 && len(commitTx) == 0 {
		return nil, ErrEmptyCommit
	}
	return &Commit{
		transactions: transactions,
		commitTx:     commitTx,
		commitID:     commitID,
		sr:           sr,
		ar:           ar,
		pr:           pr,
	}, nil
}

// Cozies returns the cozies in this commit.
func (c *Commit) Transactions() []Transaction {
	return c.transactions
}
func (c *Commit) CommitTx() CommitTransaction {
	return c.commitTx
}
func (c *Commit) Cozies() []*ParsedCoz {
	var flat []*ParsedCoz
	for _, tx := range c.transactions {
		flat = append(flat, tx...)
	}
	flat = append(flat, c.commitTx...)
	return flat
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

// Len returns the number of cozies in this commit.
func (c *Commit) Len() int {
	return len(c.Cozies())
}

// IsEmpty returns true if the commit has no cozies (invalid state).
func (c *Commit) IsEmpty() bool {
	return len(c.Cozies()) == 0
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
// Cozies are added until the final coz with `commit: true` is
// received, at which point Finalize() converts it to an immutable Commit.
//
// Per SPEC §4.2.1, state during a pending commit is "transitory" and cannot
// be referenced by external cozies until finalized.
type PendingCommit struct {
	transactions []Transaction
	commitTx     CommitTransaction
	// raw stores the original raw JSON for each coz.
	raw []json.RawMessage
	// hashAlg is the hash algorithm for state computation.
	hashAlg HashAlg
}

// NewPendingCommit creates a new empty pending commit.
func NewPendingCommit(hashAlg HashAlg) *PendingCommit {
	return &PendingCommit{
		transactions: make([]Transaction, 0),
		raw:          make([]json.RawMessage, 0),
		hashAlg:      hashAlg,
	}
}

// Push adds a coz to the pending commit.
func (p *PendingCommit) Push(cz *ParsedCoz) {
	if cz.CommitSR != nil {
		p.commitTx = append(p.commitTx, cz)
	} else {
		p.transactions = append(p.transactions, Transaction{cz})
	}
	if cz.raw != nil {
		p.raw = append(p.raw, cz.raw)
	}
}

// Transactions returns the current pending transactions.
func (p *PendingCommit) Transactions() []Transaction {
	return p.transactions
}

// CommitTx returns the commit transaction.
func (p *PendingCommit) CommitTx() CommitTransaction {
	return p.commitTx
}

// Cozies returns the current list of pending cozies.
func (p *PendingCommit) Cozies() []*ParsedCoz {
	var flat []*ParsedCoz
	for _, tx := range p.transactions {
		flat = append(flat, tx...)
	}
	if p.commitTx != nil {
		flat = append(flat, p.commitTx...)
	}
	return flat
}

// IsEmpty returns true if no cozies have been added.
func (p *PendingCommit) IsEmpty() bool {
	return len(p.Cozies()) == 0
}

// Len returns the number of pending cozies.
func (p *PendingCommit) Len() int {
	return len(p.Cozies())
}

// ComputeCommitID computes the Commit ID for the current pending cozies.
// Returns nil if no cozies have been added.
func (p *PendingCommit) ComputeCommitID() (*CommitID, error) {
	if len(p.Cozies()) == 0 {
		return nil, nil
	}
	czds := make([]coz.B64, len(p.Cozies()))
	for i, cz := range p.Cozies() {
		czds[i] = cz.Czd
	}
	return ComputeCommitID(czds, nil, []HashAlg{p.hashAlg})
}

// Finalize converts the pending commit to an immutable Commit.
//
// Arguments:
//   - ar: The computed Auth State after all cozies
//   - sr: The computed State Root (binds AR and DR)
//   - pr: The computed Principal State after all cozies
//
// Returns nil if no cozies exist.
func (p *PendingCommit) Finalize(ar AuthRoot, sr StateRoot, pr PrincipalRoot) (*Commit, error) {
	if len(p.Cozies()) == 0 {
		return nil, ErrEmptyCommit
	}

	// Compute Commit ID from all coz czds
	cid, err := p.ComputeCommitID()
	if err != nil {
		return nil, err
	}

	commit, err := newCommit(p.transactions, p.commitTx, cid, sr, ar, pr)
	if err != nil {
		return nil, err
	}
	commit.setRaw(p.raw)
	return commit, nil
}

// IntoTransactions consumes the pending commit and returns the cozies.
// Use for rollback or when abandoning a pending commit.
func (p *PendingCommit) IntoTransactions() []*ParsedCoz {
	cozies := p.Cozies()
	p.transactions = nil
	p.commitTx = nil
	p.raw = nil
	return cozies
}

// CommitBatch manages the lifecycle of a multi-coz commit.
//
// Following the database/sql Tx pattern:
//
//	batch := principal.BeginCommit()
//	batch.Apply(vtx1)    // eagerly mutates principal
//	batch.Apply(vtx2)    // second cz sees tx1's mutations
//	commit := batch.Finalize()  // recomputes state, produces Commit
//
// For single-coz commits, use [Principal.ApplyCoz] instead.
//
// Unlike Rust's CommitScope, Go has no borrow checker, so intermediate state
// IS observable between Apply() and Finalize(). This matches the database/sql
// convention: between Begin() and Commit(), the caller is responsible for
// not reading stale data.
type CommitBatch struct {
	principal *Principal
	pending   *PendingCommit
}

// Apply applies a verified coz to this commit batch.
//
// The principal's state is eagerly mutated (key set, timestamps, etc.)
// so that subsequent cozies within the same batch can see prior
// mutations (e.g., tx₂ signed by a key added in tx₁).
//
// State recomputation (KS, AS, CS, PS) is deferred to [CommitBatch.Finalize].
func (b *CommitBatch) Apply(vt *VerifiedCoz) error {
	if err := b.principal.applyCozInternal(vt.cz, vt.newKey); err != nil {
		return err
	}
	b.pending.Push(vt.cz)
	return nil
}

// VerifyAndApply verifies a Coz message and applies the resulting coz.
//
// This is a convenience method for the storage import path, combining
// [Principal.VerifyCoz] and [CommitBatch.Apply].
func (b *CommitBatch) VerifyAndApply(cz *coz.Coz, newKey *coz.Key) error {
	vt, err := b.principal.VerifyCoz(cz, newKey)
	if err != nil {
		return err
	}
	return b.Apply(vt)
}

// Finalize completes the commit batch, recomputing all state digests and
// producing an immutable [Commit].
//
// Returns ErrEmptyCommit if no cozies were applied.
func (b *CommitBatch) Finalize() (*Commit, error) {
	return b.principal.finalizeCommit(b.pending)
}

// Len returns the number of cozies applied so far.
func (b *CommitBatch) Len() int {
	return b.pending.Len()
}

// IsEmpty returns true if no cozies have been applied.
func (b *CommitBatch) IsEmpty() bool {
	return b.pending.IsEmpty()
}

// FinalizeWithCommit signs the last coz with commit:<CS> and finalizes.
//
// This is the creation-path API (Option A). It:
//  1. Applies the last cz mutation from the pay fields
//  2. Computes CS = MR(AS', DS') from post-mutation state
//  3. Injects "commit":<CS> into the pay
//  4. Signs the complete pay via the provided coz.Key
//  5. Computes czd and creates the final coz
//  6. Pushes to pending and calls finalizeCommit
//
// The pay must be a map[string]any with all fields except "commit".
// The signerKey must include private key material for signing.
func (b *CommitBatch) FinalizeWithCommit(
	pay map[string]any,
	signerKey *coz.Key,
	newKey *coz.Key,
) (*Commit, error) {
	// 1. Parse pay into CozPay to determine mutation kind
	payBytes, err := json.Marshal(pay)
	if err != nil {
		return nil, ErrMalformedPayload
	}

	var txPay CozPay
	if err := json.Unmarshal(payBytes, &txPay); err != nil {
		return nil, ErrMalformedPayload
	}

	// Create preliminary cz with placeholder czd to apply mutation
	placeholderCzd := coz.B64(make([]byte, 32))
	cz, err := ParseCoz(&txPay, placeholderCzd)
	if err != nil {
		return nil, err
	}

	// Apply mutation eagerly (newKey is *coz.Key, matching internal API)
	if err := b.principal.applyCozInternal(cz, newKey); err != nil {
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

	// 6. Parse the real coz (with commit field and real czd)
	txPay.Commit = sr.Tagged()
	realTx, err := ParseCoz(&txPay, signedCoz.Czd)
	if err != nil {
		return nil, err
	}

	// Store raw bytes for bit-perfect export
	rawEntry, err := buildRawEntry(signedCoz, newKey)
	if err != nil {
		return nil, ErrMalformedPayload
	}
	realTx.raw = rawEntry

	// 7. Replace the placeholder cz in principal.auth.Cozies
	lastIdx := len(b.principal.auth.Cozies) - 1
	b.principal.auth.Cozies[lastIdx] = realTx

	// 8. Push to pending and finalize
	b.pending.Push(realTx)
	return b.principal.finalizeCommit(b.pending)
}
