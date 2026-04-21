package cyphr

import (
	"encoding/json"
	"fmt"

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
	// tr is the Transaction Root (TR = MR(TMR, TCR)).
	tr *TransactionRoot
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
func newCommit(transactions []Transaction, commitTx CommitTransaction, tr *TransactionRoot, sr StateRoot, ar AuthRoot, pr PrincipalRoot) (*Commit, error) {
	if len(transactions) == 0 && len(commitTx) == 0 {
		return nil, ErrEmptyCommit
	}
	return &Commit{
		transactions: transactions,
		commitTx:     commitTx,
		tr:           tr,
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

// TR returns the Transaction Root (TR = MR(TMR, TCR)).
func (c *Commit) TR() *TransactionRoot {
	return c.tr
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

// PushTx adds a transaction (a grouped list of cozies) to the pending commit.
func (p *PendingCommit) PushTx(tx Transaction) {
	if len(tx) == 0 {
		return
	}

	isCommit := false
	for _, cz := range tx {
		if cz.Arrow != nil || cz.Kind == TxCommitCreate {
			isCommit = true
		}
		if cz.raw != nil {
			p.raw = append(p.raw, cz.raw)
		}
	}

	if isCommit {
		p.commitTx = append(p.commitTx, tx...)
	} else {
		p.transactions = append(p.transactions, tx)
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

// ComputeRoots computes the TMR, TCR, and TR for the current pending cozies.
func (p *PendingCommit) ComputeRoots(algs []HashAlg) (tmr *TransactionMutationRoot, tcr *TransactionCommitRoot, tr *TransactionRoot, err error) {

	// Compute TMR
	var txDigests []MultihashDigest
	for _, tx := range p.transactions {
		// Group czds for this transaction
		var czds []TaggedCzd
		for _, cz := range tx {
			czds = append(czds, TaggedCzd{Czd: cz.Czd, Alg: cz.HashAlg})
		}
		txRoot, err := ComputeTX(czds, algs)
		if err != nil {
			return nil, nil, nil, err
		}
		if txRoot != nil {
			txDigests = append(txDigests, *txRoot)
		}
	}
	tmr, err = ComputeTMR(txDigests, algs)
	if err != nil {
		return nil, nil, nil, err
	}

	// Compute TCR
	var commitCzds []TaggedCzd
	for _, cz := range p.commitTx {
		commitCzds = append(commitCzds, TaggedCzd{Czd: cz.Czd, Alg: cz.HashAlg})
	}
	tcr, err = ComputeTCR(commitCzds, algs)
	if err != nil {
		return nil, nil, nil, err
	}

	tr, err = ComputeTR(tmr, tcr, algs)
	if err != nil {
		return nil, nil, nil, err
	}

	return tmr, tcr, tr, nil
}

// Finalize converts the pending commit to an immutable Commit.
//
// Arguments:
//   - ar: The computed Auth State after all cozies
//   - sr: The computed State Root (binds AR and DR)
//   - pr: The computed Principal State after all cozies
//   - txAlgs: The explicit algorithms from the terminal arrow payload
//
// Returns nil if no cozies exist.
func (p *PendingCommit) Finalize(ar AuthRoot, sr StateRoot, pr PrincipalRoot, txAlgs []HashAlg) (*Commit, error) {
	if len(p.Cozies()) == 0 {
		return nil, ErrEmptyCommit
	}

	// Compute TR from TMR and TCR
	_, _, tr, err := p.ComputeRoots(txAlgs)
	if err != nil {
		return nil, err
	}

	commit, err := newCommit(p.transactions, p.commitTx, tr, sr, ar, pr)
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
//
// Per [pre-mutation-key-rule], authorization is evaluated against the key
// state that existed before any transactions in the commit are applied.
// CommitBatch snapshots the active key set at creation time for this purpose.
type CommitBatch struct {
	principal     *Principal
	pending       *PendingCommit
	preCommitKeys map[string]*Key // snapshot of active keys at BeginCommit()
}

// Apply applies a verified coz to this commit batch as a single-coz transaction.
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
	b.pending.PushTx(Transaction{vt.cz})
	return nil
}

// ApplyTx applies a fully grouped transaction (multiple cozies) to this commit batch.
// State mutations are applied sequentially, but the cozies are grouped in the Merkle tree.
func (b *CommitBatch) ApplyTx(vts []*VerifiedCoz) error {
	var tx Transaction
	for _, vt := range vts {
		if err := b.principal.applyCozInternal(vt.cz, vt.newKey); err != nil {
			return err
		}
		tx = append(tx, vt.cz)
	}
	b.pending.PushTx(tx)
	return nil
}

// VerifyAndApply verifies a Coz message and applies the resulting coz.
//
// This is a convenience method for the storage import path, combining
// verification and application. Per [pre-mutation-key-rule], authorization
// is checked against the pre-commit key snapshot, not the live state.
func (b *CommitBatch) VerifyAndApply(cz *coz.Coz, newKey *coz.Key) error {
	vt, err := b.principal.verifyCozWithSnapshot(cz, newKey, b.preCommitKeys)
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

// FinalizeWithArrow appends a dedicated commit/create transaction with the Arrow field and finalizes.
//
// This replaces FinalizeWithCommit (Option A). It:
//  1. Computes TMR, TCR? No, it computes TMR from the pending transactions.
//  2. Computes the current SR post-mutations.
//  3. Computes Arrow = MR(pre, SR, TMR).
//  4. Constructs a commit/create transaction with `arrow: <Arrow>`.
//  5. Signs the commit/create with the provided signerKey.
//  6. Finalizes the commit batch.
func (b *CommitBatch) FinalizeWithArrow(
	signerKey *coz.Key,
	now int64,
	authority string,
) (*Commit, error) {
	if b.pending.IsEmpty() {
		return nil, ErrEmptyCommit
	}

	// 1. Derive post-mutation algorithm set and recompute current SR.
	// b.principal.activeAlgs may be stale if the mutation added/removed an
	// algorithm. Derive from the current (post-mutation) key set to match
	// what finalizeCommit will compute.
	thumbs := make([]coz.B64, len(b.principal.auth.Keys))
	keys := make([]*Key, len(b.principal.auth.Keys))
	for i, k := range b.principal.auth.Keys {
		thumbs[i] = k.Tmb
		keys[i] = k
	}
	postAlgs := DeriveHashAlgs(keys)

	_, _, sr, err := deriveAuthState(thumbs, b.principal.dr, postAlgs)
	if err != nil {
		return nil, err
	}

	// 2. Compute TMR from pending transactions.
	// CZDs are single-algorithm, so TMR uses the signer's algorithm.
	txAlg := HashAlg(signerKey.Alg.Hash())
	tmr, err := ComputeTMRFromPending(b.pending.transactions, []HashAlg{txAlg})
	if err != nil {
		return nil, err
	}

	// 3. Ascertain Pre (previous PR).
	// b.principal.pr holds the PR from before this commit (it hasn't been
	// updated yet — that happens in finalizeCommit after Arrow validation).
	pre := b.principal.pr
	// 4. Compute Arrow = MR(pre, fwd_SR, TMR) at the signer's algorithm.
	components := [][]byte{
		pre.GetOrFirst(txAlg),
		sr.GetOrFirst(txAlg),
		tmr.GetOrFirst(txAlg),
	}
	computedDigest, err := hashSortedConcatBytes(txAlg, components...)
	if err != nil {
		return nil, err
	}
	arrow := FromSingleDigest(txAlg, computedDigest)

	// Format arrow manually like Tagged()
	algs := arrow.Algorithms()
	var taggedArrow string
	if len(algs) > 0 {
		firstAlg := algs[0]
		digest := arrow.Get(firstAlg)
		taggedArrow = fmt.Sprintf("%s:%s", firstAlg, digest.String())
	}

	// 5. Construct commit/create payload
	// Full typ = authority + "/" + suffix, per SPEC §7.2.
	payObj := map[string]any{
		"alg":   string(signerKey.Alg),
		"tmb":   signerKey.Tmb.String(),
		"typ":   authority + "/" + TxCommitCreate.String(),
		"now":   now,
		"arrow": taggedArrow,
	}

	payBytes, err := json.Marshal(payObj)
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

	// 6. Compute czd
	signedCoz := &coz.Coz{
		Pay: payBytes,
		Sig: sig,
	}
	if err := signedCoz.Meta(); err != nil {
		return nil, ErrMalformedPayload
	}

	// 7. Parse the commit transaction coz
	var txPay CozPay
	json.Unmarshal(payBytes, &txPay)
	commitTxCoz, err := ParseCoz(&txPay, signedCoz.Czd)
	if err != nil {
		return nil, err
	}

	rawEntry, err := buildRawEntry(signedCoz, nil)
	if err != nil {
		return nil, ErrMalformedPayload
	}
	commitTxCoz.raw = rawEntry

	b.pending.commitTx = []*ParsedCoz{commitTxCoz}

	// 8. Finalize
	return b.Finalize()
}

// ComputeTMRFromPending is a helper logic to extract TMR.
func ComputeTMRFromPending(transactions []Transaction, activeAlgs []HashAlg) (*TransactionMutationRoot, error) {
	if len(transactions) == 0 {
		return nil, ErrEmptyCommit
	}
	var txDigests []MultihashDigest
	for _, tx := range transactions {
		var czds []TaggedCzd
		for _, cz := range tx {
			czds = append(czds, TaggedCzd{Czd: cz.Czd, Alg: cz.HashAlg})
		}
		txRoot, err := ComputeTX(czds, activeAlgs)
		if err != nil {
			return nil, err
		}
		if txRoot != nil {
			txDigests = append(txDigests, *txRoot)
		}
	}
	return ComputeTMR(txDigests, activeAlgs)
}
