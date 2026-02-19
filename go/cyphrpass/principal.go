package cyphrpass

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/cyphrme/coz"
)

// currentTime returns current unix timestamp in seconds.
// Separated for testability.
func currentTime() int64 {
	return time.Now().Unix()
}

// Level represents the feature level of a principal.
type Level int

const (
	Level1 Level = iota + 1 // Single static key
	Level2                  // Key replacement
	Level3                  // Multi-key
	Level4                  // Actions (AAA)
	Level5                  // Rules
	Level6                  // Virtual Machine
)

// String returns a human-readable level description.
func (l Level) String() string {
	switch l {
	case Level1:
		return "L1 (single key)"
	case Level2:
		return "L2 (atomic key replacement)"
	case Level3:
		return "L3 (multi-key)"
	case Level4:
		return "L4 (actions)"
	default:
		return "unknown"
	}
}

// AuthLedger holds keys and transactions.
type AuthLedger struct {
	// Keys maps thumbprint (b64 string) to active keys.
	// Uses ordered map semantics via slice backing.
	Keys   []*Key
	keyIdx map[string]int // tmb b64 -> index in Keys

	// Revoked keys for historical verification.
	Revoked []*Key

	// Transactions history.
	Transactions []*Transaction
}

// DataLedger holds actions (Level 4+).
type DataLedger struct {
	Actions []*Action
}

// Principal represents a self-sovereign identity in the Cyphrpass protocol.
//
// A Principal has:
//   - Permanent root (PR) set at genesis, never changes
//   - Evolving state (PS) as keys, transactions, and actions change
//   - Auth ledger tracking keys and transactions
//   - Data ledger tracking actions (Level 4+)
type Principal struct {
	pr       PrincipalRoot
	ps       PrincipalState
	ks       KeyState
	commitID *CommitID // nil if no transactions
	as       AuthState
	cs       *CommitState // nil before first commit
	ds       *DataState   // nil if no actions

	auth       AuthLedger
	data       DataLedger
	hashAlg    HashAlg
	activeAlgs []HashAlg // Per SPEC §14: algorithms derived from active keyset

	// commits stores finalized commit bundles.
	commits []*Commit

	// latestTimestamp tracks the most recent `now` value seen (SPEC §14.1).
	// Used to reject timestamps in the past.
	latestTimestamp int64

	// maxClockSkew is the maximum allowed future timestamp (seconds from server time).
	// Set to 0 to disable future timestamp checking.
	// Default: 300 seconds (5 minutes).
	maxClockSkew int64
}

// Implicit creates a principal with implicit genesis (single key).
//
// Per SPEC §3.2: "Identity emerges from first key possession"
//   - PR = PS = AS = KS = tmb (fully promoted)
//
// This is the Level 1/2 genesis path.
func Implicit(key *coz.Key) (*Principal, error) {
	// Validate algorithm is supported
	if !isSupportedAlg(key.Alg) {
		return nil, ErrUnsupportedAlgorithm
	}

	hashAlg := HashAlgFromSEAlg(key.Alg)
	algs := []HashAlg{hashAlg}

	// Wrap in our Key type
	k := &Key{
		Key:       key,
		FirstSeen: 0, // Will be set by caller if known
	}

	// KS = tmb (single key promotes)
	ks, err := ComputeKS([]coz.B64{key.Tmb}, nil, algs)
	if err != nil {
		return nil, err
	}

	// AS = KS (no RS, promotes)
	as, err := ComputeAS(ks, nil, algs)
	if err != nil {
		return nil, err
	}

	// CS = AS (no commit ID at genesis, promotes)
	cs, err := ComputeCS(as, nil, algs)
	if err != nil {
		return nil, err
	}

	// PS = CS (no DS, promotes)
	ps, err := ComputePS(cs, nil, nil, algs)
	if err != nil {
		return nil, err
	}

	// PR = first PS
	pr := NewPrincipalRoot(ps)

	p := &Principal{
		pr:         pr,
		ps:         ps,
		ks:         ks,
		as:         as,
		cs:         &cs,
		hashAlg:    hashAlg,
		activeAlgs: algs,
		auth: AuthLedger{
			Keys:   []*Key{k},
			keyIdx: map[string]int{string(key.Tmb.String()): 0},
		},
	}

	return p, nil
}

// Explicit creates a principal with explicit genesis (multiple keys).
//
// Per SPEC §3.2: Multi-key accounts require explicit genesis
//   - PR = H(sort(tmb₀, tmb₁, ...))
//
// This is the Level 3+ genesis path.
func Explicit(keys []*coz.Key) (*Principal, error) {
	if len(keys) == 0 {
		return nil, ErrNoActiveKeys
	}

	hashAlg := HashAlgFromSEAlg(keys[0].Alg)
	algs := []HashAlg{hashAlg}

	// Collect thumbprints and wrap keys
	thumbprints := make([]coz.B64, len(keys))
	wrappedKeys := make([]*Key, len(keys))
	keyIdx := make(map[string]int)

	for i, k := range keys {
		thumbprints[i] = k.Tmb
		wrappedKeys[i] = &Key{Key: k}
		keyIdx[string(k.Tmb.String())] = i
	}

	// KS = H(sort(tmb₀, tmb₁, ...)) or promoted if single
	ks, err := ComputeKS(thumbprints, nil, algs)
	if err != nil {
		return nil, err
	}

	// AS = KS (no RS, promotes)
	as, err := ComputeAS(ks, nil, algs)
	if err != nil {
		return nil, err
	}

	// CS = AS (no commit ID at genesis, promotes)
	cs, err := ComputeCS(as, nil, algs)
	if err != nil {
		return nil, err
	}

	// PS = CS (no DS, promotes)
	ps, err := ComputePS(cs, nil, nil, algs)
	if err != nil {
		return nil, err
	}

	// PR frozen at genesis
	pr := NewPrincipalRoot(ps)

	return &Principal{
		pr:         pr,
		ps:         ps,
		ks:         ks,
		as:         as,
		cs:         &cs,
		hashAlg:    hashAlg,
		activeAlgs: algs,
		auth: AuthLedger{
			Keys:   wrappedKeys,
			keyIdx: keyIdx,
		},
	}, nil
}

// PR returns the Principal Root (permanent identifier).
func (p *Principal) PR() PrincipalRoot {
	return p.pr
}

// PS returns the current Principal State.
func (p *Principal) PS() PrincipalState {
	return p.ps
}

// AS returns the current Auth State.
func (p *Principal) AS() AuthState {
	return p.as
}

// KS returns the current Key State.
func (p *Principal) KS() KeyState {
	return p.ks
}

// DS returns the current Data State (nil if no actions).
func (p *Principal) DS() *DataState {
	return p.ds
}

// HashAlg returns the hash algorithm used by this principal (genesis algorithm).
func (p *Principal) HashAlg() HashAlg {
	return p.hashAlg
}

// ActiveAlgs returns the set of hash algorithms derived from active keys.
func (p *Principal) ActiveAlgs() []HashAlg {
	return p.activeAlgs
}

// CommitID returns the current Commit ID (nil if no transactions).
func (p *Principal) CommitID() *CommitID {
	return p.commitID
}

// CS returns the current Commit State (nil before first commit).
func (p *Principal) CS() *CommitState {
	return p.cs
}

// Key returns a key by thumbprint, or nil if not found.
// Searches both active and revoked keys.
func (p *Principal) Key(tmb coz.B64) *Key {
	tmbStr := string(tmb.String())

	// Check active keys
	if idx, ok := p.auth.keyIdx[tmbStr]; ok {
		return p.auth.Keys[idx]
	}

	// Check revoked keys
	for _, k := range p.auth.Revoked {
		if bytes.Equal(k.Tmb, tmb) {
			return k
		}
	}

	return nil
}

// IsKeyActive returns true if the key is in the active set.
func (p *Principal) IsKeyActive(tmb coz.B64) bool {
	_, ok := p.auth.keyIdx[string(tmb.String())]
	return ok
}

// ActiveKeys returns all active keys.
func (p *Principal) ActiveKeys() []*Key {
	return p.auth.Keys
}

// ActiveKeyCount returns the number of active keys.
func (p *Principal) ActiveKeyCount() int {
	return len(p.auth.Keys)
}

// PreRevokeKey moves a key from active to revoked set.
// This is used for test setup to simulate a key that was revoked before test entries.
// Panics if the key is not found in the active set.
func (p *Principal) PreRevokeKey(tmb coz.B64, rvk int64) {
	tmbStr := string(tmb.String())

	// Find and remove from active set
	idx, ok := p.auth.keyIdx[tmbStr]
	if !ok {
		panic("PreRevokeKey: key not found in active set")
	}

	key := p.auth.Keys[idx]
	key.Rvk = rvk // Set revocation timestamp

	// Remove from active set
	p.auth.Keys = append(p.auth.Keys[:idx], p.auth.Keys[idx+1:]...)
	delete(p.auth.keyIdx, tmbStr)

	// Rebuild keyIdx for remaining keys
	for i, k := range p.auth.Keys {
		p.auth.keyIdx[string(k.Tmb.String())] = i
	}

	// Add to revoked set
	p.auth.Revoked = append(p.auth.Revoked, key)
}

// SetMaxClockSkew configures the maximum allowed clock skew for future timestamps.
// Transactions with tx.Now > serverTime + maxClockSkew will be rejected with ErrTimestampFuture.
// Set to 0 to disable future timestamp checking (default).
// Recommended value: 300 (5 minutes).
func (p *Principal) SetMaxClockSkew(seconds int64) {
	p.maxClockSkew = seconds
}

// Level determines the current feature level.
func (p *Principal) Level() Level {
	// Level 4: has actions
	if len(p.data.Actions) > 0 {
		return Level4
	}
	// Level 3: multiple keys or transactions
	if len(p.auth.Keys) > 1 || len(p.auth.Transactions) > 0 {
		return Level3
	}
	// Level 1: single key, no transactions
	return Level1
}

// RecordAction records an action to the Data State (Level 4+).
//
// Returns the new Principal State after recording.
// The action signature must be verified before calling this.
//
// Timestamp validation (SPEC §14.1):
//   - Rejects if action.Now < latestTimestamp (TimestampPast)
//   - Rejects if action.Now > serverTime + maxClockSkew (TimestampFuture), when maxClockSkew > 0
func (p *Principal) RecordAction(action *Action) error {
	// Validate timestamp is not in the past (SPEC §14.1)
	if action.Now < p.latestTimestamp {
		return ErrTimestampPast
	}

	// Validate timestamp is not too far in the future (SPEC §14.1)
	if p.maxClockSkew > 0 {
		serverTime := currentTime()
		if action.Now > serverTime+p.maxClockSkew {
			return ErrTimestampFuture
		}
	}

	// Verify signer is an active key
	if !p.IsKeyActive(action.Signer) {
		// Check if key exists but is revoked
		for _, k := range p.auth.Revoked {
			if bytes.Equal(k.Tmb, action.Signer) {
				return ErrKeyRevoked
			}
		}
		return ErrUnknownKey
	}

	// Update signer's last_used timestamp
	p.updateLastUsed(action.Signer, action.Now)

	// Update latest timestamp
	if action.Now > p.latestTimestamp {
		p.latestTimestamp = action.Now
	}

	// Record action
	p.data.Actions = append(p.data.Actions, action)

	// Recompute DS from all action czds
	czds := make([]coz.B64, len(p.data.Actions))
	for i, a := range p.data.Actions {
		czds[i] = a.Czd
	}
	ds, err := ComputeDS(czds, nil, p.hashAlg)
	if err != nil {
		return err
	}
	p.ds = ds

	// Recompute PS = MR(CS, DS?)
	if p.cs == nil {
		return fmt.Errorf("cannot recompute PS: no commit state")
	}
	ps, err := ComputePS(*p.cs, p.ds, nil, p.activeAlgs)
	if err != nil {
		return err
	}
	p.ps = ps

	return nil
}

// ActionCount returns the number of recorded actions.
func (p *Principal) ActionCount() int {
	return len(p.data.Actions)
}

// Transactions returns all transactions in applied order.
//
// This accessor is used by storage.ExportEntries to serialize transaction history.
// The returned slice is read-only; modifications will not affect the principal.
func (p *Principal) Transactions() []*Transaction {
	return p.auth.Transactions
}

// Actions returns all actions in recorded order.
//
// This accessor is used by storage.ExportEntries to serialize action history.
// The returned slice is read-only; modifications will not affect the principal.
func (p *Principal) Actions() []*Action {
	return p.data.Actions
}

// applyTransactionInternal applies a transaction to mutate principal state.
// This is an internal method; use ApplyTransaction for the public API.
//
// Timestamp validation (SPEC §14.1):
//   - Rejects if tx.Now < latestTimestamp (TimestampPast)
//   - Rejects if tx.Now > serverTime + maxClockSkew (TimestampFuture), when maxClockSkew > 0
func (p *Principal) applyTransactionInternal(tx *Transaction, newKey *coz.Key) error {
	// Validate timestamp is not in the past (SPEC §14.1)
	if tx.Now < p.latestTimestamp {
		return ErrTimestampPast
	}

	// Validate timestamp is not too far in the future (SPEC §14.1)
	// Only check if maxClockSkew is configured (> 0)
	if p.maxClockSkew > 0 {
		serverTime := currentTime()
		if tx.Now > serverTime+p.maxClockSkew {
			return ErrTimestampFuture
		}
	}

	// Verify signer is an active key (except for self-revoke)
	if tx.Kind != TxSelfRevoke {
		if !p.IsKeyActive(tx.Signer) {
			// Check if key exists but is revoked
			for _, k := range p.auth.Revoked {
				if bytes.Equal(k.Tmb, tx.Signer) {
					return ErrKeyRevoked
				}
			}
			return ErrUnknownKey
		}
	}

	switch tx.Kind {
	case TxKeyCreate:
		if err := p.verifyPre(tx.Pre); err != nil {
			return err
		}
		if newKey == nil {
			return ErrMalformedPayload
		}
		if !bytes.Equal(newKey.Tmb, tx.ID) {
			return ErrMalformedPayload
		}
		if p.IsKeyActive(tx.ID) {
			return ErrDuplicateKey
		}
		p.addKey(newKey, tx.Now)

	case TxKeyDelete:
		if err := p.verifyPre(tx.Pre); err != nil {
			return err
		}
		if err := p.removeKey(tx.ID); err != nil {
			return err
		}

	case TxKeyReplace:
		if err := p.verifyPre(tx.Pre); err != nil {
			return err
		}
		if newKey == nil {
			return ErrMalformedPayload
		}
		if !bytes.Equal(newKey.Tmb, tx.ID) {
			return ErrMalformedPayload
		}
		// Atomic swap: add new key first, then remove signer
		p.addKey(newKey, tx.Now)
		// Remove signer directly (bypassing NoActiveKeys check since we just added)
		p.removeKeyDirect(tx.Signer)

	case TxSelfRevoke:
		if err := p.verifyPre(tx.Pre); err != nil {
			return err
		}
		if err := p.revokeKey(tx.Signer, tx.Rvk, nil); err != nil {
			return err
		}

	case TxOtherRevoke:
		if err := p.verifyPre(tx.Pre); err != nil {
			return err
		}
		if err := p.revokeKey(tx.ID, tx.Rvk, tx.Signer); err != nil {
			return err
		}

	case TxPrincipalCreate:
		// SPEC §5.1: Genesis finalization. Verify pre matches AS and id matches AS.
		if err := p.verifyPre(tx.Pre); err != nil {
			return err
		}
		// id must equal current AS (self-referential for genesis finalization)
		if !bytes.Equal(tx.ID, p.as.First()) {
			return ErrMalformedPayload
		}
		// No state mutation needed; transaction is recorded for chain continuity
	}

	// Update signer's last_used timestamp
	p.updateLastUsed(tx.Signer, tx.Now)

	// Update latest timestamp
	if tx.Now > p.latestTimestamp {
		p.latestTimestamp = tx.Now
	}

	// Record transaction in the flat history.
	// Note: czd accumulation for commit boundaries is handled by CommitBatch.
	p.auth.Transactions = append(p.auth.Transactions, tx)

	return nil
}

// verifyPre checks that the transaction's pre matches current CS.
// At genesis (before first commit), CS is promoted from AS, so pre = AS = CS.
func (p *Principal) verifyPre(pre CommitState) error {
	if p.cs == nil {
		return fmt.Errorf("cannot verify pre: no commit state")
	}
	if !bytes.Equal(p.cs.First(), pre.First()) {
		return ErrInvalidPrior
	}
	return nil
}

// addKey adds a key to the active set.
func (p *Principal) addKey(key *coz.Key, firstSeen int64) {
	k := &Key{
		Key:       key,
		FirstSeen: firstSeen,
	}
	tmbStr := string(key.Tmb.String())
	p.auth.keyIdx[tmbStr] = len(p.auth.Keys)
	p.auth.Keys = append(p.auth.Keys, k)

	// Update activeAlgs if new key introduces a new algorithm (SPEC §14)
	newAlg := HashAlgFromSEAlg(key.Alg)
	found := false
	for _, alg := range p.activeAlgs {
		if alg == newAlg {
			found = true
			break
		}
	}
	if !found {
		p.activeAlgs = append(p.activeAlgs, newAlg)
		sort.Slice(p.activeAlgs, func(i, j int) bool {
			return string(p.activeAlgs[i]) < string(p.activeAlgs[j])
		})
	}
}

// removeKey removes a key from the active set (delete, not revoke).
func (p *Principal) removeKey(tmb coz.B64) error {
	tmbStr := string(tmb.String())
	idx, ok := p.auth.keyIdx[tmbStr]
	if !ok {
		return ErrUnknownKey
	}
	if len(p.auth.Keys) == 1 {
		return ErrNoActiveKeys
	}
	p.removeKeyAtIndex(idx)
	return nil
}

// removeKeyDirect removes a key without checking for last key.
func (p *Principal) removeKeyDirect(tmb coz.B64) {
	tmbStr := string(tmb.String())
	if idx, ok := p.auth.keyIdx[tmbStr]; ok {
		p.removeKeyAtIndex(idx)
	}
}

// removeKeyAtIndex removes the key at the given index.
func (p *Principal) removeKeyAtIndex(idx int) {
	key := p.auth.Keys[idx]
	tmbStr := string(key.Tmb.String())

	// Remove from slice (preserving order)
	p.auth.Keys = append(p.auth.Keys[:idx], p.auth.Keys[idx+1:]...)

	// Update index map
	delete(p.auth.keyIdx, tmbStr)
	for i := idx; i < len(p.auth.Keys); i++ {
		p.auth.keyIdx[string(p.auth.Keys[i].Tmb.String())] = i
	}
}

// revokeKey moves a key from active to revoked.
func (p *Principal) revokeKey(tmb coz.B64, rvk int64, by coz.B64) error {
	tmbStr := string(tmb.String())
	idx, ok := p.auth.keyIdx[tmbStr]
	if !ok {
		return ErrUnknownKey
	}

	// Check BEFORE mutation: would this leave us with no keys?
	if len(p.auth.Keys) == 1 {
		return ErrNoActiveKeys
	}

	// Remove from active set
	key := p.auth.Keys[idx]
	p.removeKeyAtIndex(idx)

	// Set revocation info
	key.Revocation = &Revocation{
		Rvk: rvk,
		By:  by,
	}

	// Move to revoked set
	p.auth.Revoked = append(p.auth.Revoked, key)

	return nil
}

// updateLastUsed updates a key's last_used timestamp.
func (p *Principal) updateLastUsed(tmb coz.B64, timestamp int64) {
	tmbStr := string(tmb.String())
	if idx, ok := p.auth.keyIdx[tmbStr]; ok {
		p.auth.Keys[idx].LastUsed = timestamp
	}
}

// BeginCommit starts a new commit batch.
//
// Returns a CommitBatch that accumulates transactions. The caller MUST
// call Finalize() to complete the commit, or abandon the batch.
//
// For single-transaction commits, use [Principal.ApplyTransaction] instead.
func (p *Principal) BeginCommit() *CommitBatch {
	return &CommitBatch{
		principal: p,
		pending:   NewPendingCommit(p.hashAlg),
	}
}

// ApplyTransaction applies a single verified transaction as an atomic commit.
//
// This is the primary convenience method for the common case (one tx = one commit).
// Internally calls BeginCommit, Apply, and Finalize.
func (p *Principal) ApplyTransaction(vt *VerifiedTx) (*Commit, error) {
	batch := p.BeginCommit()
	if err := batch.Apply(vt); err != nil {
		return nil, err
	}
	return batch.Finalize()
}

// FinalizeCommit recomputes all state digests and produces an immutable Commit.
//
// This is called by CommitBatch.Finalize() — not typically called directly.
func (p *Principal) FinalizeCommit(pending *PendingCommit) (*Commit, error) {
	if pending.IsEmpty() {
		return nil, ErrEmptyCommit
	}

	// Recompute KS from active keys
	thumbprints := make([]coz.B64, len(p.auth.Keys))
	for i, k := range p.auth.Keys {
		thumbprints[i] = k.Tmb
	}
	ks, err := ComputeKS(thumbprints, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	p.ks = ks

	// Compute Commit ID from this commit's transaction czds (SPEC §4.2.1)
	cid, err := pending.ComputeCommitID()
	if err != nil {
		return nil, err
	}
	p.commitID = cid

	// Recompute AS = MR(KS, RS?)
	as, err := ComputeAS(p.ks, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	p.as = as

	// Recompute CS = MR(AS, Commit ID)
	cs, err := ComputeCS(p.as, p.commitID, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	p.cs = &cs

	// Recompute PS = MR(CS, DS?)
	ps, err := ComputePS(cs, p.ds, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	p.ps = ps

	// Finalize the pending commit into an immutable Commit
	commit, err := pending.Finalize(p.as, cs, p.ps)
	if err != nil {
		return nil, err
	}

	// Store finalized commit
	p.commits = append(p.commits, commit)

	return commit, nil
}

// Commits returns all finalized commits.
func (p *Principal) Commits() []*Commit {
	return p.commits
}

// IsKeyRevoked returns true if the key has been revoked.
func (p *Principal) IsKeyRevoked(tmb coz.B64) bool {
	for _, k := range p.auth.Revoked {
		if bytes.Equal(k.Tmb, tmb) {
			return true
		}
	}
	return false
}
