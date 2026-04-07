package cyphrpass

import (
	"bytes"
	"sort"
	"time"

	"github.com/cyphrme/coz"
	"github.com/cyphrme/malt"
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

// authLedger holds keys and cozies.
type authLedger struct {
	// Keys maps thumbprint (b64 string) to active keys.
	// Uses ordered map semantics via slice backing.
	Keys   []*Key
	keyIdx map[string]int // tmb b64 -> index in Keys

	// Revoked keys for historical verification.
	Revoked []*Key

	// Cozies history.
	Cozies []*ParsedCoz
}

// dataLedger holds actions (Level 4+).
type dataLedger struct {
	Actions []*Action
}

// Principal represents a self-sovereign identity in the Cyphrpass protocol.
//
// A Principal has:
//   - Permanent root (PR) set at principal/create (Level 3+), nil for L1/L2
//   - Evolving state (PS) as keys, cozies, and actions change
//   - Auth ledger tracking keys and cozies
//   - Data ledger tracking actions (Level 4+)
type Principal struct {
	// pg is nil until principal/create establishes it (SPEC §5.1).
	// INVARIANT: only TxPrincipalCreate sets this field. Field privacy
	// prevents external construction — Go equivalent of Rust's enum Approach C.
	pg *PrincipalGenesis
	pr PrincipalRoot
	kr KeyRoot
	tr *TransactionRoot // nil if no transactions
	ar AuthRoot
	sr StateRoot // SR = MR(AR, DR?, embedding?)
	dr *DataRoot // nil if no actions

	commitTrees CommitTrees // one MALT per active hash algorithm
	cr          *CommitRoot // nil if no transactions

	auth       authLedger
	data       dataLedger
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
//   - PS = AS = KS = tmb (fully promoted)
//   - PR is nil (L1/L2 have no PR per SPEC §5.1)
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
	kr, err := ComputeKR([]coz.B64{key.Tmb}, nil, algs)
	if err != nil {
		return nil, err
	}

	// AR = KR (no RR, promotes)
	ar, err := ComputeAR(kr, nil, nil, algs)
	if err != nil {
		return nil, err
	}

	// SR = AR (no DR at genesis, promotes)
	sr, err := ComputeSR(ar, nil, nil, algs)
	if err != nil {
		return nil, err
	}

	// PR = SR (no CR at genesis, promotes)
	pr, err := ComputePR(sr, nil, nil, algs)
	if err != nil {
		return nil, err
	}

	p := &Principal{
		pr:         pr,
		kr:         kr,
		ar:         ar,
		sr:         sr,
		hashAlg:    hashAlg,
		activeAlgs: algs,
		auth: authLedger{
			Keys:   []*Key{k},
			keyIdx: map[string]int{string(key.Tmb.String()): 0},
		},
	}

	return p, nil
}

// Explicit creates a principal with explicit genesis (multiple keys).
//
// Per SPEC §3.2: Multi-key accounts require explicit genesis
//   - PR is nil at construction (established by principal/create)
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
	kr, err := ComputeKR(thumbprints, nil, algs)
	if err != nil {
		return nil, err
	}

	// AR = KR (no RR, promotes)
	ar, err := ComputeAR(kr, nil, nil, algs)
	if err != nil {
		return nil, err
	}

	// SR = AR (no DR at genesis, promotes)
	sr, err := ComputeSR(ar, nil, nil, algs)
	if err != nil {
		return nil, err
	}

	// PR = SR (no CR at genesis, promotes)
	pr, err := ComputePR(sr, nil, nil, algs)
	if err != nil {
		return nil, err
	}

	return &Principal{
		pr:         pr,
		kr:         kr,
		ar:         ar,
		sr:         sr,
		hashAlg:    hashAlg,
		activeAlgs: algs,
		auth: authLedger{
			Keys:   wrappedKeys,
			keyIdx: keyIdx,
		},
	}, nil
}

// PR returns the Principal Root, or nil if not yet established (L1/L2).
//
// PR is only set when principal/create is processed (Level 3+, SPEC §5.1).
// INVARIANT: pr is set exclusively by TxPrincipalCreate. Field privacy
// enforces this — external code cannot construct a Principal with a forged PR.
func (p *Principal) PG() *PrincipalGenesis {
	return p.pg
}

// PS returns the current Principal State.
func (p *Principal) PR() PrincipalRoot {
	return p.pr
}

// AS returns the current Auth State.
func (p *Principal) AR() AuthRoot {
	return p.ar
}

// CR returns the current Commit Root.
func (p *Principal) CR() *CommitRoot {
	return p.cr
}

// KS returns the current Key State.
func (p *Principal) KR() KeyRoot {
	return p.kr
}

// DR returns the current Data Root (nil if no actions).
func (p *Principal) DR() *DataRoot {
	return p.dr
}

// HashAlg returns the hash algorithm used by this principal (genesis algorithm).
func (p *Principal) HashAlg() HashAlg {
	return p.hashAlg
}

// ActiveAlgs returns the set of hash algorithms derived from active keys.
func (p *Principal) ActiveAlgs() []HashAlg {
	return p.activeAlgs
}

// TR returns the Transaction Root of the most recent commit.
func (p *Principal) TR() *TransactionRoot {
	return p.tr
}

// SR returns the current State Root.
func (p *Principal) SR() StateRoot {
	return p.sr
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

// ActiveKeys returns a copy of all active keys.
func (p *Principal) ActiveKeys() []*Key {
	out := make([]*Key, len(p.auth.Keys))
	copy(out, p.auth.Keys)
	return out
}

// ActiveKeyCount returns the number of active keys.
func (p *Principal) ActiveKeyCount() int {
	return len(p.auth.Keys)
}

// PreRevokeKey moves a key from active to revoked set.
// This is used for test setup to simulate a key that was revoked before test entries.
// Returns ErrUnknownKey if the key is not found in the active set.
func (p *Principal) PreRevokeKey(tmb coz.B64, rvk int64) error {
	tmbStr := string(tmb.String())

	// Find and remove from active set
	idx, ok := p.auth.keyIdx[tmbStr]
	if !ok {
		return ErrUnknownKey
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
	return nil
}

// SetMaxClockSkew configures the maximum allowed clock skew for future timestamps.
// Cozies with cz.Now > serverTime + maxClockSkew will be rejected with ErrTimestampFuture.
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
	// Level 3: multiple keys or cozies
	if len(p.auth.Keys) > 1 || len(p.auth.Cozies) > 0 {
		return Level3
	}
	// Level 1: single key, no cozies
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
	ds, err := ComputeDR(czds, nil, p.hashAlg)
	if err != nil {
		return err
	}
	p.dr = ds

	// Recompute SR = MR(AR, DR?, embedding?)
	sr, err := ComputeSR(p.ar, p.dr, nil, p.activeAlgs)
	if err != nil {
		return err
	}
	p.sr = sr

	// Recompute PR = MR(SR, CR?, embedding?)
	pr, err := ComputePR(p.sr, p.cr, nil, p.activeAlgs)
	if err != nil {
		return err
	}
	p.pr = pr

	return nil
}

// ActionCount returns the number of recorded actions.
func (p *Principal) ActionCount() int {
	return len(p.data.Actions)
}

// Cozies returns a copy of all cozies in applied order.
func (p *Principal) Cozies() []*ParsedCoz {
	out := make([]*ParsedCoz, len(p.auth.Cozies))
	copy(out, p.auth.Cozies)
	return out
}

// Actions returns a copy of all actions in recorded order.
func (p *Principal) Actions() []*Action {
	out := make([]*Action, len(p.data.Actions))
	copy(out, p.data.Actions)
	return out
}

// applyCozInternal applies a coz to mutate principal state.
// This is an internal method; use ApplyCoz for the public API.
//
// Timestamp validation (SPEC §14.1):
//   - Rejects if cz.Now < latestTimestamp (TimestampPast)
//   - Rejects if cz.Now > serverTime + maxClockSkew (TimestampFuture), when maxClockSkew > 0
func (p *Principal) applyCozInternal(cz *ParsedCoz, newKey *coz.Key) error {
	// Validate timestamp is not in the past (SPEC §14.1)
	if cz.Now < p.latestTimestamp {
		return ErrTimestampPast
	}

	// Validate timestamp is not too far in the future (SPEC §14.1)
	// Only check if maxClockSkew is configured (> 0)
	if p.maxClockSkew > 0 {
		serverTime := currentTime()
		if cz.Now > serverTime+p.maxClockSkew {
			return ErrTimestampFuture
		}
	}

	// Verify signer is an active key (except for self-revoke and commit/create).
	// Self-revoke: signer IS the key being revoked, handled in dispatch below.
	// Commit/create: authorization is verified by verifyCozWithSnapshot against
	// the pre-commit key snapshot per [pre-mutation-key-rule]. The commit/create
	// doesn't mutate state, so no further check is needed here.
	if cz.Kind == TxRevoke && len(cz.ID) == 0 {
		// Self-revoke: signer revokes itself. Signer must be active but
		// will be removed, so we verify below in the dispatch.
	} else if cz.Kind == TxCommitCreate {
		// Commit/create: authorization already verified against pre-commit
		// snapshot. Skip live-state check.
	} else {
		if !p.IsKeyActive(cz.Signer) {
			// Check if key exists but is revoked
			for _, k := range p.auth.Revoked {
				if bytes.Equal(k.Tmb, cz.Signer) {
					return ErrKeyRevoked
				}
			}
			return ErrUnknownKey
		}
	}

	switch cz.Kind {
	case TxKeyCreate:
		if err := p.verifyPre(cz.Pre); err != nil {
			return err
		}
		if newKey == nil {
			return ErrMalformedPayload
		}
		if !bytes.Equal(newKey.Tmb, cz.ID) {
			return ErrMalformedPayload
		}
		if p.IsKeyActive(cz.ID) {
			return ErrDuplicateKey
		}
		if err := p.addKey(newKey, cz.Now); err != nil {
			return err
		}

	case TxKeyDelete:
		if err := p.verifyPre(cz.Pre); err != nil {
			return err
		}
		if err := p.removeKey(cz.ID); err != nil {
			return err
		}

	case TxKeyReplace:
		if err := p.verifyPre(cz.Pre); err != nil {
			return err
		}
		if newKey == nil {
			return ErrMalformedPayload
		}
		if !bytes.Equal(newKey.Tmb, cz.ID) {
			return ErrMalformedPayload
		}
		// Atomic swap: add new key first, then remove signer
		if err := p.addKey(newKey, cz.Now); err != nil {
			return err
		}
		// Remove signer directly (bypassing NoActiveKeys check since we just added)
		p.removeKeyDirect(cz.Signer)

	case TxRevoke:
		if err := p.verifyPre(cz.Pre); err != nil {
			return err
		}
		// Self-revoke: cz.ID is empty, target is the signer.
		// Other-revoke: cz.ID is the target key.
		target := cz.Signer
		var by *coz.B64
		if len(cz.ID) > 0 {
			target = cz.ID
			signer := coz.B64(cz.Signer)
			by = &signer
		}
		if err := p.revokeKey(target, cz.Rvk, by); err != nil {
			return err
		}

	case TxPrincipalCreate:
		// SPEC §5.1: Genesis finalization. Verify pre and id matches PS.
		if err := p.verifyPre(cz.Pre); err != nil {
			return err
		}
		// id must equal current PS (SPEC §5.1:609 — "id: Final PS = PR")
		if !bytes.Equal(cz.ID, p.pr.First()) {
			return ErrMalformedPayload
		}
		// Freeze PR at current PS (SPEC §5.1:600 — "principal/create establishes PR")
		pr := NewPrincipalGenesis(p.pr)
		p.pg = &pr
	}

	// Update signer's last_used timestamp
	p.updateLastUsed(cz.Signer, cz.Now)

	// Update latest timestamp
	if cz.Now > p.latestTimestamp {
		p.latestTimestamp = cz.Now
	}

	// Record coz in the flat history.
	// Note: czd accumulation for commit boundaries is handled by CommitBatch.
	p.auth.Cozies = append(p.auth.Cozies, cz)

	return nil
}

// verifyPre checks that the coz's pre matches current PS.
// At genesis (before first commit), PS is promoted from AS, so pre = AS = PS.
func (p *Principal) verifyPre(pre PrincipalRoot) error {
	if !bytes.Equal(p.pr.First(), pre.First()) {
		return ErrInvalidPrior
	}
	return nil
}

// addKey adds a key to the active set.
// Returns ErrKeyRevoked if the key was previously revoked (invariant I2:
// revocations are permanent).
func (p *Principal) addKey(key *coz.Key, firstSeen int64) error {
	// BUG-12 / I2: Reject re-adding a revoked key.
	if p.IsKeyRevoked(key.Tmb) {
		return ErrKeyRevoked
	}

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
	return nil
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
func (p *Principal) revokeKey(tmb coz.B64, rvk int64, by *coz.B64) error {
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
// Returns a CommitBatch that accumulates cozies. The caller MUST
// call Finalize() to complete the commit, or abandon the batch.
//
// For single-coz commits, use [Principal.ApplyCoz] instead.
func (p *Principal) BeginCommit() *CommitBatch {
	// Snapshot active keys for pre-mutation authorization checks
	// per [pre-mutation-key-rule].
	snapshot := make(map[string]*Key, len(p.auth.Keys))
	for _, k := range p.auth.Keys {
		snapshot[k.Tmb.String()] = k
	}
	return &CommitBatch{
		principal:     p,
		pending:       NewPendingCommit(p.hashAlg),
		preCommitKeys: snapshot,
	}
}

// ApplyCoz applies a single verified coz as an atomic commit.
//
// This is the primary convenience method for the common case (one cz = one commit).
// Internally calls BeginCommit, Apply, and Finalize.
func (p *Principal) ApplyCoz(vt *VerifiedCoz) (*Commit, error) {
	batch := p.BeginCommit()
	if err := batch.Apply(vt); err != nil {
		return nil, err
	}
	return batch.Finalize()
}

// finalizeCommit recomputes all state digests and produces an immutable Commit.
//
// This is called by CommitBatch.Finalize() — not typically called directly.
func (p *Principal) finalizeCommit(pending *PendingCommit) (*Commit, error) {
	if pending.IsEmpty() {
		return nil, ErrEmptyCommit
	}

	// Validate arrow field placement: only last cz may have it,
	// and last cz MUST have it (SPEC §4.4).
	cozies := pending.Cozies()
	for i, cz := range cozies {
		isLast := i == len(cozies)-1
		if cz.Arrow != nil && !isLast {
			return nil, ErrCommitNotLast
		}
		if cz.Arrow == nil && isLast {
			return nil, ErrMissingCommit
		}
	}

	// Re-derive active algorithms from post-mutation key set.
	// Per [alg-set-evolution], state digests for this commit use the
	// algorithms supported by the post-mutation key set.
	p.activeAlgs = DeriveHashAlgs(p.auth.Keys)

	// Recompute KS from active keys
	thumbprints := make([]coz.B64, len(p.auth.Keys))
	for i, k := range p.auth.Keys {
		thumbprints[i] = k.Tmb
	}
	kr, err := ComputeKR(thumbprints, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	p.kr = kr

	// Recompute AR = MR(KR, RR?, embedding?)
	ar, err := ComputeAR(p.kr, nil, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	p.ar = ar

	// Compute Transaction Roots (TMR, TCR, TR) from this commit's transactions (SPEC §14.2).
	// CZDs are single-algorithm, so TMR/TCR/TR use the commit's hash algorithm.
	tmr, _, tr, err := pending.ComputeRoots([]HashAlg{pending.hashAlg})
	if err != nil {
		return nil, err
	}
	p.tr = tr

	// Recompute SR = MR(AR, DR?, embedding?)
	sr, err := ComputeSR(p.ar, p.dr, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	p.sr = sr

	// Validate arrow field matches independently computed Arrow.
	// Arrow = MR(pre, fwd_SR, TMR)
	// We compare against the computed Arrow at the signer's specific algorithm.
	lastTx := cozies[len(cozies)-1]
	if lastTx.Arrow != nil {
		txAlgs := lastTx.Arrow.Algorithms()
		if len(txAlgs) == 0 {
			return nil, ErrCommitMismatch
		}
		txAlg := txAlgs[0]

		// pre is the PR *before* this commit. p.pr has not been updated yet
		// (that happens at the end of this function), so it correctly holds
		// the prior value.
		pre := p.pr

		components := [][]byte{
			pre.GetOrFirst(txAlg),
			sr.GetOrFirst(txAlg),
			tmr.GetOrFirst(txAlg),
		}

		computedDigest, err := hashSortedConcatBytes(txAlg, components...)
		if err != nil {
			return nil, err
		}

		txDigest := lastTx.Arrow.Get(txAlg)
		if txDigest == nil || !bytes.Equal(txDigest, computedDigest) {
			return nil, ErrCommitMismatch
		}
	}

	// Ensure per-algorithm MALTs exist for all active algorithms.
	// New algorithms get a fresh MALT populated with prior TRs via [conversion].
	if p.commitTrees == nil {
		p.commitTrees = make(CommitTrees, len(p.activeAlgs))
	}
	for _, alg := range p.activeAlgs {
		if _, ok := p.commitTrees[alg]; !ok {
			// New algorithm — create MALT and replay prior commits.
			// [conversion]: TR.GetOrFirst(alg) returns the native variant
			// if available, otherwise the first variant's bytes. The MALT
			// leaf hash H(0x00 || bytes) provides the conversion.
			log := malt.New[string](NewCyphrpassHasher(alg))
			for _, priorCommit := range p.commits {
				if priorCommit.TR() != nil {
					log.Append(priorCommit.TR().GetOrFirst(alg))
				}
			}
			p.commitTrees[alg] = log
		}
	}

	// Append current TR to all active MALTs and assemble CR.
	// Only active algorithms contribute to the current CR;
	// stale algorithm MALTs are retained but excluded.
	activeTrees := make(CommitTrees, len(p.activeAlgs))
	for _, alg := range p.activeAlgs {
		p.commitTrees[alg].Append(tr.GetOrFirst(alg))
		activeTrees[alg] = p.commitTrees[alg]
	}
	cr, err := NewCommitRootFromTrees(activeTrees)
	if err != nil {
		return nil, err
	}
	p.cr = cr

	// Recompute PR = MR(SR, CR?, embedding?)
	pr, err := ComputePR(p.sr, p.cr, nil, p.activeAlgs)
	if err != nil {
		return nil, err
	}
	p.pr = pr

	// Finalize the pending commit into an immutable Commit
	commit, err := pending.Finalize(p.ar, p.sr, p.pr)
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
