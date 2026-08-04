package cyphr

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cyphrme/malt"
)

// buildPrincipalWithCommits creates a principal with nCommits key/create
// commits and returns the principal plus all keys (genesis + added).
func buildPrincipalWithCommits(t *testing.T, nCommits int) (*Principal, []*Key) {
	t.Helper()

	keys := []*Key{{Key: makeTestCozKey(0x01)}}
	p, err := Implicit(keys[0].Key)
	if err != nil {
		t.Fatalf("Implicit failed: %v", err)
	}

	for i := 0; i < nCommits; i++ {
		newCozKey := makeTestCozKey(byte(i + 2))
		newKey := &Key{Key: newCozKey}
		signer := keys[len(keys)-1].Tmb

		cz := &ParsedCoz{
			Kind:    TxKeyCreate,
			Signer:  signer,
			HashAlg: HashSha256,
			Now:     int64(1000 + (i+1)*1000),
			Czd:     bytes.Repeat([]byte{byte(0xA0 + i)}, 32),
			Pre:     p.PR(),
			ID:      newCozKey.Tmb,
		}

		_, err := p.ApplyTransactionUnsafe(cz, newCozKey)
		if err != nil {
			t.Fatalf("commit %d failed: %v", i, err)
		}
		keys = append(keys, newKey)
	}

	return p, keys
}

func TestInclusionProofVerifies(t *testing.T) {
	p, _ := buildPrincipalWithCommits(t, 4)
	alg := p.HashAlg()
	log := p.CommitTreesAccessor()[alg]
	root := log.Root()
	hasher := NewCyphrHasher(alg)

	for i := uint64(0); i < log.Size(); i++ {
		proof, err := p.InclusionProof(alg, i)
		if err != nil {
			t.Fatalf("InclusionProof(%d) error: %v", i, err)
		}
		commit := p.Commits()[i]
		trBytes := commit.TR().GetOrFirst(alg)
		leafHash := hasher.Leaf(trBytes)

		if !malt.VerifyInclusion(hasher, leafHash, proof, root) {
			t.Errorf("inclusion proof failed for index %d", i)
		}
	}
}

func TestConsistencyProofVerifies(t *testing.T) {
	p, _ := buildPrincipalWithCommits(t, 5)
	alg := p.HashAlg()
	log := p.CommitTreesAccessor()[alg]
	newRoot := log.Root()
	hasher := NewCyphrHasher(alg)

	// Build a reference log to capture intermediate roots.
	refLog := malt.New[string](NewCyphrHasher(alg))
	roots := make([]string, 0, log.Size())
	for _, commit := range p.Commits() {
		trBytes := commit.TR().GetOrFirst(alg)
		refLog.Append(trBytes)
		roots = append(roots, refLog.Root())
	}

	for oldSize := uint64(1); oldSize < log.Size(); oldSize++ {
		proof, err := p.ConsistencyProof(alg, oldSize)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d) error: %v", oldSize, err)
		}
		oldRoot := roots[oldSize-1]

		if !malt.VerifyConsistency(hasher, proof, oldRoot, newRoot) {
			t.Errorf("consistency proof failed for old_size %d", oldSize)
		}
	}
}

func TestInclusionProofOutOfBounds(t *testing.T) {
	p, _ := buildPrincipalWithCommits(t, 3)
	alg := p.HashAlg()

	// Index == tree_size should fail.
	_, err := p.InclusionProof(alg, 3)
	if err == nil {
		t.Error("should reject out-of-bounds index")
	}

	// Large index should also fail.
	_, err = p.InclusionProof(alg, 999)
	if err == nil {
		t.Error("should reject large index")
	}
}

func TestConsistencyProofInvalidOldSize(t *testing.T) {
	p, _ := buildPrincipalWithCommits(t, 3)
	alg := p.HashAlg()

	// old_size == 0 should fail.
	_, err := p.ConsistencyProof(alg, 0)
	if err == nil {
		t.Error("should reject old_size=0")
	}

	// old_size >= tree_size should fail.
	_, err = p.ConsistencyProof(alg, 3)
	if err == nil {
		t.Error("should reject old_size >= tree_size")
	}
}

func TestProofRejectsUnknownAlgorithm(t *testing.T) {
	p, _ := buildPrincipalWithCommits(t, 2)

	// SHA-384 was never introduced (all test keys use ES256/SHA-256).
	_, err := p.InclusionProof(HashSha384, 0)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
	}

	_, err = p.ConsistencyProof(HashSha384, 1)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestCheckpointRoundTripPreservesMALTState(t *testing.T) {
	p, keys := buildPrincipalWithCommits(t, 4)
	alg := p.HashAlg()

	originalTrees := p.CommitTreesAccessor()

	restored, err := FromCheckpoint(p.PG(), p.AR(), keys, originalTrees)
	if err != nil {
		t.Fatalf("FromCheckpoint failed: %v", err)
	}

	// CR must match.
	if p.CR() == nil {
		t.Fatal("original CR should not be nil after commits")
	}
	if restored.CR() == nil {
		t.Fatal("restored CR should not be nil when trees provided")
	}
	if !bytes.Equal(p.CR().First(), restored.CR().First()) {
		t.Error("checkpoint round-trip must preserve CR")
	}

	// Proof generation must work on restored principal.
	proof, err := restored.InclusionProof(alg, 0)
	if err != nil {
		t.Fatalf("InclusionProof on restored: %v", err)
	}
	log := restored.CommitTreesAccessor()[alg]
	root := log.Root()
	hasher := NewCyphrHasher(alg)
	trBytes := p.Commits()[0].TR().GetOrFirst(alg)
	leafHash := hasher.Leaf(trBytes)

	if !malt.VerifyInclusion(hasher, leafHash, proof, root) {
		t.Error("inclusion proof must verify on checkpoint-restored principal")
	}
}

func TestCheckpointWithoutTreesHasNoCR(t *testing.T) {
	p, keys := buildPrincipalWithCommits(t, 3)

	restored, err := FromCheckpoint(p.PG(), p.AR(), keys, nil)
	if err != nil {
		t.Fatalf("FromCheckpoint failed: %v", err)
	}

	if restored.CR() != nil {
		t.Error("from_checkpoint without trees must have no CR")
	}
	if len(restored.CommitTreesAccessor()) != 0 {
		t.Error("from_checkpoint without trees must have empty commit_trees")
	}
}

func TestCheckpointPRIncludesCRWhenTreesProvided(t *testing.T) {
	p, keys := buildPrincipalWithCommits(t, 3)
	trees := p.CommitTreesAccessor()

	withTrees, err := FromCheckpoint(p.PG(), p.AR(), keys, trees)
	if err != nil {
		t.Fatalf("FromCheckpoint with trees failed: %v", err)
	}

	withoutTrees, err := FromCheckpoint(p.PG(), p.AR(), keys, nil)
	if err != nil {
		t.Fatalf("FromCheckpoint without trees failed: %v", err)
	}

	prWith := withTrees.PR().First()
	prWithout := withoutTrees.PR().First()

	if bytes.Equal(prWith, prWithout) {
		t.Error("PR must differ when CR is present vs absent")
	}
}
