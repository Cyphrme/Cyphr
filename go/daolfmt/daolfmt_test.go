package daolfmt

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"testing"
)

// ---------------------------------------------------------------------------
// Test hasher: FNV-1a (64-bit), matching the Rust test hasher exactly.
// ---------------------------------------------------------------------------

const (
	fnvOffset = 0xcbf29ce484222325
	fnvPrime  = 0x00000100000001B3
)

func fnv1a(data []byte) [8]byte {
	hash := uint64(fnvOffset)
	for _, b := range data {
		hash ^= uint64(b)
		hash *= fnvPrime
	}
	var result [8]byte
	binary.BigEndian.PutUint64(result[:], hash)
	return result
}

// SimpleHasher is a deterministic, domain-separating test hasher using
// FNV-1a (64-bit). NOT cryptographically secure.
type SimpleHasher struct{}

// Compile-time interface satisfaction check.
var _ TreeHasher[[8]byte] = SimpleHasher{}

func (SimpleHasher) Leaf(data []byte) [8]byte {
	buf := make([]byte, 1+len(data))
	buf[0] = 0x00
	copy(buf[1:], data)
	return fnv1a(buf)
}

func (SimpleHasher) Node(left, right [8]byte) [8]byte {
	var buf [1 + 8 + 8]byte
	buf[0] = 0x01
	copy(buf[1:], left[:])
	copy(buf[9:], right[:])
	return fnv1a(buf[:])
}

func (SimpleHasher) Empty() [8]byte {
	return fnv1a(nil)
}

func buildLog(n uint64) *Log[[8]byte] {
	log := New[[8]byte](SimpleHasher{})
	for i := range n {
		log.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return log
}

// ---------------------------------------------------------------------------
// Core tests
// ---------------------------------------------------------------------------

func TestEmptyRoot(t *testing.T) {
	log := New[[8]byte](SimpleHasher{})
	h := SimpleHasher{}
	if log.Root() != h.Empty() {
		t.Fatal("empty log root should equal Empty()")
	}
	if log.Size() != 0 {
		t.Fatal("empty log size should be 0")
	}
}

func TestSingleLeaf(t *testing.T) {
	log := New[[8]byte](SimpleHasher{})
	log.Append([]byte("hello"))
	h := SimpleHasher{}
	if log.Root() != h.Leaf([]byte("hello")) {
		t.Fatal("single leaf root should equal Leaf(data)")
	}
	if log.Size() != 1 {
		t.Fatal("size should be 1 after one append")
	}
}

func TestAppendReturnsSequentialIndices(t *testing.T) {
	log := New[[8]byte](SimpleHasher{})
	for i := range uint64(10) {
		index := log.Append([]byte(fmt.Sprintf("entry-%d", i)))
		if index != i {
			t.Fatalf("append should return sequential 0-based indices: got %d, want %d", index, i)
		}
	}
}

// A-EQUIV (formal model §3.4): two independently-built logs with the same
// inputs must produce identical roots.
func TestAEquivIncrementalEqualsBatch(t *testing.T) {
	for n := uint64(1); n <= 33; n++ {
		a := buildLog(n)
		b := buildLog(n)
		if a.Root() != b.Root() {
			t.Fatalf("A-EQUIV failed for n=%d: two logs produced different roots", n)
		}
	}
}

// A-STACK (formal model §3.4): after each append, the frontier stack has
// exactly popcount(size) entries.
func TestAStackPopcountInvariant(t *testing.T) {
	log := New[[8]byte](SimpleHasher{})
	for i := range uint64(64) {
		log.Append([]byte(fmt.Sprintf("leaf-%d", i)))
		expected := bits.OnesCount64(log.Size())
		if log.stackLen() != expected {
			t.Fatalf("A-STACK failed at size=%d: stackLen=%d, popcount=%d",
				log.Size(), log.stackLen(), expected)
		}
	}
}

// Determinism: same inputs, same hasher → same root.
func TestDeterministicRoot(t *testing.T) {
	build := func() [8]byte {
		log := New[[8]byte](SimpleHasher{})
		for i := range 20 {
			log.Append([]byte(fmt.Sprintf("entry-%d", i)))
		}
		return log.Root()
	}
	r1 := build()
	r2 := build()
	if r1 != r2 {
		t.Fatal("same inputs must produce same root")
	}
}

// Two-leaf tree should hash as Node(Leaf(a), Leaf(b)).
func TestTwoLeafStructure(t *testing.T) {
	log := New[[8]byte](SimpleHasher{})
	log.Append([]byte("alpha"))
	log.Append([]byte("beta"))

	h := SimpleHasher{}
	expected := h.Node(h.Leaf([]byte("alpha")), h.Leaf([]byte("beta")))
	if log.Root() != expected {
		t.Fatal("two-leaf root mismatch")
	}
}

// Domain separation: Leaf(x) must differ from Node(a, b).
func TestDomainSeparation(t *testing.T) {
	h := SimpleHasher{}
	leaf := h.Leaf([]byte("test"))
	node := h.Node(h.Leaf([]byte("a")), h.Leaf([]byte("b")))
	if leaf == node {
		t.Fatal("leaf and node hashes must differ (domain separation)")
	}
}

// Power-of-two sizes should produce deterministic roots.
func TestPowerOfTwoSizes(t *testing.T) {
	for exp := uint(1); exp <= 5; exp++ {
		n := uint64(1) << exp
		a := buildLog(n)
		b := buildLog(n)
		if a.Root() != b.Root() {
			t.Fatalf("power-of-two size %d: roots disagree", n)
		}
	}
}

// ---------------------------------------------------------------------------
// Internal helper tests
// ---------------------------------------------------------------------------

func TestLargestPow2LessThan(t *testing.T) {
	cases := []struct{ n, want int }{
		{2, 1}, {3, 2}, {4, 2}, {5, 4}, {6, 4},
		{7, 4}, {8, 4}, {9, 8}, {15, 8}, {16, 8}, {17, 16},
	}
	for _, tc := range cases {
		got := largestPow2LessThan(tc.n)
		if got != tc.want {
			t.Errorf("largestPow2LessThan(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

func TestCountTrailingOnes(t *testing.T) {
	cases := []struct {
		n    uint64
		want int
	}{
		{0b0000, 0}, {0b0001, 1}, {0b0011, 2},
		{0b0101, 1}, {0b0111, 3}, {0b1010, 0},
	}
	for _, tc := range cases {
		got := countTrailingOnes(tc.n)
		if got != tc.want {
			t.Errorf("countTrailingOnes(%b) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Proof tests
// ---------------------------------------------------------------------------

func ceilLog2(n uint64) int {
	if n <= 1 {
		return 0
	}
	return bits.Len64(n - 1)
}

// I-SOUND (formal model §4.4): a correctly generated inclusion proof
// always verifies.
func TestISoundInclusionProofsVerify(t *testing.T) {
	h := SimpleHasher{}
	for n := uint64(1); n <= 17; n++ {
		log := buildLog(n)
		root := log.Root()
		for m := uint64(0); m < n; m++ {
			proof, err := log.InclusionProof(m)
			if err != nil {
				t.Fatalf("n=%d m=%d: InclusionProof error: %v", n, m, err)
			}
			leafHash := h.Leaf([]byte(fmt.Sprintf("leaf-%d", m)))
			if !VerifyInclusion(h, leafHash, proof, root) {
				t.Fatalf("I-SOUND failed: n=%d, m=%d", n, m)
			}
		}
	}
}

// K-SOUND (formal model §5.4): a correctly generated consistency proof
// always verifies.
func TestKSoundConsistencyProofsVerify(t *testing.T) {
	h := SimpleHasher{}
	for n := uint64(2); n <= 17; n++ {
		log := buildLog(n)
		newRoot := log.Root()
		for m := uint64(1); m < n; m++ {
			proof, err := log.ConsistencyProof(m)
			if err != nil {
				t.Fatalf("n=%d m=%d: ConsistencyProof error: %v", n, m, err)
			}
			oldRoot := buildLog(m).Root()
			if !VerifyConsistency(h, proof, oldRoot, newRoot) {
				t.Fatalf("K-SOUND failed: n=%d, m=%d", n, m)
			}
		}
	}
}

// Inclusion proof rejects a tampered leaf hash.
func TestInclusionRejectsWrongLeaf(t *testing.T) {
	h := SimpleHasher{}
	log := buildLog(8)
	root := log.Root()
	proof, err := log.InclusionProof(3)
	if err != nil {
		t.Fatal(err)
	}
	wrongLeaf := h.Leaf([]byte("wrong"))
	if VerifyInclusion(h, wrongLeaf, proof, root) {
		t.Fatal("should reject wrong leaf")
	}
}

// Inclusion proof rejects a wrong root.
func TestInclusionRejectsWrongRoot(t *testing.T) {
	h := SimpleHasher{}
	log := buildLog(8)
	proof, err := log.InclusionProof(3)
	if err != nil {
		t.Fatal(err)
	}
	leafHash := h.Leaf([]byte("leaf-3"))
	wrongRoot := h.Leaf([]byte("wrong"))
	if VerifyInclusion(h, leafHash, proof, wrongRoot) {
		t.Fatal("should reject wrong root")
	}
}

// Consistency proof rejects a wrong old root.
func TestConsistencyRejectsWrongOldRoot(t *testing.T) {
	h := SimpleHasher{}
	log := buildLog(8)
	newRoot := log.Root()
	proof, err := log.ConsistencyProof(4)
	if err != nil {
		t.Fatal(err)
	}
	wrongOldRoot := h.Leaf([]byte("wrong"))
	if VerifyConsistency(h, proof, wrongOldRoot, newRoot) {
		t.Fatal("should reject wrong old root")
	}
}

// Consistency proof rejects a wrong new root.
func TestConsistencyRejectsWrongNewRoot(t *testing.T) {
	h := SimpleHasher{}
	log := buildLog(8)
	proof, err := log.ConsistencyProof(4)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := buildLog(4).Root()
	wrongNewRoot := h.Leaf([]byte("wrong"))
	if VerifyConsistency(h, proof, oldRoot, wrongNewRoot) {
		t.Fatal("should reject wrong new root")
	}
}

// I-SIZE (§4.4): |PATH(m, D_n)| ≤ ⌈log₂(n)⌉.
func TestInclusionProofSizeBounded(t *testing.T) {
	for n := uint64(1); n <= 33; n++ {
		log := buildLog(n)
		maxLen := ceilLog2(n)
		for m := uint64(0); m < n; m++ {
			proof, err := log.InclusionProof(m)
			if err != nil {
				t.Fatalf("n=%d m=%d: error: %v", n, m, err)
			}
			if len(proof.Path) > maxLen {
				t.Fatalf("I-SIZE violated: n=%d m=%d, path len %d > ceil_log2 %d",
					n, m, len(proof.Path), maxLen)
			}
		}
	}
}

// K-SIZE (§5.4): |PROOF(m, D_n)| ≤ ⌈log₂(n)⌉ + 1.
func TestConsistencyProofSizeBounded(t *testing.T) {
	for n := uint64(2); n <= 33; n++ {
		log := buildLog(n)
		maxLen := ceilLog2(n) + 1
		for m := uint64(1); m < n; m++ {
			proof, err := log.ConsistencyProof(m)
			if err != nil {
				t.Fatalf("n=%d m=%d: error: %v", n, m, err)
			}
			if len(proof.Path) > maxLen {
				t.Fatalf("K-SIZE violated: n=%d m=%d, path len %d > ceil_log2+1 %d",
					n, m, len(proof.Path), maxLen)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Error-case tests
// ---------------------------------------------------------------------------

func TestInclusionProofEmptyTree(t *testing.T) {
	log := New[[8]byte](SimpleHasher{})
	_, err := log.InclusionProof(0)
	if err == nil {
		t.Fatal("expected error for empty tree")
	}
}

func TestInclusionProofOutOfBounds(t *testing.T) {
	log := buildLog(5)
	_, err := log.InclusionProof(5)
	if err == nil {
		t.Fatal("expected error for out-of-bounds index")
	}
	_, err = log.InclusionProof(100)
	if err == nil {
		t.Fatal("expected error for far out-of-bounds index")
	}
}

func TestConsistencyProofEmptyTree(t *testing.T) {
	log := New[[8]byte](SimpleHasher{})
	_, err := log.ConsistencyProof(0)
	if err == nil {
		t.Fatal("expected error for empty tree")
	}
}

func TestConsistencyProofOldSizeZero(t *testing.T) {
	log := buildLog(5)
	_, err := log.ConsistencyProof(0)
	if err == nil {
		t.Fatal("expected error for old_size=0")
	}
}

func TestConsistencyProofOldSizeGeNewSize(t *testing.T) {
	log := buildLog(5)
	_, err := log.ConsistencyProof(5)
	if err == nil {
		t.Fatal("expected error for old_size == new_size")
	}
	_, err = log.ConsistencyProof(10)
	if err == nil {
		t.Fatal("expected error for old_size > new_size")
	}
}

// Verifier rejects invalid index directly.
func TestVerifyInclusionRejectsBadIndex(t *testing.T) {
	h := SimpleHasher{}
	proof := &InclusionProof[[8]byte]{Index: 5, TreeSize: 5}
	if VerifyInclusion(h, h.Leaf([]byte("x")), proof, h.Empty()) {
		t.Fatal("should reject index >= tree_size")
	}
}

// Verifier rejects invalid old_size directly.
func TestVerifyConsistencyRejectsOldSizeZero(t *testing.T) {
	h := SimpleHasher{}
	proof := &ConsistencyProof[[8]byte]{OldSize: 0, NewSize: 5}
	if VerifyConsistency(h, proof, h.Empty(), h.Empty()) {
		t.Fatal("should reject old_size=0")
	}
}

// Verifier rejects old_size >= new_size.
func TestVerifyConsistencyRejectsOldGeNew(t *testing.T) {
	h := SimpleHasher{}
	proof := &ConsistencyProof[[8]byte]{OldSize: 5, NewSize: 5}
	if VerifyConsistency(h, proof, h.Empty(), h.Empty()) {
		t.Fatal("should reject old_size >= new_size")
	}
}
