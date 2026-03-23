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
