// Package daolfmt implements a Dense, Append-Only, Left-Filled Merkle Tree
// conforming to RFC 9162 §2.1.
//
// The tree is parameterized by a [TreeHasher] that defines the hash
// operations. It supports O(1) amortized appends via a frontier stack and
// O(1) root extraction.
//
// Zero external dependencies — callers provide their own hash implementation.
//
// # Panic Policy
//
// This package panics in two locations where the stack state is guaranteed
// by structural invariants:
//
//   - [Log.Append] — merge pops are bounded by countTrailingOnes(size),
//     which guarantees sufficient stack depth by construction (A-STACK).
//   - [Log.Root] — iterates a non-empty stack (guarded by size > 0).
//
// These guard invariants proven correct by the formal model (§3.4 A-STACK,
// A-EQUIV). They are not input-validation panics.
package daolfmt

import "math/bits"

// TreeHasher defines the hash abstraction for the Merkle tree.
//
// The tree is fully generic over this interface — callers provide the
// concrete hash implementation.
//
// # Model Mapping
//
//	| Method | Formal model (§1) | Operation                |
//	|:-------|:-------------------|:-------------------------|
//	| Leaf   | H.leaf(d)          | H(0x00 || data)          |
//	| Node   | H.node(l, r)       | H(0x01 || left || right) |
//	| Empty  | H.empty            | H("")                    |
//
// # Domain Separation (C-DOMAIN)
//
// Implementations must ensure Leaf(d) ≠ Node(l, r) for all inputs.
// The standard approach is to prepend 0x00 for leaves and 0x01 for
// interior nodes before hashing (RFC 9162 §2.1).
type TreeHasher[D comparable] interface {
	// Leaf hashes a leaf entry: H(0x00 || data).
	Leaf(data []byte) D

	// Node hashes two child nodes: H(0x01 || left || right).
	Node(left, right D) D

	// Empty returns the hash of the empty string: H(""). Root of an empty tree.
	Empty() D
}

// Log is a dense, append-only, left-filled Merkle tree (RFC 9162 §2.1).
//
// The tree supports O(1) amortized appends via a frontier stack and O(1)
// root extraction. Leaf hashes are retained for proof generation.
type Log[D comparable] struct {
	hasher TreeHasher[D]
	leaves []D
	size   uint64
	stack  []D
}

// New creates a new empty log with the given hasher.
func New[D comparable](hasher TreeHasher[D]) *Log[D] {
	return &Log[D]{hasher: hasher}
}

// Append adds a new entry to the log and returns the 0-based leaf index.
//
// Uses the incremental stack-based algorithm from the formal model §3.2:
// push the leaf hash, then merge complete pairs by counting trailing ones
// in the pre-increment size.
func (l *Log[D]) Append(data []byte) uint64 {
	hash := l.hasher.Leaf(data)
	l.leaves = append(l.leaves, hash)
	l.stack = append(l.stack, hash)

	mergeCount := countTrailingOnes(l.size)
	for range mergeCount {
		// Structure-guarded: mergeCount is bounded by the number of trailing
		// 1-bits in l.size, guaranteeing at least 2 elements on the stack.
		// See: package doc § Panic Policy.
		right := l.stack[len(l.stack)-1]
		l.stack = l.stack[:len(l.stack)-1]
		left := l.stack[len(l.stack)-1]
		l.stack = l.stack[:len(l.stack)-1]
		l.stack = append(l.stack, l.hasher.Node(left, right))
	}

	index := l.size
	l.size++
	return index
}

// Size returns the current number of leaves in the log.
func (l *Log[D]) Size() uint64 {
	return l.size
}

// Root returns the current root hash of the log.
//
// For an empty tree, returns H.Empty(). For a non-empty tree, folds the
// frontier stack right-to-left per §3.3.
func (l *Log[D]) Root() D {
	if l.size == 0 {
		return l.hasher.Empty()
	}

	// Zero-alloc fold: iterate the stack in reverse, accumulating
	// node hashes from right to left.
	r := l.stack[len(l.stack)-1]
	for i := len(l.stack) - 2; i >= 0; i-- {
		r = l.hasher.Node(l.stack[i], r)
	}
	return r
}

// Hasher returns the hasher used by this log.
func (l *Log[D]) Hasher() TreeHasher[D] {
	return l.hasher
}

// stackLen returns the number of entries in the frontier stack.
// Used for testing invariant A-STACK.
func (l *Log[D]) stackLen() int {
	return len(l.stack)
}

// mth computes the batch Merkle Tree Hash per formal model §2.1.
//
// Returns the root hash of an ordered list of leaf hashes using the
// recursive definition. Used internally for proof generation.
func mth[D comparable](hasher TreeHasher[D], leaves []D) D {
	switch len(leaves) {
	case 0:
		return hasher.Empty()
	case 1:
		return leaves[0]
	default:
		k := largestPow2LessThan(len(leaves))
		left := mth(hasher, leaves[:k])
		right := mth(hasher, leaves[k:])
		return hasher.Node(left, right)
	}
}

// largestPow2LessThan returns the largest power of 2 strictly less than n
// (formal model §2.2). Panics if n <= 1.
func largestPow2LessThan(n int) int {
	if n <= 1 {
		panic("largestPow2LessThan requires n > 1")
	}
	// 2^(floor(log2(n - 1)))
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// countTrailingOnes counts the trailing 1-bits in the binary representation.
func countTrailingOnes(n uint64) int {
	return bits.TrailingZeros64(^n)
}
