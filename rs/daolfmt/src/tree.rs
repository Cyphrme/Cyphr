use std::fmt::Debug;

use crate::Error;
use crate::proof::{ConsistencyProof, InclusionProof};

/// Hash abstraction for the Merkle tree.
///
/// Defines the three operations required by the tree: leaf hashing,
/// interior node hashing, and the empty-tree hash. The tree is fully
/// generic over this trait — callers provide the concrete hash
/// implementation.
///
/// # Domain Separation (C-DOMAIN)
///
/// Implementations **must** ensure `hash_leaf(d) ≠ hash_children(l, r)`
/// for all inputs. The standard approach is to prepend `0x00` for leaves
/// and `0x01` for interior nodes before hashing (RFC 9162 §2.1).
pub trait TreeHasher {
    /// The digest type produced by this hasher.
    ///
    /// Must be cheaply cloneable, comparable, and printable for debugging.
    type Digest: Clone + Eq + Debug;

    /// Hash a leaf entry: `H(0x00 || data)`.
    fn hash_leaf(&self, data: &[u8]) -> Self::Digest;

    /// Hash two children: `H(0x01 || left || right)`.
    fn hash_children(&self, left: &Self::Digest, right: &Self::Digest) -> Self::Digest;

    /// Hash of the empty string: `H("")`. Used as the root of an empty tree.
    fn hash_empty(&self) -> Self::Digest;
}

/// A dense, append-only, left-filled Merkle tree (RFC 9162 §2.1).
///
/// The tree is parameterized by a [`TreeHasher`] that defines the hash
/// operations. It supports O(1) amortized appends via a frontier stack
/// and O(1) root extraction.
///
/// Leaf hashes are retained for future proof generation.
pub struct Log<H: TreeHasher> {
    hasher: H,
    /// Stored leaf hashes for proof generation.
    leaves: Vec<H::Digest>,
    /// Number of leaves appended.
    size: u64,
    /// Frontier stack: roots of complete subtrees along the right edge.
    stack: Vec<H::Digest>,
}

impl<H: TreeHasher> Log<H> {
    /// Create a new empty log with the given hasher.
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            leaves: Vec::new(),
            size: 0,
            stack: Vec::new(),
        }
    }

    /// Append a new entry to the log. Returns the 0-based leaf index.
    ///
    /// Uses the incremental stack-based algorithm from the formal model
    /// §3.2: push the leaf hash, then merge complete pairs by counting
    /// trailing ones in the pre-increment size.
    pub fn append(&mut self, data: &[u8]) -> u64 {
        let hash = self.hasher.hash_leaf(data);
        self.leaves.push(hash.clone());
        self.stack.push(hash);

        let merge_count = count_trailing_ones(self.size);
        for _ in 0..merge_count {
            // Safety: merge_count is bounded by the number of trailing 1-bits
            // in self.size, which guarantees at least 2 elements on the stack
            // for each merge iteration.
            let right = self.stack.pop().expect("stack underflow in merge");
            let left = self.stack.pop().expect("stack underflow in merge");
            self.stack.push(self.hasher.hash_children(&left, &right));
        }

        let index = self.size;
        self.size += 1;
        index
    }

    /// Current number of leaves in the log.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Current root hash of the log.
    ///
    /// For an empty tree, returns `H.empty`. For a non-empty tree, merges
    /// the frontier stack right-to-left per §3.3.
    pub fn root(&self) -> H::Digest {
        if self.size == 0 {
            return self.hasher.hash_empty();
        }

        let mut r = self.stack.clone();
        while r.len() > 1 {
            let right = r.pop().expect("stack underflow in root");
            let left = r.pop().expect("stack underflow in root");
            r.push(self.hasher.hash_children(&left, &right));
        }
        r.pop().expect("stack empty after merge")
    }

    /// Returns a reference to the hasher.
    pub fn hasher(&self) -> &H {
        &self.hasher
    }

    /// Returns the number of entries in the frontier stack.
    ///
    /// Exposed for testing invariant A-STACK: `stack_len() == popcount(size)`.
    #[doc(hidden)]
    pub fn stack_len(&self) -> usize {
        self.stack.len()
    }

    /// Returns a reference to the stored leaf hashes.
    #[doc(hidden)]
    pub fn leaf_hashes(&self) -> &[H::Digest] {
        &self.leaves
    }

    /// Generate an inclusion proof for the leaf at `index` (formal model §4.2).
    ///
    /// The proof demonstrates that the leaf at `index` exists in the current
    /// tree. Verify with [`verify_inclusion`](crate::verify_inclusion).
    pub fn inclusion_proof(&self, index: u64) -> Result<InclusionProof<H::Digest>, Error> {
        if self.size == 0 {
            return Err(Error::EmptyTree);
        }
        if index >= self.size {
            return Err(Error::IndexOutOfBounds {
                index,
                tree_size: self.size,
            });
        }
        let path = self.path(index as usize, &self.leaves);
        Ok(InclusionProof {
            index,
            tree_size: self.size,
            path,
        })
    }

    /// Generate a consistency proof from `old_size` to the current size
    /// (formal model §5.2).
    ///
    /// The proof demonstrates that the tree at `old_size` is a prefix of
    /// the current tree. Verify with
    /// [`verify_consistency`](crate::verify_consistency).
    pub fn consistency_proof(&self, old_size: u64) -> Result<ConsistencyProof<H::Digest>, Error> {
        if self.size == 0 {
            return Err(Error::EmptyTree);
        }
        if old_size == 0 || old_size >= self.size {
            return Err(Error::InvalidOldSize {
                old_size,
                new_size: self.size,
            });
        }
        let path = self.subproof(old_size as usize, &self.leaves, true);
        Ok(ConsistencyProof {
            old_size,
            new_size: self.size,
            path,
        })
    }

    /// PATH algorithm for inclusion proofs (formal model §4.2).
    ///
    /// Recursively computes the sibling hashes from leaf `m` to the root.
    fn path(&self, m: usize, leaves: &[H::Digest]) -> Vec<H::Digest> {
        let n = leaves.len();
        if n == 1 {
            // P-BASE: single leaf, no siblings needed.
            return Vec::new();
        }
        let k = largest_pow2_lt(n);
        if m < k {
            // P-LEFT: leaf is in the left (complete) subtree.
            let mut result = self.path(m, &leaves[..k]);
            result.push(mth(&self.hasher, &leaves[k..]));
            result
        } else {
            // P-RIGHT: leaf is in the right subtree.
            let mut result = self.path(m - k, &leaves[k..]);
            result.push(mth(&self.hasher, &leaves[..k]));
            result
        }
    }

    /// SUBPROOF algorithm for consistency proofs (formal model §5.2).
    ///
    /// Recursively computes the intermediate hashes proving that the
    /// first `m` leaves are a prefix of the `leaves` slice.
    fn subproof(&self, m: usize, leaves: &[H::Digest], b: bool) -> Vec<H::Digest> {
        let n = leaves.len();
        if m == n {
            if b {
                // C-SAME: old tree equals current subtree, flag is true.
                return Vec::new();
            } else {
                // C-HASH: old tree equals current subtree, flag is false.
                return vec![mth(&self.hasher, leaves)];
            }
        }
        let k = largest_pow2_lt(n);
        if m <= k {
            // C-LEFT: old size fits within left subtree.
            let mut result = self.subproof(m, &leaves[..k], b);
            result.push(mth(&self.hasher, &leaves[k..]));
            result
        } else {
            // C-RIGHT: old size exceeds left subtree.
            let mut result = self.subproof(m - k, &leaves[k..], false);
            result.push(mth(&self.hasher, &leaves[..k]));
            result
        }
    }
}

/// Batch Merkle Tree Hash per formal model §2.1.
///
/// Computes the root hash of an ordered list of leaf hashes using the
/// recursive definition. Used in tests to verify A-EQUIV against the
/// incremental construction.
pub fn mth<H: TreeHasher>(hasher: &H, leaves: &[H::Digest]) -> H::Digest {
    match leaves.len() {
        0 => hasher.hash_empty(),
        1 => leaves[0].clone(),
        n => {
            let k = largest_pow2_lt(n);
            let left = mth(hasher, &leaves[..k]);
            let right = mth(hasher, &leaves[k..]);
            hasher.hash_children(&left, &right)
        },
    }
}

/// Largest power of 2 strictly less than n (formal model §2.2).
///
/// Defined for n > 1. Panics if n ≤ 1.
pub(crate) fn largest_pow2_lt(n: usize) -> usize {
    assert!(n > 1, "largest_pow2_lt requires n > 1, got {n}");
    // 2^(floor(log2(n - 1)))
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Count trailing one-bits in the binary representation of n.
fn count_trailing_ones(n: u64) -> u32 {
    (!n).trailing_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_largest_pow2_lt() {
        assert_eq!(largest_pow2_lt(2), 1);
        assert_eq!(largest_pow2_lt(3), 2);
        assert_eq!(largest_pow2_lt(4), 2);
        assert_eq!(largest_pow2_lt(5), 4);
        assert_eq!(largest_pow2_lt(6), 4);
        assert_eq!(largest_pow2_lt(7), 4);
        assert_eq!(largest_pow2_lt(8), 4);
        assert_eq!(largest_pow2_lt(9), 8);
        assert_eq!(largest_pow2_lt(15), 8);
        assert_eq!(largest_pow2_lt(16), 8);
        assert_eq!(largest_pow2_lt(17), 16);
    }

    #[test]
    fn test_count_trailing_ones() {
        assert_eq!(count_trailing_ones(0b0000), 0);
        assert_eq!(count_trailing_ones(0b0001), 1);
        assert_eq!(count_trailing_ones(0b0011), 2);
        assert_eq!(count_trailing_ones(0b0101), 1);
        assert_eq!(count_trailing_ones(0b0111), 3);
        assert_eq!(count_trailing_ones(0b1010), 0);
    }
}
