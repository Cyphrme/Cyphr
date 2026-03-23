//! Correctness tests for DAOLFMT.
//!
//! Tests verify the fundamental invariants from the formal model
//! (docs/models/verifiable-log.md):
//!
//! - **A-EQUIV**: incremental append equals batch construction
//! - **A-STACK**: stack size equals popcount(n)
//! - **Determinism**: same inputs → same root

use daolfmt::{Log, TreeHasher, mth};

// ---------------------------------------------------------------------------
// SimpleHasher: a deterministic, domain-separating test hasher.
//
// Uses FNV-1a (64-bit) as the mixing function. Not cryptographically
// secure — only deterministic and domain-separating, which is sufficient
// for testing A-EQUIV and A-STACK.
// ---------------------------------------------------------------------------

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001B3;

fn fnv1a(data: &[u8]) -> [u8; 8] {
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash.to_be_bytes()
}

struct SimpleHasher;

impl TreeHasher for SimpleHasher {
    type Digest = [u8; 8];

    fn hash_leaf(&self, data: &[u8]) -> [u8; 8] {
        // H(0x00 || data) — domain separation
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(0x00);
        buf.extend_from_slice(data);
        fnv1a(&buf)
    }

    fn hash_children(&self, left: &[u8; 8], right: &[u8; 8]) -> [u8; 8] {
        // H(0x01 || left || right) — domain separation
        let mut buf = Vec::with_capacity(1 + 8 + 8);
        buf.push(0x01);
        buf.extend_from_slice(left);
        buf.extend_from_slice(right);
        fnv1a(&buf)
    }

    fn hash_empty(&self) -> [u8; 8] {
        // H("")
        fnv1a(&[])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn empty_root() {
    let log = Log::new(SimpleHasher);
    assert_eq!(log.root(), SimpleHasher.hash_empty());
    assert_eq!(log.size(), 0);
}

#[test]
fn single_leaf() {
    let mut log = Log::new(SimpleHasher);
    log.append(b"hello");
    assert_eq!(log.root(), SimpleHasher.hash_leaf(b"hello"));
    assert_eq!(log.size(), 1);
}

#[test]
fn append_returns_sequential_indices() {
    let mut log = Log::new(SimpleHasher);
    for i in 0u64..10 {
        let index = log.append(format!("entry-{i}").as_bytes());
        assert_eq!(index, i, "append should return sequential 0-based indices");
    }
}

/// A-EQUIV (formal model §3.4): incremental construction equals batch
/// construction for all sizes 1..=33.
///
/// This is the fundamental correctness property.
#[test]
fn a_equiv_incremental_equals_batch() {
    for n in 1u64..=33 {
        let mut log = Log::new(SimpleHasher);
        for i in 0..n {
            log.append(format!("leaf-{i}").as_bytes());
        }

        let incremental_root = log.root();
        let batch_root = mth(&SimpleHasher, log.leaf_hashes());

        assert_eq!(
            incremental_root, batch_root,
            "A-EQUIV failed for n={n}: incremental root != batch root"
        );
    }
}

/// A-STACK (formal model §3.4): after each append, the frontier stack
/// has exactly popcount(size) entries.
#[test]
fn a_stack_popcount_invariant() {
    let mut log = Log::new(SimpleHasher);
    for i in 0u64..64 {
        log.append(format!("leaf-{i}").as_bytes());
        let expected_stack_len = log.size().count_ones() as usize;
        assert_eq!(
            log.stack_len(),
            expected_stack_len,
            "A-STACK failed at size={}: stack_len={}, popcount={}",
            log.size(),
            log.stack_len(),
            expected_stack_len
        );
    }
}

/// Determinism: same inputs, same hasher → same root.
#[test]
fn deterministic_root() {
    let build = || {
        let mut log = Log::new(SimpleHasher);
        for i in 0..20 {
            log.append(format!("entry-{i}").as_bytes());
        }
        log.root()
    };

    assert_eq!(build(), build(), "same inputs must produce same root");
}

/// Two-leaf tree should hash as H.node(H.leaf(a), H.leaf(b)).
#[test]
fn two_leaf_structure() {
    let mut log = Log::new(SimpleHasher);
    log.append(b"alpha");
    log.append(b"beta");

    let expected = SimpleHasher.hash_children(
        &SimpleHasher.hash_leaf(b"alpha"),
        &SimpleHasher.hash_leaf(b"beta"),
    );
    assert_eq!(log.root(), expected);
}

/// Domain separation: hash_leaf(x) must differ from hash_children(a, b)
/// for arbitrary inputs.
#[test]
fn domain_separation() {
    let leaf = SimpleHasher.hash_leaf(b"test");
    let node =
        SimpleHasher.hash_children(&SimpleHasher.hash_leaf(b"a"), &SimpleHasher.hash_leaf(b"b"));

    // While not a formal proof, this verifies the prefix bytes produce
    // different outputs for our test hasher.
    assert_ne!(
        leaf, node,
        "leaf and node hashes must differ (domain separation)"
    );
}

/// Power-of-two sizes should produce complete binary trees.
#[test]
fn power_of_two_sizes() {
    for exp in 1..=5u32 {
        let n = 1u64 << exp;
        let mut log = Log::new(SimpleHasher);
        for i in 0..n {
            log.append(format!("leaf-{i}").as_bytes());
        }
        // For power-of-two sizes, the stack should have exactly 1 entry
        // (the single complete subtree root).
        assert_eq!(
            log.stack_len(),
            1,
            "power-of-two size {n} should have stack_len=1"
        );
    }
}
