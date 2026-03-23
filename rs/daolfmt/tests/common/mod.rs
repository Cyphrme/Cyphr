//! Shared test utilities for DAOLFMT integration tests.

use daolfmt::TreeHasher;

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

/// A deterministic, domain-separating test hasher using FNV-1a (64-bit).
///
/// NOT cryptographically secure — only used for invariant testing.
pub struct SimpleHasher;

impl TreeHasher for SimpleHasher {
    type Digest = [u8; 8];

    fn hash_leaf(&self, data: &[u8]) -> [u8; 8] {
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(0x00);
        buf.extend_from_slice(data);
        fnv1a(&buf)
    }

    fn hash_children(&self, left: &[u8; 8], right: &[u8; 8]) -> [u8; 8] {
        let mut buf = Vec::with_capacity(1 + 8 + 8);
        buf.push(0x01);
        buf.extend_from_slice(left);
        buf.extend_from_slice(right);
        fnv1a(&buf)
    }

    fn hash_empty(&self) -> [u8; 8] {
        fnv1a(&[])
    }
}
