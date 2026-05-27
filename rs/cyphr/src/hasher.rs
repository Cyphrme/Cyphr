//! Cryptographic hashing abstraction trait and implementations.

use coz::HashAlg;
use coz::digest::Digest;
use coz::sha2::{Sha256, Sha384, Sha512};

/// A trait representing a cryptographic hash function used within Cyphr.
pub trait CyphrHasher: Send + Sync {
    /// Hashes the given data and returns the resulting digest.
    fn hash(&self, data: &[u8]) -> Vec<u8>;

    /// Returns the digest size (output size) of the hash function in bytes.
    fn output_size(&self) -> usize;
}

/// Hasher implementation for SHA-256.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Hasher;

impl CyphrHasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        32
    }
}

/// Hasher implementation for SHA-384.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha384Hasher;

impl CyphrHasher for Sha384Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut h = Sha384::new();
        h.update(data);
        h.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        48
    }
}

/// Hasher implementation for SHA-512.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha512Hasher;

impl CyphrHasher for Sha512Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut h = Sha512::new();
        h.update(data);
        h.finalize().to_vec()
    }

    fn output_size(&self) -> usize {
        64
    }
}

/// Extension implementation on the standard `HashAlg` enum.
/// This maintains backwards compatibility and simplifies migration.
impl CyphrHasher for HashAlg {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256Hasher.hash(data),
            HashAlg::Sha384 => Sha384Hasher.hash(data),
            HashAlg::Sha512 => Sha512Hasher.hash(data),
        }
    }

    fn output_size(&self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }
}
