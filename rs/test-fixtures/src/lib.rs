//! # Test Fixtures
//!
//! Types and generation logic for Cyphr integration test fixtures.
//!
//! This crate provides:
//! - **Pool**: Key pool parsing and validation (`pool.toml`)
//! - **Intent**: Test intent definitions (`*.toml`)
//! - **Golden**: Generated test output (`*.json`)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    generate()    ┌─────────────────┐
//! │  Intent (TOML)  │ ──────────────►  │  Golden (JSON)  │
//! │  Human-editable │                  │  Real Coz msgs  │
//! └─────────────────┘                  └─────────────────┘
//! ```
//!
//! **Invariant**: `golden = f(intent, pool)` — deterministic, stateless.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod error;
pub mod golden;
pub mod intent;
pub mod pool;

pub use cyphr_storage::{CommitEntry, KeyEntry};
pub use error::Error;
pub use golden::{Generator, Golden, GoldenCoz, GoldenExpected, GoldenKey, GoldenSetup, generate};
pub use intent::Intent;
pub use pool::{Pool, PoolKey};
