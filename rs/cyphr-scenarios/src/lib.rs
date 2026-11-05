//! End-to-end scenario harness for Cyphr.
//!
//! Scenarios drive the shipped `cyphr-server` and `cyphr` binaries over
//! loopback, behind a proxy that injects partitions, delay, drops and
//! node outages on seeded schedules. Nothing here mocks a peer or the CLI.

pub mod actions;
pub mod bins;
pub mod capability;
pub mod carrier;
pub mod faults;
pub mod harness;
pub mod oracle;
pub mod peer;
pub mod proxy;

pub use capability::Capability;
pub use harness::Harness;
