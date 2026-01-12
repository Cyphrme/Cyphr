# Known Issues

## Test Vector Fixture Issues

### 1. `other_revoke_by_peer` was missing `pre` field (FIXED)

**Status**: Fixed in commit [f6018dfdc4396eb89db6f9c49cb9ee97a9c279e7]

The `transactions/mutations.json` fixture for `other_revoke_by_peer` was missing the required `pre` field in its `pay` object. Per SPEC §4.2, `key/revoke` with an `id` (other-revoke) requires `pre` like other state-mutating transactions.

**Fix**: Added `"pre": "5fQVYENKNTg8jDH_Yf3hp74yZhToFsYeDhSK5SNGAcc"` to the pay object.

### 2. `transaction_sequence_replay` Tx2 had incorrect `pre` value (FIXED)

**Status**: Fixed in Go implementation; Rust tests need update

The fixture's Tx2 `pre` value was incorrect:

- Wrong: `SZRYo5Ecm5UfjfqAwOYpyE8YJuxOawbT2WfWDLAvfh8`
- Correct: `f6-Goy9lj_fprCjDRMaGbTMNbuQ4FDRC5L1vAqJG2p8`

**Go tests now validate fixture `pre`**: The Go integration tests verify that each fixture `pre` value matches the computed AS before applying transactions. This catches fixture data errors.

**TODO (Rust)**: Update Rust integration tests (`rs/tests/integration.rs`) to validate fixture `pre` values instead of computing from live state. This would make Rust tests stricter and catch fixture bugs.

---

## Rust Integration Test Design Note

The Rust integration tests (`rs/tests/integration.rs`) construct the `pre` field from the principal's **current computed auth state** rather than using the fixture's `pre` value:

```rust
TransactionKind::KeyAdd {
    pre: principal.auth_state().clone(),  // Uses live state, not fixture
    id: ...
}
```

This means the Rust tests validate correctness of the state machine but do **not** validate that fixture `pre` values are correct. This is why missing/incorrect `pre` fields in fixtures weren't detected by Rust tests.

The Go integration tests use the fixture's `pre` value directly, which is why these issues were discovered during Go implementation.

**Recommendation**: Consider adding fixture `pre` validation to Rust tests to catch fixture errors.
