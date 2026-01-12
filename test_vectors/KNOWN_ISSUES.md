# Known Issues

## Test Vector Fixture Issues

### 1. `other_revoke_by_peer` was missing `pre` field (FIXED)

**Status**: Fixed in commit [f6018dfdc4396eb89db6f9c49cb9ee97a9c279e7]

The `transactions/mutations.json` fixture for `other_revoke_by_peer` was missing the required `pre` field in its `pay` object. Per SPEC §4.2, `key/revoke` with an `id` (other-revoke) requires `pre` like other state-mutating transactions.

**Fix**: Added `"pre": "5fQVYENKNTg8jDH_Yf3hp74yZhToFsYeDhSK5SNGAcc"` to the pay object.

### 2. `transaction_sequence_replay` has incorrect chained `pre` values

**Status**: Open - requires signature regeneration

The `transaction_sequence_replay` test contains a sequence of three transactions. The `pre` values in the second and third transactions don't match the computed AS after applying the previous transactions. This requires:

1. Regenerating the signed transactions with correct `pre` values
2. Computing new signatures with the updated pay objects
3. Recomputing the `czd` values

**Workaround**: Test is skipped in Go integration tests.

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
