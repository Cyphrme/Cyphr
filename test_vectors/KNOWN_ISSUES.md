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

**Fixed (Rust)**: Updated Rust integration tests to validate fixture `pre` values. Tests now assert fixture `pre` matches computed AS before applying transactions.

### 3. Rust: Implement unsupported algorithm test from fixture

**Status**: FIXED

The Rust integration tests now load `unsupported_key` from the fixture and verify genesis returns `UnsupportedAlgorithm` error. This replaces the old `unsupported_alg` flag approach.

### 4. `ts_multi_tx_sorted` Tx2 had incorrect `pre` value (FIXED)

**Status**: Fixed in both Go and Rust

The `state/computation.json` fixture's `ts_multi_tx_sorted` test had an incorrect `pre` value for Tx2:

- Wrong: `M4yNEaCQiWrNDKd6XrERMzZL9gBHXidU4wWq45xX6ms`
- Correct: `f6-Goy9lj_fprCjDRMaGbTMNbuQ4FDRC5L1vAqJG2p8`

**Root cause**: Go state tests were skipping transaction-based tests, so the incorrect value was never validated.

**Fix**:

1. Updated fixture with correct `pre` value
2. Expanded Go state tests to run ALL tests (not just genesis-only)
3. Rust tests caught this with the new fixture `pre` validation

---

## Integration Test Design Note (RESOLVED)

Both Go and Rust integration tests now validate fixture `pre` values per SPEC §15.6.

**Previous behavior** (Rust): Used live `auth_state()` instead of fixture `pre`
**Current behavior** (Both): Validate fixture `pre` matches computed AS, then use fixture value

This catches fixture data errors during testing.
