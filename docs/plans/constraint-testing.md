# PLAN: Constraint-Driven Testing

## Goal

Implement an automated intent-driven testing framework ensuring symmetric 100% enforcement of the 158 formal Cyphrpass constraints. Both positive transactional paths and negative adversarial cases must be programmatically verified identically across Rust and Go.

## Constraints

- Zero modifications to the core Cyphrpass specification or principal algorithms may be made to accommodate testing.
- Must verify failure conditions identically across both `rs/cyphrpass` and `go/cyphrpass`.

## Decisions

| Decision                  | Choice                                              | Rationale                                                                                                                  |
| :------------------------ | :-------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------- |
| Error Translation Mapping | Map string tags sequentially in the testing harness | Prevents muddying the production error enums with specific test references or constraint tags directly.                    |
| Test Vector Synthesis     | Extend Rust `fixture-gen`                           | Manually writing complex negative TOML states is brittle and verbose. Synthetic programmatic generation protects velocity. |

## Risks & Assumptions

| Risk / Assumption          | Severity | Status    | Mitigation / Evidence                                                                                                                                                                                                                                            |
| :------------------------- | :------- | :-------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Risk:** Error Ambiguity  | HIGH     | Mitigated | If multiple constraints map to the same base error, false positive intent passes occur if it caught the wrong failure logic. _Mitigation:_ We will isolate test payloads perfectly so only a single failure condition is mathematically possible during the run. |
| **Risk:** Gen Bias         | MEDIUM   | Mitigated | Over-indexing on `rs/` to build tests might blindly bake Rust-specific quirks into tests. _Mitigation:_ `fixture-gen` will bypass standard Rust validation routines (`finalize()`), mapping pure raw state mathematically to the expected invalid TOMLs.         |
| **Assump:** TOML Integrity | N/A      | Validated | The `tests/intents` deserializers can seamlessly extract an optional nested `[test.expected]` error target without breaking legacy snapshot CI setups.                                                                                                           |

## Open Questions

- None.

## Scope

### In Scope

- Updating `go/testfixtures` and `rs/test-fixtures` schema logic to process `[test.expected] error = "[tag]"`.
- Refactoring `fixture-gen` to allow synthetic violation payloads strictly based on constraint tags.
- Verifying Go and Rust identically reject adversarial TOML intents.

### Out of Scope

- Testing symmetric cryptographic mathematics (delegated externally to Coz standard test sweeps).
- Formal Verification via TLA+ or Alloy (focusing strictly on runtime testing).

## Phases

1. **Phase 1: Intent Framework Translation Upgrade** — Map literal ISO constraint tags (e.g., `error = "[txn-no-mixing]"`) to native error variants.
   - [x] Audit existing error matching infrastructure and build constraint coverage matrix.
   - [x] Write new gap-filling TOML test cases for constraints reachable with existing OverrideIntent fields.
   - [x] Fix `[no-revoke-non-self]` spec-implementation divergence (Go + Rust).
   - [x] Update Go `go/testfixtures/runner.go` (`matchesExpectedError`) to translate formal machine spec tags like `[auth-frozen]` into the appropriate native error matching logic.
   - [x] Update Rust TOML matching logic in `rs/cyphrpass-storage/tests/e2e.rs` to map constraint tags inside `test.expected.error` to specific `cyphrpass::Error` variants.
   - [x] Smoke-test: convert `err_revoke_non_self` and `revoke_non_self_fails` to use `[no-revoke-non-self]` tag syntax. Passes both impls.

2. **Phase 2: OverrideIntent Expansion (Constraint Generation)** — Expand the existing native overriding mechanisms.
   - [x] Extend `OverrideIntent` schema with `now` and `inject_pre` fields in both Go and Rust.
   - [x] Wire `now` override into Go E2E runner (`e2e_runner.go`).
   - [x] Upgrade existing E2E error tests to use formal constraint tags (`[commit-pre-chain]`, `[verification-timestamp-order]`, `[create-uniqueness]`, `[naked-revoke-error]`).
   - [x] Fix constraint tag → error code mapping divergence: `[commit-pre-chain]`/`[no-orphan-pre]` must resolve to `BrokenChain` in Rust (import pipeline remapping).
   - [ ] Wire `now` and `inject_pre` overrides into Rust fixture generator (`golden.rs`).
   - [ ] Write `tests/intents/authentication_constraints.toml` targeting remaining 🟡 TESTABLE constraints (`[transaction-pre-required]`).
   - [ ] Write tests for 🔶 NEEDS_OVERRIDE constraints that require implementation work: `[data-action-no-pre]` (not enforced), `[commit-one-or-more]` (needs empty commit override).

3. **Phase 3: Execution & Protocol Sweep** — Run the test runners to verify constraint checking parity.
   - [x] All E2E error tests pass with constraint tag syntax in both Go and Rust.
   - [ ] Execute Go intent tests against new authentication constraint vectors.
   - [ ] Execute Rust intent tests against new authentication constraint vectors.
   - [ ] Guarantee no false-positive test passes occur due to generic `InvalidPrior` or `UnknownKey` errors catching a failure for the wrong sequence reason.

## Verification

- [ ] All new negative intents cleanly parse across Rust.
- [ ] All new negative intents cleanly parse across Go.
- [ ] CI pipeline validates deterministic rejection logic with 0 false positives.

## Technical Debt

| Item                                                                                                                                                                   | Severity | Why Introduced                                               | Follow-Up                                                         | Resolved |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- | :----------------------------------------------------------- | :---------------------------------------------------------------- | :------: |
| `[no-revoke-non-self]` divergence: Go allows other-revoke (`principal.go:559`), Rust enforces self-only by construction (`CozKind::SelfRevoke`), spec says MUST reject | HIGH     | Pre-existing — surfaced by constraint audit                  | Fixed: Go guard + Rust id validation                              |    ☑    |
| Go `revokeKey()` still accepts `by` parameter, always nil after non-self revoke removal                                                                                | LOW      | Divergence fix left unused parameter                         | Clean up if Level 5+ design confirms self-only revoke permanently |    ☐     |
| `err_delete_unknown_key` uses `UnknownSigner` expectation as parity workaround                                                                                         | LOW      | Rust import conflates signer-not-found with target-not-found | Consider richer error types in storage layer to distinguish       |    ☐     |
| `[data-action-no-pre]` constraint not enforced in either impl                                                                                                          | MEDIUM   | Discovery during Phase 2 override work                       | Add `pre` field rejection to action parsing before writing test   |    ☐     |
| `[commit-one-or-more]` requires E2E infrastructure for empty commits                                                                                                   | LOW      | Discovery during Phase 2 — structural gap                    | Extend E2E runner to support commit with no transactions          |    ☐     |

## Deviation Log

| Commit | Planned                     | Actual                                                     | Rationale                                                            |
| :----- | :-------------------------- | :--------------------------------------------------------- | :------------------------------------------------------------------- |
| 1      | Coverage matrix + gap tests | + discovered `[no-revoke-non-self]` divergence             | Divergence surfaced during audit; tests intentionally failed         |
| 2      | (not originally planned)    | Fixed divergence in Go + Rust, fixed `rt_key_revoke_cycle` | Required to make new constraint tests pass; spec alignment mandatory |
| 3      | Phase 1 tag mapping         | Constraint tag resolution in Go + Rust                     | Exactly as planned                                                   |
| 4      | Phase 2 override expansion  | + E2E test upgrade to constraint tags, mapping fix         | Upgraded 4 existing tests; fixed BrokenChain/InvalidPrior mapping    |

## Retrospective

### Process

...

### Outcomes

...

### Pipeline Improvements

...

## References

- Sketch: `.sketches/2026-04-08-constraint-testing.md`
