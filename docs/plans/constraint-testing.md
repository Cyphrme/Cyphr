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
   - [ ] Update Go `go/testfixtures/runner.go` (`matchesExpectedError`) to translate formal machine spec tags like `[auth-frozen]` into the appropriate native error matching logic.
   - [ ] Update Rust TOML matching logic in `rs/test-fixtures` to map constraint tags inside `test.expected.error` to specific `cyphrpass::Error` variants.

2. **Phase 2: OverrideIntent Expansion (Constraint Generation)** — Expand the existing native overriding mechanisms.
   - [ ] Refactor the `OverrideIntent` schema inside `go/testfixtures/intent.go` and `rs/test-fixtures/src/intent.rs` to allow arbitrary structural manipulation (e.g., overriding/injecting the `commit` tag into non-terminal cozies, forcing bad timestamps, or corrupting signature bytes).
   - [ ] Write `tests/intents/authentication_constraints.toml` which natively utilizes these new `OverrideIntent` vectors to target strictly specific Level 1-4 auth constraints, generating the bad states uniformly across both Go and Rust intent parsing logic.

3. **Phase 3: Execution & Protocol Sweep** — Run the test runners to verify constraint checking parity.
   - [ ] Execute Go intent tests against `authentication_constraints.toml` and resolve any uncovered blind spots in `go/cyphrpass`.
   - [ ] Execute Rust intent tests against `authentication_constraints.toml` and resolve any uncovered blind spots in `rs/cyphrpass`.
   - [ ] Guarantee no false-positive test passes occur due to generic `InvalidPrior` or `UnknownKey` errors catching a failure for the wrong sequence reason.

## Verification

- [ ] All new negative intents cleanly parse across Rust.
- [ ] All new negative intents cleanly parse across Go.
- [ ] CI pipeline validates deterministic rejection logic with 0 false positives.

## Technical Debt

| Item                                                                                                                                                                   | Severity | Why Introduced                              | Follow-Up                            | Resolved |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- | :------------------------------------------ | :----------------------------------- | :------: |
| `[no-revoke-non-self]` divergence: Go allows other-revoke (`principal.go:559`), Rust enforces self-only by construction (`CozKind::SelfRevoke`), spec says MUST reject | HIGH     | Pre-existing — surfaced by constraint audit | Fixed: Go guard + Rust id validation |    ☑    |

## Deviation Log

| Commit | Planned | Actual | Rationale |
| :----- | :------ | :----- | :-------- |

## Retrospective

### Process

...

### Outcomes

...

### Pipeline Improvements

...

## References

- Sketch: `.sketches/2026-04-08-constraint-testing.md`
