# PLAN: Panic Removal from Rust Library Code

## Goal

Remove all `unwrap()` and `expect()` calls from production (non-test) Rust
library code. These are inappropriate in library crates — they propagate as
panics rather than `Result`s, making the library hostile to downstream
consumers who can't recover from errors.

Test code (`#[cfg(test)]` modules) is excluded — panics in tests are idiomatic.
CLI binary code is lower priority but included for completeness.

## Constraints

- Pre-alpha: backwards compatibility is not a concern
- Test code panics are acceptable and out of scope
- `test-fixtures` crate is a dev-only tool — lower priority than core/storage
- Each panic site needs individual assessment: some are genuine invariants
  (and should use `debug_assert!` or an internal error), some are lazy error
  handling that should return `Result`

## Scope

### In Scope

Phase 1 — `cyphrpass` core library (`rs/cyphrpass/src/`):

| File             | Line | Panic                                                       | Classification                                          |
| :--------------- | :--- | :---------------------------------------------------------- | :------------------------------------------------------ |
| `principal.rs`   | L24  | `.expect("system time before unix epoch")`                  | **Invariant** — system clock pre-epoch is unrecoverable |
| `principal.rs`   | L319 | `.expect("CommitState must have at least one variant")`     | ✅ **Propagated** — `get_or_err()?`                     |
| `principal.rs`   | L325 | `.expect("AuthState must have at least one variant")`       | ✅ **Propagated** — `get_or_err()?`                     |
| `principal.rs`   | L397 | `.expect("pre_revoke_key: key not found in active set")`    | **Invariant** — test-only helper, documented panic      |
| `principal.rs`   | L557 | `.expect("CS must exist after genesis")`                    | ✅ **Propagated** — `.ok_or(Error::StateMismatch)?`     |
| `principal.rs`   | L802 | `.expect("non-empty pending should produce Commit ID")`     | ✅ **Propagated** — `.ok_or(Error::EmptyCommit)?`       |
| `principal.rs`   | L822 | `.expect("just pushed")`                                    | **Invariant** — just pushed, can't be empty             |
| `principal.rs`   | L897 | `.expect("CommitState must have at least one variant")`     | ✅ **Propagated** — `get_or_err()?`                     |
| `principal.rs`   | L910 | `.expect("AuthState must have at least one variant")`       | ✅ **Propagated** — `get_or_err()?`                     |
| `principal.rs`   | L915 | `.expect("pre CommitState must have at least one variant")` | ✅ **Propagated** — `get_or_err()?`                     |
| `principal.rs`   | L969 | `.expect("key existence verified by contains_key check")`   | **Invariant** — pre-checked 4 lines above               |
| `state.rs`       | L628 | `.expect("KeyState must have at least one variant")`        | ✅ **Propagated** — `get_or_err()?`                     |
| `state.rs`       | L660 | `.unwrap()` on `commit_id`                                  | ✅ **Propagated** — `if let` match pattern              |
| `state.rs`       | L669 | `.expect("AuthState must have at least one variant")`       | ✅ **Propagated** — `get_or_err()?`                     |
| `state.rs`       | L675 | `.expect("CommitID must have at least one variant")`        | ✅ **Propagated** — `get_or_err()?`                     |
| `state.rs`       | L737 | `.expect("CommitState must have at least one variant")`     | ✅ **Propagated** — `get_or_err()?`                     |
| `commit.rs`      | —    | _Audited: zero production panics_                           | ✅ All panics in `#[cfg(test)]`                         |
| `transaction.rs` | —    | _Audited: zero production panics_                           | ✅ All panics in `#[cfg(test)]`                         |
| `action.rs`      | —    | _Audited: zero production panics_                           | ✅ All panics in `#[cfg(test)]`                         |

Phase 2 — `cyphrpass-storage` crate (`rs/cyphrpass-storage/src/`):

| File        | Lines      | Count | Classification                                            |
| :---------- | :--------- | :---- | :-------------------------------------------------------- |
| `export.rs` | L35-154    | ~15   | Mix of serialization invariants and state access          |
| `file.rs`   | L47        | 1     | `.expect("PrincipalRoot must have at least one variant")` |
| `import.rs` | (pre-test) | 0     | Clean — all panics are in test module                     |

Phase 3 — `cyphrpass-cli` crate (`rs/cyphrpass-cli/src/`):

| File               | Lines       | Count | Classification                   |
| :----------------- | :---------- | :---- | :------------------------------- |
| `commands/tx.rs`   | L95,146,170 | 3     | State variant access `.expect()` |
| `commands/init.rs` | L65         | 1     | State variant access `.expect()` |
| `commands/io.rs`   | L95,113,130 | 3     | State variant access `.expect()` |
| `commands/key.rs`  | L349,362    | 2     | `keystore.get(tmb).unwrap()`     |

### Out of Scope

- Test modules (`mod tests { ... }`) — panics are idiomatic in Rust tests
- `test-fixtures` crate — dev-only tool, panics acceptable
- Go implementation — no Go panics identified in prior audit

## Classification Key

- **Invariant**: The condition genuinely cannot fail in a correctly-constructed
  program. Use `debug_assert!` or leave as-is with a justifying comment.
  Example: `self.commits.last().expect("just pushed")`.

- **Propagate**: The condition CAN fail for a caller providing bad input or
  in degraded state. Replace with `Result`/`Option` propagation using `?`
  or `.ok_or(Error::...)`.

- **Audit**: Needs case-by-case reading to determine classification.

## Approach

The dominant panic pattern is **state variant access**: calling
`.get(alg).expect("must have variant")` on `MultihashDigest`. This suggests
a helper method would eliminate the majority of panics:

```rust
impl MultihashDigest {
    /// Get the first variant's bytes, or error if empty.
    pub fn first_variant(&self) -> Result<&[u8]> { ... }

    /// Get variant by algorithm, or error if missing.
    pub fn get_or_err(&self, alg: HashAlg) -> Result<&[u8]> { ... }
}
```

With this helper, most `.get(alg).expect("must have variant")` patterns become
`.get_or_err(alg)?`.

## Decisions

| Decision                  | Choice                         | Rationale                                                         |
| :------------------------ | :----------------------------- | :---------------------------------------------------------------- |
| System time panic (L24)   | **Keep**                       | Pre-epoch system clock is unrecoverable; no reasonable error path |
| "just pushed" panics      | **Keep with comment**          | Post-push emptiness is a logic bug, not a runtime error           |
| State variant `.expect()` | **Convert to `Result`**        | Dominant pattern; callers should handle missing variants          |
| CLI panics                | **Convert to `anyhow` errors** | CLI already uses `anyhow`; panics should be `bail!()`             |

## Phases

### Phase 1: Core Library (`cyphrpass`) ✅

- [x] Add `get_or_err()` / `first_variant()` helpers to `MultihashDigest`
- [x] Add `EmptyMultihash` error variant to `Error` enum
- [x] Convert `principal.rs` production panics (L319, L325, L557, L802, L897, L910, L915)
- [x] Convert `state.rs` production panics (L628, L660, L669, L675, L737)
- [x] Audit `commit.rs` — zero production panics found
- [x] Audit `transaction.rs` — zero production panics found
- [x] Audit `action.rs` — zero production panics found
- [x] Update function signatures: `compute_as`/`compute_cs`/`compute_ps` → `Result`, `commit_state_tagged` → `Result<String>`
- [x] Update downstream callers (`golden.rs`, `key.rs`, `e2e.rs`)

### Phase 2: Storage Crate (`cyphrpass-storage`)

- [ ] Convert `export.rs` production panics (serialization and state access)
- [ ] Convert `file.rs` L47 panic

### Phase 3: CLI Crate (`cyphrpass-cli`)

- [ ] Convert `tx.rs`, `init.rs`, `io.rs` state access panics to `anyhow` errors
- [ ] Convert `key.rs` keystore access panics

## Verification

### Automated Tests

```bash
# Full Rust test suite — must all pass
cargo test --workspace

# Go test suite — must still pass (cross-language parity)
cd go && go test ./...

# Clippy — should not introduce new warnings
cargo clippy --workspace
```

### Manual Verification

- Grep for remaining production panics: `rg 'unwrap\(\)|expect\(' rs/cyphrpass/src/ rs/cyphrpass-storage/src/ rs/cyphrpass-cli/src/ --glob '!*test*'`
- The only acceptable surviving panics should be the classified **Invariant** sites (L24, L822 in principal.rs) with justifying comments

## Risks & Assumptions

| Risk                                          | Severity | Mitigation                                                                               |
| :-------------------------------------------- | :------- | :--------------------------------------------------------------------------------------- |
| Signature changes cascade to callers          | MEDIUM   | Many functions already return `Result`; adding `?` propagation is mechanical             |
| `MultihashDigest::get()` signature change     | MEDIUM   | Adding a new method (`get_or_err`) avoids breaking existing `get()`                      |
| Export serialization "can't fail" assumptions | LOW      | `serde_json::to_value` on known types genuinely can't fail; may keep these as invariants |

## Technical Debt

### Retained Panics (Classified Invariants)

4 production panics intentionally retained with documented justification:

| File           | Line | Pattern                                   | Rationale                                        |
| :------------- | :--- | :---------------------------------------- | :----------------------------------------------- |
| `principal.rs` | L24  | `expect("system time before unix epoch")` | Pre-epoch system clock is genuinely unreoverable |
| `principal.rs` | L402 | `expect("pre_revoke_key: key not found")` | Test-only helper function, documented panic      |
| `principal.rs` | L825 | `expect("just pushed")`                   | Immediately follows `Vec::push()`                |
| `principal.rs` | L957 | `expect("key existence verified")`        | Pre-checked by `contains_key` 4 lines above      |

These may be revisited in a future hardening pass but are not considered
bugs — they represent genuine logical invariants or test-only code.
