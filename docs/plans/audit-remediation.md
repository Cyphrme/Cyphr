# PLAN: API Coherence Audit Remediation

## Goal

Remediate the 12 bugs, 9 feature deviations, and 43 remediation items
identified by the [2026-02-20 API Coherence Audit][audit], bringing both the
Go (3.0/5) and Rust (4.3/5) implementations to a level of correctness,
safety, and encapsulation that can support Level 5+ protocol features
(lifecycle states, fork detection, data actions) without inheriting existing
deficiencies.

## Constraints

- No breaking changes to `SPEC.md` semantics.
- Go and Rust must remain independently buildable — no shared codegen.
- Workstreams 1-2 are prerequisites for 3-7; 3-6 are independent of each
  other; 7 depends on 5.
- P3 items are resolved opportunistically via boy-scout policy, not as
  dedicated workstreams.
- Any workstream that balloons beyond its sketch scope is split, not expanded.

## Decisions

| Decision                       | Choice                                           | Rationale                                                                             |
| :----------------------------- | :----------------------------------------------- | :------------------------------------------------------------------------------------ |
| Error handling strategy (Go)   | Sentinel errors via `errors.New`                 | Matchable with `errors.Is`, minimal boilerplate, idiomatic Go                         |
| Error handling strategy (Rust) | `thiserror` enum with `#[from]`                  | Type-safe, matchable, consistent with existing `keystore::Error`                      |
| Key gen dedup (Rust)           | `Alg::generate_keypair()` + `keypair.thumbprint` | Uses coz-rs runtime dispatch; verified against source at `coz-rs/src/key.rs` L572-622 |
| `VerifiedTx` rename            | Won't fix                                        | `Tx` is idiomatic Go, universally understood (resolved during WS2)                    |
| P3 governance                  | Boy-scout policy                                 | Too small for individual workstreams; resolved when touching relevant files           |

## Scope

### In Scope

- **WS1-4**: Correctness, error hardening, encapsulation, CLI dedup (complete)
- **WS5**: Cross-implementation parity (BUG-7, DEV-1/2/3, C.1, D.10, Rust `debug_assert!`)
- **WS6**: Verification infrastructure (spec-anchored test vectors, negative tests, fuzz eval)
- **WS7**: Structural invariant improvements (`pre` hoisting, data action pipeline, I4)
- **Boy Scout**: P3 items resolved opportunistically during workstream execution

### Out of Scope

- Lifecycle state implementation (Level 5+ — see charter)
- Fork detection (consumer/service-layer concern)
- Protocol versioning strategy (orthogonal)
- Consumer onboarding / hello-world examples (premature)
- Go CLI (new feature, not remediation)

## Phases

### Phase 1: Go Hardening (Complete)

- [x] **WS1: Correctness, Safety & Type Representation** — Eliminated panics,
      removed dead variant, fixed `typSuffix`, added revoked-key guard, constrained
      `TransactionKind`, disambiguated `Revocation.By` semantics.
      [Sketch](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/.sketches/2026-02-24-go-correctness-safety.md)
- [x] **WS2: Error Hardening** — Replaced `fmt.Errorf` with sentinel errors,
      added `errors.Is`/`errors.As` support throughout core and state modules.
      [Sketch](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/.sketches/2026-02-24-go-error-hardening.md)
- [x] **WS3: Encapsulation Hardening** — Unexported internal fields, defensive
      copies from collection accessors, unexported `NewCommit`/`FinalizeCommit`.
      [Sketch](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/.sketches/2026-02-24-go-encapsulation-hardening.md)

### Phase 2: Rust CLI (Complete)

- [x] **WS4: CLI Deduplication & Error Typing** — Three commits:
  1. Removed `eprintln!` debug output (BUG-8)
  2. Extracted ~350 lines into `commands/common.rs` (C.2)
  3. Added `cli::Error` enum (11 variants), replaced `Box<dyn Error>`,
     deduped key gen via `common::generate_key()`. `key.rs` 522→309 lines.
     [Sketch](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/.sketches/2026-02-24-rust-cli-deduplication.md)

### Phase 3: Cross-Implementation Parity (Not Started)

- [ ] **WS5** — Port `ComputeCommitIDTagged` to Go (BUG-7, DEV-3), refactor
      Go import/test paths to use atomic `VerifyAndApply` (C.1, D.10), decide Go
      commit-based storage question (DEV-1, DEV-2), replace Rust `debug_assert!`
      with `Result` returns.

### Phase 4: Verification & Invariants (Not Started)

- [ ] **WS6** — Hand-computed reference vectors (§C.4, §E.5), negative tests
      for BUG-12 / timestamp regression (§E.4), fuzz/property-test evaluation
      (§E.1, §E.2), I5 observation congruence coverage.
- [ ] **WS7** — Hoist `pre` verification (C.3), settle data action pipeline
      (C.7, B.6), `latestTimestamp` atomicity (C.6), structural I4 enforcement.
      Depends on WS5 storage decisions.

## Boy-Scout Policy (P3)

P3 items resolved opportunistically when a workstream touches a relevant file:

| Item | Description                              | Status                                |
| :--- | :--------------------------------------- | :------------------------------------ |
| E.1  | ~~`VerifiedTx` → `VerifiedTransaction`~~ | Won't fix (idiomatic Go)              |
| A.3  | `#[doc(hidden)]` on Rust test helpers    | Checked during WS4 — no leakage found |
| B.5  | Go `checkExpected` block refactoring     | Pending (WS6)                         |
| D.7  | `Entry` extractor asymmetry              | Checked during WS4 — parity OK        |
| D.4  | Accessor visibility symmetries           | Resolved during WS3                   |
| E.2  | Rust accessor symmetries                 | Checked during WS4 — no issues        |
| E.3  | Rust visibility consistency              | Checked during WS4 — no issues        |
| A.A  | AI "what not why" comment cleanup        | Ongoing                               |

## Tech Debt

| ID   | Severity | Area         | Description                                                                                                        | Introduced   |
| :--- | :------- | :----------- | :----------------------------------------------------------------------------------------------------------------- | :----------- |
| TD-1 | LOW      | Rust CLI     | `Error::Storage(String)` catch-all — refine into specific variants as patterns emerge                              | WS4 Commit 3 |
| TD-2 | LOW      | Rust Storage | `FileStoreError` re-exported from `cyphrpass-storage` for `#[from]` use — revisit if storage errors are refactored | WS4 Commit 3 |

## Verification

- [x] WS1-4: `go test ./...` all pass; `cargo test --workspace` all 125 pass
- [x] WS1-4: Zero `Box<dyn Error>` in CLI code, zero `SigningKey::generate` in commands/, zero `fmt.Errorf` in core
- [ ] WS5: Cross-language golden fixture parity
- [ ] WS6: Spec-anchored reference vectors pass in both languages
- [ ] WS7: `pre` hoisting verified by existing test suite + new negative tests

## References

- AUDIT: [2026-02-20-api-coherence-audit.md](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/audit/2026-02-20-api-coherence-audit.md)
- CHARTER: [spec-alignment.md](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/charters/spec-alignment.md)
- SKETCHES: `.sketches/2026-02-24-go-*.md`, `.sketches/2026-02-24-rust-cli-deduplication.md`

[audit]: ../audit/2026-02-20-api-coherence-audit.md
