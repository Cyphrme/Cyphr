# API Coherence Audit: Cyphrpass Identity Protocol

**Date:** 2026-02-20
**Auditor:** Gemini & Claude (Antigravity) + nrd
**Status:** Complete — Awaiting remediation plan approval

---

## Phase 0: Scope Definition

**Language Targets:**
| Language | Path |
|:---------|:---------------------|
| Go | `go/cyphrpass` |
| Rust | `rs/cyphrpass` |

**Exclusions (initial):**

- `rs/cyphrpass-cli`
- `rs/cyphrpass-storage`
- `go/storage`
- `rs/test-fixtures` / `rs/fixture-gen`
- `tests/`
- Vendored dependencies

> **Scope expansion:** During Phase 2, the audit scope was expanded with user approval to include `rs/cyphrpass-cli` (Component 4), `rs/cyphrpass-storage` and `go/storage` (Component 3), and test fixtures (Component 5). These modules were added because they are direct consumers of the core API and their usage patterns revealed systemic issues.

**Constraints:**

- Must strictly align with SPEC.md's semantic definitions.
- Rust library code must not panic (Result-driven entirely).
- Go library code must use explicit error wrapping.

---

## Phase 1: Surface Discovery

### Surface Map

The complete surface map tracking public types, accessors, and mutations has been generated and validated using code intelligence tools (`go doc`, `cargo`). A preliminary check with DepMap confirmed no hidden external cryptographic dependencies aside from `Coz` itself.

**(Detailed map resides in `api_surface_map.md` artifact until Phase 1 is verified).**

---

## Phase 2: Iterative Component Audit

### Component 1: Principal, Genesis, Transaction, & Commit

**Scope:** The full core protocol surface — `Principal`, genesis factories, state accessors, `Transaction`/`TransactionKind`, `VerifiedTx`/`VerifiedTransaction`, `Commit`/`PendingCommit`/`CommitBatch`/`CommitScope`, `Key`, `Action`, and error types in both Go and Rust.

#### Summary

| Dimension              | Go   | Rust | Notes                                                                                                 |
| :--------------------- | :--- | :--- | :---------------------------------------------------------------------------------------------------- |
| **A. Minimal Surface** | WARN | PASS | Go exposes `AuthLedger`/`DataLedger` fields, `NewCommit` panics, `FinalizeCommit` is public           |
| **B. Type Safety**     | WARN | PASS | Go `TransactionKind` is bare `int`; Go `Revocation.By` cannot distinguish self vs. other-revoke       |
| **C. Composability**   | PASS | PASS | Both `ApplyTransaction`→`BeginCommit`→`Finalize` compose cleanly                                      |
| **D. Monosemicity**    | FAIL | PASS | Go retains `TxOtherRevoke` variant removed from Rust; Go `typSuffix` is semantically wrong            |
| **E. Naming**          | WARN | PASS | Go `VerifiedTx` vs Rust `VerifiedTransaction`; Go `Rvk` field on `Key` collides with `Revocation.Rvk` |
| **F. Error Handling**  | WARN | PASS | Go `NewCommit` panics instead of returning error; Go `verifyPre` uses `fmt.Errorf` not sentinel       |

---

#### Finding D.1 — `TxOtherRevoke` parity gap [FAIL]

**Go** retains `TxOtherRevoke` (transaction.go:28) and full `applyTransactionInternal` handling (principal.go:532-538). **Rust** explicitly removed other-revoke — all `key/revoke` transactions are parsed as `SelfRevoke` (transaction.rs:192-196).

This is not just a surface divergence. The Go `ParseTransaction` dispatches on `id` presence:

```go
// transaction.go:142-150
case TypKeyRevoke:
    if pay.ID != "" {
        tx.Kind = TxOtherRevoke  // ← Rust will reject this
```

A valid Go transaction payload with `id` set would be accepted by Go but rejected or silently misinterpreted by Rust. This breaks cross-implementation parity.

**Recommendation:** Remove `TxOtherRevoke` from Go, or document explicitly in SPEC.md if other-revoke is intentionally deferred.

---

#### Finding D.2 — `typSuffix` is semantically wrong [FAIL]

Go's `typSuffix` (transaction.go:221-228) splits at the **first** `/`:

```go
func typSuffix(typ string) string {
    for i := 0; i < len(typ); i++ {
        if typ[i] == '/' {
            return typ[i+1:]
        }
    }
    return typ
}
```

For `cyphr.me/key/create`, this returns `key/create` (correct by accident: the authority has no `/`). But for a namespaced authority like `org/cyphr.me/key/create`, this returns `cyphr.me/key/create`, which fails the switch.

**Rust** uses `ends_with` (transaction.rs:180), which is correct regardless of authority structure.

**Recommendation:** Replace `typSuffix` with `strings.HasSuffix` checks matching Rust's approach.

---

#### Finding A.1 — Go `AuthLedger`/`DataLedger` fields are exported [WARN]

Go exports `AuthLedger.Keys`, `AuthLedger.Revoked`, `AuthLedger.Transactions`, `DataLedger.Actions` as public fields (principal.go:50-63). These are internal bookkeeping structures that should be accessed only through `Principal` accessors.

**Rust** properly scopes `AuthLedger.keys` as `pub` but gates construction through the `Principal` API, and `Commit::new` is `pub(crate)`.

In Go, any consumer can directly mutate `AuthLedger.Keys` and corrupt state.

**Recommendation:** Unexport `AuthLedger` and `DataLedger` fields, or make the types themselves unexported.

---

#### Finding A.2 — Go `NewCommit` and `FinalizeCommit` are public [WARN]

`NewCommit` (commit.go:34) panics on empty input and is a public constructor for an internal type. `FinalizeCommit` (principal.go:708) is documented as "not typically called directly" but is exported.

**Rust** properly gates both: `Commit::new` is `pub(crate)`, and `finalize_commit` is `pub(crate)`.

**Recommendation:** Unexport `NewCommit`. Consider whether `FinalizeCommit` should also be unexported — its only caller should be `CommitBatch.Finalize`.

---

#### Finding B.1 — Go `TransactionKind` is a bare `int` [WARN]

Go (transaction.go:21):

```go
type TransactionKind int
```

Rust (transaction.rs:32):

```rust
pub enum TransactionKind {
    KeyCreate { pre: CommitState, id: Thumbprint },
    // ...
}
```

Go's `iota` pattern means you can construct arbitrary `TransactionKind(99)` values, and the data (`Pre`, `ID`, `Rvk`) lives in a flat `Transaction` struct with optional fields that may or may not be populated. Rust's sum type makes invalid states unrepresentable.

This is idiomatic Go (enums don't exist), but worth calling out for the audit record.

---

#### Finding B.2 — Go `Revocation.By` cannot distinguish absent vs. self [WARN]

Go (key.go:12-13):

```go
type Revocation struct {
    Rvk int64
    By  coz.B64  // nil for self-revoke
}
```

Rust (key.rs:11):

```rust
pub struct Revocation {
    pub rvk: i64,
    pub by: Option<Thumbprint>,  // None = self-revoke
}
```

Go's `coz.B64` is `[]byte`, so `nil` and empty slice are semantically different but practically confusable. Rust's `Option<Thumbprint>` is unambiguous.

---

#### Finding B.3 — Go `Key.Rvk` field shadows `Revocation.Rvk` [WARN]

Go `Key` (key.go:17-28) embeds `*coz.Key` which has no `Rvk` field, but the `Transaction` struct has both `Rvk int64` (for revoke timestamp) and the key has `Revocation.Rvk`. Meanwhile Rust `Key` has no direct `rvk` field — revocation is cleanly nested in `Option<Revocation>`.

---

#### Finding E.1 — `VerifiedTx` vs `VerifiedTransaction` naming [WARN]

Go uses `VerifiedTx`; Rust uses `VerifiedTransaction`. The prior audit (2026-02-03) noted this. It's idiomatic per each language (Go favors abbreviation), but for a protocol with cross-implementation consumers, having a glossary-locked name would reduce confusion.

---

#### Finding F.1 — Go `NewCommit` panics on empty input [WARN]

```go
// commit.go:34
func NewCommit(txs []*Transaction, ...) *Commit {
    if len(txs) == 0 {
        panic("Commit must contain at least one transaction")
    }
```

Per `engineering.md §Panic Policy`, library code must not panic. Rust uses `debug_assert!` (also questionable — see prior audit finding S2-1), but at least doesn't panic in release.

**Recommendation:** Return `(*Commit, error)` or make the function unexported.

---

#### Finding F.2 — Go `verifyPre` uses `fmt.Errorf` instead of sentinel [WARN]

```go
// principal.go:570-572
func (p *Principal) verifyPre(pre CommitState) error {
    if p.cs == nil {
        return fmt.Errorf("cannot verify pre: no commit state")
    }
```

This error is not matchable via `errors.Is`. All other principal errors use sentinel values per SPEC §17. This breaks error handling consistency.

**Recommendation:** Create `ErrNoCommitState` sentinel, or merge into an existing variant.

---

#### Finding A.3 — `PreRevokeKey` / `active_keys_mut` are test helpers on public API [INFO]

Both languages expose test-setup helpers (`PreRevokeKey` in Go, `pre_revoke_key` and `active_keys_mut` in Rust) as public methods. Both panic on bad input.

**Rust** documents this with `/// # Panics` sections but doesn't use `#[doc(hidden)]`.
**Go** has a comment but it's public API.

**Recommendation:** In Rust, add `#[doc(hidden)]` or move behind a `test-helpers` feature flag. In Go, prefix with `Test` if possible, or document the panic contract clearly.

---

#### Recommended Changes

| ID      | Priority | Description                                                       |
| :------ | :------- | :---------------------------------------------------------------- |
| **D.1** | P0       | Remove `TxOtherRevoke` from Go or document intentional divergence |
| **D.2** | P0       | Fix Go `typSuffix` to use `strings.HasSuffix`                     |
| **F.1** | P1       | Go `NewCommit`: return error or unexport                          |
| **F.2** | P1       | Go `verifyPre`: replace `fmt.Errorf` with sentinel                |
| **A.1** | P1       | Unexport Go `AuthLedger`/`DataLedger` fields                      |
| **A.2** | P2       | Unexport Go `NewCommit`, consider `FinalizeCommit`                |
| **A.3** | P3       | Mark test helpers with `#[doc(hidden)]` or feature flag           |
| **E.1** | P3       | Consider aligning `VerifiedTx`→`VerifiedTransaction` naming       |

---

**Status:** ✅ Reviewed. `TxOtherRevoke` confirmed as legacy dead code (removed from SPEC). Proceeding to Component 2.

---

### Component 2: State Types, MultihashDigest, & Compute Functions

**Scope:** `KeyState`, `AuthState`, `CommitState`, `CommitID`, `DataState`, `PrincipalState`, `PrincipalRoot`, `MultihashDigest`, `TaggedDigest`, `HashAlg`, and all `Compute*`/`compute_*` functions across Go and Rust.

#### Summary

| Dimension              | Go   | Rust | Notes                                                                                                          |
| :--------------------- | :--- | :--- | :------------------------------------------------------------------------------------------------------------- |
| **A. Minimal Surface** | WARN | PASS | Go `MultihashDigest.Variants()` exposes internal map; `NewMultihashDigest` panics                              |
| **B. Type Safety**     | PASS | PASS | Both use newtype wrappers for all state types                                                                  |
| **C. Composability**   | PASS | PASS | Compute\* functions compose identically                                                                        |
| **D. Monosemicity**    | WARN | WARN | `DataState` representation diverges (Go: `coz.B64`, Rust: `Cad`); `HashAlg` sourcing differs                   |
| **E. Naming**          | WARN | PASS | Go `DeriveHashAlgs` exported vs Rust `derive_hash_algs` crate-private intent; Go accessor pattern inconsistent |
| **F. Error Handling**  | WARN | PASS | Go `ParseHashAlg`/`ParseTaggedDigest` use `fmt.Errorf`; Go `NewMultihashDigest` panics                         |

---

#### Finding D.3 — `DataState` inner type divergence [WARN]

**Go** (state.go:41-43):

```go
type DataState struct {
    digest coz.B64
}
```

**Rust** (state.rs:114):

```rust
pub struct DataState(pub Cad);
```

Go stores raw bytes (`coz.B64 = []byte`). Rust stores a `coz::Cad` (content-addressed digest type). This means:

- Go's `DataState.Bytes()` returns `coz.B64`; Rust's `DataState.as_cad()` returns `&Cad`.
- Different accessor names, different underlying semantics.

The `Cad` type carries additional semantic meaning that `[]byte` does not. If `Cad` adds validation or behavior downstream, the Go side will silently diverge.

**Recommendation:** Evaluate whether Go should wrap a proper typed digest rather than raw bytes.

---

#### Finding D.4 — `HashAlg` definition sourcing diverges [WARN]

**Go** (state.go:72):

```go
type HashAlg coz.HshAlg  // = string alias
```

**Rust** (state.rs:179):

```rust
pub use coz::HashAlg;  // re-exported from coz-rs
```

Go defines `HashAlg` as a local type alias over `coz.HshAlg`. Rust re-exports `coz::HashAlg` directly from the `coz` crate, making it the **same** type. Both converge to the same algorithm set (`SHA-256`, `SHA-384`, `SHA-512`), but Go's extra indirection means `HashAlg` and `coz.HshAlg` are distinct types in Go.

This is functionally fine but architecturally notable — if `coz-go` adds hash algorithm validation, Go cyphrpass won't benefit without explicit bridging.

---

#### Finding A.4 — Go `MultihashDigest.Variants()` exposes internals [WARN]

Go (multihash.go:93-95):

```go
func (m MultihashDigest) Variants() map[HashAlg]coz.B64 {
    return m.variants
}
```

This returns the **underlying map by value** (but Go maps are reference types), so callers can mutate the internal state of any MultihashDigest. This is especially dangerous since state types (KS, AS, CS, PS, PR) embed MultihashDigest.

**Rust** returns `&BTreeMap<HashAlg, Box<[u8]>>` (immutable borrow).

**Recommendation:** Return a defensive copy, or provide iteration-only access matching Rust's pattern.

---

#### Finding F.3 — Go `NewMultihashDigest` panics on empty [WARN]

Go (multihash.go:19-22):

```go
func NewMultihashDigest(variants map[HashAlg]coz.B64) MultihashDigest {
    if len(variants) == 0 {
        panic("MultihashDigest must have at least one variant")
    }
```

Same class of issue as BUG-3 (`NewCommit`). Library code panicking on recoverable input.

Rust uses `debug_assert!` (same concern as noted in Component 1, but at least release-mode safe).

---

#### Finding F.4 — Go `ParseHashAlg` and `ParseTaggedDigest` use `fmt.Errorf` [WARN]

Go (state.go:97, 137, 145, 150, 156, 176):

All error paths use `fmt.Errorf` — none are matchable via `errors.Is`. Rust has structured error variants (`MalformedDigest`, `DigestLengthMismatch`, `UnsupportedAlgorithm`).

For a protocol library, callers need to distinguish "bad format" from "unsupported algorithm" from "wrong digest length."

**Recommendation:** Use sentinel errors or typed errors matching Rust's error variants.

---

#### Finding E.2 — Go accessor pattern inconsistency [WARN]

State type accessors in Go use mixed patterns:

| Go Accessor                    | Returns   | Rust Equivalent                                     |
| :----------------------------- | :-------- | :-------------------------------------------------- |
| `AuthState.Tagged()`           | `string`  | `Principal.commit_state_tagged()`                   |
| `CommitState.Tagged()`         | `string`  | `Principal.commit_state_tagged()`                   |
| `MultihashDigest.First()`      | `coz.B64` | `MultihashDigest.first_variant()` → `Result<&[u8]>` |
| `MultihashDigest.GetOrFirst()` | `coz.B64` | `MultihashDigest.get_or_err()` → `Result<&[u8]>`    |

Key differences:

- Go `First()` returns nil on empty; Rust `first_variant()` returns `Err(EmptyMultihash)`.
- Go `GetOrFirst()` silently falls back; Rust `get_or_err()` returns `Result`.
- Go has `Tagged()` on both `AuthState` and `CommitState` (duplicated logic); Rust has `commit_state_tagged()` only on `Principal`.

---

#### Finding E.3 — Go exports `DeriveHashAlgs` and `isSupportedAlg` asymmetry [INFO]

`DeriveHashAlgs` is exported (capitalized), suggesting it's public API. `isSupportedAlg` is unexported. Both are utility functions.

Rust exports `derive_hash_algs` (public) but `hash_alg_from_str` is also public. The Rust side is more consistent — all algorithm-related helpers are public.

---

#### Finding D.5 — `compute_commit_id_tagged` has no Go equivalent [INFO]

Rust has `compute_commit_id_tagged` (state.rs:539-601) for cross-algorithm czd conversion (SPEC §20, Multihash Identifiers). Go has no equivalent — it only has `ComputeCommitID` which takes raw `coz.B64` slices without algorithm tagging.

This means Go cannot correctly compute multi-algorithm Commit IDs when transactions use different signing algorithms. This is a functional gap, not just a surface one.

**Recommendation:** Log as potential BUG if multi-algorithm keysets are intended to work in Go.

---

#### Recommended Changes

| ID      | Priority | Description                                                          |
| :------ | :------- | :------------------------------------------------------------------- |
| **D.3** | P2       | Evaluate Go `DataState` inner type vs Rust `Cad` divergence          |
| **D.5** | P1       | Go missing `ComputeCommitIDTagged` for cross-algorithm support       |
| **A.4** | P1       | Go `MultihashDigest.Variants()` leaks mutable reference to internals |
| **F.3** | P1       | Go `NewMultihashDigest` panics (same class as BUG-3)                 |
| **F.4** | P2       | Go `ParseHashAlg`/`ParseTaggedDigest` — use structured errors        |
| **E.2** | P3       | Reconcile Go/Rust accessor patterns on MultihashDigest               |

---

**Status:** ✅ Reviewed. Proceeding to Component 3 (Storage Layer).

---

### Component 3: Storage Layer

**Scope:** `Store` trait/interface, `Entry`, `Genesis`, `LoadPrincipal`/`load_principal`, `ExportEntries`/`export_entries`, `QueryOpts`, error types, and Rust-only types (`CommitEntry`, `Checkpoint`, `FileStore`).

#### Summary

| Dimension              | Go   | Rust | Notes                                                                                                                                                  |
| :--------------------- | :--- | :--- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A. Minimal Surface** | PASS | WARN | Rust `Entry.now` is `pub`; Rust `load_principal` has debug `eprintln!` in production code                                                              |
| **B. Type Safety**     | WARN | PASS | Go `Genesis` uses interface + type-switch vs Rust enum; Go `Entry.Raw` is mutable `pub`                                                                |
| **C. Composability**   | WARN | PASS | Go import uses separate `VerifyTransaction`+`ApplyTransaction` (non-atomic); Rust uses `verify_and_apply_transaction`                                  |
| **D. Monosemicity**    | WARN | WARN | Rust has `CommitEntry`, `Checkpoint`, commit-based storage absent from Go; Go has `SigBytes`/`KeyJSON`/`Typ`/`IsTransaction` on Entry absent from Rust |
| **E. Naming**          | PASS | PASS | Naming is consistent within each language                                                                                                              |
| **F. Error Handling**  | PASS | PASS | Both use structured errors; Go sentinels, Rust `thiserror` enums                                                                                       |

---

#### Finding D.6 — Commit-based storage and `Checkpoint` are Rust-only [WARN]

Rust has:

- `CommitEntry` (lib.rs:206-250) — commit bundling with embedded state digests
- `FileStore.append_commit()` / `get_commits()` (file.rs:143-203)
- `load_principal_from_commits()` (import.rs:246-257)
- `Checkpoint` (import.rs:48-58) + `load_from_checkpoint()` (import.rs:201-219)

Go has none of these. Go only supports the flat JSONL format (one entry per line).

This is a significant feature gap. If prod storage moves to commit-based format, Go cannot participate. If checkpoint-based sync is needed for thin clients, Go has no path.

**Recommendation:** Decide if Go should support commit-based storage. If so, port `CommitEntry`, `load_principal_from_commits`, and `Checkpoint`.

---

#### Finding D.7 — Go `Entry` has field extractors absent from Rust [INFO]

Go `Entry` has `SigBytes()`, `KeyJSON()`, `Typ()`, `IsTransaction()` (entry.go:94-148).
Rust `Entry` has only `pay_bytes()`, `raw_json()`, `as_value()`, `from_json()`.

In Rust, field extraction happens inline in import.rs via `serde_json::Value` access. The logic is equivalent but not encapsulated on the `Entry` type.

This is an asymmetric design choice — Go centralizes extraction on `Entry`, Rust distributes it across consumers. Neither is wrong, but it affects refactoring surface.

---

#### Finding C.1 — Go import uses non-atomic verify+apply [WARN]

Go (import.go:150-166):

```go
verifiedTx, err := principal.VerifyTransaction(cz, newKey)
// ...
if _, err := principal.ApplyTransaction(verifiedTx); err != nil {
```

Rust (import.rs:300-301):

```rust
principal.verify_and_apply_transaction(&pay_json, &sig, czd, new_key)
```

Go's **import path** makes two separate calls — `VerifyTransaction` then `ApplyTransaction`. If any code path between these two calls mutates the principal (not currently possible in single-threaded Go, but a latent risk), the verified transaction could become stale. Rust's single call is atomic by construction.

**Note:** Go's _core API_ already provides `CommitBatch.VerifyAndApply()` (commit.go:225), which is the atomic equivalent. The issue is that the storage import path does not use it.

**Recommendation:** Refactor `go/storage` import to use `CommitBatch.VerifyAndApply` instead of separate calls.

---

#### Finding A.5 — Rust `load_principal` has debug `eprintln!` [WARN]

Rust (import.rs:153-166):

```rust
eprintln!("  [load_principal] initial AS={}", {
    // ...debug output...
});
for k in principal.active_keys() {
    eprintln!("  [load_principal] genesis_key tmb={}", k.tmb.to_b64());
}
```

This is debug output left in production code. It writes to stderr on every principal load.

**Recommendation:** Remove or gate behind `#[cfg(debug_assertions)]` or a `tracing` instrument.

---

#### Finding B.4 — Go `Entry.Raw` is publicly mutable [WARN]

Go (entry.go:24):

```go
type Entry struct {
    Raw json.RawMessage  // public, mutable
    Now int64            // public, mutable
}
```

Rust (lib.rs:92-97):

```rust
pub struct Entry {
    raw_json: Box<RawValue>,  // private
    pub now: i64,             // public (read)
}
```

Go's `Entry.Raw` is a public `json.RawMessage` (= `[]byte`), which can be mutated by any consumer. This undercuts the "bit-perfect preservation" invariant that the type's doc comment explicitly calls "CRITICAL."

**Recommendation:** Unexport `Raw`, provide `Bytes()` for read access (which already exists).

---

#### Finding D.8 — Go `containsKeyPrefix` manually scans vs Rust `str.contains` [INFO]

Go (entry.go:152-165):

```go
func containsKeyPrefix(typ string) bool {
    for i := 0; i+5 <= len(typ); i++ {
        if typ[i:i+5] == "/key/" {
```

The same as D.2's `typSuffix` issue — hand-rolled string searching where `strings.Contains(typ, "/key/")` would be correct and clear. Not a bug per se (the result is identical), but unnecessary complexity.

---

#### Recommended Changes

| ID      | Priority | Description                                                                    |
| :------ | :------- | :----------------------------------------------------------------------------- |
| **D.6** | P1       | Decide Go commit-based storage path; port `CommitEntry`+`Checkpoint` if needed |
| **A.5** | P1       | Remove `eprintln!` debug output from Rust `load_principal`                     |
| **C.1** | P2       | Add `VerifyAndApplyTransaction` to Go `Principal` for atomic import            |
| **B.4** | P2       | Unexport Go `Entry.Raw`, rely on `Bytes()` accessor                            |
| **D.8** | P3       | Replace Go `containsKeyPrefix` with `strings.Contains`                         |

---

**Status:** ✅ Reviewed. All three core components audited.

---

### Component 4: CLI

**Scope:** Rust-only `cyphrpass-cli` crate: `main.rs`, `lib.rs`, `keystore.rs`, `commands/{init,key,tx,inspect,io}.rs`. No Go CLI exists.

#### Summary

| Dimension              | Go  | Rust | Notes                                                       |
| :--------------------- | :-- | :--- | :---------------------------------------------------------- |
| **A. Minimal Surface** | N/A | WARN | 5 helper functions copy-pasted across all command modules   |
| **B. Type Safety**     | N/A | PASS | clap enums, thiserror, proper error types                   |
| **C. Composability**   | N/A | FAIL | massive duplication; no shared command utilities module     |
| **D. Monosemicity**    | N/A | WARN | `Box<dyn Error>` used throughout instead of typed CLI error |
| **E. Naming**          | N/A | PASS | consistent naming                                           |
| **F. Error Handling**  | N/A | WARN | `.into()` string errors, `.ok_or("string")` patterns        |

---

#### Finding C.2 — CLI helper functions duplicated across 5 modules [FAIL]

The following functions are **copy-pasted identically** across `init.rs`, `key.rs`, `tx.rs`, `inspect.rs`, and `io.rs`:

| Function                       | Copies | Lines each |
| :----------------------------- | :----- | :--------- |
| `load_key_from_keystore`       | 4      | ~25        |
| `extract_genesis_from_commits` | 3      | ~50        |
| `parse_store`                  | 5      | ~5         |
| `parse_principal_root`         | 4      | ~5         |
| `decode_b64`                   | 4      | ~3         |

Total: **~350 lines of duplicated code**. Any bug fix must be applied to every copy.

**Recommendation:** Extract to a `commands/common.rs` shared module.

---

#### Finding C.3 — Key generation match arms are near-identical [WARN]

`generate_and_store_key` in `init.rs` and `generate_key_for_add` in `key.rs` each have 4 match arms (ES256, ES384, ES512, Ed25519) that differ only in the type parameter. Each arm is ~20 lines. Together, ~320 lines of code that could be a single generic function or use the `Alg` enum dispatch from `coz`.

```rust
// Current: 4 near-identical arms
"ES256" => { let key = SigningKey::<ES256>::generate(); ... }
"ES384" => { let key = SigningKey::<ES384>::generate(); ... }
// ... etc
```

**Recommendation:** Use coz's `Alg` runtime dispatch or a macro to eliminate the duplication.

---

#### Finding D.9 — `Box<dyn Error>` hides error provenance [WARN]

Every CLI command function returns `Result<(), Box<dyn std::error::Error>>`. This loses type information and makes error matching impossible for callers. The keystore already has a proper `keystore::Error` enum.

**Recommendation:** Create a `cli::Error` enum wrapping keystore, storage, and cyphrpass errors. Low priority since CLI is the outermost layer.

---

#### Finding F.5 — String-based errors in CLI commands [WARN]

Errors are returned as `.ok_or("signing failed")`, `format!("unknown algorithm: {algo}").into()`, etc. These are not matchable and lose type safety.

---

#### Recommended Changes

| ID      | Priority | Description                                            |
| :------ | :------- | :----------------------------------------------------- |
| **C.2** | P0       | Extract duplicated CLI helpers to `commands/common.rs` |
| **C.3** | P2       | De-duplicate key generation match arms                 |
| **D.9** | P3       | Add `cli::Error` enum                                  |
| **F.5** | P3       | Replace string errors with typed variants              |

---

**Status:** ✅ Reviewed.

---

### Component 5: Test Fixtures

**Scope:** Go `testfixtures` package (pool, intent, golden, runner, e2e_runner); Rust `test-fixtures` crate (pool, intent, golden+Generator); Rust `fixture-gen` crate.

#### Summary

| Dimension              | Go   | Rust | Notes                                                                          |
| :--------------------- | :--- | :--- | :----------------------------------------------------------------------------- |
| **A. Minimal Surface** | PASS | PASS | Clean API boundaries                                                           |
| **B. Type Safety**     | WARN | PASS | Go uses `map[string]any` for pay construction in e2e_runner                    |
| **C. Composability**   | PASS | PASS | Both share pool/intent/golden formats                                          |
| **D. Monosemicity**    | WARN | WARN | Go consumes goldens only; Rust generates them. Fixture flow is one-directional |
| **E. Naming**          | WARN | PASS | Go uses `Name` field on `PoolKey` (GitHub Issue #2 — under review)             |
| **F. Error Handling**  | PASS | PASS | Both consistent                                                                |

---

#### Finding D.10 — Go fixture runner uses non-atomic verify+apply (same as C.1) [INFO]

`signAndApplyTransaction` in `e2e_runner.go:284-319` calls `VerifyTransaction` then `ApplyTransaction` separately, matching the pattern identified in Finding C.1. This is the same issue surfacing in a different consumer.

---

#### Finding B.5 — Go `checkExpected` has repetitive verification blocks [INFO]

`runner.go:160-336` has nearly identical blocks for KS, AS, PS, CS, PR, DS, and three MultihashXX maps. Each block does: parse `alg:digest`, look up variant, compare. This is ~180 lines that could be factored into a helper like `assertDigest(name, expected, principal.KS())`.

---

#### Finding D.11 — Go consumes goldens but cannot generate them [INFO]

Rust is the single source of truth for golden fixtures via `test-fixtures::Generator` (1400+ lines). Go can only consume generated goldens. This is architecturally intentional (Rust is the reference implementation for fixture generation), but means Go's E2E runner cannot produce new test cases independently.

---

#### Finding E.3 — Go `PoolKey.Name` field (GitHub Issue #2) [INFO]

`PoolKey.Name` is arguably redundant with the TOML key or should be called `tag`. This is already tracked as GitHub Issue #2. No additional action needed here.

---

#### Recommended Changes

| ID      | Priority | Description                                                    |
| :------ | :------- | :------------------------------------------------------------- |
| **B.5** | P3       | Factor `checkExpected` verification blocks into generic helper |
| **E.3** | P3       | Tracked as GitHub Issue #2                                     |

---

---

## Phase 3: Cross-Cutting Analysis

This phase evaluates the systemic properties and internal consistency of each implementation independently, then scores overall coherence. While cross-language parity is important (tracked in the deviations log), an API must first be internally coherent.

### 3.1 Consistency Audit

#### **Go Implementation**

- [ ] **Naming conventions:** Generally adheres to Go idioms, but initializers are semantically inconsistent: `NewEntry` returns `(*Entry, error)`, whereas `NewCommit` and `NewMultihashDigest` panic on invalid input. Accessor naming patterns vary (`First()` returns nil; `GetOrFirst()` provides fallback).
- [ ] **Error handling strategy:** Fractured. The `storage` package uses good typed errors (`LoadError`), and the core provides some sentinels, but multiple modules regress to `fmt.Errorf` (F.2, F.4), preventing `errors.Is` matching. The use of panics in core logic (F.1, F.3) is a systemic violation of library design principles.
- [ ] **Common patterns:** Domain typing is inconsistent. While `state.go` introduces robust newtypes for digests, `transaction.go` relies on a bare `int` for `TransactionKind` and `[]byte` for `coz.B64` fields, creating nullable state risks absent from a true sum-type architecture.
- [ ] **Immutability contracts (systemic):** Go types that claim immutability structurally fail to enforce it. `Commit` is documented as "immutable once finalized" (commit.go:16), yet `SetRaw()` is a public mutator and `Transactions()` returns a slice of mutable pointers to internal state. This same slice-of-pointer-return pattern pervades the API (`AuthLedger.Keys`, `MultihashDigest.Variants()`, `Principal.Commits()`, `Principal.Transactions()`, `Principal.Actions()`), forming a **systemic anti-pattern** where callers can silently corrupt internal state through returned references.
- [x] **Documentation style:** Consistent. Both packages use Go doc comments with SPEC section references.

#### **Rust Implementation**

- [x] **Naming conventions:** Excellent internal uniformity. Standardized Rust idioms (`from_pay`, `as_value`, `to_b64`) are used systemically across both `cyphrpass` and `cyphrpass-storage`.
- [ ] **Error handling strategy:** Strong in the core (`thiserror` enums strictly define the failure domain), but systemically degraded in the `cyphrpass-cli` crate, which uniformly returns `Box<dyn Error>` and relies heavily on stringly-typed `.map_err()`/`.ok_or()` (D.9, F.5).
- [ ] **Common patterns:** The core libraries execute trait composition beautifully, but the CLI layer exhibits a systemic failure of composability, opting for massive copy-paste duplication (~350 lines over 5 modules) instead of sharing application-layer logic (C.2).
- [ ] **`debug_assert!` in core library (3 occurrences):** `state.rs:423`, `multihash.rs:43`, `commit.rs:52` contain `debug_assert!` calls that panic in debug builds. These appear to be internal invariant checks (not reachable from external input), but should be explicitly triaged: if truly unreachable, document why; if potentially reachable, convert to `Result`.
- [x] **Documentation style:** Consistent. Core crate uses `///` doc comments with `# Panics` sections where applicable.

### 3.2 Layering & Encapsulation Audit

#### **Go Implementation**

- [ ] **Encapsulation (Leaky):** Go exhibits a **systemic** issue with encapsulation. The root cause is a single anti-pattern: returning internal collections by reference without defensive copies. This manifests across multiple types:
  - `storage.Entry.Raw` — publicly mutable `json.RawMessage` on a type that documents "CRITICAL" bit-perfect preservation.
  - `cyphrpass.MultihashDigest.Variants()` — returns internal map (Go maps are reference types), allowing mutation of state digests.
  - `cyphrpass.Principal` — publicly exposes `AuthLedger` and `DataLedger` fields.
  - `cyphrpass.Commit.SetRaw()` — public mutator on a type documented as "immutable once finalized."
  - `cyphrpass.Commit.Transactions()` — returns `[]*Transaction`, a mutable slice of mutable pointers.
  - `cyphrpass.Commit.Raw()` — returns `[]json.RawMessage`, mutable slice reference.
  - **Systemic recommendation:** Audit all public methods returning slices/maps for defensive copy needs. Consider an unexported inner type with exported read-only accessors.
- [x] **Dependency Direction:** Clean. `cyphrpass` knows nothing of `storage`.

#### **Rust Implementation**

- [x] **Encapsulation (Tight):** Rust achieves excellent internal layering. Internal construction relies on `pub(crate)` (e.g., `Commit::new`, `finalize_commit`), and external mutation is tightly controlled by the borrow checker and immutable references. The `&[&Key]` / `&BTreeMap` patterns prevent the class of issues Go exhibits.
- [x] **Dependency Direction:** Clean. Core, storage, and CLI maintain strict boundaries.

### 3.3 Coherence Score

| Criterion        | Go      | Rust    | Notes                                                                                                                                                                                 |
| :--------------- | :------ | :------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Minimal Surface  | 2       | 5       | Go systemically leaks internal mutable state (A.1, A.4, BUG-10, BUG-11) and exposes panic-prone constructors (A.2). Rust uses `pub(crate)` and borrow-checker enforcement throughout. |
| Type Safety      | 3       | 5       | Rust's sum types prevent invalid states. Go hampered by `int` enums (B.1), nullable `[]byte` (B.2), and structurally unenforced immutability contracts.                               |
| Composability    | 4       | 3       | Go's core compose chain is clean (`BeginCommit`→`VerifyAndApply`→`Finalize`); import path is the exception (C.1). Rust's core is excellent but CLI is a systemic failure (C.2, C.3).  |
| Monosemicity     | 3       | 4       | Go retains dead `TxOtherRevoke`. Rust has minor duplication only in CLI layer.                                                                                                        |
| Naming Coherence | 4       | 5       | Go has minor constructor/accessor pattern variances. Rust is uniformly idiomatic.                                                                                                     |
| Error Handling   | 2       | 4       | Go panics in library code (BUG-3, BUG-5) and uses unmatchable `fmt.Errorf`. Rust core is flawless; CLI degrades to `Box<dyn Error>`.                                                  |
| **Overall**      | **3.0** | **4.3** | **Go** urgently needs an encapsulation and panic-safety hardening pass. **Rust** requires CLI deduplication and error typing.                                                         |

---

### 3.4 Scope Limitations

This audit covers **API surface coherence** — type safety, naming, error handling, encapsulation, and cross-language parity. The following concerns are intentionally excluded and tracked for follow-up:

- **Lifecycle state implementation** — The formal model (`docs/models/principal-state-model.md`) defines 6 base states (Active, Frozen, Deleted, Zombie, Dead, Nuked) × 2 error states. Whether either implementation models these states is not audited here. Both implementations currently target Levels 1–4; lifecycle complexity may be partially deferred.
- **Authorization predicate correctness (I1)** — Pre-state key membership (`signer.tmb ∈ active_keys(s)`) is the single most critical security invariant. This audit checks error handling around `verifyPre` but does not verify behavioral correctness of authorization.
- **AS monotonicity (I2)** — Revocations must be permanent. Whether either implementation allows un-revoking a key is not audited.
- **MHMR computation correctness** — SPEC §20.4–20.5 defines the Multi Hash Merkle Root algorithm. This audit identifies missing Go support (BUG-7) but does not verify that either implementation's computation matches the spec.
- **Implicit promotion edge cases** — SPEC §2.2.5 and §9.1 define single-node promotion (no hashing). Edge cases (single-key KS, genesis CS, single-action DS) are not audited for cross-implementation consistency.
- **Data action completeness** — SPEC §6.7 defines stateless signed messages. DS computation and data action lifecycle are not audited beyond type representation (D.3).

These gaps are addressed in Appendix B (Behavioral Correctness Audit).

---

## Phase 4: Remediation Plan

> **Checkpoint:** This plan requires user approval before any code changes begin.

### P0 — Critical (Spec violations, correctness bugs)

1. [ ] **[Go `transaction.go`]** Remove `TxOtherRevoke` variant — dead code, concept removed from SPEC. Remove from `TransactionKind` enum, `String()`, and `applyTransactionInternal` case. — _BUG-1, D.1_
2. [ ] **[Go `transaction.go`]** Fix `typSuffix` — splits at first `/`, breaks for namespaced authorities (e.g., `org/cyphr.me/key/create`). Replace with `strings.HasSuffix` matching Rust. — _BUG-2, D.2_

### P1 — High (Encapsulation violations, significant safety issues)

#### Go: Panic-Safety Hardening

3. [ ] **[Go `commit.go`]** `NewCommit` — panics on empty input. Change to return `(*Commit, error)` or unexport. — _BUG-3, F.1_
4. [ ] **[Go `multihash.go`]** `NewMultihashDigest` — panics on empty input. Change to return `(MultihashDigest, error)` or unexport. — _BUG-5, F.3_

#### Go: Encapsulation Hardening (Systemic Anti-Pattern)

5. [ ] **[Go `multihash.go`]** `Variants()` — returns internal map reference. Return defensive copy or provide iteration-only access. — _BUG-6, A.4_
6. [ ] **[Go `commit.go`]** `SetRaw()` — public mutator on "immutable" `Commit`. Remove or restrict to package-level. — _BUG-10_
7. [ ] **[Go `commit.go`]** `Transactions()` — returns `[]*Transaction` (mutable slice of mutable pointers). Return copies or unexport. — _BUG-11_
8. [ ] **[Go `principal.go`]** Unexport `AuthLedger` and `DataLedger` fields, or make the types themselves unexported. Provide read-only accessors. — _A.1_

#### Go: Error Handling

9. [ ] **[Go `principal.go`]** `verifyPre` — uses `fmt.Errorf`. Replace with sentinel error (e.g., `ErrNoCommitState`). — _BUG-4, F.2_
10. [ ] **[Go `state.go`]** `ParseHashAlg` / `ParseTaggedDigest` — use `fmt.Errorf` throughout. Introduce sentinel or typed errors (`ErrUnsupportedAlgorithm`, `ErrMalformedDigest`, `ErrDigestLengthMismatch`). — _F.4_

#### Go: Functional Gap

11. [ ] **[Go `state.go`]** Missing `ComputeCommitIDTagged` — Go cannot handle multi-algorithm keysets per SPEC §20 (Multihash Identifiers). Port from Rust's `compute_commit_id_tagged`. — _BUG-7, D.5_

#### Rust: Debug Output

12. [ ] **[Rust `import.rs`]** Remove `eprintln!` debug output from `load_principal` (lines 153, 165). Replace with `tracing::debug!` or gate behind `#[cfg(debug_assertions)]`. — _BUG-8, A.5_

#### Rust: CLI Deduplication

13. [ ] **[Rust `cyphrpass-cli`]** Extract ~350 lines of duplicated helpers (`load_key_from_keystore`, `extract_genesis_from_commits`, `parse_store`, `parse_principal_root`, `decode_b64`) into `commands/common.rs`. — _BUG-9, C.2_

### P2 — Medium (Parity gaps, moderate quality issues)

14. [ ] **[Go `storage`]** Refactor import path to use `CommitBatch.VerifyAndApply` instead of separate `VerifyTransaction` + `ApplyTransaction` calls. — _C.1_
15. [ ] **[Go `testfixtures`]** Refactor `e2e_runner.go` to use atomic `VerifyAndApply` rather than separate calls. — _D.10_
16. [ ] **[Go `transaction.go`]** Document or refactor `TransactionKind` from a bare `int` to a more robust representation to prevent invalid states. — _B.1_
17. [ ] **[Go `key.go`]** Disambiguate `Revocation.By` (currently `coz.B64` where `nil` and empty slice are confusable; consider newtype or pointer). — _B.2_
18. [ ] **[Go `commit.go`]** Unexport `NewCommit` — only caller should be `FinalizeCommit`. Consider also unexporting `FinalizeCommit` if `CommitBatch.Finalize` is the canonical path. — _A.2_
19. [ ] **[Go `storage/entry.go`]** Unexport `Entry.Raw` — callers should use `Bytes()` accessor for read access. Preserves bit-perfect invariant. — _B.4_
20. [ ] **[Rust `cyphrpass-cli`]** De-duplicate key generation match arms (~320 lines across `init.rs`/`key.rs`). Use `coz::Alg` runtime dispatch or a macro. — _C.3_
21. [ ] **[Go `state.go`]** Evaluate `DataState` inner type — Go uses `coz.B64` (raw bytes), Rust uses `coz::Cad`. Determine if Go should wrap a typed digest. — _D.3_
22. [ ] **[Go/Rust]** Decide Go commit-based storage path. If needed, port `CommitEntry`, `load_principal_from_commits`, `Checkpoint`, `load_from_checkpoint` from Rust. — _D.6, DEV-1, DEV-2_

### P3 — Low (Style, minor redundancies, low-risk improvements)

23. [ ] **[Go `principal.go`/Rust]** Mark test helpers (`PreRevokeKey`, `active_keys_mut`) with `#[doc(hidden)]`, feature flag, or `Test` prefix. — _A.3_
24. [ ] **[Go/Rust]** Consider aligning `VerifiedTx` → `VerifiedTransaction` naming cross-language. — _E.1_
25. [ ] **[Go `storage/entry.go`]** Replace hand-rolled `containsKeyPrefix` with `strings.Contains(typ, "/key/")`. — _D.8_
26. [ ] **[Go `testfixtures`]** Factor `checkExpected` repetitive verification blocks into a generic helper. — _B.5_
27. [ ] **[Go `testfixtures`]** Resolve `PoolKey.Name` field redundancy. — _E.3 (GitHub Issue #2)_
28. [ ] **[Go `key.go`]** Clarify documentation on why `Key.Rvk` exists alongside `Revocation.Rvk` to avoid shadowing confusion. — _B.3_
29. [ ] **[Go `state.go`]** Re-export `HashAlg` directly from `coz` like Rust does to maintain strict cross-crate typing, rather than creating a local alias. — _D.4_
30. [ ] **[Go `state.go`]** Make visibility symmetric: either both `DeriveHashAlgs` and `isSupportedAlg` should be public, or both private. — _E.3_
31. [ ] **[Go `storage/entry.go`]** Document the asymmetric design choice to centralize `Entry` extractors in Go versus inline access in Rust. — _D.7_
32. [ ] **[Go `testfixtures`]** Document that Go intentionally delegates golden fixture generation to Rust as the single source of truth. — _D.11_
33. [ ] **[Rust `cyphrpass-cli`]** Add `cli::Error` enum wrapping keystore, storage, and cyphrpass errors (low priority — CLI is outermost layer). — _D.9, F.5_
34. [ ] **[Rust `cyphrpass`]** Triage 3 `debug_assert!` occurrences in core (`state.rs:423`, `multihash.rs:43`, `commit.rs:52`): document unreachability or convert to `Result`. — _Phase 3 §3.1_
35. [ ] **[Go `state.go`]** Reconcile `MultihashDigest` accessor patterns (`First()` vs `GetOrFirst()`) with Rust (`first_variant()` / `get_or_err()` returning `Result`). — _E.2_

---

### Language-Specific Checklists

#### Go

| Check                                               | Status | Notes                                                                                                                    |
| :-------------------------------------------------- | :----- | :----------------------------------------------------------------------------------------------------------------------- |
| Exported types have doc comments                    | ✅     | Consistent SPEC references                                                                                               |
| Error types implement `Error` and support `Is`/`As` | ❌     | `fmt.Errorf` used in `verifyPre`, `ParseHashAlg`, `ParseTaggedDigest` (items 9-10)                                       |
| Unexported fields for invariant protection          | ❌     | `AuthLedger`, `DataLedger`, `Entry.Raw` exported (items 8, 19)                                                           |
| Meaningful zero values or require constructors      | ⚠️     | Constructors exist but some panic instead of erroring (items 3-4)                                                        |
| No `panic` in library code paths                    | ❌     | `NewCommit`, `NewMultihashDigest`, `PreRevokeKey` (items 3-4)                                                            |
| Context propagation for cancellation                | N/A    | Protocol library operates synchronously; no long-running operations requiring cancellation                               |
| Options pattern for configurable constructors       | ⚠️     | `SetMaxClockSkew` is a post-construction setter; consider options pattern for `Implicit`/`Explicit` if more config grows |

#### Rust

| Check                                            | Status | Notes                                                                                                                                                                              |
| :----------------------------------------------- | :----- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public items have doc comments (`///`)           | ✅     | Consistent with `# Panics` sections                                                                                                                                                |
| `#[must_use]` on Result-returning functions      | ✅     | 23 occurrences across `state.rs` and `multihash.rs`; thorough coverage                                                                                                             |
| `#[non_exhaustive]` on enums for future-proofing | N/A    | Pre-1.0; omitting `#[non_exhaustive]` ensures exhaustive `match` catches missing variants at compile time — a correctness aid during active development. Revisit at stabilization. |
| No `unwrap()`/`expect()` in library code paths   | ✅     | Core library clean; all `.unwrap()` calls are test-only                                                                                                                            |
| `pub(crate)` for internal-only items             | ✅     | Excellent usage across core and storage                                                                                                                                            |
| Correct `Send`/`Sync` bounds on public types     | N/A    | No async or cross-thread usage; no explicit bounds needed                                                                                                                          |
| Feature flags documented with `cfg_attr`         | N/A    | No feature-gated functionality in core crate                                                                                                                                       |

---

## Bug Log

Bugs discovered during the audit that require code changes. Tracked here for resolution after audit completes.

| ID     | Severity | Component            | Description                                                                                                                                                                       | Status |
| :----- | :------- | :------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----- |
| BUG-1  | P0       | Go `transaction.go`  | `TxOtherRevoke` variant is dead code — concept removed from SPEC. Remove variant, remove `applyTransactionInternal` case, remove `String()` case.                                 | Open   |
| BUG-2  | P0       | Go `transaction.go`  | `typSuffix` splits at first `/` — breaks for namespaced authorities. Replace with `strings.HasSuffix`.                                                                            | Open   |
| BUG-3  | P1       | Go `commit.go`       | `NewCommit` panics on empty input. Library code must not panic per `engineering.md`. Return error or unexport.                                                                    | Open   |
| BUG-4  | P1       | Go `principal.go`    | `verifyPre` uses `fmt.Errorf` — not matchable via `errors.Is`. Replace with sentinel.                                                                                             | Open   |
| BUG-5  | P1       | Go `multihash.go`    | `NewMultihashDigest` panics on empty input. Library code must not panic.                                                                                                          | Open   |
| BUG-6  | P1       | Go `multihash.go`    | `Variants()` returns internal map reference — callers can mutate state type internals.                                                                                            | Open   |
| BUG-7  | P1       | Go `state.go`        | Missing `ComputeCommitIDTagged` — Go cannot handle multi-algorithm keysets per SPEC §20 (Multihash Identifiers).                                                                  | Open   |
| BUG-8  | P1       | Rust `import.rs`     | `eprintln!` debug output in `load_principal` — writes to stderr in production on every load. Remove or gate.                                                                      | Open   |
| BUG-9  | P1       | Rust `cyphrpass-cli` | ~350 lines of copy-pasted helpers across 5 command modules. Extract to `commands/common.rs`.                                                                                      | Open   |
| BUG-10 | P1       | Go `commit.go`       | `Commit.SetRaw()` is a public mutator on a type documented as "immutable once finalized" (commit.go:16). Violates immutability invariant. Remove or make `pub(crate)` equivalent. | Open   |
| BUG-11 | P1       | Go `commit.go`       | `Commit.Transactions()` returns `[]*Transaction` — mutable slice of mutable pointers to internal state. Same systemic pattern as BUG-6. Return copies or unexport fields.         | Open   |

---

## Feature Deviation Log

Features present in one implementation but absent from the other. Neither language is "secondary" — both are reference implementations and should converge on the full SPEC surface.

| ID    | Feature                         | Go                                               | Rust                                                                            | Maturity                                                      | Notes                                                                  |
| :---- | :------------------------------ | :----------------------------------------------- | :------------------------------------------------------------------------------ | :------------------------------------------------------------ | :--------------------------------------------------------------------- |
| DEV-1 | Checkpoint-based loading        | ❌                                               | ✅ `from_checkpoint` + `load_from_checkpoint`                                   | Implemented (~60 lines, computes KS/CS/PS from trusted state) | Needed for thin-client sync per SPEC §6.3.3                            |
| DEV-2 | Commit-based storage format     | ❌                                               | ✅ `CommitEntry`, `append_commit`, `get_commits`, `load_principal_from_commits` | Implemented + tested                                          | Required if prod storage moves to one-commit-per-line JSONL            |
| DEV-3 | Cross-algorithm czd conversion  | ❌                                               | ✅ `TaggedCzd`, `compute_commit_id_tagged`                                      | Implemented + tested                                          | Required for multi-algorithm keysets per SPEC §14.2                    |
| DEV-4 | Entry field extractors          | ✅ `SigBytes`, `KeyJSON`, `Typ`, `IsTransaction` | ❌ (inline in `import.rs`)                                                      | Go side richer                                                | Rust delegates extraction to consumers                                 |
| DEV-5 | `TxOtherRevoke`                 | ✅ (dead code)                                   | ❌                                                                              | Removed from SPEC                                             | Go should remove (tracked as BUG-1)                                    |
| DEV-6 | `verify_and_apply_transaction`  | ⚠️ `CommitBatch.VerifyAndApply` exists in core   | ✅                                                                              | Implemented                                                   | Go core has the atomic method; `go/storage` import path doesn't use it |
| DEV-7 | `CommitScope` (borrow-enforced) | N/A (Go lacks borrow checker)                    | ✅                                                                              | Implemented                                                   | Go has `CommitBatch` — idiomatic equivalent, no structural enforcement |
| DEV-8 | CLI tool                        | ❌                                               | ✅ `cyphrpass-cli` (init, key, tx, inspect, import/export)                      | Implemented + tested                                          | Go has no CLI at all                                                   |
| DEV-9 | Golden fixture generation       | ❌ (consume-only)                                | ✅ `test-fixtures::Generator` (1400+ lines)                                     | Implemented + tested                                          | Go can run goldens but not produce them                                |

---

### 1.1 Go Surface (`go/cyphrpass`)

#### Types (Structs, Enums, Aliases)

- `Action`
- `ActionPay`
- `Commit`
- `CommitID`
- `CommitState`
- `DataState`
- `HashAlg` (string alias of `coz.HshAlg`)
- `Key`
- `KeyState`
- `Level` (int)
- `MultihashDigest`
- `PendingCommit`
- `Principal`
- `PrincipalRoot`
- `PrincipalState`
- `Revocation`
- `TaggedDigest`
- `Transaction`
- `TransactionKind` (int)
- `TransactionPay`
- `VerifiedTx`

#### Functions & Constructors

- `ComputePS(cs CommitState, ds *DataState, nonce coz.B64, algs []HashAlg) (PrincipalState, error)`
- `ComputeCommitID(czds []coz.B64, nonce coz.B64, algs []HashAlg) (*CommitID, error)`
- `NewPrincipalRoot(ps PrincipalState) PrincipalRoot`
- `ParseTransaction(pay *TransactionPay, czd coz.B64) (*Transaction, error)`
- `ParseTaggedDigest(s string) (TaggedDigest, error)`

### 1.2 Go Surface (`go/storage`)

#### Types (Structs, Enums)

- `Entry`
- `ExplicitGenesis`
- `ImplicitGenesis`
- `LoadError`
- `QueryOpts`

#### Traits / Interfaces

- `Genesis`
- `Store`

#### Functions

- `ExportEntries(principal *cyphrpass.Principal) []*Entry`
- `LoadPrincipal(genesis Genesis, entries []*Entry) (*cyphrpass.Principal, error)`
- `NewEntry(data []byte) (*Entry, error)`
- `NewEntryFromValue(v any) (*Entry, error)`
- `PersistEntries(store Store, principal *cyphrpass.Principal) (int, error)`
- `ReplayEntry(principal *cyphrpass.Principal, entry *Entry, index int) error`

---

### 1.3 Rust Surface (`rs/cyphrpass`)

#### Types (Structs, Enums)

- `Action`
- `AuthLedger`
- `AuthState`
- `Commit`
- `CommitID`
- `CommitScope`
- `CommitState`
- `DataLedger`
- `DataState`
- `HashAlg`
- `Key`
- `KeyState`
- `Level`
- `MultihashDigest`
- `PendingCommit`
- `Principal`
- `PrincipalRoot`
- `PrincipalState`
- `Thumbprint`
- `Transaction`
- `TransactionKind`
- `VerifiedAction`
- `VerifiedTransaction`

#### Functions (Key Entry Points)

- `Principal::implicit(key: Key) -> Result<Self>`
- `Principal::explicit(keys: Vec<Key>) -> Result<Self>`
- `Principal::from_checkpoint(...)`
- `Transaction::from_pay(...)`
- `verify_transaction(...)`
- `Action::from_pay(...)`

#### Constants

- `TransactionKind::KEY_CREATE`
- `TransactionKind::KEY_DELETE`
- `TransactionKind::KEY_REPLACE`
- `TransactionKind::KEY_REVOKE`
- `TransactionKind::PRINCIPAL_CREATE`

### 1.4 Rust Surface (`rs/cyphrpass-storage`)

#### Types (Structs, Enums)

- `Checkpoint`
- `CommitEntry`
- `Entry`
- `EntryError`
- `ExportError`
- `FileStore`
- `FileStoreError`
- `Genesis`
- `LoadError`
- `PersistError`
- `QueryOpts`

#### Traits / Interfaces

- `Store`

#### Functions

- `export_commits(principal: &Principal) -> Result<Vec<CommitEntry>, ExportError>`
- `export_entries(principal: &Principal) -> Result<Vec<Entry>, ExportError>`
- `load_from_checkpoint(...)`
- `load_principal(genesis: Genesis, entries: &[Entry]) -> Result<Principal, LoadError>`
- `load_principal_from_commits(...)`
- `persist_entries<S: Store>(...)`

---

## 📋 Open Questions for Review

1. **Completeness:** Does this map accurately reflect the intended public surface?
2. **Exclusions:** Are there any types here (like `TransactionPay`, `ActionPay` in Go, or `CommitEntry` in Rust) that should actually be private/internal?

---

## Appendix A: AI-Generated Code Audit

> **Framework:** 4-Layer AI Audit Protocol (ODC-based)
> **Principle of Zero Trust:** Every AI-generated line treated as a high-risk external contribution.

### Layer 1: Logic & Performance

**Status: PASS**

No algorithmic inefficiencies detected. The core computation paths (state derivation, Merkle multi-hashing, commit ID computation) use standard cryptographic patterns:

- Hash computations in `state.go` and `state.rs` use `crypto/sha256`/`sha2` crate — no hand-rolled crypto.
- Sorting uses standard library (`sort.Slice` in Go, `BTreeMap` ordering in Rust) — no O(n²) sorts.
- Key lookups use indexed maps (`keyIdx map[string]int` in Go, linear scan over small keyset in Rust) — appropriate for the domain (keysets are small, typically 1-5 keys).
- No unnecessary re-computation of state digests — compute functions are called once per commit, not per transaction.

**One minor note:** Go's `containsKeyPrefix` (entry.go:152) hand-rolls a substring search rather than using `strings.Contains`. This is an ODC **Algorithm** marker (preferring verbose iteration over standard library), but functionally correct. Already tracked as item 25.

---

### Layer 2: Dependencies

**Status: PASS**

All dependencies verified against official registries. No hallucinated packages, no phantom versions.

#### Go (`go/go.mod`)

| Dependency                               | Registry             | Status | Notes                                         |
| :--------------------------------------- | :------------------- | :----- | :-------------------------------------------- |
| `github.com/cyphrme/coz` v1.0.0          | GitHub (first-party) | ✅     | Core cryptographic library, same organization |
| `github.com/pelletier/go-toml/v2` v2.2.4 | GitHub/pkg.go.dev    | ✅     | Well-known TOML parser (~5k stars)            |

#### Rust (`rs/cyphrpass/Cargo.toml`)

| Dependency   | Registry                | Status | Notes                                     |
| :----------- | :---------------------- | :----- | :---------------------------------------- |
| `coz`        | Workspace (first-party) | ✅     | Core cryptographic library                |
| `indexmap`   | crates.io               | ✅     | Widely-used ordered map (~100M downloads) |
| `serde`      | crates.io               | ✅     | De facto serialization standard           |
| `serde_json` | crates.io               | ✅     | Standard JSON companion to serde          |
| `thiserror`  | crates.io               | ✅     | Standard derive macro for error types     |

No cross-ecosystem borrowing. No version hallucinations. Dependency surface is minimal and well-curated.

---

### Layer 3: Stylistic Signature ("Transformer Cadence")

**Status: WARN — Low severity**

#### Marker A — Procedural Step Comments (Go)

`verified_tx.go:44-84` exhibits the classic AI-generated "step-by-step narration" pattern:

```go
// Parse the payload to extract signer thumbprint   ← what, not why
var pay TransactionPay
// ...
// Look up the signing key                          ← what, not why
signerKey := p.Key(pay.Tmb)
// ...
// Check if key is revoked                          ← what, not why
if !signerKey.IsActive() {
// ...
// Verify the signature using the coz library       ← what, not why
valid, err := signerKey.Key.VerifyCoz(cz)
// ...
// Parse the transaction                            ← what, not why
tx, err := ParseTransaction(&pay, cz.Czd)
// ...
// Build the complete entry: {pay, sig, key?}       ← what, not why
rawEntry, err := buildRawEntry(cz, newKey)
```

Every comment describes **what** the next line does, not **why**. A human would write `// Signer must be active — self-revoke is handled in apply` rather than `// Check if key is revoked`. This pattern recurs in `state.go` (`// Compute hash for each algorithm variant` appears 5 times at lines 313, 352, 379, 415, 479).

**Severity: Low.** The code logic itself is correct and well-structured. The comments are redundant rather than misleading.

#### Marker A — Repetitive Accessor Docs (Rust)

`principal.rs` has 30+ accessor methods with `/// Get the ...` documentation:

```rust
/// Get the Principal Root (permanent identifier).      // L288
/// Get the current Principal State.                    // L293
/// Get the current Auth State.                         // L298
/// Get the current Key State.                          // L334
/// Get the hash algorithm used by this principal.      // L339
/// Get all active keys.                                // L363
/// Get all transactions (across all commits).          // L407
/// Get all finalized commits.                          // L412
/// Get the Commit ID of the last finalized commit.     // L417
/// Get the current Commit State.                       // L424
/// Get all actions.                                    // L477
```

This "Get the X" pattern is textbook Transformer output — it reads the function name and generates a paraphrase. A human doc comment would add context: `/// Active keyset — keys that haven't been revoked. Used for signature verification.`

Similarly, `transaction.rs:147-172` has 6 consecutive `/// Get the ...` docs that add zero value beyond the method signature.

**Severity: Low.** The docs aren't wrong, but they're semantically empty. They consume vertical space without aiding comprehension.

#### Marker B — Defensive Bloat

**Not detected.** The codebase shows minimal defensive coding. Go has only 1 `} else {` after an early-return pattern (transaction.go:148). No redundant nil-guard stacking. No unnecessary wrapper layers. This is a strong counter-signal — the code is lean.

#### Marker C — Context Collapse

**Not detected.** The codebase does not exhibit increasing complexity over iterations. Functions have consistent cyclomatic complexity and clear single-responsibility boundaries.

---

### Layer 4: Instruction Adherence

**Status: WARN — One violation identified**

#### Constraint: "SPEC says key/revoke must be self-signed"

The SPEC explicitly removed the concept of other-revoke. Go's `transaction.go` retains `TxOtherRevoke` as a variant with full dispatch handling. This is a textbook "attention failure" — the model likely trained on an earlier version of the spec that included other-revoke, and retained it despite the constraint changing. Already tracked as BUG-1.

#### Constraint: "Library code must not panic"

The project's own `engineering.md` establishes a no-panic policy for library code. Go's `NewCommit` and `NewMultihashDigest` both panic. This suggests the constraint was present in the prompt context but overridden by the model's "convenience" bias toward panics for simple validation. Already tracked as BUG-3, BUG-5.

#### Constraint: "Bit-perfect preservation"

`Entry.Raw` documents "CRITICAL" bit-perfect preservation but exposes the field publicly with no copy protection. The model adhered to the _documentation_ constraint but failed to enforce it _structurally_. This is a subtle attention split — acknowledging the invariant in prose while violating it in type design. Already tracked as item 19.

---

### AI Audit Summary

| Layer                              | Status               | Key Findings                                                                                                                                                                                  |
| :--------------------------------- | :------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Layer 1:** Logic & Performance   | ✅ PASS              | No algorithmic inefficiencies. Standard crypto patterns throughout.                                                                                                                           |
| **Layer 2:** Dependencies          | ✅ PASS              | All 7 dependencies verified. Zero hallucinated packages. Minimal surface.                                                                                                                     |
| **Layer 3:** Stylistic Signature   | ⚠️ WARN              | Procedural "what not why" comments in Go (`verified_tx.go`, `state.go`). Repetitive `/// Get the...` docs in Rust (`principal.rs`, `transaction.rs`). No defensive bloat or context collapse. |
| **Layer 4:** Instruction Adherence | ⚠️ WARN              | 3 constraint violations (all already tracked): `TxOtherRevoke` retention (BUG-1), panics in library code (BUG-3/5), bit-perfect invariant not structurally enforced (item 19).                |
| **Overall**                        | **CONDITIONAL PASS** | Code is logically sound and algorithmically correct. AI-isms are cosmetic (comments) rather than structural. All substantive violations were already caught by the API Coherence Audit.       |

**Priority Remediations (AI-specific):**

1. Rewrite procedural comments in `verified_tx.go` and `state.go` to explain _why_, not _what_.
2. Replace `/// Get the...` accessor docs in Rust with context-rich descriptions.
3. No new bugs surfaced — all Layer 4 violations are already in the Bug Log.

---

## Appendix B: Behavioral Correctness Audit

> **Scope:** This appendix addresses the behavioral correctness gaps identified in §3.4 (Scope Limitations). It evaluates implementation alignment with formal model invariants (`docs/models/principal-state-model.md`) and SPEC behavioral requirements. Where features are not yet implemented, it assesses whether the current API is structured to support natural implementation.

### B.1 Lifecycle State Implementation

**Formal model requirement:** 6 base states (Active, Frozen, Deleted, Zombie, Dead, Nuked) × 2 error states (OK, Errored) = 12 lifecycle combinations. The GADT ensures `¬(Deleted ∧ Frozen)` is unconstructible.

**Finding: NOT IMPLEMENTED**

Neither Go nor Rust models any lifecycle state. No `Frozen`, `Deleted`, `Zombie`, `Dead`, `Nuked`, or `Errored` state exists anywhere in either codebase (confirmed via identifier search — zero results for all lifecycle terms).

**Authorization path impact:** `apply_transaction_internal` in both implementations has **no lifecycle gating**. A frozen or deleted principal would accept mutations identically to an active one.

**API structural readiness:** ADEQUATE — The `Principal` struct in both languages can naturally accommodate a lifecycle field:

- **Rust:** A `lifecycle: Lifecycle` enum field (matching the formal model's GADT constructors) would compose cleanly with the existing `apply_transaction_internal` match arms. The `Error` enum already has variants for authorization failures (`UnknownKey`, `KeyRevoked`) — lifecycle-specific variants (`PrincipalFrozen`, `PrincipalDeleted`) would be natural additions.
- **Go:** A `lifecycle` field with iota constants would mirror the pattern already established by `TransactionKind`. Guard checks at the top of `applyTransactionInternal` would integrate without restructuring.

**Verdict:** The absence is expected (Levels 1–4 focus). The API structure supports natural addition. No remediation needed now, but this should be the first concern when Level 5+ work begins.

---

### B.2 Authorization Predicate (I1: Pre-State Key Membership)

**Formal model invariant:**

```
∀ commit c, state s:
  valid(c, s) ⟹ signer(c).tmb ∈ active_keys(s)
```

**Finding: PASS**

Both implementations correctly enforce pre-state key membership:

- **Go** `VerifyTransaction` (verified*tx.go:56-58): `signerKey := p.Key(pay.Tmb)` looks up the key in the \_current* principal state. If the key doesn't exist, returns `ErrUnknownKey`. `applyTransactionInternal` (principal.go:479-490) additionally checks `p.IsKeyActive(tx.Signer)` for non-self-revoke transactions.
- **Rust** `apply_transaction_internal` (principal.rs:717-727): `!self.is_key_active(&tx.signer)` check precedes all match arms (except self-revoke). Returns `Error::UnknownKey` or `Error::KeyRevoked`.

Both correctly exempt self-revoke from the active-key check (a revoked key may sign its own revocation).

---

### B.3 AS Monotonicity (I2: Revocation Permanence)

**Formal model invariant:**

```
∀ k ∈ s.KS: k.rvk = Some(_) ⟹ k ∈ s'.KS ∧ k.rvk = Some(_)
```

**Finding: WARN — Partial enforcement**

Revocation moves keys from the active map to a separate revoked map in both implementations:

- **Go** `revokeKey` (principal.go:644-670): Removes from `auth.Keys`, sets `key.Revocation`, appends to `auth.Revoked`.
- **Rust** `revoke_key` (principal.rs:937-964): Removes from `auth.keys` via `shift_remove`, sets `key.revocation = Some(Revocation{...})`, inserts into `auth.revoked`.

No un-revoke path exists — revocations are permanent once applied. **However:**

> [!WARNING]
> **Neither `addKey` (Go) nor `add_key` (Rust) checks the revoked set.** A `key/create` transaction with the thumbprint of a previously revoked key would succeed, effectively re-adding a revoked key to the active set.
>
> - Go `addKey` (principal.go:580-604): Appends to `auth.Keys` without checking `auth.Revoked`.
> - Rust `add_key` (principal.rs:913-917): Inserts into `auth.keys` without checking `auth.revoked`.
> - The `DuplicateKey` check in `apply_transaction_internal` only checks the _active_ set, not the revoked set.

**SPEC analysis:** SPEC §6.2 (`key/delete`) explicitly says "Deleted keys can be re-added later (via `key/create`)." SPEC §6.4 (`key/revoke`) says revocation means "a key is compromised and should never be trusted again" — but does not explicitly prohibit re-adding the same thumbprint. Since thumbprints are derived from public key material, re-adding a revoked key would require possessing the same key pair, which is a contradictory scenario for a "compromised" key.

**Decision (confirmed by nrd):** Revoked keys are revoked for all time and must never be re-added. This is not a spec ambiguity — it is a correctness bug. Add a revoked-set check to `addKey`/`add_key` to reject `key/create` for any thumbprint present in the revoked set. Logged as **BUG-12** (P1).

---

### B.4 MHMR Computation Correctness

**SPEC requirement (§20.4–20.5):** Sort child digests lexicographically. Single child → implicit promotion (no hashing). Multiple children → concatenate sorted, hash with target algorithm H.

**Finding: PASS (partial verification)**

Both implementations have MHMR computation with correct structure:

- **Go** `ComputeKS` (state.go:290), `ComputeAS` (state.go:369), `ComputeCS` (state.go:405), `ComputePS` (state.go:440): All follow the pattern: collect digests, sort, MR or promote.
- **Rust** `compute_key_state`, `compute_auth_state`, `compute_commit_state`, `compute_principal_state`: Equivalent structure.
- **Implicit promotion** is tested: `TestComputeKS_ImplicitPromotion` (Go state_test.go:42) documents "SPEC §7.2: Single key, no nonce → KS = tmb."

**Cross-implementation parity** is enforced by shared golden fixtures (generated by Rust, consumed by Go). If MHMR diverged, golden tests would fail.

**Gap:** No explicit test for the MHMR cross-algorithm conversion case (SPEC §20.2) — where a child node's digest algorithm differs from the target H. This is the scenario BUG-7 (`ComputeCommitIDTagged`) addresses for Go.

---

### B.5 Implicit Promotion Handling

**SPEC requirement (§2.2.5, §9.1):** Single-component Merkle trees promote the lone value without hashing.

**Finding: PASS**

Both implementations correctly handle promotion:

- **Single-key KS:** `ComputeKS` / `compute_key_state` returns the thumbprint directly when one key is present.
- **Genesis CS:** When no commit exists, AS is promoted to CS (verified in genesis import paths).
- **Single-action DS:** Not testable — data actions are not implemented (see B.6).

Golden fixture parity enforces correct behavior across implementations.

---

### B.6 Data Action Implementation

**SPEC requirement (§6.7):** Stateless signed messages, no `pre`, ordered by `now`.

**Finding: NOT IMPLEMENTED**

No `data/create` or equivalent handling exists in either Go or Rust core. The `Action` type exists in both:

- **Go:** `Action` struct, `DataLedger` with `Actions` field.
- **Rust:** `Action` struct, `DataLedger` with minimal fields.

But no transaction dispatch handles data action types, no DS computation occurs, and no DS-related `TransactionKind` variants exist.

**API structural readiness:** MIXED

- **Rust:** The `TransactionKind` enum is a sum type — adding `DataCreate { ... }` would be natural. However, data actions are explicitly **not** transactions per SPEC ("Data actions are not transactions and do not mutate AS"). This means they may need a parallel path rather than being shoehorned into the transaction model. The existing `Action::from_pay` factory suggests this was considered.
- **Go:** `DataLedger` is exported (flagged in A.1 of the surface audit), suggesting it was intended for direct access. The `Action` type exists but has no `Apply` or `Verify` method.

**Key design question:** Should data actions share the transaction pipeline (verify → apply → commit) or have their own pipeline? SPEC says "no `pre`" and "no chain," which implies a separate path. The current API structure leans toward a separate path (Action vs Transaction types are distinct), which aligns with SPEC intent.

---

### B.7 Behavioral Bug Log

| ID     | Severity | Component | Description                                                                                                                                                                                                                                                 | Status |
| :----- | :------- | :-------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----- |
| BUG-12 | P1       | Go/Rust   | `addKey`/`add_key` does not check the revoked set — a `key/create` with a previously revoked thumbprint would succeed, violating I2 (revocation permanence). Confirmed: revoked keys must never be re-added. Add revoked-set check to both implementations. | Open   |

### B.8 Structural Readiness Summary

| Feature                  | Implementation Status | API Ready?      | Notes                                                                         |
| :----------------------- | :-------------------- | :-------------- | :---------------------------------------------------------------------------- |
| Lifecycle states         | Not implemented       | ✅ Yes          | Principal struct supports natural addition; Error enum has room for variants  |
| Lifecycle gating         | Not implemented       | ✅ Yes          | Guard checks at top of `apply_transaction_internal` would integrate naturally |
| Revoked key re-add guard | Not implemented       | ✅ Yes          | Single check in `addKey`/`add_key` — trivial to add                           |
| Data action pipeline     | Partially stubbed     | ⚠️ Needs design | Action types exist but pipeline is unclear (separate vs shared with tx)       |
| MHMR cross-algorithm     | Rust only             | ⚠️ Go gap       | Go needs `ComputeCommitIDTagged` (tracked as BUG-7)                           |

---

## Appendix C: Cross-Cutting Concerns

> **Scope:** Patterns visible only when viewing the complete audit holistically. These were not apparent during individual audit rounds but emerge from the interconnections between findings across phases, appendices, and the formal model. Each concern either connects multiple findings to a shared root cause, identifies a dependency ordering constraint for remediation, or surfaces a growth-trajectory risk.

### C.1 Encapsulation Failures Share a Root Cause

BUG-6 (`Variants()` leaks map ref), BUG-10 (`SetRaw()` mutator), BUG-11 (`Transactions()` leaks slice), BUG-12 (revoked key re-add), item 8 (exported `AuthLedger`/`DataLedger`), and item 19 (`Entry.Raw`) are all symptoms of one root cause: **Go's type system doesn't enforce ownership boundaries, and the codebase hasn't compensated with discipline-level guards at mutation points.**

A single encapsulation hardening pass addressing the root cause (unexport fields, defensive copies, guard checks at mutation points) would resolve six findings simultaneously rather than treating each as an independent fix.

### C.2 Go Error Types Are a Prerequisite for Lifecycle

Go uses `fmt.Errorf` in several places (BUG-4, items 9-10), producing unmatchable errors. The compound effect: **if consumers can't distinguish `ErrKeyRevoked` from `ErrUnknownKey` from `ErrTimestampPast` programmatically, then adding lifecycle error conditions (`ErrPrincipalFrozen`, `ErrPrincipalDeleted`) to the same system is meaningless.** Callers would have no way to react differently to lifecycle rejections vs. key rejections.

**Implication for remediation ordering:** Go error hardening (items 9-10, BUG-4) must precede lifecycle implementation (B.1). These are not independent workstreams.

### C.3 `pre` Verification Is Per-Arm — a Fragility

Both Go and Rust call `verifyPre`/`verify_pre` inside every match arm individually, not once before the dispatch. If someone adds a new `TransactionKind` variant and forgets the `verifyPre` call, **chain integrity breaks silently.**

Rust's exhaustive match mitigates this (the compiler forces handling new arms), but Go's switch doesn't — `TxOtherRevoke` (BUG-1) already demonstrates how dead arms accumulate without detection.

**Recommendation:** Hoist `pre` verification to a single check before the switch/match, with an explicit opt-out for naked self-revoke. This converts "every transaction validates `pre`" from a per-arm discipline to a structural invariant.

### C.4 Golden Fixtures Verify Parity, Not Spec Correctness

Go consumes golden fixtures generated by Rust (DEV-9). **Golden tests verify that Go and Rust produce the same answer — not that either answer is correct per SPEC.** If both implementations had the same MHMR computation bug (e.g., wrong sort order in an edge case), golden tests would pass.

**Recommendation:** Add a small set of hand-computed reference vectors — state trees computed manually from SPEC §9 and §20.5 — to provide a spec-anchored ground truth independent of either implementation.

### C.5 `TransactionKind` Design Divergence Compounds Over Time

Go uses bare `int` iota constants; Rust uses a proper enum with associated data. Each new transaction kind requires Go to update 3+ disconnected sites (constant, `String()`, switch case) with zero compiler enforcement. Rust adds one enum variant and the compiler catches every missing match.

As the protocol grows toward Level 5 (rules, freeze/unfreeze) and data actions, **Go's maintenance burden grows quadratically (sites × kinds) while Rust's grows linearly.** The current 6 Go variants are manageable; 12+ would not be. Go's `TransactionKind` design should be reconsidered before the kind count grows further.

### C.6 `latestTimestamp` Isn't Commit-Atomic

Both implementations update `latestTimestamp` inside `apply_transaction_internal`, which runs during commit assembly — **before** the commit is finalized. If a commit starts (transactions applied) but never finalizes (e.g., validation failure after partial application), `latestTimestamp` is already advanced. Subsequent transactions would be validated against a timestamp from an uncommitted state.

Rust's `CommitScope` partially mitigates this (scope controls the mutation boundary), but the timestamp lives on `Principal`, not the scope. Go's `CommitBatch` has the same exposure.

**This is a temporal atomicity hole** — distinct from the structural atomicity concern in C.2/D.10.

### C.7 Data Action Pipeline Decision Cascades Into Storage

The data action pipeline design (B.6: separate vs. shared with transactions) cascades into the storage layer. The storage layer's `Entry`, `Export`, and `Replay` functions are built around transactions. If data actions get a separate pipeline, they need parallel storage paths — which means storage audit findings (item 19 `Entry.Raw` mutability, item 20 non-atomic import, D.7 extractor asymmetry) must be solved for **two pipelines instead of one.**

**Implication for remediation ordering:** Settle the data action pipeline design before the storage hardening pass to avoid rework.

---

### C.8 Recommended Remediation Ordering

Based on the dependency graph above:

```
1. Go error hardening ──────────────────────┐
   (BUG-4, items 9-10)                      │
                                             ▼
2. Encapsulation pass ──────────── 3. Lifecycle implementation
   (BUG-6/10/11/12, items 8/19)      (B.1, when Level 5+ begins)

4. `pre` verification hoisting
   (C.3 — structural invariant)

5. Data action pipeline design ──── 6. Storage hardening
   (B.6 — architecture decision)       (items 19-20, D.7)

7. Hand-computed spec vectors
   (C.4 — independent of above)
```

Items 1-2 are prerequisites with downstream dependencies. Items 4 and 7 are independent and can be done in parallel. Items 5-6 are sequentially dependent on each other but independent of 1-3.
