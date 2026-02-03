# API Coherence Audit: Phase 0 & 1

**Date:** 2026-02-03
**Auditor:** Gemini (Antigravity) + Claude (review)
**Status:** In Progress

---

## Phase 0: Scope Definition

**Language Targets:**
| Language | Path | Version / Edition |
|:---------|:-----|:------------------|
| Go | `go/cyphrpass` | 1.21+ |
| Rust | `rs/cyphrpass` | 2021 Edition |
| Vectors | `tests/` | Language-agnostic |

**Entry Points:**

- **Go:** `github.com/Cyphrme/Cyphrpass/go/cyphrpass`
- **Rust:** `cyphrpass` crate (`rs/cyphrpass/src/lib.rs`)

**Exclusions:**

- `rs/cyphrpass-cli` (consumer, not core API)
- `rs/cyphrpass-storage` (Phase 2 audit candidate, separate concern)
- `go/storage` (same rationale as Rust)
- `fixture-gen`, `test-fixtures` (tooling, not protocol)
- Vendored dependencies

**Constraints:**

- **SPEC.md** is authoritative.
- **Semantic parity** between Go and Rust implementations.
- **Pre-1.0:** Breaking changes acceptable per `engineering.md §3`.

---

## Phase 1: Surface Discovery

### 1.1 Go Surface (`go/cyphrpass`)

#### State Types (SPEC §7)

| Type               | File           | Description                                 |
| :----------------- | :------------- | :------------------------------------------ |
| `KeyState`         | `state.go`     | Digest of active thumbprints (SPEC §7.2)    |
| `TransactionState` | `state.go`     | Merkle root of transaction czds (SPEC §7.3) |
| `AuthState`        | `state.go`     | `H(sort(KS, TS?, RS?))` (SPEC §7.5)         |
| `DataState`        | `state.go`     | Action digest via Cad (SPEC §7.4)           |
| `PrincipalState`   | `state.go`     | `H(sort(AS, DS?))` (SPEC §7.6)              |
| `PrincipalRoot`    | `state.go`     | Immutable first PS (SPEC §7.7)              |
| `HashAlg`          | `state.go`     | Hash algorithm enum (SHA-256/384/512)       |
| `Level`            | `principal.go` | Feature level enum (1–6)                    |

#### Principal API

| Item          | Signature                                                          | Notes                |
| :------------ | :----------------------------------------------------------------- | :------------------- |
| `Implicit`    | `(key *coz.Key) (*Principal, error)`                               | Level 1/2 genesis    |
| `Explicit`    | `(keys []*coz.Key) (*Principal, error)`                            | Level 3+ genesis     |
| **Accessors** | `PR()`, `PS()`, `AS()`, `KS()`, `DS()`, `TS()`                     | State getters        |
|               | `HashAlg()`, `ActiveAlgs()`, `Level()`                             | Algorithm/level info |
| **Key ops**   | `Key(tmb)`, `IsKeyActive(tmb)`, `ActiveKeys()`, `ActiveKeyCount()` | Key lookups          |
| **Mutation**  | `VerifyTransaction(cz, newKey) (*VerifiedTx, error)`               | Verify + parse       |
|               | `ApplyVerified(vt *VerifiedTx) error`                              | Apply verified tx    |
| **Actions**   | `RecordAction(action *Action) error`                               | Level 4+             |
|               | `ActionCount() int`, `Actions() []*Action`                         | Action accessors     |
| **History**   | `Transactions() []*Transaction`                                    | Transaction list     |
| **Config**    | `SetMaxClockSkew(seconds)`, `PreRevokeKey(tmb, rvk)`               | Test/config helpers  |

#### Transaction Types

| Type               | File             | Description                                                                                              |
| :----------------- | :--------------- | :------------------------------------------------------------------------------------------------------- |
| `Transaction`      | `transaction.go` | Parsed mutation (Kind, Signer, Pre, ID, Rvk, etc.)                                                       |
| `TransactionKind`  | `transaction.go` | Enum: `TxKeyCreate`, `TxKeyDelete`, `TxKeyReplace`, `TxSelfRevoke`, `TxOtherRevoke`, `TxPrincipalCreate` |
| `TransactionPay`   | `transaction.go` | JSON payload struct for parsing                                                                          |
| `ParseTransaction` | `transaction.go` | `(pay, czd) -> (*Transaction, error)`                                                                    |
| `VerifiedTx`       | `verified_tx.go` | Type-safe verified wrapper                                                                               |

#### Commit Types (SPEC §4.2.1)

| Type               | File        | Description                             |
| :----------------- | :---------- | :-------------------------------------- |
| `Commit`           | `commit.go` | Finalized atomic bundle                 |
| `PendingCommit`    | `commit.go` | In-progress commit builder              |
| `NewCommit`        | `commit.go` | Factory: `(txs, ts, as, ps) -> *Commit` |
| `NewPendingCommit` | `commit.go` | Factory: `(hashAlg) -> *PendingCommit`  |

#### Supporting Types

| Type              | File           | Description                                                     |
| :---------------- | :------------- | :-------------------------------------------------------------- |
| `Key`             | `key.go`       | Key wrapper with metadata (FirstSeen, LastUsed, Rvk, RevokedBy) |
| `Action`          | `action.go`    | Signed action for Level 4+                                      |
| `AuthLedger`      | `principal.go` | Keys + Transactions container                                   |
| `DataLedger`      | `principal.go` | Actions container                                               |
| `MultihashDigest` | `multihash.go` | Multi-algorithm digest bundle                                   |

#### Error Types (SPEC §17)

| Sentinel                                                                       | Category            |
| :----------------------------------------------------------------------------- | :------------------ |
| `ErrInvalidSignature`, `ErrUnknownKey`, `ErrInvalidPrior`                      | Transaction (§17.1) |
| `ErrTimestampPast`, `ErrTimestampFuture`, `ErrKeyRevoked`                      | Temporal            |
| `ErrMalformedPayload`, `ErrDuplicateKey`, `ErrThresholdNotMet`                 | Validation          |
| `ErrNoActiveKeys`, `ErrUnsupportedAlgorithm`                                   | Internal            |
| `ErrEmptyCommit`, `ErrMissingFinalizer`                                        | Commit lifecycle    |
| `ErrRecoveryNotDesignated`, `ErrAccountRecoverable`, `ErrAccountUnrecoverable` | Recovery (§17.2)    |
| `ErrStateMismatch`, `ErrChainBroken`, `ErrDerivationMismatch`                  | State (§17.3)       |
| `ErrUnauthorizedAction`                                                        | Action (§17.4)      |

---

### 1.2 Rust Surface (`rs/cyphrpass`)

#### State Types (SPEC §7)

| Type               | File       | Description                        |
| :----------------- | :--------- | :--------------------------------- |
| `KeyState`         | `state.rs` | Wraps `MultihashDigest`            |
| `TransactionState` | `state.rs` | Wraps `MultihashDigest`            |
| `AuthState`        | `state.rs` | Wraps `MultihashDigest`            |
| `DataState`        | `state.rs` | Wraps `Cad`                        |
| `PrincipalState`   | `state.rs` | Wraps `MultihashDigest`            |
| `PrincipalRoot`    | `state.rs` | Immutable; `from_initial(ps)`      |
| `HashAlg`          | `state.rs` | Enum: `Sha256`, `Sha384`, `Sha512` |

#### Principal API

| Item              | Signature                                                                   | Notes                 |
| :---------------- | :-------------------------------------------------------------------------- | :-------------------- |
| `implicit`        | `(key: Key) -> Result<Self>`                                                | Level 1/2 genesis     |
| `explicit`        | `(keys: Vec<Key>) -> Result<Self>`                                          | Level 3+ genesis      |
| `from_checkpoint` | `(pr, auth_state, keys) -> Result<Self>`                                    | Import/restore        |
| **Accessors**     | `pr()`, `ps()`, `auth_state()`, `key_state()`                               | State refs            |
|                   | `hash_alg()`, `active_algs()`                                               | Algorithm info        |
| **Key ops**       | `get_key(tmb)`, `is_key_active(tmb)`, `active_keys()`, `active_key_count()` | Key lookups           |
|                   | `active_keys_mut()`                                                         | Test helper (mutable) |

#### Transaction Types

| Type                  | File             | Description                                                                 |
| :-------------------- | :--------------- | :-------------------------------------------------------------------------- |
| `Transaction`         | `transaction.rs` | Parsed (internal); `from_pay(pay, czd, raw)`                                |
| `VerifiedTransaction` | `transaction.rs` | Type-safe verified wrapper                                                  |
| `TransactionKind`     | `transaction.rs` | Enum with embedded data: `KeyCreate { pre, id }`, `KeyRevoke { ... }`, etc. |

**Key difference:** Rust's `TransactionKind` uses enum variants with associated data; Go uses a flat struct with optional fields. Both are idiomatic.

#### Commit Types (SPEC §4.2.1)

| Type            | File        | Description                             |
| :-------------- | :---------- | :-------------------------------------- |
| `Commit`        | `commit.rs` | Finalized bundle                        |
| `PendingCommit` | `commit.rs` | Builder; `push(tx)`, `finalize(as, ps)` |

#### Supporting Types

| Type                       | File           | Description            |
| :------------------------- | :------------- | :--------------------- |
| `Key`                      | `key.rs`       | Key with metadata      |
| `Action`                   | `action.rs`    | Level 4+ action        |
| `AuthLedger`, `DataLedger` | `principal.rs` | Container types        |
| `MultihashDigest`          | `multihash.rs` | Multi-algorithm digest |

#### Error Types (SPEC §17)

| Variant                                                                                                       | Category           |
| :------------------------------------------------------------------------------------------------------------ | :----------------- |
| `InvalidSignature`, `UnknownKey`, `UnknownAlg`, `InvalidPrior`                                                | Transaction        |
| `TimestampPast`, `TimestampFuture`, `KeyRevoked`                                                              | Temporal           |
| `MalformedPayload`, `DuplicateKey`, `ThresholdNotMet`                                                         | Validation         |
| `NoActiveKeys`, `UnsupportedAlgorithm(String)`                                                                | Internal           |
| `CommitInProgress`, `NoPendingCommit`, `EmptyCommit`, `MissingFinalizationMarker`, `TransitoryStateReference` | Commit lifecycle   |
| `RecoveryNotDesignated`, `AccountRecoverable`, `UnrecoverablePrincipal`                                       | Recovery           |
| `StateMismatch`, `ChainBroken`, `HashAlgMismatch`                                                             | State              |
| `UnauthorizedAction`                                                                                          | Action             |
| `Coz(coz::Error)`                                                                                             | Wrapped dependency |

---

### 1.3 Go ↔ Rust Parity Summary

| Concept           | Go                        | Rust                   | Parity                       |
| :---------------- | :------------------------ | :--------------------- | :--------------------------- |
| Genesis factories | `Implicit`, `Explicit`    | `implicit`, `explicit` | ✓                            |
| Checkpoint import | —                         | `from_checkpoint`      | Rust-only                    |
| State accessors   | `PR()`, `AS()`, etc.      | `pr()`, `auth_state()` | ✓ (naming differs)           |
| Verified wrapper  | `VerifiedTx`              | `VerifiedTransaction`  | ✓                            |
| Commit model      | `Commit`, `PendingCommit` | Same                   | ✓                            |
| Error types       | Sentinel `var`            | `thiserror` enum       | ✓ (idiomatic)                |
| Level accessor    | `Level()`                 | —                      | Go-only? (verify in Phase 2) |

---

### 1.4 Test Surface (`tests/`)

| Directory        | Contents                                                                                                               | Count    |
| :--------------- | :--------------------------------------------------------------------------------------------------------------------- | :------- |
| `golden/`        | Pre-computed JSON fixtures (mutations, multi_key, algorithm_diversity, state_computation, edge_cases, actions, errors) | 41 tests |
| `e2e/`           | TOML intent files (round_trip, genesis_load, edge_cases, error_conditions)                                             | 19 tests |
| `intents/`       | Source TOML for fixture generation                                                                                     | —        |
| `keys/pool.toml` | Shared test key pool (ES256, ES384, Ed25519, RS256 for error testing)                                                  | 9 keys   |

**Coverage notes:**

- Levels 1–3 well covered; Level 4 (actions) partial.
- Algorithms: ES256, ES384, Ed25519 covered; ES512 not present.
- Genesis: Both implicit and explicit paths tested.
- Error rejection: 10 dedicated error tests in `golden/errors/`.

---

## Observations & Gaps

1. **`from_checkpoint`** exists in Rust but not Go. Needed for storage import parity?
2. **`Level()` accessor** in Go; confirm Rust equivalent (may be derived from key count + transactions).
3. **Storage crates** (`go/storage`, `rs/cyphrpass-storage`) excluded from Phase 1. Should Phase 2 include them?
4. **`TS()` accessor** on Principal: Go has it; Rust needs verification.
5. **Error naming:** Go uses `ErrKeyRevoked`; Rust uses `KeyRevoked`. Consistent with language idioms but worth documenting for cross-impl consumers.

---

## Checkpoint

**Ready to proceed to Phase 2: Iterative Component Audit.**

Proposed component order:

1. **Principals & Genesis** — Core identity creation
2. **State Types** — Merkle digests and multihash
3. **Transactions** — Parsing, verification, application
4. **Commits** — Atomic bundling
5. **Actions** — Level 4+ operations
6. **Errors** — SPEC §17 coverage

Please confirm or adjust before proceeding.

---

## Phase 2: Iterative Component Audit

---

### Component 1: Principal & Genesis

**Scope:** `Principal` struct, genesis factories (`Implicit`/`Explicit`), accessors, and state management in both Go and Rust.

#### Summary

The `Principal` is the core identity container. Both implementations follow similar patterns:

- Genesis via `Implicit` (single key, Level 1/2) or `Explicit` (multi-key, Level 3+)
- State computation: PR, PS, AS, KS, TS, DS
- Key operations: lookup, active check, add, remove, revoke
- Transaction application via `ApplyVerified` / `apply_verified`

#### Findings

| Dimension              | Go   | Rust | Notes                                                                                     |
| :--------------------- | :--- | :--- | :---------------------------------------------------------------------------------------- |
| **A. Minimal Surface** | PASS | PASS | Internal fields private; accessors expose only what's needed.                             |
| **B. Type Safety**     | WARN | PASS | Go uses `coz.B64` as thumbprint; Rust has dedicated `Thumbprint` newtype.                 |
| **C. Composability**   | PASS | PASS | Higher-level ops (`ApplyVerified`) compose lower primitives (`addKey`, `recomputeState`). |
| **D. Monosemicity**    | WARN | WARN | `from_checkpoint` exists only in Rust; Go may need equivalent for storage parity.         |
| **E. Naming**          | PASS | PASS | Consistent idioms: Go `PR()`, Rust `pr()`.                                                |
| **F. Error Handling**  | PASS | PASS | Both use domain-specific errors per SPEC §17.                                             |

#### Detailed Findings

##### B.1 [Go] Thumbprint uses `coz.B64` not domain type

**Issue:** Go represents thumbprints as `coz.B64` (a `[]byte` alias) rather than a dedicated newtype. This makes it possible to confuse thumbprints with other base64 values.

**Evidence:**

```go
// go/cyphrpass/principal.go:259
func (p *Principal) Key(tmb coz.B64) *Key {
    tmbStr := string(tmb.String())
    ...
}
```

**Rust counterpart:** Uses `coz::Thumbprint` newtype with dedicated semantics.

**Recommendation:** Consider introducing a `Thumbprint` type alias or wrapper in Go for clarity, though `coz.B64` is acceptable if the coz library standardizes on this.

**Severity:** Low — type aliases within the coz ecosystem are consistent; this is more a purity observation than a bug risk.

---

##### D.1 [Go ↔ Rust] `from_checkpoint` parity gap

**Issue:** Rust provides `Principal::from_checkpoint(pr, auth_state, keys)` for loading principals from trusted storage snapshots without replaying full history. Go lacks an equivalent.

**Evidence:**

```rust
// rs/cyphrpass/src/principal.rs:228-272
pub fn from_checkpoint(
    pr: PrincipalRoot,
    auth_state: AuthState,
    keys: Vec<Key>,
) -> Result<Self> { ... }
```

**Go:** No `FromCheckpoint` function; imports require replaying all transactions.

**Impact:** Storage layer in Rust can efficiently load from checkpoints; Go storage must use a different approach or replay.

**Recommendation:** Add `FromCheckpoint(pr PrincipalRoot, as AuthState, keys []*Key) (*Principal, error)` to Go for API parity.

---

##### D.2 [Rust] `Level` accessor exists; Go also has it

Both implementations provide `Level()` / `level()` accessors — confirmed parity.

---

##### A.1 [Both] Test-only helpers exposed

**Issue:** `PreRevokeKey` and `active_keys_mut` are public but intended for test setup.

**Evidence:**

- Go: `PreRevokeKey(tmb, rvk)` — panics if key not found
- Rust: `active_keys_mut()` — bypasses state recomputation

**Mitigation:** These are acceptable for test ergonomics but should be documented with `// Test helper` comments (Go) or `#[doc(hidden)]` (Rust) to signal non-public-API status.

---

##### C.1 [Both] Commit lifecycle coupling

**Observation:** Transaction application in both languages auto-begins commits if none is pending. This is convenient but couples `apply_verified` to commit lifecycle.

```rust
// rs/cyphrpass/src/principal.rs:727-729
if self.auth.pending.is_none() {
    self.auth.pending = Some(PendingCommit::new(self.hash_alg));
}
```

```go
// go/cyphrpass/principal.go:536-537
p.auth.Transactions = append(p.auth.Transactions, tx)
p.currentCommitCzds = append(p.currentCommitCzds, tx.Czd)
```

**Assessment:** PASS — the auto-commit behavior matches SPEC §4.2.1 for single-transaction commits while supporting multi-transaction bundles. Coherent design.

---

#### Recommended Changes

| ID       | Priority | Description                                                    |
| :------- | :------- | :------------------------------------------------------------- |
| **P2-1** | P2       | Add `FromCheckpoint` to Go for storage import parity.          |
| **P3-1** | P3       | Annotate `PreRevokeKey` / `active_keys_mut` as test-only.      |
| **P3-2** | P3       | Consider Go `Thumbprint` type alias for documentation clarity. |

---

#### Open Questions for User

1. **Checkpoint parity:** Should `FromCheckpoint` be added to Go, or will storage handle this differently?
2. **Test helper visibility:** Prefer `#[doc(hidden)]` or explicit `_test` naming?

---

**Checkpoint:** Awaiting user acknowledgment before proceeding to Component 2 (State Types).

---

### Component 2: State Types

**Scope:** `KeyState`, `TransactionState`, `AuthState`, `DataState`, `PrincipalState`, `PrincipalRoot`, `HashAlg`, `MultihashDigest`, and compute functions in Go and Rust per SPEC §7.

#### Summary

State types form the Merkle tree hierarchy that defines Principal identity:

```
PS = H(AS, DS?)
├── AS = H(KS, TS?, RS?)
│   ├── KS = H(tmb₀, tmb₁, ... , nonce?) or promoted
│   └── TS = H(czd₀, czd₁, ... , nonce?) or promoted
└── DS = H(action_czd₀, ... , nonce?) or promoted
```

Both implementations use `MultihashDigest` as the underlying storage, wrapping it in type-safe newtypes to prevent accidental mixing.

#### Findings

| Dimension              | Go   | Rust | Notes                                                                   |
| :--------------------- | :--- | :--- | :---------------------------------------------------------------------- |
| **A. Minimal Surface** | PASS | PASS | Compute functions expose minimal API; internal hashing hidden.          |
| **B. Type Safety**     | PASS | PASS | Distinct newtypes prevent mixing KS with TS, AS, etc.                   |
| **C. Composability**   | PASS | PASS | `ComputeAS(ks, ts, ...)` cleanly composes lower states.                 |
| **D. Monosemicity**    | PASS | PASS | Each compute function has one job; implicit promotion is explicit.      |
| **E. Naming**          | WARN | PASS | Go `GetOrFirst` vs Rust fallback-via-`or_else`; minor idiom difference. |
| **F. Error Handling**  | PASS | PASS | Rust panics in debug on empty variants; Go panics unconditionally.      |

#### Detailed Findings

##### B.1 [Both] Newtype wrapping is correct

Both languages wrap `MultihashDigest` in distinct types:

**Go:**

```go
type KeyState struct { MultihashDigest }
type TransactionState struct { MultihashDigest }
// etc.
```

**Rust:**

```rust
pub struct KeyState(pub MultihashDigest);
pub struct TransactionState(pub MultihashDigest);
// etc.
```

This prevents accidental assignment of `KeyState` to `AuthState`, enforcing the SPEC §7 hierarchy.

---

##### D.1 [Both] Implicit promotion semantics correct

Both implement SPEC §7.1 implicit promotion rules:

- Single key with no nonce: `KS = tmb` (no hashing)
- Single transaction with no nonce: `TS = czd`
- Only KS, no TS/RS/nonce: `AS = KS`
- Only AS, no DS/nonce: `PS = AS`

This is verified by unit tests in both languages (`full_promotion_chain`, `ks_single_key_promotion`).

---

##### E.1 [Go] `GetOrFirst` fallback method

**Observation:** Go exposes `GetOrFirst(alg)` as a convenience method for algorithm fallback.

```go
// go/cyphrpass/multihash.go:76
func (m MultihashDigest) GetOrFirst(alg HashAlg) coz.B64 {
    if d := m.Get(alg); d != nil { return d }
    return m.First()
}
```

**Rust:** Achieves the same with inline `or_else`:

```rust
ks.get(alg).or_else(|| ks.0.variants().values().next().map(AsRef::as_ref))
```

**Assessment:** Go's dedicated method is cleaner; Rust could benefit from a `get_or_first()` method for consistency. Minor ergonomic difference.

---

##### F.1 [Both] Panic on empty variants

**Go:**

```go
// go/cyphrpass/multihash.go:19-22
func NewMultihashDigest(variants map[HashAlg]coz.B64) MultihashDigest {
    if len(variants) == 0 {
        panic("MultihashDigest must have at least one variant")
    }
    ...
}
```

**Rust:**

```rust
// rs/cyphrpass/src/multihash.rs:42-46
pub fn new(variants: BTreeMap<HashAlg, Box<[u8]>>) -> Self {
    debug_assert!(
        !variants.is_empty(),
        "MultihashDigest must have at least one variant"
    );
    Self { variants }
}
```

**Discrepancy:** Go panics unconditionally; Rust panics only in debug builds.

**Risk:** In release builds, Rust could create an invalid `MultihashDigest` with no variants, leading to downstream panics on `First()`.

**Recommendation:** Rust should match Go's behavior and panic unconditionally, or return `Result` to force handling.

---

##### A.1 [Both] DataState uses single algorithm

**Observation:** Both implementations treat `DataState` as single-algorithm (not multi-variant):

**Go:**

```go
type DataState struct { digest coz.B64 }  // Not MultihashDigest
```

**Rust:**

```rust
pub struct DataState(pub Cad);  // Single Cad, not MultihashDigest
```

**Rationale:** Per the code comments, DataState follows the Rust implementation's design. Actions (Level 4+) are simpler and don't require algorithm agility for now.

**Assessment:** PASS — consistent design choice documented in both codebases.

---

##### B.2 [Rust] HashAlg re-exported from coz

**Observation:** Rust re-exports `HashAlg` from `coz`:

```rust
pub use coz::HashAlg;
```

**Go:** Defines its own `HashAlg` type alias:

```go
type HashAlg coz.HshAlg
```

**Assessment:** Both approaches work; Rust's re-export ensures single source of truth.

---

#### Recommended Changes

| ID       | Priority | Description                                                                                                    |
| :------- | :------- | :------------------------------------------------------------------------------------------------------------- |
| **S2-1** | P2       | Rust: Change `debug_assert!` to unconditional `assert!` in `MultihashDigest::new()` for safety parity with Go. |
| **S3-1** | P3       | Rust: Add `get_or_first()` method to `MultihashDigest` for API parity with Go.                                 |

---

**Checkpoint:** Awaiting user acknowledgment before proceeding to Component 3 (Transactions & Auth).

---

### Component 3: Transactions & Auth

**Scope:** `Transaction`, `TransactionKind`, `VerifiedTx`/`VerifiedTransaction`, parsing, verification, and application per SPEC §4.2 and §5.

#### Summary

Both implementations follow the "verify-then-apply" pattern:

1. Parse raw Coz message into `Transaction`
2. Verify signature → produce `VerifiedTx`/`VerifiedTransaction`
3. Apply verified transaction to Principal state

| Layer        | Go                              | Rust                         |
| :----------- | :------------------------------ | :--------------------------- |
| Parsing      | `ParseTransaction()`            | `Transaction::from_pay()`    |
| Verification | `Principal.VerifyTransaction()` | `verify_transaction()`       |
| Application  | `Principal.ApplyVerified()`     | `Principal.apply_verified()` |

#### Findings

| Dimension              | Go   | Rust | Notes                                                                 |
| :--------------------- | :--- | :--- | :-------------------------------------------------------------------- |
| **A. Minimal Surface** | PASS | PASS | Internal fields unexported; verification enforced via wrapper types.  |
| **B. Type Safety**     | WARN | PASS | Go `TransactionKind` is `int`; Rust uses sum type with embedded data. |
| **C. Composability**   | PASS | PASS | Clean `verify → apply` pipeline; `VerifiedTx` enforces flow.          |
| **D. Monosemicity**    | WARN | PASS | Rust removed other-revoke; Go still has `TxOtherRevoke` variant.      |
| **E. Naming**          | PASS | PASS | Consistent: `Czd`, `is_finalizer`/`IsCommit`, `signer`/`Signer`.      |
| **F. Error Handling**  | PASS | PASS | Both return structured errors from §17.                               |

#### Detailed Findings

##### B.1 [Go ↔ Rust] TransactionKind representation

**Go:** Uses `iota`-based enum; transaction data stored separately in `Transaction` struct:

```go
type TransactionKind int
const (
    TxKeyCreate TransactionKind = iota
    TxKeyDelete
    TxKeyReplace
    TxSelfRevoke
    TxOtherRevoke  // ← still present
    TxPrincipalCreate
)
```

**Rust:** Uses algebraic enum with embedded data:

```rust
pub enum TransactionKind {
    KeyCreate { pre: AuthState, id: Thumbprint },
    KeyDelete { pre: AuthState, id: Thumbprint },
    KeyReplace { pre: AuthState, id: Thumbprint },
    SelfRevoke { rvk: i64 },
    PrincipalCreate { pre: AuthState, id: AuthState },
    // No OtherRevoke - removed per directive
}
```

**Assessment:** Rust's approach is more type-safe (data co-located with variant). Go's approach requires discipline to ensure `Pre`/`ID` fields are set correctly per kind.

**Severity:** Medium — functional parity exists, but Go's design is more error-prone.

---

##### D.1 [Go] OtherRevoke variant exists; Rust removed it

**Issue:** Go still has `TxOtherRevoke` for revoking another key's thumbprint. Rust explicitly removed other-revoke per "zami's directive" (see comment in `parse_kind`).

**Evidence:**

```go
// Go: transaction.go:27-28
TxSelfRevoke
TxOtherRevoke
```

```rust
// Rust: transaction.rs:199-202
// All key/revoke transactions are self-revoke (SPEC §4.2.4)
// Other-revoke was removed per zami's directive
Ok(TransactionKind::SelfRevoke { rvk })
```

**Impact:** Go implementation can process other-revoke transactions that Rust would reject as malformed (or silently treat as self-revoke).

**Recommendation:** Align implementations — either:

1. Remove `TxOtherRevoke` from Go, or
2. Document the intentional divergence and update Rust if other-revoke is needed

---

##### A.1 [Both] VerifiedTx/VerifiedTransaction enforces verify-before-apply

Both languages use newtype wrappers to enforce that only verified transactions can be applied:

**Go:**

```go
type VerifiedTx struct {
    tx     *Transaction // unexported
    signer *Key
    newKey *coz.Key
}
// Can only be created via Principal.VerifyTransaction()
```

**Rust:**

```rust
pub struct VerifiedTransaction {
    tx: Transaction,  // private field
    new_key: Option<Key>,
}
// Can only be created via verify_transaction()
// #[cfg(test)] from_transaction_unsafe() for testing
```

**Assessment:** PASS — excellent use of the type system to prevent logic errors.

---

##### E.1 [Both] Commit finalization flag

Both implementations correctly parse and propagate the `commit` field:

| Language | Field             | Accessor            |
| :------- | :---------------- | :------------------ |
| Go       | `tx.IsCommit`     | `vt.IsCommit()`     |
| Rust     | `tx.is_finalizer` | `tx.is_finalizer()` |

**Assessment:** PASS — naming differs slightly but semantics match SPEC §4.2.1.

---

##### B.2 [Both] Raw message preservation for storage

Both store the original Coz message for bit-perfect round-trips:

**Go:**

```go
tx.Raw = rawEntry  // json.RawMessage
```

**Rust:**

```rust
tx.raw: coz::CozJson  // Preserves pay + sig
```

**Assessment:** PASS — essential for storage export/import parity.

---

##### F.1 [Go ↔ Rust] Algorithm inference from digest length

Both implementations infer hash algorithm from the `pre` field's byte length:

```rust
// Rust: transaction.rs:230-234
let alg = match pre_bytes.len() {
    32 => HashAlg::Sha256,
    48 => HashAlg::Sha384,
    64 => HashAlg::Sha512,
    _ => return Err(Error::MalformedPayload),
};
```

**Go:** Hardcodes SHA-256 assumption:

```go
// Go: transaction.go:189
tx.Pre = AuthState{FromSingleDigest(HashSha256, preBytes)}
```

**Discrepancy:** Go assumes all `pre` fields are SHA-256; Rust infers from length.

**Impact:** Go will misinterpret SHA-384 or SHA-512 `pre` values as SHA-256 digests.

**Recommendation:** Update Go to match Rust's length-based inference.

---

##### F.2 [Go] `typ` parsing is brittle and untested

**Issue:** `transaction.go:208` `typSuffix` logic splits at the _first_ slash:

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

If `typ` is `cyphr.me/cyphrpass/key/create` (namespaced per SPEC), this returns `cyphrpass/key/create`, which fails the switch statement expectation of `key/create`.

**Impact:** Go implementation fails to parse valid namespaced transactions. This is a critical correctness failure. Code path appears untested (tests use manual struct construction).

**Fix:** Use `strings.HasSuffix` (like Rust's `ends_with`) or proper URN parsing.

---

#### Recommended Changes

| ID       | Priority | Description                                                                        |
| :------- | :------- | :--------------------------------------------------------------------------------- |
| **T1-1** | P1       | Go: Implement length-based hash algorithm inference in `parsePre()` to match Rust. |
| **T1-2** | P1       | Go: Fix `typ` parsing to handle namespaced URIs (use `HasSuffix`). Add unit tests. |
| **T2-1** | P2       | Align on other-revoke: either remove from Go or add to Rust.                       |
| **T3-1** | P3       | Consider refactoring Go `TransactionKind` to carry embedded data (larger lift).    |

---

**Checkpoint:** Awaiting user acknowledgment before proceeding to Component 4 (Commits).

---

### Component 4: Commits

**Scope:** `Commit`, `PendingCommit`, commit finalization, and TS computation per SPEC §4.2.1.

#### Summary

Both implementations model the atomic commit lifecycle:

1. `PendingCommit::new()` — start building a bundle
2. `push(tx)` — add transactions (returns `true` when finalizer seen)
3. `finalize(as, ps)` → `Commit` — freeze with computed states

| Concept             | Go                          | Rust                         |
| :------------------ | :-------------------------- | :--------------------------- |
| Finalized commit    | `*Commit`                   | `Commit` (owned)             |
| Pending commit      | `*PendingCommit`            | `PendingCommit`              |
| Transaction storage | `[]*Transaction`            | `Vec<VerifiedTransaction>`   |
| TS computation      | `PendingCommit.ComputeTS()` | `PendingCommit.compute_ts()` |

#### Findings

| Dimension              | Go   | Rust | Notes                                                        |
| :--------------------- | :--- | :--- | :----------------------------------------------------------- |
| **A. Minimal Surface** | PASS | PASS | Internal fields private; accessors expose read-only views.   |
| **B. Type Safety**     | WARN | PASS | Go stores `*Transaction`; Rust stores `VerifiedTransaction`. |
| **C. Composability**   | PASS | PASS | `push → finalize` pipeline is clean.                         |
| **D. Monosemicity**    | PASS | PASS | Single purpose per method.                                   |
| **E. Naming**          | PASS | PASS | Consistent: `TS()`, `ts()`, `IsEmpty()`, `is_empty()`.       |
| **F. Error Handling**  | WARN | WARN | Rust returns `Option`; Go returns `error`. Inconsistent.     |

#### Detailed Findings

##### B.1 [Go ↔ Rust] Transaction type in Commit

**Go:** Stores raw `*Transaction`:

```go
type Commit struct {
    transactions []*Transaction
    // ...
}
```

**Rust:** Stores `VerifiedTransaction`:

```rust
pub struct Commit {
    transactions: Vec<VerifiedTransaction>,
    // ...
}
```

**Impact:** Go's `Commit` could theoretically contain unverified transactions if constructed improperly (though `NewCommit` is not public). Rust enforces verification at the type level.

**Assessment:** Rust is more type-safe. Go relies on convention — acceptable given the private constructor.

---

##### F.1 [Go ↔ Rust] Error handling in finalize

**Go:** Returns structured errors:

```go
func (p *PendingCommit) Finalize(...) (*Commit, error) {
    if len(p.transactions) == 0 {
        return nil, ErrEmptyCommit
    }
    if !last.IsCommit {
        return nil, ErrMissingFinalizer
    }
    // ...
}
```

**Rust:** Returns `Option`:

```rust
pub fn finalize(self, ...) -> Option<Commit> {
    if self.transactions.is_empty() { return None; }
    if !last.is_finalizer() { return None; }
    // ...
}
```

**Discrepancy:** Go distinguishes between "empty commit" and "missing finalizer" errors; Rust collapses both into `None`.

**Recommendation:** Rust could return `Result<Commit, CommitError>` for richer diagnostics. Low priority since callers typically know why finalization failed based on prior state.

---

##### A.1 [Go] Raw JSON storage for commits

Go explicitly stores raw JSON for storage round-trips:

```go
type Commit struct {
    raw []json.RawMessage
}

func (c *Commit) SetRaw(raw []json.RawMessage) { c.raw = raw }
```

Rust stores the raw bytes inside each `VerifiedTransaction.raw` field instead.

**Assessment:** Both approaches work; Rust's is more encapsulated.

---

##### D.1 [Both] Commit TS is per-commit, not cumulative

Both correctly implement SPEC §4.2.1:

> "TS = MR(sort(czd₀, czd₁, ...)) for transactions in THIS commit only"

```go
// Go: commit.go:136-144
func (p *PendingCommit) ComputeTS() (*TransactionState, error) {
    czds := make([]coz.B64, len(p.transactions))
    for i, tx := range p.transactions {
        czds[i] = tx.Czd
    }
    return ComputeTS(czds, nil, []HashAlg{p.hashAlg})
}
```

```rust
// Rust: commit.rs:147-153
pub fn compute_ts(&self) -> Option<TransactionState> {
    let czds: Vec<&coz::Czd> = self.transactions.iter().map(|t| t.czd()).collect();
    compute_ts(&czds, None, &[self.hash_alg])
}
```

**Assessment:** PASS — both are correct per spec.

---

##### E.1 [Both] Constructor panic on empty

**Go:** Panics unconditionally:

```go
func NewCommit(...) *Commit {
    if len(txs) == 0 {
        panic("Commit must contain at least one transaction")
    }
}
```

**Rust:** Uses `debug_assert!`:

```rust
pub(crate) fn new(...) -> Self {
    debug_assert!(!transactions.is_empty(), ...);
}
```

**Discrepancy:** Same pattern as `MultihashDigest::new()` — Rust only panics in debug.

**Recommendation:** Already captured in S2-1; applies here too.

---

#### Recommended Changes

| ID       | Priority | Description                                                                      |
| :------- | :------- | :------------------------------------------------------------------------------- |
| **C4-1** | P3       | Rust: Consider `Result` return for `finalize()` to distinguish error cases.      |
| **C4-2** | P3       | Apply S2-1 pattern: use `assert!` instead of `debug_assert!` in `Commit::new()`. |

---

**Checkpoint:** Awaiting user acknowledgment before proceeding to Component 5 (Actions).

---

### Component 5: Actions (Level 4 Data State)

**Scope:** `go/cyphrpass/action.go` vs `rs/cyphrpass/src/action.rs`. Handling of signed user actions stored in Data State (DS).

#### Summary

Actions are stateless signed Coz messages.

| Feature       | Go              | Rust                                        | Notes                                    |
| :------------ | :-------------- | :------------------------------------------ | :--------------------------------------- |
| **Structure** | `Action` struct | `Action` struct                             | Rust includes full `Pay`, Go only `Raw`. |
| **Parsing**   | `ParseAction`   | `Action::from_pay`                          | Go validates minimal fields.             |
| **Accessors** | `Typ`, `Signer` | `typ()`, `signer()`, `msg()`, `get_field()` | Rust exposes payload content.            |

#### Findings

##### A.1 [Go] Opaque Action API

**Issue:** Go's `Action` struct discards the parsed `coz.Pay` object, retaining only specific metadata (`Typ`, `Signer`, `Now`, `Czd`) and the `Raw` JSON.

```go
type Action struct {
    Typ    string
    Signer coz.B64
    Now    int64
    Czd    coz.B64
    Raw    json.RawMessage
}
```

There is no way to access the actual content of the action (e.g., `msg` field for comments) without re-parsing `Raw` manually.

**Rust:** Retains `pay: Pay` and provides `msg()` and `get_field()` accessors.

**Recommendation:** Add `Pay *coz.Pay` to Go struct or provide accessor methods to retrieve content.

---

#### Recommended Changes

| ID       | Priority | Description                                                                        |
| :------- | :------- | :--------------------------------------------------------------------------------- |
| **A5-1** | P3       | Go: Add accessors or exposed `Pay` field to `Action` struct for content retrieval. |

---

**Checkpoint:** Awaiting user acknowledgment before proceeding to Component 6 (Errors & Cross-Cutting).

---

### Component 6: Errors & Cross-Cutting Patterns

**Scope:** Error types, error taxonomy per SPEC §17, and cross-cutting patterns across both implementations.

#### Summary

Both implementations define structured error types aligned with SPEC §17:

| Category           | Go                                           | Rust                                                     |
| :----------------- | :------------------------------------------- | :------------------------------------------------------- |
| Transaction errors | `ErrInvalidSignature`, `ErrUnknownKey`, etc. | `Error::InvalidSignature`, `Error::UnknownKey`, etc.     |
| Recovery errors    | `ErrRecoveryNotDesignated`, etc.             | `Error::RecoveryNotDesignated`, etc.                     |
| State errors       | `ErrStateMismatch`, etc.                     | `Error::StateMismatch`, etc.                             |
| Commit errors      | `ErrEmptyCommit`, `ErrMissingFinalizer`      | `Error::EmptyCommit`, `Error::MissingFinalizationMarker` |

#### Findings

| Dimension              | Go   | Rust | Notes                                                   |
| :--------------------- | :--- | :--- | :------------------------------------------------------ |
| **A. Minimal Surface** | PASS | PASS | Both expose only necessary error types.                 |
| **B. Type Safety**     | PASS | PASS | Go uses sentinel errors; Rust uses `thiserror` enum.    |
| **C. Composability**   | PASS | PASS | Rust has `From<coz::Error>`; Go uses separate wrapping. |
| **D. Monosemicity**    | WARN | PASS | Go comments reference §14; should be §17.               |
| **E. Naming**          | WARN | PASS | Minor naming variances (see below).                     |
| **F. Error Handling**  | PASS | PASS | Both provide clear error messages.                      |

#### Detailed Findings

##### D.1 [Go] SPEC section reference incorrect

**Issue:** Go error comments reference §14 instead of §17:

```go
// Transaction errors (SPEC §14.1)  // ← Should be §17.1
var (
    ErrInvalidSignature = ...
```

```rust
// Correct in Rust:
/// Cyphrpass error type covering all error conditions from SPEC §17.
#[derive(Debug, Error)]
pub enum Error { ... }
```

**Recommendation:** Update Go comments to reference §17.

---

##### E.1 [Go ↔ Rust] Naming variances

| Concept               | Go                        | Rust                               |
| :-------------------- | :------------------------ | :--------------------------------- |
| Missing finalizer     | `ErrMissingFinalizer`     | `Error::MissingFinalizationMarker` |
| Account unrecoverable | `ErrAccountUnrecoverable` | `Error::UnrecoverablePrincipal`    |
| Hash mismatch         | `ErrDerivationMismatch`   | `Error::HashAlgMismatch`           |

**Assessment:** Minor — semantically equivalent but inconsistent naming.

---

##### B.1 [Rust] Error enum with `From` trait

Rust provides automatic conversion from `coz::Error`:

```rust
/// Underlying Coz error.
#[error("coz: {0}")]
Coz(#[from] coz::Error),
```

Go handles coz errors differently (typically wrapping in domain errors).

**Assessment:** PASS — idiomatic difference.

---

##### A.1 [Rust] Extra error variants

Rust has additional error variants not present in Go:

| Rust                              | Go Equivalent |
| :-------------------------------- | :------------ |
| `Error::UnknownAlg`               | Not present   |
| `Error::CommitInProgress`         | Not present   |
| `Error::NoPendingCommit`          | Not present   |
| `Error::TransitoryStateReference` | Not present   |

**Assessment:** Rust is more complete. These may be needed in Go depending on commit lifecycle implementation.

---

#### Cross-Cutting Patterns Summary

From Components 1-5, here are the recurring cross-cutting patterns:

| Pattern                   | Go                      | Rust                       | Recommendation                          |
| :------------------------ | :---------------------- | :------------------------- | :-------------------------------------- |
| Empty invariant checks    | Unconditional panic     | `debug_assert!`            | Rust → `assert!` (S2-1)                 |
| Hash algorithm inference  | Hardcoded SHA-256       | Length-based inference     | Go → length-based (T1-1)                |
| Other-revoke support      | Present                 | Removed                    | Align (T2-1)                            |
| Verified transaction type | Uses raw `*Transaction` | Uses `VerifiedTransaction` | Go acceptable with private constructors |
| Error taxonomy            | §14 references          | §17 references             | Update Go comments                      |

---

#### Recommended Changes

| ID       | Priority | Description                                                                          |
| :------- | :------- | :----------------------------------------------------------------------------------- |
| **E5-1** | P3       | Go: Update error comments to reference SPEC §17 instead of §14.                      |
| **E5-2** | P3       | Align error naming: `MissingFinalizer` vs `MissingFinalizationMarker`.               |
| **E5-3** | P3       | Go: Consider adding `ErrCommitInProgress`, `ErrTransitoryStateReference` for parity. |

---

## Phase 2 Summary

All iterative component audits are complete. Here is the consolidated recommendation table:

| ID       | Priority | Component   | Description                                                            |
| :------- | :------- | :---------- | :--------------------------------------------------------------------- |
| **T1-1** | P1       | Transaction | Go: Implement length-based hash algorithm inference in `parsePre()`.   |
| **S2-1** | P2       | State       | Rust: Change `debug_assert!` to `assert!` in `MultihashDigest::new()`. |
| **T2-1** | P2       | Transaction | Align other-revoke support between Go and Rust.                        |
| **P1-1** | P2       | Principal   | Go: Add `FromCheckpoint` for storage import parity with Rust.          |
| **S3-1** | P3       | State       | Rust: Add `get_or_first()` method to `MultihashDigest`.                |
| **C4-1** | P3       | Commit      | Rust: Consider `Result` return for `finalize()`.                       |
| **C4-2** | P3       | Commit      | Apply S2-1 pattern to `Commit::new()`.                                 |
| **E5-1** | P3       | Errors      | Go: Update SPEC section references from §14 to §17.                    |
| **E5-2** | P3       | Errors      | Align error naming conventions.                                        |
| **E5-3** | P3       | Errors      | Go: Add missing commit lifecycle error variants.                       |
| **P1-2** | P3       | Principal   | Annotate test helpers with visibility markers.                         |
| **T3-1** | P3       | Transaction | Consider refactoring Go `TransactionKind` to embedded data.            |
| **A5-1** | P3       | Actions     | Go: Add methods/fields to `Action` to access payload content.          |
| **T1-2** | P1       | Transaction | Go: Fix brittle `typ` parsing to support namespaced URIs.              |

---

**Checkpoint:** Phase 2 complete. Awaiting user acknowledgment before proceeding to Phase 3 (Cross-Cutting Analysis) or Phase 4 (Remediation Planning).

---

# Phase 3: Cross-Cutting Analysis

## 3.1 Consistency Audit

### Naming Convention Adherence

| Pattern           | Go                                      | Rust                            | Consistent?    |
| :---------------- | :-------------------------------------- | :------------------------------ | :------------- |
| Type names        | PascalCase (`KeyState`)                 | PascalCase (`KeyState`)         | ✅             |
| Function names    | PascalCase exported (`ComputeKS`)       | snake_case (`compute_ks`)       | ✅ (idiomatic) |
| Constants         | PascalCase (`TypKeyCreate`)             | SCREAMING_SNAKE in `mod typ`    | ✅ (idiomatic) |
| Error names       | `Err` prefix (`ErrInvalidSignature`)    | `Error::` variants              | ✅ (idiomatic) |
| Accessor methods  | Direct name (`PR()`, `PS()`)            | snake_case (`pr()`, `ps()`)     | ✅ (idiomatic) |
| Boolean accessors | `Is` prefix (`IsCommit()`, `IsEmpty()`) | `is_` prefix (`is_finalizer()`) | ✅ (idiomatic) |

**Semantic Naming Consistency:**

| Concept                      | Go               | Rust                   | Aligned?               |
| :--------------------------- | :--------------- | :--------------------- | :--------------------- |
| Genesis factory (single key) | `Implicit(key)`  | `implicit(key)`        | ✅                     |
| Genesis factory (multi-key)  | `Explicit(keys)` | `explicit(keys)`       | ✅                     |
| Checkpoint restore           | _Not present_    | `from_checkpoint(...)` | ❌ Gap                 |
| Auth State accessor          | `AS()`           | `auth_state()`         | ⚠️ Minor (Go is terse) |
| Transaction finalization     | `IsCommit`       | `is_finalizer`         | ⚠️ Minor semantic      |

---

### Error Handling Strategy

| Pattern         | Go                           | Rust                     | Notes                 |
| :-------------- | :--------------------------- | :----------------------- | :-------------------- |
| Error taxonomy  | SPEC §17 (documented as §14) | SPEC §17                 | ✅ (Go needs doc fix) |
| Error chaining  | `fmt.Errorf("%w")`           | `#[from]` with thiserror | ✅                    |
| Sentinel errors | `var Err* = errors.New()`    | `Error::*` enum variants | ✅ (idiomatic)        |
| Panic policy    | Unconditional on invariant   | `debug_assert!` only     | ❌ Discrepancy (S2-1) |
| Result types    | `(T, error)` tuple           | `Result<T, Error>`       | ✅ (idiomatic)        |

---

### Common Pattern Uniformity

| Pattern               | Go Usage                                       | Rust Usage                                 | Uniform?       |
| :-------------------- | :--------------------------------------------- | :----------------------------------------- | :------------- |
| Builder pattern       | `PendingCommit.Push().Finalize()`              | `PendingCommit.push().finalize()`          | ✅             |
| Newtype wrappers      | Struct embedding (`KeyState{MultihashDigest}`) | Tuple struct (`KeyState(MultihashDigest)`) | ✅             |
| Verified wrapper type | `VerifiedTx`                                   | `VerifiedTransaction`                      | ⚠️ Name length |
| Raw preservation      | `json.RawMessage` field                        | `CozJson` field in tx                      | ✅             |
| Implicit promotion    | Implemented per SPEC §7                        | Implemented per SPEC §7                    | ✅             |

---

## 3.2 Layering Audit

### Dependency Direction

```
┌───────────────────────────────────────────────────────┐
│                     External Users                     │
└───────────────────────────────────────────────────────┘
                          │
                          ▼
┌───────────────────────────────────────────────────────┐
│              Principal (top-level API)                 │
│   - Genesis factories (implicit/explicit)              │
│   - State accessors (PR, PS, AS, KS, DS, TS)          │
│   - Transaction verification + application            │
└───────────────────────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Transaction │  │    Commit    │  │    State     │
│              │  │              │  │              │
│ - Parse      │  │ - Pending    │  │ - KS, TS, AS │
│ - Verify     │  │ - Finalize   │  │ - DS, PS, PR │
│ - Apply      │  │ - TS compute │  │ - MultihashD │
└──────────────┘  └──────────────┘  └──────────────┘
          │               │               │
          └───────────────┼───────────────┘
                          ▼
┌───────────────────────────────────────────────────────┐
│                   Key / Error / Coz                    │
│   - Key struct with metadata                           │
│   - Error taxonomy (SPEC §17)                          │
│   - Coz integration (signing, verification)            │
└───────────────────────────────────────────────────────┘
```

**Findings:**

| Check                              | Status  | Notes                                           |
| :--------------------------------- | :------ | :---------------------------------------------- |
| Lower layers don't import higher   | ✅ PASS | No circular dependencies                        |
| Abstractions at appropriate levels | ✅ PASS | `Principal` → `State` → `Coz` layering is clean |
| No leaky abstractions              | ✅ PASS | Internal compute functions not exported         |
| Single responsibility              | ✅ PASS | Each module has focused purpose                 |

---

### Module Cohesion

| Module        | Primary Responsibility             | Cohesion |
| :------------ | :--------------------------------- | :------- |
| `principal`   | Identity container lifecycle       | HIGH     |
| `state`       | Merkle tree state computation      | HIGH     |
| `transaction` | Auth mutation parsing/verification | HIGH     |
| `commit`      | Atomic bundle lifecycle            | HIGH     |
| `key`         | Key metadata wrapper               | HIGH     |
| `error`       | Domain error taxonomy              | HIGH     |
| `multihash`   | Algorithm-agnostic digest          | HIGH     |

---

## 3.3 Coherence Scoring

| Criterion               | Go Score  | Rust Score | Notes                                    |
| :---------------------- | :-------: | :--------: | :--------------------------------------- |
| **A. Minimal Surface**  |    4/5    |    5/5     | Go exposes test helpers publicly         |
| **B. Type Safety**      |    4/5    |    5/5     | Go uses `int` enum vs Rust ADT           |
| **C. Composability**    |    5/5    |    5/5     | Clean verify→apply pipelines             |
| **D. Monosemicity**     |    4/5    |    5/5     | Go has orphan `TxOtherRevoke`            |
| **E. Naming Coherence** |    4/5    |    5/5     | Minor variances in error names           |
| **F. Error Handling**   |    4/5    |    4/5     | Rust `Option` on finalize                |
| **Overall**             | **4.2/5** | **4.8/5**  | Both strong; Rust slightly more polished |

---

## Cross-Cutting Recommendations

| ID     | Priority | Scope | Description                                                   |
| :----- | :------- | :---- | :------------------------------------------------------------ |
| **X1** | P2       | Go    | Add `FromCheckpoint` for parity with Rust                     |
| **X2** | P2       | Rust  | Use `assert!` instead of `debug_assert!` for invariants       |
| **X3** | P2       | Both  | Align `TxOtherRevoke` — remove from Go or document divergence |
| **X4** | P3       | Go    | Update error doc comments (§14 → §17)                         |
| **X5** | P3       | Go    | Implement length-based hash algorithm inference               |
| **X6** | P3       | Both  | Align naming: `VerifiedTx` ↔ `VerifiedTransaction`           |

---

**Checkpoint:** Phase 2 complete. Awaiting user acknowledgment before proceeding to Phase 3 (Cross-Cutting Analysis) or Phase 4 (Remediation Planning).

---

# Phase 3: Cross-Cutting Analysis (Revised)

> **Clarification:** Phase 3 examines **internal coherence within each implementation**, looking for boundary violations, naming drift, and pattern inconsistencies within a single codebase—not cross-implementation comparison.

---

## 3A: Go Internal Coherence Audit

**Scope:** All 14 files in `go/cyphrpass/` (~45KB source)

### Naming Consistency

| Pattern                          | Adherence | Notes                                                                 |
| :------------------------------- | :-------: | :-------------------------------------------------------------------- |
| Exported types: PascalCase       |    ✅     | `KeyState`, `Principal`, `Transaction`                                |
| Methods without `Get` prefix     |    ✅     | `PR()`, `PS()`, `AS()` — idiomatic                                    |
| Boolean predicates: `Is*` prefix |    ✅     | `IsActive()`, `IsKeyActive()`, `IsEmpty()`, `IsCommit()`              |
| Constructor naming: `New*`       |    ✅     | `NewCommit`, `NewPendingCommit`, `NewMultihashDigest`, `NewDataState` |
| Factory naming: direct name      |    ✅     | `Implicit()`, `Explicit()`, `ParseTransaction()`, `ParseAction()`     |

**Finding G1:** Accessor methods use terse abbreviations (`PR()`, `PS()`, `AS()`, `KS()`, `DS()`, `TS()`). This is internally consistent but requires domain knowledge. No action needed—documented in SPEC §7.

---

### Error Handling Patterns

| Pattern                                     |      Usage      | Notes                               |
| :------------------------------------------ | :-------------: | :---------------------------------- |
| Sentinel errors (`var Err* = errors.New()`) | ✅ 14 sentinels | Consistent taxonomy                 |
| Error wrapping (`fmt.Errorf("%w")`)         |     0 uses      | Not needed—errors are at boundaries |
| Returning naked `nil`, `error`              |       ✅        | Idiomatic Go style                  |

**Finding G2:** All errors are defined in `error.go` as sentinels. No ad-hoc errors created inline. This is excellent for error matching and debugging.

**Finding G3:** The error file references SPEC §14 instead of §17. This is a documentation bug (captured as E5-1).

---

### Panic Policy

| Location           | Reason                | Assessment     |
| :----------------- | :-------------------- | :------------- |
| `multihash.go:20`  | Empty variants        | ✅ Invariant   |
| `commit.go:34`     | Empty commit          | ✅ Invariant   |
| `principal.go:302` | Key not in active set | ⚠️ Test helper |
| `state_test.go:16` | Test setup            | ✅ Test code   |

**Finding G4:** Three production panics all guard constructor invariants. `PreRevokeKey` panic in `principal.go:302` is reasonable—it's a test helper that would indicate test setup error.

---

### Layer Violation Check

**Import graph analysis:**

| File             | External Imports               | Internal Imports |
| :--------------- | :----------------------------- | :--------------- |
| `error.go`       | `errors`                       | —                |
| `key.go`         | `coz`                          | —                |
| `multihash.go`   | `coz`, `sort`                  | —                |
| `state.go`       | `coz`, `crypto/*`, `sort`      | —                |
| `action.go`      | `coz`, `encoding/json`         | —                |
| `transaction.go` | `coz`, `encoding/json`         | —                |
| `commit.go`      | `encoding/json`                | —                |
| `verified_tx.go` | `coz`, `encoding/json`, `time` | —                |
| `principal.go`   | `coz`, `time`                  | —                |

**Finding G5:** No internal package imports—all files are in the same flat package. No circular dependencies possible by design. Clean layering via call graph (Principal → Transaction → State → Coz).

---

### Pattern Uniformity

| Pattern                            | Files Using                                | Consistent? |
| :--------------------------------- | :----------------------------------------- | :---------: |
| `json.RawMessage` for preservation | `transaction.go`, `action.go`, `commit.go` |     ✅      |
| Pointer receivers for mutation     | All structs with methods                   |     ✅      |
| Value receivers for accessors      | `MultihashDigest`, state types             |     ✅      |
| Nil-safe accessors                 | `DS()`, `TS()` return `*T`                 |     ✅      |

**Finding G6:** Consistent use of pointer types for optional state (`*TransactionState`, `*DataState`) vs value types for required state (`KeyState`, `AuthState`). This correctly models SPEC semantics.

---

### Documentation Consistency

| Pattern            | Adherence | Notes                                |
| :----------------- | :-------: | :----------------------------------- |
| Package doc exists |    ✅     | `cyphrpass.go` has comprehensive doc |
| Type docs          |    ✅     | All exported types documented        |
| SPEC references    |    ⚠️     | Inconsistent (§14 vs §17 in errors)  |
| Example code       |    ✅     | Package doc includes example         |

---

### Go Internal Findings Summary

| ID     | Type | Description                                        | Severity |
| :----- | :--- | :------------------------------------------------- | :------- |
| **G1** | Info | Terse state abbreviations require domain knowledge | Low      |
| **G2** | Pass | All errors centralized in `error.go`               | —        |
| **G3** | Bug  | Error docs reference §14 instead of §17            | P3       |
| **G4** | Pass | Panic usage appropriate for invariants             | —        |
| **G5** | Pass | Clean flat package, no circular deps               | —        |
| **G6** | Pass | Consistent pointer/value semantics                 | —        |

**Overall Go Internal Coherence:** ✅ **PASS** — No significant boundary violations or pattern drift.

---

**Checkpoint:** Go internal audit complete. Proceeding to Rust internal audit.

---

## 3B: Rust Internal Coherence Audit

**Scope:** All 9 files in `rs/cyphrpass/src/` (~120KB source)

### Naming Consistency

| Pattern                           | Adherence | Notes                                                       |
| :-------------------------------- | :-------: | :---------------------------------------------------------- |
| Types: PascalCase                 |    ✅     | `KeyState`, `Principal`, `Transaction`                      |
| Functions/methods: snake_case     |    ✅     | `compute_ks()`, `is_key_active()`                           |
| Boolean predicates: `is_*` prefix |    ✅     | `is_active()`, `is_empty()`, `is_finalizer()`               |
| Accessors without `get_`          |    ✅     | `pr()`, `ps()`, `auth_state()`, `key_state()`               |
| Constructors: `new`, `from_*`     |    ✅     | `new()`, `from_pay()`, `from_single()`, `from_checkpoint()` |

**Finding R1:** Accessor naming uses full words (`auth_state()`) except for state abbreviations (`pr()`, `ps()`). This is intentional—SPEC §7 defines these abbreviations.

---

### Error Handling Patterns

| Pattern                     | Usage | Notes                                |
| :-------------------------- | :---: | :----------------------------------- |
| `thiserror` derive          |  ✅   | Single `Error` enum in `error.rs`    |
| `Result<T, Error>` alias    |  ✅   | `crate::error::Result`               |
| `?` propagation             |  ✅   | Throughout codebase                  |
| `Option` for optional state |  ✅   | `data_state() -> Option<&DataState>` |
| `From` conversions          |  ✅   | `Error::Coz(#[from] coz::Error)`     |

**Finding R2:** Error handling is exemplary. All error variants are domain-specific with SPEC §17 references.

---

### Panic Policy (Production Code Only)

| Location       | Type            | Reason                  | Assessment             |
| :------------- | :-------------- | :---------------------- | :--------------------- |
| `state.rs:255` | `debug_assert!` | Empty state computation | ⚠️ Should be `assert!` |
| `commit.rs:47` | `debug_assert!` | Empty transactions      | ⚠️ Should be `assert!` |

**Finding R3:** Two production `debug_assert!` calls. In release mode, these invariant checks are bypassed. Per `go.md` parity and safety principles, these should be `assert!`. **Already captured as S2-1.**

---

### Module Dependency Graph

```
lib.rs
   ├── error.rs       (no internal deps)
   ├── key.rs         (no internal deps)
   ├── multihash.rs → state.rs (HashAlg only)
   ├── state.rs     → multihash.rs
   ├── action.rs      (no internal deps)
   ├── transaction.rs → error, key, state
   ├── commit.rs    → state, transaction
   └── principal.rs → action, commit, error, key, state, transaction
```

**Finding R4:** `multihash.rs` ↔ `state.rs` has a bidirectional dependency:

- `multihash.rs` imports `HashAlg` from `state.rs`
- `state.rs` imports `MultihashDigest` from `multihash.rs`

This is NOT a cycle violation because:

1. Rust's module system allows flat crate-level imports
2. The types don't depend on each other at construction time
3. `HashAlg` is a simple enum with no dependencies

**Assessment:** Acceptable design—no layering violation.

---

### Pattern Uniformity

| Pattern                        | Files Using                   | Consistent? |
| :----------------------------- | :---------------------------- | :---------: |
| `Box<[u8]>` for digest storage | `multihash.rs`, `state.rs`    |     ✅      |
| `&self` for accessors          | All files                     |     ✅      |
| `&mut self` for mutations      | `principal.rs`, `key.rs`      |     ✅      |
| `impl Iterator` returns        | `principal.rs`                |     ✅      |
| `Option` for nullable state    | `principal.rs`, `state.rs`    |     ✅      |
| `CozJson` for raw preservation | `transaction.rs`, `action.rs` |     ✅      |

**Finding R5:** No `unwrap()` in library code paths (only in test code). This follows `rust.md` guidelines.

---

### Documentation Consistency

| Pattern             | Adherence | Notes                                 |
| :------------------ | :-------: | :------------------------------------ |
| Module docs (`//!`) |    ✅     | All modules have docs                 |
| Type docs (`///`)   |    ✅     | All public types documented           |
| SPEC references     |    ✅     | Consistent §17 references in error.rs |
| `#[must_use]`       |    ⚠️     | Not applied to `Result`-returning fns |

**Finding R6:** `#[must_use]` is not applied to `Result`-returning functions. Per `rust.md`, this should be added for functions where ignoring the result is a bug.

---

### Rust Internal Findings Summary

| ID     | Type | Description                                           | Severity |
| :----- | :--- | :---------------------------------------------------- | :------- |
| **R1** | Info | Mixed abbreviation/full naming (intentional per SPEC) | —        |
| **R2** | Pass | Exemplary error handling with thiserror               | —        |
| **R3** | Bug  | Two `debug_assert!` should be `assert!`               | P2       |
| **R4** | Pass | Bidirectional dep is acceptable flat crate pattern    | —        |
| **R5** | Pass | No `unwrap()` in library code                         | —        |
| **R6** | Info | Consider `#[must_use]` on Result-returning fns        | P3       |

**Overall Rust Internal Coherence:** ✅ **PASS** — One actionable finding (R3/S2-1), one enhancement (R6).

---

**Checkpoint:** Rust internal audit complete. Phase 3 revised complete.

---

## Consolidated Findings

This audit identified **23 recommendations** across 4 phases. After deduplication and consolidation, the final count is **15 unique action items**.

---

## P1 — Critical (Must Fix)

These items represent correctness issues that could cause subtle bugs or protocol violations.

| ID       | Scope | Description                                                         | Component   | Effort |
| :------- | :---- | :------------------------------------------------------------------ | :---------- | :----- |
| **T1-1** | Go    | **Implement length-based hash algorithm inference in `parsePre()`** | Transaction | Medium |

**Details:**

- **Current:** Go hardcodes SHA-256 when parsing the `pre` field.
- **Issue:** Transactions using SHA-384 or SHA-512 will fail to parse correctly.
- **Fix:** Infer algorithm from digest length: 32 bytes → SHA-256, 48 → SHA-384, 64 → SHA-512. Match Rust implementation in `pre_from_digest()`.
- **File:** `go/cyphrpass/transaction.go` (around `parsePre()`)

| **T1-2** | Go | **Fix `typ` parsing to handle namespaced URIs** | Transaction | Medium |

**Details:**

- **Current:** Go splits `typ` at first slash. `cyphr.me/cyphrpass/key/create` becomes `cyphrpass/key/create`, surviving parse but failing switch.
- **Issue:** Untested code path fails on valid SPEC inputs.
- **Fix:** Use `strings.HasSuffix`. Add unit test covering namespaced keys.
- **File:** `go/cyphrpass/transaction.go` (`typSuffix`)

---

## P2 — High (Should Fix)

These items represent API consistency, type safety, or parity issues between implementations.

| ID       | Scope | Description                                                  | Component     | Effort |
| :------- | :---- | :----------------------------------------------------------- | :------------ | :----- |
| **S2-1** | Rust  | **Change `debug_assert!` to `assert!` for empty invariants** | State, Commit | Low    |
| **T2-1** | Both  | **Align `TxOtherRevoke` handling**                           | Transaction   | Medium |
| **P1-1** | Go    | **Add `FromCheckpoint()` constructor**                       | Principal     | Medium |

**Details:**

### S2-1: Assert vs Debug-Assert

- **Current:** Rust uses `debug_assert!` for invariant checks (e.g., empty `MultihashDigest`, empty `Commit`).
- **Issue:** Invariant violations pass silently in release builds.
- **Fix:** Replace with `assert!` for parity with Go's unconditional panics.
- **Files:** `rs/cyphrpass/src/multihash.rs`, `rs/cyphrpass/src/commit.rs`

### T2-1: Other-Revoke Handling

- **Current:** Go has `TxOtherRevoke` (one key revokes another); Rust removed it per earlier directive.
- **Issue:** Semantic divergence between implementations.
- **Options:**
  1. Remove from Go (match Rust)
  2. Re-add to Rust (match Go)
  3. Document as intentional divergence (Level 5+ feature)
- **Recommendation:** Remove from Go — it's a Level 5+ feature not currently exercised.

### P1-1: Checkpoint Constructor

- **Current:** Rust has `Principal::from_checkpoint()` for storage import; Go lacks equivalent.
- **Issue:** Go cannot restore principals from persisted state without replaying transactions.
- **Fix:** Add `FromCheckpoint(pr, as, keys) (*Principal, error)` to Go.
- **File:** `go/cyphrpass/principal.go`

---

## P3 — Medium (Nice to Have)

These items represent naming consistency, documentation, or minor API improvements.

| ID       | Scope | Description                                                         | Component   | Effort |
| :------- | :---- | :------------------------------------------------------------------ | :---------- | :----- |
| **E5-1** | Go    | **Update error comments: §14 → §17**                                | Errors      | Low    |
| **E5-2** | Both  | **Align error naming conventions**                                  | Errors      | Low    |
| **S3-1** | Rust  | **Add `get_or_first()` method to `MultihashDigest`**                | State       | Low    |
| **C4-1** | Rust  | **Consider `Result` return for `finalize()`**                       | Commit      | Low    |
| **P1-2** | Both  | **Annotate test helpers with visibility markers**                   | Principal   | Low    |
| **R6**   | Rust  | **Add `#[must_use]` to `Result`-returning functions**               | API         | Low    |
| **X6**   | Both  | **Align verified tx naming: `VerifiedTx` ↔ `VerifiedTransaction`** | Transaction | Low    |
| **T3-1** | Go    | **Consider refactoring `TransactionKind` to embedded data**         | Transaction | High   |
| **A5-1** | Go    | **Add content accessors to `Action` struct**                        | Actions     | Low    |

**Notes:**

- **T3-1** is marked High effort because it requires restructuring Go's transaction parsing. Defer unless pursuing full type-safety parity with Rust.
- **E5-2** involves deciding on canonical names: prefer `MissingFinalizer` vs `MissingFinalizationMarker`.
- **X6** is purely cosmetic; both names are valid. Consider harmonizing if there's a breaking change window.

---

## Implementation Order

Recommended sequence based on dependency and impact:

```
Phase A: Critical Path (T1-1, T1-2)
   └─→ Fix `parsePre` hash inference
   └─→ Fix `typ` parsing logic and add tests

Phase B: Type Safety (S2-1, T2-1, P1-1)
   └─→ S2-1: Quick Rust fix
   └─→ T2-1: Remove TxOtherRevoke from Go
   └─→ P1-1: Add FromCheckpoint to Go

Phase C: Polish (E5-1, E5-2, S3-1, C4-1, P1-2, R6)
   └─→ Documentation, API polish, and #[must_use] annotations

Phase D: Optional Refactoring (T3-1, X6)
   └─→ Only if pursuing full API harmonization
```

---

## Summary Statistics

| Priority      | Count  |   Effort   |
| :------------ | :----: | :--------: |
| P1 (Critical) |   2    |   Medium   |
| P2 (High)     |   3    | Low-Medium |
| P3 (Medium)   |   9    |  Low-High  |
| **Total**     | **14** |     —      |

---

## Audit Conclusion

Both implementations demonstrate **strong API coherence**:

- Clean layering with no circular dependencies
- Idiomatic patterns for each language
- Consistent error handling and naming conventions
- Proper type-safety (Rust) and convention-based safety (Go)

**Final Scores:**
| Implementation | Score | Assessment |
|:---------------|:-----:|:-----------|
| Go | 4.2/5 | Solid; minor gaps in type safety and parity |
| Rust | 4.8/5 | Excellent; near-ideal API design |

The **one critical item (T1-1)** should be addressed immediately. The **P2 items** should be addressed in the next development cycle. **P3 items** can be addressed opportunistically.

---

**Audit Complete.** Awaiting user approval of remediation plan before closing.
