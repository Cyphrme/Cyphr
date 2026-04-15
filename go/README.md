# Cyphr Go Implementation

Go implementation of the Cyphr self-sovereign identity protocol.

## Installation

```bash
go get github.com/cyphrme/cyphr
```

## Quick Start

### Create a Principal

```go
package main

import (
    "fmt"
    "github.com/cyphrme/coz"
    "github.com/cyphrme/cyphr"
)

func main() {
    // Generate a key
    key, _ := coz.NewKey("ES256")

    // Implicit genesis: single key, identity = thumbprint
    principal, _ := cyphr.Implicit(key)

    fmt.Printf("Identity (PR): %s\n", principal.PR())
    fmt.Printf("Level: %v\n", principal.Level()) // Level 1
}
```

### Verify and Apply Cozies

```go
// Receive a signed coz (Coz message)
cozMsg := &coz.Coz{
    Pay: payloadBytes,
    Sig: signatureBytes,
}

// Verify signature and parse
vt, err := principal.VerifyCoz(cozMsg, newKey)
if err != nil {
    // Handle: ErrInvalidSignature, ErrUnknownKey, ErrKeyRevoked, etc.
}

// Apply verified coz as atomic commit
commit, err := principal.ApplyCoz(vt)
```

### Multi-Coz Commits

```go
batch := principal.BeginCommit()
batch.Apply(vt1) // first coz
batch.Apply(vt2) // second coz sees first's mutations
commit, err := batch.Finalize()
```

### Record Actions (Level 4)

```go
action := &cyphr.Action{
    Signer: signerThumbprint,
    Now:    time.Now().Unix(),
    Czd:    actionCzd,  // coz digest of the action
}

err := principal.RecordAction(action)
// principal.Level() is now Level4
// principal.DR() contains action digest
```

## API Reference

### Genesis

| Function         | Description                                   |
| ---------------- | --------------------------------------------- |
| `Implicit(key)`  | Single-key genesis, PR = key thumbprint       |
| `Explicit(keys)` | Multi-key genesis, PR = H(sorted thumbprints) |

### State Accessors

| Method         | Returns             | Description                            |
| -------------- | ------------------- | -------------------------------------- |
| `PG()`         | `*PrincipalGenesis` | Permanent identity (nil for L1/L2)     |
| `PR()`         | `PrincipalRoot`     | Current principal root (evolves)       |
| `SR()`         | `StateRoot`         | State root = MR(AR, DR?)               |
| `AR()`         | `AuthRoot`          | Auth root = MR(KR, RR?)                |
| `KR()`         | `KeyRoot`           | Key root = MR(thumbprints)             |
| `DR()`         | `*DataRoot`         | Data root = H(action czds), nil if L<4 |
| `CR()`         | `*CommitRoot`       | Commit root (MALT of TRs)              |
| `TR()`         | `*TransactionRoot`  | Transaction root of latest commit      |
| `Level()`      | `Level`             | Current feature level (1-4)            |
| `HashAlg()`    | `HashAlg`           | Primary hash algorithm                 |
| `ActiveAlgs()` | `[]HashAlg`         | Hash algorithms from active keyset     |

### Cozies

| Method                   | Description                             |
| ------------------------ | --------------------------------------- |
| `VerifyCoz(coz, newKey)` | Verify signature, return `*VerifiedCoz` |
| `ApplyCoz(vt)`           | Apply verified coz as atomic commit     |
| `BeginCommit()`          | Start multi-coz commit batch            |

### Keys

| Method             | Description            |
| ------------------ | ---------------------- |
| `Key(tmb)`         | Get key by thumbprint  |
| `IsKeyActive(tmb)` | Check if key is active |
| `ActiveKeys()`     | All active keys        |
| `ActiveKeyCount()` | Number of active keys  |

## Error Handling

```go
import "errors"

commit, err := principal.ApplyCoz(vt)
switch {
case errors.Is(err, cyphr.ErrInvalidPrior):
    // Coz pre doesn't match current PR
case errors.Is(err, cyphr.ErrTimestampPast):
    // Coz timestamp older than latest
case errors.Is(err, cyphr.ErrDuplicateKey):
    // Key already in KR
case errors.Is(err, cyphr.ErrNoActiveKeys):
    // Would leave principal with no active keys
case errors.Is(err, cyphr.ErrEmptyCommit):
    // Finalized a commit with no cozies
case errors.Is(err, cyphr.ErrCommitMismatch):
    // Arrow field doesn't match computed state
}
```

## Testing

```bash
cd go
go test ./...
```

### Test Suites

| Suite          | Tests | Description                          |
| -------------- | ----- | ------------------------------------ |
| `TestGolden_*` | 47    | Pre-computed fixtures (golden tests) |
| `TestE2E_*`    | 21    | Dynamic intent-driven tests          |
| Unit tests     | ~15   | Package-level unit tests             |

**Golden tests** consume pre-computed JSON fixtures from `../tests/golden/`.

**E2E tests** parse TOML intent files from `../tests/e2e/` and dynamically
generate transactions at runtime, providing round-trip verification.

## See Also

- [SPEC.md](../SPEC.md) — Full protocol specification
- [tests/README.md](../tests/README.md) — Test fixture documentation
