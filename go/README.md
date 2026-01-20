# Cyphrpass Go Implementation

Go implementation of the Cyphrpass self-sovereign identity protocol.

## Installation

```bash
go get github.com/cyphrme/cyphrpass
```

## Quick Start

### Create a Principal

```go
package main

import (
    "fmt"
    "github.com/cyphrme/coz"
    "github.com/cyphrme/cyphrpass"
)

func main() {
    // Generate a key
    key, _ := coz.NewKey("ES256")

    // Implicit genesis: single key, identity = thumbprint
    principal, _ := cyphrpass.Implicit(key)

    fmt.Printf("Identity (PR): %s\n", principal.PR())
    fmt.Printf("Level: %v\n", principal.Level()) // Level 1
}
```

### Verify and Apply Transactions

```go
// Receive a signed transaction (Coz message)
cozMsg := &coz.Coz{
    Pay: payloadBytes,
    Sig: signatureBytes,
}

// Verify signature and parse
vtx, err := principal.VerifyTransaction(cozMsg, newKey)
if err != nil {
    // Handle: ErrInvalidSignature, ErrUnknownKey, ErrKeyRevoked, etc.
}

// Apply verified transaction (safe API)
err = principal.ApplyVerified(vtx)
```

### Record Actions (Level 4)

```go
action := &cyphrpass.Action{
    Signer: signerThumbprint,
    Now:    time.Now().Unix(),
    Czd:    actionCzd,  // coz digest of the action
}

err := principal.RecordAction(action)
// principal.Level() is now Level4
// principal.DS() contains action digest
```

## API Reference

### Genesis

| Function         | Description                                   |
| ---------------- | --------------------------------------------- |
| `Implicit(key)`  | Single-key genesis, PR = key thumbprint       |
| `Explicit(keys)` | Multi-key genesis, PR = H(sorted thumbprints) |

### State Accessors

| Method    | Returns          | Description                        |
| --------- | ---------------- | ---------------------------------- |
| `PR()`    | `PrincipalRoot`  | Permanent identity (never changes) |
| `PS()`    | `PrincipalState` | Current state (evolves)            |
| `AS()`    | `AuthState`      | Auth state = H(KS, TS?, RS?)       |
| `KS()`    | `KeyState`       | Key state = H(thumbprints)         |
| `DS()`    | `DataState`      | Data state = H(action czds)        |
| `Level()` | `Level`          | Current feature level (1-6)        |

### Transactions

| Method                            | Description                           |
| --------------------------------- | ------------------------------------- |
| `VerifyTransaction(coz, newKey)`  | Verify signature, return `VerifiedTx` |
| `ApplyVerified(vtx)`              | Apply verified transaction (safe API) |
| `ApplyTransactionUnsafe(tx, key)` | Testing only—no signature check       |

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

err := principal.ApplyVerified(vtx)
switch {
case errors.Is(err, cyphrpass.ErrInvalidPrior):
    // Transaction pre doesn't match current AS
case errors.Is(err, cyphrpass.ErrTimestampPast):
    // Transaction timestamp older than latest
case errors.Is(err, cyphrpass.ErrDuplicateKey):
    // Key already in KS
case errors.Is(err, cyphrpass.ErrNoActiveKeys):
    // Would leave principal with no active keys
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
| `TestGolden_*` | 41    | Pre-computed fixtures (golden tests) |
| `TestE2E_*`    | 19    | Dynamic intent-driven tests          |
| Unit tests     | ~15   | Package-level unit tests             |

**Golden tests** consume pre-computed JSON fixtures from `../tests/golden/`.

**E2E tests** parse TOML intent files from `../tests/e2e/` and dynamically
generate transactions at runtime, providing round-trip verification.

## See Also

- [SPEC.md](../SPEC.md) — Full protocol specification
- [tests/README.md](../tests/README.md) — Test fixture documentation
