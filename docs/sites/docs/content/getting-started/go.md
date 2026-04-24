+++
title       = "Go"
description = "Create and manage Cyphr principals with the Go module"
weight      = 0
toc         = true
+++

## Installation

Requires Go 1.24 or later.

```bash
go get github.com/cyphrme/cyphr@latest
```

The module depends on [coz](https://github.com/Cyphrme/Coz) for
cryptographic signing and key management.

## Creating a Principal

A **principal** is a self-sovereign identity. At Level 1, a principal is a
single key — the key's thumbprint _is_ the identity.

```go
package main

import (
	"fmt"
	"log"

	"github.com/cyphrme/coz"
	"github.com/cyphrme/cyphr"
)

func main() {
	// Generate a new ES256 key pair.
	key, err := coz.NewKey(coz.ES256)
	if err != nil {
		log.Fatal(err)
	}

	// Create a Level 1 principal (implicit genesis).
	p, err := cyphr.Implicit(key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Principal Root:", p.PR())
	fmt.Println("Level:", p.Level())
	fmt.Println("Active keys:", p.ActiveKeyCount())
}
```

At Level 1, implicit promotion means that the key thumbprint promotes through
KR → AR → SR → PR. One value. One identity. No ceremony.

## Inspecting State

Every principal exposes its internal Merkle state:

```go
fmt.Println("KR:", p.KR())   // Key Root
fmt.Println("AR:", p.AR())   // Auth Root
fmt.Println("SR:", p.SR())   // State Root
fmt.Println("PR:", p.PR())   // Principal Root (observable identity)
```

At Level 1 all four are identical — they diverge as you add keys, commit
transactions, and record actions.

## Multi-Key Genesis (Level 3)

For principals with multiple concurrent keys, use explicit genesis:

```go
key1, _ := coz.NewKey(coz.ES256)
key2, _ := coz.NewKey(coz.ES256)

p, err := cyphr.Explicit([]*coz.Key{key1, key2})
if err != nil {
	log.Fatal(err)
}

fmt.Println("Active keys:", p.ActiveKeyCount()) // 2
fmt.Println("Level:", p.Level())                // L3 (multi-key)
```

## Applying Transactions

State mutations are applied as signed Coz messages. Each transaction is
individually signed and verified before application:

```go
// ApplyCoz verifies the signature and applies the mutation
// as an atomic single-transaction commit.
commit, err := p.ApplyCoz(verifiedCoz)
if err != nil {
	log.Fatal(err)
}
```

For multi-transaction commits, use the batch API:

```go
batch := p.BeginCommit()
batch.Apply(vtx1)
batch.Apply(vtx2)
commit, err := batch.Finalize()
```

Each commit bundles one or more signed transactions into an atomic unit with
a finality marker, appended to the principal's MALT (Merkle Append-only Log
Tree).

## Recording Actions (Level 4)

At Level 4, principals can record **Authenticated Atomic Actions** — each
action is individually signed and bound to the principal's state tree:

```go
err := p.RecordAction(&cyphr.Action{
	Typ:    "cyphr.me/comment/create",
	Signer: key.Tmb,
	Now:    time.Now().Unix(),
	Czd:    actionCzd,
})
```

Actions do not mutate the Auth Tree. They are recorded in the Data Tree,
and the Data Root (DR) is folded into the State Root at the next
recomputation.

## Next Steps

- Read the [Protocol Specification](../specification.html) for the full
  formal treatment
- Browse the [source](https://github.com/Cyphrme/Cyphr/tree/main/go) for
  implementation details
- Run `go test ./...` from the `go/` directory to execute the test suite
