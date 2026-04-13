# Cyphr Agent Configuration

## Predicate System

This project uses [predicate](https://github.com/nrdxp/predicate) for agent configuration.

> [!IMPORTANT]
> You **must** review [.agent/PREDICATE.md](.agent/PREDICATE.md) and follow its instructions before beginning work.

**Active Personas:**

- `go.md` — Go idioms for the `go/` implementation
- `rust.md` — Rust idioms for the `rs/` implementation
- `depmap.md` — DepMap MCP server for dependency-aware code exploration
- `personalization.md` — User naming preferences

---

## Project Overview

**Cyphr** is a self-sovereign identity protocol built on cryptographic state trees. It replaces passwords with public key cryptography, enabling:

- Secure multi-device authentication
- Key rotation and revocation
- Individually-signed atomic actions
- No central authority required

The protocol is specified in `SPEC.md` and has dual implementations in **Go** (`go/`) and **Rust** (`rs/`), both currently supporting Levels 1-4 (single key through authenticated actions).

All cryptographic operations use the [Coz](https://github.com/Cyphrme/Coz) JSON messaging specification.

---

## Build & Commands

### Go Implementation (`go/`)

```bash
# Run tests
go test ./...

# Run specific package tests
go test ./principal/...
```

### Rust Implementation (`rs/`)

```bash
# Build all crates
cargo build

# Run all tests
cargo test

# Run specific crate tests
cargo test -p cyphr-storage
```

### Test Fixtures

```bash
# Regenerate golden fixtures
cargo run -p fixture-gen
```

---

## Code Style

- **Go:** Follow standard Go conventions; see `go/README.md`
- **Rust:** Follow Rust idioms; see `rs/README.md`
- **Formatting:** Use `treefmt` (configured in `treefmt.toml`)
- **Naming:** Use canonical terminology from `SPEC.md` (Principal Root, Auth State, Data State, etc.)
- **Error handling:** Library code must not panic; use `Result` propagation. `unwrap()`/`expect()` are acceptable only in test code.

---

## Architecture

```
Cyphr/
├── SPEC.md                 # Protocol specification (source of truth)
├── docs/                   # Project documentation
│   ├── models/             # Formal domain models
│   └── plans/              # Durable implementation plans
├── go/                     # Go implementation
│   ├── cyphr/              # Core Principal logic
│   ├── storage/            # Storage backends
│   └── testfixtures/       # Test fixture loading
├── rs/                     # Rust implementation
│   ├── cyphr/              # Core crate (Principal, state, multihash)
│   ├── cyphr-storage/      # Storage crate (FileStore, export/import)
│   ├── cyphr-cli/          # CLI binary
│   ├── test-fixtures/      # Golden fixture definitions
│   └── fixture-gen/        # Fixture generation binary
└── tests/                  # Language-agnostic test vectors
    ├── golden/             # Pre-computed golden fixtures
    └── e2e/                # End-to-end intent files
```

Key abstractions:

- **Principal** — Identity container (PR + state tree)
- **Transaction** — Signed state mutation (key/create, key/revoke, etc.)
- **Commit** — Atomic bundle of transactions with finality marker
- **State types** — `AuthRoot = MR(KR, RR?)`, `StateRoot = MR(AR, DR?, embedding?)` — the hierarchical Merkle tree that derives the observable `PR`

---

## Testing

- **Shared fixtures:** Cross-language test vectors in `tests/`
- **Golden tests:** Pre-computed expected outputs for deterministic operations
- **E2E tests:** Intent-driven scenarios exercising full principal lifecycle
- **Parity:** Both implementations must pass identical test vectors

---

## Security

- **Never commit secrets or private keys**
- **Cryptographic operations:** Use Coz library exclusively
- **Key material:** Handle with care; zeroize after use in Rust
- **Validation:** Verify all signatures before accepting transactions
- **Audit history:** See `ai_audit.txt` for previous security reviews

---

## Configuration

- **Nix:** Development shell via `shell.nix`
- **direnv:** Auto-load with `.envrc`
- **VS Code:** Workspace settings in `.vscode/`

---

## Stability

- **Status:** Currently pre-alpha; the specification is experimental and in flux
- **Correctness over compatibility:** We are striving for a correct and working spec, experimenting toward it
- **Backwards compatibility is not a concern:** We may move in a direction, then decide to abandon it; there is no concern for supporting these codepaths until we reach stability
- **SPEC alignment:** The specification is the source of truth. If you sense a contradiction in it, please alert us, but otherwise consider it authoritative

---

## Workflow

- **C.O.R.E. interaction:** We follow a consistent pattern of crafting an implementation plan, building a task list, and then using the C.O.R.E. workflow over multiple rounds for coherently iterating through our task list
- **Well-scoped work:** You do not need to capture the entire implementation plan or task list in a single round of C.O.R.E.; rather, C.O.R.E. is useful for focusing in and finishing a collection of tasks at well-defined boundaries. We typically move through several rounds of C.O.R.E. to complete a single task list and plan.
- **Commit strategy:** We are in a mono-repo, so be sure to add necessary context to commits (e.g. `feat(rs/transaction): ...`), specifying what implementation and concern we are working on
- **C.O.R.E. compliance:** C.O.R.E. tries to specify its steps are strict and not to be liberally modified, but I'll just reiterate that point. Follow the outlined procedure as precisely as possible without adding steps or extending it.
- **Socratic primacy:** We are a team. All the rules, C.O.R.E., and everything else is written to reinforce a spirit of collaboration over rushed implementation. If you are unsure or unclear, always bias toward stopping to clarify. Never make assumptions or make unilateral design decisions without consulting.
- **Never commit:** Outlined in C.O.R.E. already, but just to clarify: it is absolutely imperative that you do not make commits yourself, but only report a commit message for your changes and allow your human partner to commit on your behalf. This means you need to always STOP and report at commit boundaries as outlined in C.O.R.E.
