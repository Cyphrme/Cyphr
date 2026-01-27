# Cyphrpass Agent Configuration

## Predicate System

This project uses [predicate](https://github.com/nrdxp/predicate) for agent configuration.

**Installation Location:** `.agent/`

### How Predicates Work

**Predicates** are foundational rulesets. Any file placed directly in `.agent/predicates/` is **always active** — the agent must read and adhere to all of them unconditionally. These are the non-negotiable rules that govern agent behavior.

**Fragments** are context-specific extensions stored in `.agent/predicates/fragments/`. These are **opt-in** — only fragments explicitly listed below as "active" are loaded, and typically only when relevant to the current task (e.g., load `rust.md` when working on Rust code).

```
.agent/
├── predicates/
│   ├── engineering.md         # Base engineering ruleset (always active)
│   └── fragments/             # Context-specific extensions (opt-in)
│       └── ...                # e.g., go.md, rust.md, depmap.md
└── workflows/
    └── ...                    # Task-specific workflows
```

> [!IMPORTANT]
> The agent must read **all** files directly in `.agent/predicates/` before beginning work. These predicates are non-negotiable.

**Active Fragments:**

- `go.md` — Go idioms for the `go/` implementation
- `rust.md` — Rust idioms for the `rs/` implementation
- `depmap.md` — DepMap MCP server for dependency-aware code exploration
- `integral.md` — Holistic problem-solving framework
- `personalization.md` — User naming preferences

**Available Workflows:**

- `/ai-audit` — Audit code for AI-generated patterns
- `/core` — C.O.R.E. structured interaction protocol
- `/humanizer` — Remove AI writing patterns from text
- `/predicate` — Re-read global rules; combats context drift

---

## Project Overview

**Cyphrpass** is a self-sovereign identity protocol built on cryptographic state trees. It replaces passwords with public key cryptography, enabling:

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
cargo test -p cyphrpass-storage
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

---

## Architecture

```
Cyphrpass/
├── SPEC.md           # Protocol specification (source of truth)
├── go/               # Go implementation
│   ├── principal/    # Core Principal logic
│   ├── coz/         # Coz integration
│   └── storage/     # Storage backends
├── rs/               # Rust implementation
│   ├── cyphrpass/    # Core crate
│   ├── cyphrpass-storage/  # Storage crate
│   └── test-fixtures/      # Fixture generation
└── tests/            # Language-agnostic test vectors
    ├── golden/       # Pre-computed golden fixtures
    └── e2e/          # End-to-end intent files
```

Key abstractions:

- **Principal** — Identity container (PR + state tree)
- **Transaction** — Signed state mutation (key/add, key/revoke)
- **Commit** — Atomic bundle of transactions with finality marker

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
