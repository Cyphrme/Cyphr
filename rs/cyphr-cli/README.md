# cyphr-cli

The reference command-line interface for the [Cyphr](https://cyphr.me) self-sovereign identity protocol.

This tool allows you to generate keys, create Principals, sign and verify Cozies, and manage cryptographic state directly from the terminal. It utilizes the core [`cyphr`](https://crates.io/crates/cyphr) protocol library and the [`cyphr-storage`](https://crates.io/crates/cyphr-storage) backend.

## Installation

```bash
cargo install cyphr-cli
```

## Basic Usage

### Generate a keypair

```bash
cyphr key generate --algo ES256 --tag my-key
```

### Initialize a new Principal

```bash
cyphr init --algo ES256
```

This generates a new ECDSA keypair, creates an implicit Level 1 Principal, and stores both the keypair and Principal state to your local storage directory.

### View Principal keys

```bash
cyphr key list --identity KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc
```

### Add a key to a Principal

```bash
cyphr key add --identity KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc \
             --signer KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc
```

### Inspect Principal state

```bash
cyphr inspect --identity KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc
```

### Export and import

```bash
# Export a principal to JSONL
cyphr export --identity KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc \
            --output backup.jsonl

# Import a principal from JSONL
cyphr import --input backup.jsonl
```

For full documentation and all available commands, run:

```bash
cyphr --help
```

### Demo Script

A complete working walkthrough is provided in [`demo.sh`](./demo.sh), demonstrating key generation, identity creation, key addition, revocation, and export/import operations.

## Documentation

- **[Protocol Specification](https://docs.cyphr.me)**
- **[Project Homepage](https://cyphr.me)**
