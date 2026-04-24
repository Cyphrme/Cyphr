# cyphr-cli

The reference command-line interface for the [Cyphr](https://cyphr.me) self-sovereign identity protocol.

This tool allows you to generate keys, create Principals, sign and verify Cozies, and manage cryptographic state directly from the terminal. It utilizes the core [`cyphr`](https://crates.io/crates/cyphr) protocol library and the [`cyphr-storage`](https://crates.io/crates/cyphr-storage) backend.

## Installation

```bash
cargo install cyphr-cli
```

## Basic Usage

### Initialize a new Principal

```bash
cyphr new --alg es256
```

This generates a new ECDSA keypair, creates an implicit Level 1 Principal, and saves the state to your local storage directory.

### Sign a payload

```bash
cyphr sign --payload '{"action":"login"}'
```

### View Principal State

```bash
cyphr status
```

For full documentation and all available commands, run:

```bash
cyphr --help
```

## Documentation

- **[Protocol Specification](https://docs.cyphr.me)**
- **[Project Homepage](https://cyphr.me)**
