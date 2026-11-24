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

Keys are stored unencrypted at rest, in a file only you can read. See
[Key storage](../../docs/guides/key-storage.md) for what that means and what
the CLI does to protect the file.

### Initialize a new Principal

```bash
cyphr init --algo ES256
```

This generates a new ECDSA keypair, creates an implicit Level 1 Principal, and stores both the keypair and Principal state to your local storage directory.

### Move a Level 1 Principal up

A Level 1 Principal has no commit, so commands that need one (`key add`,
`data action`, `data commit`) refuse it until you say so. Create its genesis
commit explicitly:

```bash
cyphr upgrade --identity KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc
```

or repeat the command with `--upgrade`, which creates the genesis commit as
part of it (for `key add`, the new key goes into that one genesis commit, and
the identity becomes the key set's Principal Genesis, which the output names).
Nothing is signed without one of the two.

### View Principal keys

```bash
cyphr key list --identity KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc
```

### Add a key to a Principal

On a principal that already has its genesis commit (see above):

```bash
cyphr key add --identity KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc \
             --signer KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc
```

### Inspect Principal state

```bash
cyphr inspect --identity KPmtN3BqeOROzcuL4xfs86o9TPpba0ujA2scXzX2XBc
```

### Pair a device

Each device enrolls its own key; no private key is exported or copied. On
the new device, sign a pairing request for the principal, then carry the
file to a device already in the principal and accept it there:

```sh
cyphr key request --identity <PR> --file request.json
cyphr key accept --identity <PR> --signer <TMB> --file request.json
```

The request is signed by the new key (a proof of possession) under an
application typ, `<authority>/pairing/create`. `accept` refuses a request
whose signature does not verify, that names another principal or
authority, or whose `now` is more than 300 seconds from the accepting
device's clock (`--window` changes it). The window is an implementation
choice: SPEC 17.2 and 17.3 (at `be0663f`) require a bounded timestamp
window and leave N to the verifier.

Replay limit: a request replayed after acceptance is refused while its key
is active. Within the window, if the owner deleted that key and runs
`accept` again on the same file, the key is added back. The MVP has no
challenge nonce.

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
