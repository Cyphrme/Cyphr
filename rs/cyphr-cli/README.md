# Cyphr CLI

Reference CLI for the [Cyphr Identity Protocol](../SPEC.md). Exercises the `cyphr` and `cyphr-storage` Rust libraries.

## Quick Start

```bash
# Generate a key
cyphr key generate --algo ES256 --tag "main"

# Create an identity (implicit genesis)
cyphr key add --identity <tmb> --signer <tmb>

# List active keys
cyphr key list --identity <pr>

# Export identity for backup
cyphr export --identity <pr> --output backup.jsonl

# Import identity
cyphr import --input backup.jsonl
```

## Installation

```bash
cargo install --path rs/cyphr-cli
```

Or run directly:

```bash
cargo run -p cyphr-cli -- <command>
```

## Global Options

| Flag                | Default             | Description               |
| :------------------ | :------------------ | :------------------------ |
| `--store <uri>`     | `file:./cyphr-data` | Storage backend           |
| `--keystore <path>` | `./cyphr-keys.json` | Private key storage       |
| `--output <format>` | `table`             | Output: `table` or `json` |

## Commands

### `key generate`

Generate a new keypair and store in keystore.

```bash
cyphr key generate --algo ES256 --tag "laptop"
```

### `key add`

Add a key to an identity. Creates a signed `key/create` transaction.

```bash
# Generate new key and add it
cyphr key add --identity <pr> --signer <tmb>

# Add existing key
cyphr key add --identity <pr> --key <new-tmb> --signer <tmb>
```

### `key revoke`

Revoke a key from an identity. Creates a signed `key/revoke` transaction.

```bash
cyphr key revoke --identity <pr> --key <tmb-to-revoke> --signer <tmb>
```

### `key list`

List keys in keystore or for a specific identity.

```bash
# List all keystore keys
cyphr key list

# List active keys for identity
cyphr key list --identity <pr>
```

### `inspect`

Display identity state.

```bash
cyphr inspect --identity <pr>
```

### `tx list`

List transactions for an identity.

```bash
cyphr tx list --identity <pr>
```

### `tx verify`

Verify transaction chain integrity.

```bash
cyphr tx verify --identity <pr>
```

### `export`

Export identity commits to JSONL file.

```bash
cyphr export --identity <pr> --output backup.jsonl
```

### `import`

Import identity from JSONL file.

```bash
cyphr import --input backup.jsonl
```

## Example Workflow

```bash
# 1. Generate genesis key
cyphr key generate --algo ES256 --tag genesis
# Output: tmb: ABC123...

# 2. Add a second key (creates identity with first transaction)
cyphr key add --identity ABC123... --signer ABC123...
# Output: added key XYZ789...

# 3. List active keys
cyphr key list --identity ABC123...
# Output:
#   ABC123... (ES256) [genesis]
#   XYZ789... (ES256) [-]

# 4. Revoke the second key
cyphr key revoke --identity ABC123... --key XYZ789... --signer ABC123...

# 5. Export for backup
cyphr export --identity ABC123... --output my-identity.jsonl
```

## Storage Format

Identities are stored as JSONL files (one commit per line) in the storage directory. Each commit contains:

- `txs`: Array of signed transactions
- `commit_id`: Commit ID digest
- `as`: Auth State digest
- `cs`: Commit State digest
- `ps`: Principal State digest

See [SPEC.md](../SPEC.md) for protocol details.

## License

See repository root.
