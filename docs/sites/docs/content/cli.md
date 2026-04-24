+++
title       = "CLI Reference"
description = "Command-line interface for the Cyphr protocol"
weight      = 2
toc         = true
+++

## Installation

```bash
cargo install cyphr-cli
```

Or build from source:

```bash
git clone https://github.com/Cyphrme/Cyphr
cd Cyphr/rs
cargo install --path cyphr-cli
```

## Global Options

Every command accepts these flags:

| Flag          | Default             | Description                                 |
| ------------- | ------------------- | ------------------------------------------- |
| `--store`     | `file:./cyphr-data` | Storage backend URI                         |
| `--keystore`  | `./cyphr-keys.json` | Path to private key file                    |
| `--authority` | `cyphr.me`          | Authority domain for transaction `typ` URIs |
| `--output`    | `table`             | Output format: `table` or `json`            |

## Commands

### `cyphr init`

Create a new identity. Generates a key pair and a Level 1 principal by
default.

```bash
# Implicit genesis — generates a new ES256 key
cyphr init

# Implicit genesis — with a specific algorithm
cyphr init --algo Ed25519

# Implicit genesis — using an existing key from the keystore
cyphr init --key <thumbprint>

# Explicit genesis — multiple keys (Level 3)
cyphr init --keys <tmb1>,<tmb2>
```

| Flag     | Default | Description                                                  |
| -------- | ------- | ------------------------------------------------------------ |
| `--algo` | `ES256` | Algorithm for genesis key (ES256, ES384, ES512, Ed25519)     |
| `--key`  | —       | Use existing key from keystore (by thumbprint)               |
| `--keys` | —       | Comma-separated thumbprints for explicit (multi-key) genesis |

### `cyphr key generate`

Generate a new key pair and store it in the keystore. Does not associate it
with any identity.

```bash
cyphr key generate
cyphr key generate --algo Ed25519
cyphr key generate --algo ES256 --tag "laptop"
```

| Flag     | Default | Description                      |
| -------- | ------- | -------------------------------- |
| `--algo` | `ES256` | Algorithm                        |
| `--tag`  | —       | Human-readable label for the key |

### `cyphr key add`

Add a key to an existing identity. Produces a signed `key/create`
transaction, commits it, and persists the updated state.

```bash
# Add a specific key from the keystore
cyphr key add --identity <pr> --key <tmb> --signer <signer-tmb>

# Generate and add a new key in one step
cyphr key add --identity <pr> --signer <signer-tmb>
```

| Flag         | Required | Description                                         |
| ------------ | -------- | --------------------------------------------------- |
| `--identity` | yes      | Principal Root (base64url)                          |
| `--key`      | no       | Thumbprint of key to add (generates one if omitted) |
| `--signer`   | yes      | Thumbprint of the signing key (must be active)      |

### `cyphr key revoke`

Revoke a key from an identity. The protocol only supports **self-revoke** —
the key being revoked must be the signer. This is enforced by the CLI.

```bash
cyphr key revoke --identity <pr> --key <tmb> --signer <tmb>
```

`--key` and `--signer` must be the same thumbprint.

| Flag         | Required | Description                           |
| ------------ | -------- | ------------------------------------- |
| `--identity` | yes      | Principal Root (base64url)            |
| `--key`      | yes      | Thumbprint of key to revoke           |
| `--signer`   | yes      | Must equal `--key` (self-revoke only) |

### `cyphr key list`

List keys. Without `--identity`, lists all keys in the local keystore.
With `--identity`, lists active keys for a specific principal.

```bash
# List keystore keys
cyphr key list

# List active keys for an identity
cyphr key list --identity <pr>
```

### `cyphr inspect`

Display the full state tree of an identity: PR (Principal Root),
SR (State Root), KR (Key Root), AR (Auth Root), active keys, and
commit count.

```bash
cyphr inspect --identity <pr>
```

Example table output:

```text
Identity: U5XUZots-WmQ...

State:
  PR: U5XUZots-WmQ...
  PS: 7kB2n9xF...
  KS: U5XUZots-WmQ...
  AS: U5XUZots-WmQ...

Active Keys (2):
  U5XUZots-WmQ... (ES256) [laptop]
  rT3kMn7x...     (ES256) [phone]

Commits: 3
```

### `cyphr tx list`

List all transactions (cozies) for an identity, across all commits.

```bash
cyphr tx list --identity <pr>
```

### `cyphr tx verify`

Verify the full transaction chain for an identity. Replays all commits from
genesis, recomputes state digests, and confirms they match stored values.

```bash
cyphr tx verify --identity <pr>
```

Example output:

```text
Verification: OK
  Identity: U5XUZots-WmQ...
  Commits: 3 verified
  Transactions: 5 verified
  PS: 7kB2n9xF...
```

### `cyphr export`

Export an identity to a JSONL (JSON Lines) file. Each line is one
serialized commit.

```bash
cyphr export --identity <pr> --output principal.jsonl
```

### `cyphr import`

Import an identity from a JSONL file.

```bash
cyphr import --input principal.jsonl
```

## Walkthrough

A complete session creating an identity, adding a key, and verifying:

```bash
# Create an identity
cyphr init
# Created identity
#   pr: U5XUZots-WmQ...
#   keys:
#     U5XUZots-WmQ... (ES256) [-]

# Generate a second key
cyphr key generate --tag phone
# Generated ES256 key
#   tmb: rT3kMn7x...
#   tag: phone

# Add the second key to the identity
cyphr key add --identity U5XUZots-WmQ... --key rT3kMn7x... --signer U5XUZots-WmQ...

# Inspect the updated state
cyphr inspect --identity U5XUZots-WmQ...

# Verify integrity
cyphr tx verify --identity U5XUZots-WmQ...
```

## Output Formats

All commands support `--output json` for machine consumption:

```bash
cyphr inspect --identity <pr> --output json
```

```json
{
  "pr": "U5XUZots-WmQ...",
  "ps": "7kB2n9xF...",
  "ks": "U5XUZots-WmQ...",
  "as": "U5XUZots-WmQ...",
  "active_keys": [...],
  "commit_count": 3
}
```
