# Cyphrpass

**Self-sovereign identity and authentication built on cryptographic state trees.**

Cyphrpass replaces passwords with public key cryptography, enabling secure multi-device authentication, key rotation, and individually-signed atomic actions—all without a central authority.

```
┌──────────────────────────────────────────────────────────────────┐
│                          PRINCIPAL                               │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │  Principal Root (PR) — Permanent identity, never changes  │   │
│  └───────────────────────────────────────────────────────────┘   │
│                               ▼                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │  Principal State (PS) = MR(CS, DS?)                       │   │
│  └───────────────────────────────────────────────────────────┘   │
│            ▼                              ▼                      │
│  ┌──────────────────────┐     ┌───────────────────────┐          │
│  │  Commit State (CS)   │     │   Data State (DS)     │          │
│  │  = MR(AS, CommitID)  │     │   = H(action czds)    │          │
│  └──────────────────────┘     └───────────────────────┘          │
│            ▼                                                     │
│  ┌──────────────────────┐                                        │
│  │   Auth State (AS)    │                                        │
│  │   = MR(KS, RS?)      │                                        │
│  └──────────────────────┘                                        │
│         ▼        ▼                                               │
│  ┌──────────┐ ┌──────┐                                           │
│  │  KS      │ │  RS  │                                           │
│  │ (keys)   │ │(rule)│                                           │
│  └──────────┘ └──────┘                                           │
└──────────────────────────────────────────────────────────────────┘
```

## The Problem

The internet's authentication layer is broken:

- **Passwords** are inherently insecure—phished, leaked, and reused across services
- **OAuth/SSO** centralizes identity under tech giants who control access to the digital world
- **No non-repudiation**—users can't prove they authored content; platforms can manipulate history
- **No portability**—your identity is fragmented across services, owned by corporations

## The Solution

Cyphrpass provides **self-sovereign identity** for the internet:

```
┌──────────────────────────────────────────────────────────────────────┐
│  YOU own your keys.  YOU control your identity.  No intermediaries.  │
└──────────────────────────────────────────────────────────────────────┘
```

### Core Principles

| Old World                   | Cyphrpass                                 |
| --------------------------- | ----------------------------------------- |
| Passwords stored on servers | Keys never leave your devices             |
| Identity owned by platforms | Identity = cryptographic root you control |
| Trust corporations          | Verify mathematics                        |
| History can be rewritten    | Every action signed, immutable            |
| Centralized authority       | Decentralized, self-sovereign             |

### Use Cases

**Authentication Without Passwords**

- Login by proving key possession—no secrets transmitted
- Multi-device support with cryptographic key management
- Instant revocation when a device is compromised

**Non-Repudiation & Provenance**

- Journalists sign articles—readers verify authenticity
- Whistleblowers prove authorship without revealing identity
- Historical records with cryptographic proof of origin
- Comments, votes, posts—all individually verifiable

**Decentralized Authority**

- No single point of failure or control
- Portable identity across services
- M-of-N key schemes for organizations
- Recovery without trusting a third party

**Cryptographic Foundation**

- Built on standard algorithms (ES256, ES384, Ed25519)
- Signing, verification, and encrypted communications
- Algorithm-agile—upgrade without losing identity

## Feature Levels

| Level | Description                  | Use Case                      |
| ----- | ---------------------------- | ----------------------------- |
| **1** | Single static key (PR = tmb) | IoT devices, hardware tokens  |
| **2** | Key replacement              | Single-device rotation        |
| **3** | Multi-key management         | Multi-device users            |
| **4** | Authenticated Atomic Actions | Signed posts, comments, votes |
| **5** | Weighted permissions         | M-of-N signing, tiered access |
| **6** | Programmable rules           | Smart contracts               |

## How It Works

1. **Genesis** — Generate a key, derive your permanent identity (PR = thumbprint)
2. **Key Management** — Add/remove/revoke keys via signed transactions
3. **Actions** — Sign atomic operations (posts, votes, etc.) with any authorized key
4. **Verification** — Anyone can verify the chain back to genesis

See implementation READMEs for concrete code examples.

## Commit Chain

Every key mutation forms a cryptographically linked chain:

```
Genesis (tmb)  ──pre──▶  key/create  ──pre──▶  key/revoke  ──pre──▶  ...
     │                       │                      │
     ▼                       ▼                      ▼
    CS₀                     CS₁                    CS₂
```

## Repository Structure

```
Cyphrpass/
├── SPEC.md                 # Full protocol specification
├── docs/                   # Plans, models, ADRs
├── go/                     # Go implementation
│   └── README.md           # Go-specific documentation
├── rs/                     # Rust implementation
│   ├── cyphrpass/          # Core crate
│   ├── cyphrpass-storage/  # Storage crate
│   ├── cyphrpass-cli/      # CLI binary
│   └── README.md           # Rust-specific documentation
├── tests/                  # Language-agnostic test fixtures
│   ├── golden/             # Pre-computed golden fixtures (40 tests)
│   ├── e2e/                # E2E intent files (5 scenarios)
│   └── README.md           # Test fixture documentation
```

## Implementations

| Language | Status        | Package                        |
| -------- | ------------- | ------------------------------ |
| **Go**   | Levels 1-4 ✅ | `github.com/cyphrme/cyphrpass` |
| **Rust** | Levels 1-4 ✅ | `cyphrpass`                    |

Both implementations support Levels 1-4 (single key through authenticated actions). Levels 5-6 (weighted permissions, programmable rules) are specified but not yet implemented.

All tests pass using shared language-agnostic test vectors.

## Built On Coz

Cyphrpass uses [Coz](https://github.com/Cyphrme/Coz) for all cryptographic operations—a JSON messaging specification supporting ES256, ES384, ES512, and Ed25519.

## Documentation

- **[SPEC.md](SPEC.md)** — Full protocol specification
- **[go/README.md](go/README.md)** — Go implementation guide
- **[rs/README.md](rs/README.md)** — Rust implementation guide
- **[tests/README.md](tests/README.md)** — Test fixture documentation
