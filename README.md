# Cyphr

**Self-sovereign identity and authentication built on cryptographic state trees.**

Cyphr replaces passwords with public key cryptography, enabling secure multi-device authentication, key rotation, and individually-signed atomic actions, all without a central authority.

```
┌──────────────────────────────────────────────────────────────────┐
│                          PRINCIPAL                               │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │  Principal Genesis (PG) — Permanent identity, never changes│  │
│  └───────────────────────────────────────────────────────────┘   │
│                               ▼                                  │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │  Principal Root (PR) = MR(SR, CR?)                        │   │
│  └───────────────────────────────────────────────────────────┘   │
│            ▼                              ▼                      │
│  ┌──────────────────────┐     ┌───────────────────────┐          │
│  │  State Root (SR)     │     │  Commit Root (CR)     │          │
│  │  = MR(AR, DR?)       │     │  = MALT(TR₀,TR₁,...) │          │
│  └──────────────────────┘     └───────────────────────┘          │
│            ▼                                                     │
│  ┌──────────────────────┐     ┌───────────────────────┐          │
│  │   Auth Root (AR)     │     │   Data Root (DR)      │          │
│  │   = MR(KR, RR?)      │     │   = H(action czds)    │          │
│  └──────────────────────┘     └───────────────────────┘          │
│         ▼        ▼                                               │
│  ┌──────────┐ ┌──────┐                                           │
│  │  KR      │ │  RR  │                                           │
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

Cyphr provides **self-sovereign identity** for the internet:

```
┌──────────────────────────────────────────────────────────────────────┐
│  YOU own your keys.  YOU control your identity.  No intermediaries.  │
└──────────────────────────────────────────────────────────────────────┘
```

### Core Principles

| Old World                   | Cyphr                                     |
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
    PR₀                     PR₁                    PR₂
```

## Repository Structure

```
Cyphr/
├── SPEC.md                 # Full protocol specification
├── docs/                   # Documentation and planning
│   ├── sites/blog/         # blog.cyphr.me source
│   ├── sites/docs/         # docs.cyphr.me source
│   └── ...                 # Plans, models, charters
├── go/                     # Go implementation (flat package)
│   ├── storage/            # Storage backends
│   ├── testfixtures/       # Test fixture loading
│   └── README.md           # Go-specific documentation
├── rs/                     # Rust implementation
│   ├── cyphr/              # Core crate
│   ├── cyphr-storage/      # Storage crate
│   ├── cyphr-cli/          # CLI binary
│   ├── fixture-gen/        # Golden fixture generation
│   ├── test-fixtures/      # Golden fixture definitions
│   └── README.md           # Rust-specific documentation
├── tests/                  # Language-agnostic test vectors
│   ├── golden/             # Pre-computed golden fixtures
│   ├── e2e/                # E2E scenario files
│   ├── intents/            # Intent definitions per category
│   └── README.md           # Test fixture documentation
```

## Implementations

| Language | Status        | Package                    |
| -------- | ------------- | -------------------------- |
| **Go**   | Levels 1-4 ✅ | `github.com/cyphrme/cyphr` |
| **Rust** | Levels 1-4 ✅ | `cyphr`                    |

Both implementations support Levels 1-4 (single key through authenticated actions). Levels 5-6 (weighted permissions, programmable rules) are specified but not yet implemented.

All tests pass using shared language-agnostic test vectors.

## Built On

- **[Coz](https://github.com/Cyphrme/Coz)** — Cryptographic JSON messaging (ES256, ES384, ES512, Ed25519)
- **[MALT](https://github.com/Cyphrme/malt)** — Merkle Append-only Log Tree

## Documentation

- **[docs.cyphr.me](https://docs.cyphr.me)** — Getting started guides, CLI reference, and glossary
- **[blog.cyphr.me](https://blog.cyphr.me)** — Project blog
- **[SPEC.md](SPEC.md)** — Full protocol specification
- **[go/README.md](go/README.md)** — Go implementation guide
- **[rs/README.md](rs/README.md)** — Rust implementation guide
- **[tests/README.md](tests/README.md)** — Test fixture documentation
