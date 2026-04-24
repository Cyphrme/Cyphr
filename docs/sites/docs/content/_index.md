+++
title = "cyphr"
description = "Self-sovereign identity protocol — documentation"
+++

# cyphr

**cyphr** is a self-sovereign identity protocol built on cryptographic state
trees. It replaces passwords with public key cryptography, enabling secure
multi-device authentication, key rotation and revocation, and individually
signed atomic actions — all without a central authority.

Built on [Coz](https://github.com/Cyphrme/Coz) cryptographic JSON messaging
and [MALT](https://github.com/Cyphrme/malt) append-only Merkle trees.

> These docs are under active development. The protocol specification is the
> canonical reference; the guides here will expand as the project matures.

## Getting Started

<nav class="section-nav">
  <a href="getting-started/go.html" class="section-link">
    <strong>Go</strong>
    <span>Install the module, create a principal, and inspect identity state.</span>
  </a>
  <a href="getting-started/rust.html" class="section-link">
    <strong>Rust</strong>
    <span>Add the crate, construct a principal, and explore the type system.</span>
  </a>
</nav>

## Reference

<nav class="section-nav">
  <a href="specification.html" class="section-link">
    <strong>Protocol Specification</strong>
    <span>The authoritative protocol specification — state trees, transactions, commits, and beyond.</span>
  </a>
</nav>

## Links

- Source: [github.com/Cyphrme/Cyphr](https://github.com/Cyphrme/Cyphr)
- Rust crate: [crates.io/crates/cyphr](https://crates.io/crates/cyphr)
- Go module: [github.com/cyphrme/cyphr](https://pkg.go.dev/github.com/cyphrme/cyphr)
- Blog: [blog.cyphr.me](https://blog.cyphr.me)
