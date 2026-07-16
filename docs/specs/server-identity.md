# SPEC: Server Identity Discovery

<!--
  Implementation-domain design record for cyphr-server's identity and
  capability discovery endpoint. This document does NOT replace SPEC.md;
  it records rulings the spec leaves to the implementation (the HTTP
  transport layer), the same role `docs/specs/http-envelope.md` plays for
  the response envelope this endpoint rides in.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
  "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be
  interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
  when, they appear in all capitals.
-->

## Domain

**Problem Domain:** A single GET endpoint through which a cyphr-server
publishes what it honestly is: a keyed server ("attestor") names its
stable Principal Genesis (PG) and its current signing key; a keyless
server ("repository") says so and nothing more. This is the trust root a
client's offline verification starts from -- pin the PG here, then fetch
and replay the server's own chain through the ordinary storage surface to
verify any later key.

**Target System:** `rs/cyphr-server` -- one route (`GET /server`), its
handler, and its response payload type. It reads two `AppState` fields
and writes nothing.

**Scope boundary:** This document covers exactly the tier declaration and
the identity fields that accompany it. It does NOT define a fuller
capability-declaration surface (supported algorithms, protocol levels,
rate limits) -- that is a roadmap item, noted below. It does NOT sign the
response; the payload rides in `Envelope::unsigned` like every other
response today (`docs/specs/http-envelope.md`), and giving the server a
statement over its own discovery payload is a later node's concern.

## Route choice

`GET /server`. A short, unversioned-prefix path was chosen over something
like `/v1/server` or `/meta`: the envelope's `v` field
(`docs/specs/http-envelope.md` `[envelope-version]`) already versions the
body, so a second version marker in the path would be redundant. `/meta`
was considered and rejected as a name -- it invites exactly the wider
capability surface this node explicitly does not build (see Roadmap
below), and a route name should not promise more than its handler
delivers.

`VERIFIED: rs/cyphr-server/src/lib.rs:154 -- build_router registers GET /server`

## Wire shape

The response is an ordinary enveloped JSON body. The `payload` is
internally tagged by `tier`, so a client reads the capability level
structurally -- the same discipline the envelope's `statement.kind`
already uses (`docs/specs/http-envelope.md` `[envelope-statement-structural]`).

A keyed, bootstrapped server:

```json
{
  "v": 1,
  "payload": {
    "tier": "attestor",
    "pg": "cGdA...tagged-digest",
    "alg": "Ed25519",
    "pub": "…base64url…",
    "tmb": "…base64url…"
  },
  "statement": { "kind": "unsigned" }
}
```

A keyless server, or a keyed process whose principal has not been
bootstrapped:

```json
{
  "v": 1,
  "payload": { "tier": "repository" },
  "statement": { "kind": "unsigned" }
}
```

- `tier` -- `"attestor"` or `"repository"`, lowercase, always present.
- `pg`, `alg`, `pub`, `tmb` -- present ONLY on `attestor`. `pg` is the
  server's stable Principal Genesis (a tagged digest, the same identifier
  `GET /tip?pr=<pg>` and `GET /patch?pr=<pg>` serve the chain under).
  `alg`, `pub`, `tmb` describe the server's CURRENT signing key: `pub` and
  `tmb` are base64url, matching the encoding every other coz-adjacent
  field on the wire uses.

`VERIFIED: rs/cyphr-server/src/routes.rs:104-118 -- IdentityResponse, #[serde(tag = "tier", rename_all = "lowercase")]`

### `[identity-r-absence]` Repository carries no identity-shaped fields

A `repository` payload MUST NOT carry `pg`, `alg`, `pub`, or `tmb` --
neither as empty strings nor as `null`. The internally tagged enum makes
this structural rather than a convention a handler could violate by
accident: the `Repository` variant has no fields to populate, so there is
nothing for a hasty edit to leave as a placeholder. A client that finds
`payload.tier == "repository"` therefore never needs to also check
whether the identity fields are empty -- their absence from the object is
the whole signal.

`VERIFIED: rs/cyphr-server/tests/identity_publication.rs -- keyless_server_declares_repository_with_no_identity_fields, keyed_but_unbootstrapped_principal_declares_repository (payload.get("pg").is_none(), etc.); rs/cyphr-server/tests/keyless_matrix.rs -- keyless_discovery_declares_repository_tier`

### `[identity-r-both-options]` Attestor requires both AppState options

The handler declares `attestor` if and only if `AppState.principal` AND
`AppState.identity` are both `Some`. These are two independently settable
fields (`AppState` construction sets `identity` from
`config.signing_key_path`; `principal` is set later, only inside
`serve` (`rs/cyphr-server/src/lib.rs`), by bootstrapping against the
engine) -- a keyed-but-not-yet-bootstrapped process is possible whenever
the router is built directly rather than through `serve()` (every
integration test in this crate does exactly that). The handler matches
the pair explicitly; it never assumes one field's presence implies the
other's.

`VERIFIED: rs/cyphr-server/src/routes.rs:260-278 -- identity() matches (&state.principal, &state.identity)`

### `[identity-r-principal-not-key]` Tier tracks the principal, not the key file

A keyed-but-unbootstrapped process declares `repository`, not `attestor`,
even though a signing key is configured. The reasoning: `attestor` is a
promise that a client can pin something durable and later verify it by
replaying a chain. A signing key alone is not that -- until the principal
is bootstrapped there is no genesis commit, no PG, and no chain to
replay. Declaring `attestor` here would let a client pin a PG that might
never be reachable through `/tip`. The tier therefore tracks
`AppState.principal` (has an established, servable chain been created or
loaded?), not `AppState.identity` (is a key file configured?).

`VERIFIED: rs/cyphr-server/tests/identity_publication.rs -- keyed_but_unbootstrapped_principal_declares_repository`

### `[identity-r-current-key]` Key material comes from the live identity, never the files

`alg`, `pub`, and `tmb` are read exclusively from `AppState.identity` --
the same live, rotation-refreshed handle `auth::login` and
`auth::middleware` sign and verify with
(`AppState::rotate_signing_key` refreshes it after a rotation). `pg` is
read exclusively from `AppState.principal`. The handler never reads the
on-disk genesis record (`server-principal.json`) or the signing-key file
directly: each fact has exactly one source of truth in memory, and that
source is already kept current by the rotation path this endpoint does
not need to know about.

`VERIFIED: rs/cyphr-server/src/routes.rs:260-278; rs/cyphr-server/src/lib.rs:104-137 (AppState::rotate_signing_key)`

### `[identity-r-501-pointer]` The keyless auth rejection points here

`POST /auth/login` and `POST /auth/challenge` on a keyless server reject
with the same 501 as before (`docs/specs/http-envelope.md`
`[envelope-r-auth]`, finding F5), and the rejection text now also names
`GET /server` as where the declared capability tier lives, byte-identical
across both endpoints. A client that gets rejected has somewhere honest
to look rather than being left to guess whether the server is keyless by
design or genuinely broken.

`VERIFIED: rs/cyphr-server/src/auth/login.rs:359-364 -- keyless_identity_rejection(); rs/cyphr-server/tests/keyless_matrix.rs -- capability-absence assertions check message.contains("/server")`

## The TOFU pinning story

This endpoint is the trust root the server-receipts offline verification
starts from. The model is Trust-On-First-Use (TOFU), the same shape
Certificate Transparency and KERI use for a first contact with no prior
out-of-band trust anchor:

1. **Pin the PG on first contact.** A client's first `GET /server`
   against a given host records the returned `pg`. This is the only
   moment trust is extended on faith; every later interaction verifies
   against the pinned value instead of re-trusting the network.
2. **The PG is rotation-stable.** A server's Principal Genesis never
   changes across a key rotation -- rotation extends the chain with a
   `key/replace` commit and leaves the genesis untouched
   (`rs/cyphr-server/src/auth/principal.rs`'s `ServerPrincipal::rotate`
   doc comment). A client that pinned `pg` on day one still recognizes
   the same server after any number of rotations.
3. **The current key is NOT the identity -- the chain is.** `alg`/`pub`/
   `tmb` in an `attestor` payload describe whichever key is active right
   now; trusting them directly (rather than as one point on a verified
   chain) would mean re-doing TOFU on every rotation. The identity that
   persists is the PG and the validated sequence of commits under it.
4. **Verify a later key by replaying the server's own chain.** Because
   the server is an ordinary principal in its own store
   (`rs/cyphr-server/src/auth/principal.rs`'s module doc, SPEC.md
   §3.7.1/§5.1), a client verifies any key the server claims later by
   fetching that chain through the same public surface every other
   principal's chain is served through -- `GET /tip?pr=<pinned-pg>` for
   the current state, `GET /patch?pr=<pinned-pg>` for the commit
   history -- and replaying it with the ordinary protocol validation
   rules. A key is trusted only once it is reached by replaying from the
   pinned genesis, never because the discovery endpoint merely asserted
   it.
5. **A changed PG means a different principal -- refuse loudly.** If a
   later `GET /server` against the same host returns a `pg` that does not
   match the pinned value, the client is not talking to the server it
   trusted before (a redeployment with a fresh genesis, a
   misconfiguration, or an active attack are all indistinguishable from
   the wire alone). The correct response is a loud, visible refusal, the
   same posture WebAuthn and TOFU-SSH take on a changed identity -- never
   a silent re-pin.

## Roadmap: not built here

A fuller capability-declaration surface -- which algorithms the server
accepts, protocol level limits, rate limits, and similar operational
metadata -- is a natural extension of this endpoint's shape but is
explicitly out of scope for this node. This document records the tier
and identity fields only; a later node that adds more fields extends
`IdentityResponse` and this document rather than inventing a second
endpoint.

## Statement payload -- deferred

Whether a future node signs the discovery response (nesting a coz under
`statement` the way `docs/specs/http-envelope.md` describes for other
endpoints) is not settled here. Today's payload is always
`Envelope::unsigned`; the TOFU story above does not depend on a
signature, since the chain replay against the pinned PG is itself the
verification.
