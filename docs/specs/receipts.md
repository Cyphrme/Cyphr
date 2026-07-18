# SPEC: Server Receipts

<!--
  Implementation-domain design record for cyphr-server's signed
  commit-acceptance receipts and tip reports. This document does NOT
  replace SPEC.md; it settles the response envelope's statement slot
  (`docs/specs/http-envelope.md`'s "Statement payload -- deferred"
  section) for the two endpoints that attest server-observed facts, the
  same role `docs/specs/server-identity.md` plays for the discovery
  endpoint.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
  "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be
  interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
  when, they appear in all capitals.
-->

## Domain

**Problem Domain:** An attestor -- a keyed, bootstrapped cyphr-server --
can do more than accept and serve commits: it can sign a statement over
what it just did or currently sees, giving a client something
attributable to hold onto and later prove to a third party. This
document defines that statement's claim schema for the two endpoints
where it applies, and the procedure by which a client verifies a
receipt entirely offline, without trusting the server again.

**Target System:** `rs/cyphr-server` -- the `/push` and `/tip` handlers'
statement slot (`src/routes.rs`), the composition module that builds and
signs it (`src/receipt.rs`), and the genesis-key extension to `GET
/server`'s attestor payload (`src/routes.rs`'s `IdentityResponse`).

**Scope boundary:** This document covers exactly what an attestor signs
into `/push` and `/tip`, and the offline verification procedure those
signatures enable. It does not cover equivocation detection (comparing
two receipts for the same principal and sequence) or third-party
key-inclusion proofs -- both are later, separate designs built on top of
the claim schema this document pins.

## The attestor condition

Receipts are issued if and only if the attestor condition holds:
`AppState.principal` AND `AppState.identity` are both `Some`, matched
explicitly, never assumed from one field's presence
(`docs/specs/server-identity.md` `[identity-r-both-options]`). A keyless
server, and a keyed-but-unbootstrapped process, emit `Envelope::unsigned`
exactly as before this document -- byte-compatible with every prior
release.

`VERIFIED: rs/cyphr-server/src/routes.rs -- push() and tip() match (&state.principal, &state.identity); rs/cyphr-server/tests/receipts.rs -- keyless_push_and_tip_responses_stay_unsigned, keyed_but_unbootstrapped_push_and_tip_responses_stay_unsigned`

## Claim schema

A receipt is an ordinary coz (`{pay, sig}`), composed and signed exactly
as a bearer token (`src/auth/token.rs`'s `issue_token`): `coz::Pay::new()`,
a dedicated `typ`, extra claims, serde to bytes, `identity.sign`,
`coz::CozJson{pay, sig}`. It carries no payload-byte binding -- the
claims themselves ARE the attestation, and a client cross-checks them
against the enveloped payload's own fields.

### `typ` constants

- `cyphr-server/receipt/commit` -- a commit-acceptance receipt (`/push`).
- `cyphr-server/receipt/tip` -- a tip report (`/tip`).

Each is a dedicated constant, distinct from the bearer token's
`cyphr-server/auth/token`, so no signature the server key produces can
be replayed across purposes (the F22 lesson bearer tokens already
close).

### Standard fields (both kinds)

- `alg` -- the signing algorithm.
- `now` -- the server's signing time, i64 Unix seconds. No sub-second
  precision is introduced anywhere in this design; the chain's native
  timestamp form is the only one used.
- `tmb` -- the signing key's thumbprint (b64ut).
- `typ` -- one of the two constants above.

### Claims (both kinds)

- `pr` -- the ATTESTED principal's genesis identifier (matching the
  bearer token's field name for the same concept).
- `sequence` -- the accepted/attested commit's 0-indexed position,
  derived as the post-state tip's `commit_count - 1`.
- `commit_id` -- the accepted/attested commit's id.
- `roots` -- a nested object, `{pr, sr, ar, cr}`, carrying the
  post-state roots exactly as the tip payload does. Nested so the root
  `pr` (the post-commit Principal Root) never collides with the
  top-level `pr` claim (the genesis identifier) -- the two are different
  facts that happen to share a SPEC field name. All four values are
  tagged digest strings, satisfying SPEC §2.2.3's explicitly-labeled
  exemption.

### Additional claims (tip reports only)

- `commit_count` -- the principal's total commit count.
- `last_updated` -- the timestamp of the most recent commit.

No other claims are carried by either kind.

`VERIFIED: rs/cyphr-server/src/receipt.rs -- COMMIT_RECEIPT_TYP, TIP_REPORT_TYP, sign_receipt; rs/cyphr-server/tests/golden/receipt_commit.json, receipt_tip.json -- byte-exact vectors`

## Rulings

### `[receipts-r-push-tip-only]` Only push and tip carry a statement

Patch, entity, auth, and discovery responses stay unsigned. Silence is
not a ruling -- each is recorded explicitly:

- **Patch -- EXCLUDED.** Patch content is self-certifying chain data:
  every coz it returns already carries its own signature, and the tip
  report (not a per-commit statement) is the freshness attestation over
  that chain. Signing patch responses would attest nothing a client
  cannot already verify from the coz content itself.
- **Entity -- EXCLUDED**, unchanged from `docs/specs/http-envelope.md`
  `[envelope-r-entity]`: raw content-addressed bytes never join the
  envelope at all.
- **Auth (`/auth/login`, `/auth/challenge`) -- EXCLUDED.** The bearer
  token issued by a successful login is itself already a signed coz;
  layering a second, redundant server statement over the response that
  carries it adds no new attestable fact.
- **Discovery (`GET /server`) -- EXCLUDED.** Its own statement slot
  remains `Envelope::unsigned`, unchanged from
  `docs/specs/server-identity.md`'s "Statement payload -- deferred"
  section: the TOFU story does not depend on a signature over discovery
  itself, since chain replay against the pinned PG is the verification.

`VERIFIED: rs/cyphr-server/src/routes.rs -- patch(), entity(), auth::login handlers, identity() all construct Envelope::unsigned unconditionally`

### `[receipts-r-attestor-only]` Only an attestor signs

`docs/specs/server-identity.md` `[identity-r-both-options]`'s match
governs receipts too: a keyless server and a keyed-but-unbootstrapped
process both emit `Envelope::unsigned`, byte-compatible with every
response those configurations produced before this document.

`VERIFIED: rs/cyphr-server/tests/keyless_matrix.rs (unmodified); rs/cyphr-server/tests/receipts.rs`

### `[receipts-r-stateless]` Issuance is stateless (decision D2)

The server persists nothing new to issue a receipt: no receipt log, no
retention window, no server-side received-at timestamp. The recipient
holds the trust object -- the same pattern Certificate Transparency's
SCTs and KERI's signed events use: the issuer signs and forgets, and the
receiving party is responsible for retaining what it needs to later
prove.

A client that wants to rely on a receipt later (as evidence toward
equivocation detection, or simply as its own record of "the server
accepted this") MUST retain the receipt itself -- its `pay` and `sig`
together are the complete, self-contained trust object. Nothing else
needs to be retained alongside it: the claims already carry everything
the offline verification procedure below needs, given a pinned PG and
the ability to fetch the server's chain.

`VERIFIED: rs/cyphr-server/src/receipt.rs -- sign_receipt has no side effects beyond signing; no new persistence surface anywhere in this node's diff`

### `[receipts-r-genesis-hint]` The genesis key is a trustless hint

`GET /server`'s attestor payload gains a nested `genesis` object
(`alg`, `pub`, `tmb`, `first_seen`), distinct from the existing
current-key fields (which describe whichever key is active right now
and may differ from the genesis key after a rotation). The genesis key
is published because it is not otherwise reconstructible from served
blobs: the server's `principal/create` cozy carries no embedded key
material (`rs/cyphr-server/src/auth/principal.rs`'s `build_genesis`), so
a third-party verifier has no other public source for it.

Publishing it is safe precisely because it is a HINT, not a trusted
assertion: a client that receives it MUST independently re-derive the
PG from it alone (`cyphr::Principal::explicit(vec![genesis_key])` then
`pr_tagged()`) and refuse to proceed if the result does not match the
pinned `pg`. Only after that derivation succeeds does the genesis key
become useful -- as the seed for replaying the server's own chain, never
as a trusted fact in itself.

`VERIFIED: rs/cyphr-server/src/routes.rs -- IdentityResponse::Attestor.genesis, GenesisKeyInfo; rs/cyphr-server/tests/receipts.rs -- offline_verification_replays_chain_and_verifies_commit_receipt`

## Offline verification procedure

A client verifies a receipt without ever re-trusting the server that
issued it, using only HTTP responses and local replay:

1. **Pin the PG and the genesis-key hint from `GET /server`.** Record
   the attestor payload's `pg` and its nested `genesis` object.
2. **Re-derive the PG from the genesis key alone.** Construct
   `cyphr::Principal::explicit(vec![genesis_key])` and call `pr_tagged()`.
   If the result does not equal the pinned `pg`, refuse loudly -- the
   published genesis key does not back the pinned identity.
3. **Fetch the server's own chain via `GET /patch?pr=<pg>`.** The server
   is an ordinary principal in its own store
   (`docs/specs/server-identity.md`'s TOFU story, step 4), served
   through the same public surface every other principal's chain is.
4. **Replay into a SECOND, independent local engine** -- a fresh
   in-memory `StorageEngine`, never the server's own engine or state.
   Submit each patch entry's blobs via `submit_commit`, passing
   `Genesis::Explicit(vec![genesis_key])` explicitly on every call: the
   genesis key is never embedded on the wire, so auto-detection cannot
   recover it from the replayed blobs themselves.
5. **Confirm the receipt's signing key is active in the REPLAYED
   chain**, not merely asserted by discovery: load the fully replayed
   principal and check `is_key_active(receipt.tmb)`.
6. **Verify the signature with plain `coz::verify_json`**, sourcing the
   public key from the replayed principal's active key material (step
   5) -- never from discovery's own current-key claim.

A verifier that completes all six steps has established the receipt's
authenticity using only material it fetched and validated itself: no
step trusts a bare assertion from the server under scrutiny.

`VERIFIED: rs/cyphr-server/tests/receipts.rs -- offline_verification_replays_chain_and_verifies_commit_receipt`

## Roadmap: not built here

Equivocation detection -- comparing two receipts sharing the same `pr`
and `sequence` but differing `commit_id`/`roots` -- and third-party
key-inclusion proofs are both later designs. The claim schema above is
what makes that comparison well-defined; building the comparison itself
is out of scope for this document.
