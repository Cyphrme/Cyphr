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
into `/push` and `/tip`, the offline verification procedure those
signatures enable, and tip-vs-tip equivocation evidence built on top of
that claim schema (below). It does not cover cross-kind equivocation
(commit receipt vs. tip report) or third-party key-inclusion proofs --
both are later, separate designs.

## The attestor condition

Receipts are issued if and only if the attestor condition holds:
`AppState.principal` AND `AppState.identity` are both `Some`, matched
explicitly, never assumed from one field's presence
(`docs/specs/server-identity.md` `[identity-r-both-options]`). A keyless
server, and a keyed-but-unbootstrapped process, emit `Envelope::unsigned`
exactly as before this document -- byte-compatible with every prior
release.

Enforced in `rs/cyphr-server/src/routes.rs`'s `push()` and `tip()`
handlers, and covered by `rs/cyphr-server/tests/receipts.rs`'s
`keyless_push_and_tip_responses_stay_unsigned` and
`keyed_but_unbootstrapped_push_and_tip_responses_stay_unsigned`.

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
be replayed across purposes -- the same replay-across-purposes closure
bearer tokens already apply.

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

Implemented in `rs/cyphr-server/src/receipt.rs`'s
`COMMIT_RECEIPT_TYP`, `TIP_REPORT_TYP`, and `sign_receipt`; pinned by
the byte-exact golden vectors `rs/cyphr-server/tests/golden/receipt_commit.json`
and `receipt_tip.json`.

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

Enforced in `rs/cyphr-server/src/routes.rs`: `patch()`, `entity()`,
the `auth::login` handlers, and `identity()` all construct
`Envelope::unsigned` unconditionally.

### `[receipts-r-attestor-only]` Only an attestor signs

`docs/specs/server-identity.md` `[identity-r-both-options]`'s match
governs receipts too: a keyless server and a keyed-but-unbootstrapped
process both emit `Envelope::unsigned`, byte-compatible with every
response those configurations produced before this document.

Covered by `rs/cyphr-server/tests/keyless_matrix.rs` and
`rs/cyphr-server/tests/receipts.rs`.

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

`rs/cyphr-server/src/receipt.rs`'s `sign_receipt` has no side effects
beyond signing, and this design introduces no new persistence surface.

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

Implemented in `rs/cyphr-server/src/routes.rs`'s
`IdentityResponse::Attestor.genesis` and `GenesisKeyInfo`; exercised by
`rs/cyphr-server/tests/receipts.rs`'s
`offline_verification_replays_chain_and_verifies_commit_receipt`.

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
   public key from the replayed principal's active key material (step 5) -- never from discovery's own current-key claim.

A verifier that completes all six steps has established the receipt's
authenticity using only material it fetched and validated itself: no
step trusts a bare assertion from the server under scrutiny.

Exercised end-to-end by `rs/cyphr-server/tests/receipts.rs`'s
`offline_verification_replays_chain_and_verifies_commit_receipt`.

## Equivocation evidence

Two conflicting signed tip reports about the same principal state are
portable, self-contained proof of server misbehavior: a verifier
holding both raw receipts needs nothing further to demonstrate the
server signed two different, mutually exclusive claims about the
identical chain position -- the same shape of evidence Certificate
Transparency's split-view detection and KERI's duplicity model both
rest on. Detection is verifier-side and stateless: the server neither
detects nor stores anything toward this; the check is a pure function
a verifier runs on bytes it already retained.

### The pinned predicate

Two cozies are a proven equivocation if and only if:

1. Both pays carry `typ == TIP_REPORT_TYP` -- a commit receipt
   smuggled in as either side is rejected outright, not diagnosed
   further.
2. EACH signature verifies under its own caller-supplied key. The
   helper takes TWO keys, one per receipt -- possibly identical (the
   same-key case is the degenerate form of a cross-key-rotation
   pair). The caller MUST have already verified both keys as active
   keys of the SAME server principal's chain at each receipt's `now`,
   via the offline verification procedure above; the helper never
   resolves or chain-checks keys itself, which is what keeps it pure
   while still covering the cross-rotation case -- the server's
   identity is its CHAIN, not any single key.
3. Both claim the same `pr` AND the same `sequence`.
4. They differ in `commit_id` OR in any `roots` field.

Anything else is a diagnosed non-equivocation, distinguished by
outcome: wrong `typ`, an unverifiable signature, a different
principal, a different sequence, or claim-identical reports (no
conflict at all).

Implemented in `rs/cyphr-server/src/receipt.rs`'s
`EquivocationVerdict` and `check_equivocation`; all seven arms are
covered by `rs/cyphr-server/tests/equivocation.rs`.

### What a verifier retains

Exactly two things, nothing else: the two raw receipt cozies (`pay`
and `sig` together, byte-exact) and the server-chain segment that
binds BOTH signing keys as active for the attested principal at each
receipt's `now` (the segment may span a rotation, so the two keys can
differ). No server cooperation, no additional server-side record, and
no timestamp beyond what the receipts themselves carry is needed to
reconstruct or re-check the proof later.

### What the server cannot deny

Both statements carry the server's own signature over conflicting
facts about the same chain position. A signature the server's key
produced is not repudiable by the server after the fact -- the same
non-repudiation property the claim schema above gives every receipt --
so a verifier holding both cozies holds proof the server made two
irreconcilable claims about one commit sequence, independent of
whether the server admits, explains, or disputes it.

### Deferred: cross-kind conflict

This predicate pins tip-vs-tip only. A commit receipt (`/push`) and a
tip report (`/tip`) making conflicting claims about the same
`pr`/`sequence` is a distinct, later extension: comparing across the
two `typ` constants requires deciding which claims are even
comparable between the two schemas (a tip report carries
`commit_count`/`last_updated`; a commit receipt does not), which this
document does not settle. `check_equivocation` rejects a mixed-`typ`
pair outright rather than attempting a partial comparison.

## Roadmap: not built here

Third-party key-inclusion proofs, and cross-kind equivocation (commit
receipt vs. tip report, "Deferred: cross-kind conflict" above), are
both later designs, out of scope for this document.
