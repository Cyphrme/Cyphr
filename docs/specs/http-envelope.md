# SPEC: HTTP Response Envelope

<!--
  Implementation-domain design record for the cyphr-server HTTP response
  envelope. This document does NOT replace SPEC.md; it records rulings the
  spec leaves to the implementation (the HTTP transport layer).

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
  "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be
  interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
  when, they appear in all capitals.
-->

## Domain

**Problem Domain:** The versioned envelope that wraps cyphr-server's HTTP
JSON responses. The envelope carries an explicit version, the
endpoint-specific payload, and an OPTIONAL server statement — a coz
(`{pay, sig}`) the server signs over the response. Its purpose is to keep
the wire format from calcifying: an unversioned, unsigned JSON body cannot
later grow a server attestation without breaking every client, so the
version and the statement slot are designed in from day one even though
this server does not yet sign responses.

**Target System:** `rs/cyphr-server` — the HTTP response layer only. The
envelope is transport: it *carries* a coz, it does not change the coz wire
format (`{pay, sig, key?}`), which is SPEC.md's and the `coz` crate's.

**Scope boundary:** This document defines the container and records the
rulings below. It does not wrap any handler's response (that is a later
adoption step) and does not define what a signed statement's payload
*claims* (that is the server-receipt design, later still). This document
pins only that the slot is a coz.

## Wire shape

Every JSON response body is an envelope object with three fields, in this
order:

```json
{
  "v": 1,
  "payload": { "...": "endpoint-specific" },
  "statement": { "kind": "unsigned" }
}
```

A response the server has attested carries the statement as a coz:

```json
{
  "v": 1,
  "payload": { "...": "endpoint-specific" },
  "statement": {
    "kind": "signed",
    "coz": { "pay": { "...": "signed claims" }, "sig": "…base64url…" }
  }
}
```

- `v` — an integer wire version, present in both forms. `[envelope-version]`
- `payload` — the endpoint-specific response object, unchanged from its
  pre-envelope shape (adoption wraps the existing struct).
- `statement` — the server statement slot, always present and explicitly
  discriminated by `kind`. `"unsigned"` is an explicit marker; `"signed"`
  carries the coz under `coz`. `[envelope-statement-structural]`

### `[envelope-version]` Explicit integer version

The envelope MUST carry a `v` field present in both signed and unsigned
forms. It is an integer (not a string): smaller on the wire, ordered, and
trivially compared. The current version is `1`.

Implemented by `ENVELOPE_VERSION` and `Envelope::v` in
`rs/cyphr-server/src/envelope.rs`; the golden vectors show `v` present
in both forms.

### `[envelope-statement-structural]` Structural signed/unsigned distinction

Signed and unsigned forms MUST be distinguishable by structure, never by
the mere absence of a signature a client could misread as attestation. The
`statement` object is therefore always present and tagged by `kind`: an
unsigned response is `{"kind":"unsigned"}` — an affirmative "the server did
not attest this", not a missing field. A client decides trust by reading
`statement.kind`, never by probing for a `sig`. The signed form nests a
pristine coz under `coz`, byte-identical to a standalone coz, so a verifier
can lift `{pay, sig}` out unchanged.

Implemented by `rs/cyphr-server/src/envelope.rs`'s `Statement` (serde
`tag="kind", content="coz"`); covered by a structural-distinction unit
test, and the two golden vectors differ by `kind`, not by omission.

## Rulings

Six rulings the envelope requires. Each is explicit; silence is not a
ruling.

### `[envelope-r-entity]` Entity endpoint — EXCLUDED

`GET /e/{digest}` does NOT participate in the envelope. The response is
content-addressed bytes (`application/octet-stream`) that self-verify: a
client hashes the bytes and checks them against the digest it requested, so
the entity is already tamper-evident without a server statement. Wrapping
it would force a binary→base64 JSON re-encoding and add envelope bytes for
no trust gain. The bytes stay raw.

Implemented by `entity()` in `rs/cyphr-server/src/routes.rs:220-246`,
returning a raw octet-stream keyed by the requested `TaggedDigest`.

### `[envelope-r-auth]` Challenge and login — INCLUDED

`POST /auth/challenge` and `POST /auth/login` JSON responses DO join the
envelope. The motive is a single, uniform version story: every JSON body a
client parses carries `v` in the same place, so version detection is one
mechanism, not a per-endpoint special case. The bearer token in a login
response is itself already a signed coz, but that is the token's own
signature over auth claims — orthogonal to the envelope's response-level
statement slot, which stays `unsigned` for these endpoints until a
later adoption step signs responses.

`ChallengeResponse` and `LoginResponse`
(`rs/cyphr-server/src/auth/login.rs:311-324`) are bare JSON today.

### `[envelope-r-error]` Error bodies — NOT enveloped

Error responses keep their current bare shape, `{"error": "<message>"}`,
and are NOT wrapped. HTTP status codes already carry the live semantics
(400/401/404/409/422/500), and an error body is not a state-or-time claim
the server would ever attest. Enveloping errors would add a version and an
always-`unsigned` statement to bodies that gain nothing from either, and
complicate the uniform `AppError::into_response` path. Errors stay as-is.

`AppError::into_response` (`rs/cyphr-server/src/error.rs:64-68`) emits
`{"error": message}`; the status code carries the semantics.

### `[envelope-r-migration]` Migration — flag-day, version-gated

Adopting the envelope is a breaking wire change. cyphr-server is pre-1.0
(`Cargo.toml` version `0.1.0`, molten), so the cutover is a flag-day: the
enveloped shape replaces the bare shape outright, with no dual-serving
window. The `v` field IS the forward migration path — it is what makes the
break detectable rather than silent. A client detects the transition
structurally: a pre-envelope client that expected `commit_count` at the top
level now finds `payload.commit_count` and an unfamiliar `v`; a
version-aware client reads `v` first and, on an unrecognized value, fails
closed (refuses to interpret the body) rather than guessing. Because every
future envelope change bumps `v`, a client never has to distinguish
envelope revisions by probing individual fields.

`rs/cyphr-server/Cargo.toml` is version `0.1.0` (pre-1.0);
`ENVELOPE_VERSION = 1` is the first version clients gate on.

### `[envelope-r-status]` HTTP status codes — PRESERVED

The envelope MUST NOT collapse or relocate HTTP status semantics into the
body. Success responses keep their codes (200 OK for tip/patch, 201 CREATED
for push) and the envelope rides only inside those 2xx bodies. Error paths
keep their non-2xx codes and their bare error body. A client still branches
on the HTTP status first; the envelope never becomes a `200`-wrapping-an-
error anti-pattern.

`rs/cyphr-server/src/routes.rs:212-217` (201 CREATED on push) and
`error.rs:83-126` (status mapping) are unchanged by the envelope
adoption.

### `[envelope-r-cr]` Commit Root in the tip payload — INCLUDED

The tip payload SHOULD carry `cr` (Commit Root), which today's
`TipResponse` omits even though the storage layer's `TipState` provides it.
`cr` is a legitimate element of a principal's attestable state; a future
signed statement over a tip could not attest the commit root if the payload
never carried it. The envelope-adoption step (which wraps
`TipResponse`) adds the field; this document records the ruling that
it belongs in the payload.

`rs/cyphr-storage/src/index/types.rs:97` has `TipState.cr` present,
while `rs/cyphr-server/src/routes.rs:57-65`'s `TipResponse` (before
this ruling) omitted `cr`.

## Statement payload — deferred

What a signed statement's `pay` *claims* (its `typ`, and whether it binds a
digest of the payload, the tip, or something else) is NOT settled here.
This document pins only that the slot is a coz `{pay, sig}`. The golden vector's
signed `pay` is illustrative, not normative: it demonstrates a valid coz in
the slot, not the claim schema a server-receipt design will define. The `v`
field is the escape hatch — settling those semantics later bumps the
version rather than silently reinterpreting `v: 1` bytes.
