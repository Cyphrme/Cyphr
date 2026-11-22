# cyphr-server HTTP API reference

This is the reference for every route `cyphr-server` serves. It lists each
route's parameters, response shape, status codes, authentication and
rate-limit class, and notes where the code differs from `SPEC.md`. It
describes the code as built; it is not a protocol specification. The
protocol's normative text is `SPEC.md`, and the envelope's design record is
`docs/specs/http-envelope.md`.

Every `SPEC.md` section number and quotation in this reference is from the
spec author's branch tip (`be0663f`). The in-tree `SPEC.md` carries
unratified edits to some cited sections (for example §4.4, §6.4 and §13.7),
so it is not a reliable source for them.

The router in `rs/cyphr-server/src/lib.rs` (`build_router`) registers 15
routes. Every other method and path answers `404` with
`{"error":"route not found"}`. All 15 are documented below.

| Route                  | Purpose                                     | Auth             | Rate class         |
| :--------------------- | :------------------------------------------ | :--------------- | :----------------- |
| `GET /tip`             | Current state of a principal                | none             | `read`             |
| `GET /patch`           | Commit chain delta for a principal          | none             | `read`             |
| `GET /branches`        | Every branch head held for a principal      | none             | `read`             |
| `GET /proof`           | Certificate that a claim holds of the log   | none             | `read`             |
| `GET /evidence`        | Principal-fork evidence                     | none             | `read`             |
| `POST /push`           | Submit a commit bundle                      | optional bearer  | `push`             |
| `POST /revoke`         | Submit a self-signed naked revoke           | none             | `revoke`           |
| `GET /revoked`         | Naked revokes held for named keys           | none             | `read`             |
| `GET /e/{digest}`      | Content-addressed blob lookup               | none             | `read`             |
| `GET /server`          | Server identity and capability tier         | none             | `read`             |
| `GET /healthz`         | Storage liveness probe                      | none             | `read`             |
| `GET /metrics`         | Prometheus counters                         | none             | `read`             |
| `POST /auth/challenge` | Issue a single-use login challenge          | none             | `login`            |
| `POST /auth/login`     | Exchange a signed login for a bearer token  | none (signed)    | `login`            |
| `POST /auth/session`   | Check a bearer token and report its binding | the token (body) | per-IP bucket only |

## Conventions

### Envelope

Every JSON response except those listed under "Not enveloped" is an
envelope (`rs/cyphr-server/src/envelope.rs`):

```json
{
  "v": 1,
  "payload": {},
  "statement": { "kind": "unsigned" }
}
```

`statement` is `{"kind":"unsigned"}` or
`{"kind":"signed","coz":{"pay":{…},"sig":"…"}}`. Clients decide trust from
`statement.kind`, never from the presence of a signature. Routes not named
under "Signed statements" always answer `unsigned`.

Handler errors are envelopes whose payload is `{"error": "<text>", "now":
<unix seconds>}` plus, for some refusals, `"kind": "<stable-kind>"`. Refusals
built by the fences carry no `now`: `{"error": …, "limit_bytes": n}` for a
`413`, `{"error": …, "limit_commits": n}` for a `402`, and `{"error": "rate
limit exceeded"}` for a `429`; the admission `403` is
`{"error": "admission required", "policy": "invite"}`. All are unsigned
envelopes. Branch
on `kind` or the status code, not on `error` text. The kinds are listed in
`docs/guides/operating-a-server.md` ("Refusals name their kind").

**Not enveloped:**

- `GET /e/{digest}` returns raw `application/octet-stream` bytes
  (`[envelope-r-entity]` in `docs/specs/http-envelope.md`).
- `GET /healthz` returns a bare JSON object (`{"status":"ok"}`), not an
  envelope. `docs/specs/http-envelope.md` records it as an explicit exclusion
  (`[envelope-r-healthz]`).
- `GET /metrics` returns `text/plain; version=0.0.4; charset=utf-8`.
- A request whose query string does not deserialize (a missing `pr`, a
  non-numeric `to`) is rejected by the web framework's query extractor with
  `400` before any handler runs. This reference does not pin that body's
  shape; it was not exercised.
- Unpinned edge, reasoned from the code and not tested: `POST /auth/login`
  and `POST /auth/session` read their body with the framework's `String`
  extractor, so a chunked body (no `Content-Length`) over the cap is likely
  refused by the framework with an un-enveloped `413`. Only `POST /push`
  buffers the body in the fence.

### Signed statements

A signed statement exists only on a server that holds both a bootstrapped
principal and a signing key (an _attestor_; `GET /server` reports
`"tier":"attestor"`). A server that cannot sign, or whose signing fails,
answers the same payload `unsigned`; a client must not read an unsigned
answer as an error.

| Response                                  | `statement.coz.pay.typ`       | Claims                                                                                     |
| :---------------------------------------- | :---------------------------- | :----------------------------------------------------------------------------------------- |
| `GET /tip`, Active                        | `cyphr-server/receipt/tip`    | `pr`, `sequence`, `commit_id`, `roots{pr,sr,ar,cr}`, `commit_count`, `last_updated`        |
| `GET /tip`, in Error; `GET /patch`, Error | `cyphr-server/receipt/held`   | `pr`, `fork_point{height,pre}`, `heads[{commit_id,sequence,held_since}]`; no roots, no tip |
| `GET /patch`, Active                      | `cyphr-server/receipt/tip`    | as `/tip`; only when `to` is absent and the served range reaches the tip (else `unsigned`) |
| `POST /push` (201)                        | `cyphr-server/receipt/commit` | `pr`, `sequence`, `commit_id`, `roots{pr,sr,ar,cr}`                                        |

Every statement's `pay` also carries `alg`, `now` and `tmb` (the signer's
key). `roots.cr` is JSON `null` when no commit root exists yet, never `""`.
`pr` in a statement is the bare principal genesis identifier. Receipt design
is in `docs/specs/receipts.md`. Wire bytes are pinned by
`commit_receipt_matches_golden_vector` and `tip_report_matches_golden_vector`
in `rs/cyphr-server/tests/receipts.rs`; an Error-state `/patch` is signed
only when unbounded (`to` absent).

### Principal identifiers

`pr` (and `principal_id` in `/push`) accepts a tagged digest (`SHA-256:<b64>`)
or a bare canonical base64url digest. Responses name a principal by its bare
digest.

### Rate-limit classes

From `rs/cyphr-server/src/rate_limit.rs` (`classify`). Every request also
draws on the `per_ip` bucket. A refusal is `429`. Defaults and tuning are in
`docs/guides/operating-a-server.md` ("The fences").

| Class    | Requests                                       |
| :------- | :--------------------------------------------- |
| `read`   | every `GET`                                    |
| `push`   | `POST /push`                                   |
| `login`  | `POST /auth/challenge`, `POST /auth/login`     |
| `revoke` | `POST /revoke`                                 |
| (none)   | `POST /auth/session`: the `per_ip` bucket only |

### Status codes every route can return

| Status | When                                                                                                      |
| :----- | :-------------------------------------------------------------------------------------------------------- |
| `413`  | The declared `Content-Length` exceeds the body cap (default 2 MiB), or a body read exceeds it.            |
| `429`  | The `per_ip` bucket or the route's class bucket is empty.                                                 |
| `403`  | Witness mode only: any `POST`, `PUT`, `DELETE` or `PATCH` request (the middleware tests only the method). |

A `POST /push` can additionally draw `402` (per-principal commit quota),
`403` (admission policy) and `503` (admission store unavailable); see that
route. `docs/guides/operating-a-server.md` shows the fence response bodies.

### Engine error mapping

Routes that call the storage engine (`/tip`, `/patch`, `/branches`,
`/evidence`, `/e/{digest}`, `/push`, `/revoke`, and the login routes'
principal lookups) map its failures through one function,
`AppError::engine` (`rs/cyphr-server/src/error.rs`):

| Engine failure                                                         | Status | `kind`                                           |
| :--------------------------------------------------------------------- | :----- | :----------------------------------------------- |
| not found                                                              | `404`  | `not_found`                                      |
| ambiguous (a digest held at several positions)                         | `409`  | `ambiguous`                                      |
| invalid input; malformed blob                                          | `400`  | `invalid_input`, `malformed_blob`                |
| protocol: state mismatch; commit mismatch                              | `409`  | `state_mismatch`, `commit_mismatch`              |
| branch limit reached (principal Active; in Error the refusal is `423`) | `409`  | `branch_limit`                                   |
| a signing key was revoked                                              | `401`  | none                                             |
| principal is in Error: only a fork resolution is admitted              | `423`  | `errored`                                        |
| any other protocol refusal                                             | `422`  | `coz_reuse`, `genesis_incomplete`, or `protocol` |
| protocol storage failure; blob store, index, load or storage failure   | `500`  | none                                             |
| a sync of the record failed, now or earlier (durability lost)          | `500`  | none                                             |

A failed sync of the record is a `500` with the generic body
`{"error":"internal storage error"}`. The engine then refuses every later
write the same way, on every route that writes, until the process
restarts; reads do not check the flag. The cause is in the server log at `error` level
(`internal engine error`, `record not durable, writes refused until restart`). See "Durability"
in `docs/guides/operating-a-server.md`.

The route sections below list only the codes a route adds or where a row
above is reachable in an unexpected way.

## Reads

### `GET /tip`

The principal's current tip. Semantics: `SPEC.md` §13.8 "Suggested API"
(non-normative).

Query: `pr` (string, required): principal identifier.

**200, Active** (`docs/specs/http-envelope.md` `[envelope-r-cr]`):

```json
{
  "v": 1,
  "payload": {
    "principal_id": "<bare PG>",
    "pr": "SHA-256:…",
    "sr": "SHA-256:…",
    "ar": "SHA-256:…",
    "cr": "SHA-256:…",
    "commit_id": "SHA-256:…",
    "commit_count": 3,
    "root": { "size": 3, "pr": { "SHA-256": "<b64url>" } },
    "last_updated": 1700000002,
    "now": 1700000100
  },
  "statement": { "kind": "signed", "coz": { "pay": {…}, "sig": "…" } }
}
```

- `sr`, `ar` are `null` for a Dead principal; `cr` is `null` before any
  commit root exists.
- `root` is `{size, pr}`: the principal's root at its last commit, with
  `size` equal to `commit_count` and `pr` a map from hash family to
  base64url digest. A thin client pins it; `GET /proof` certificates are
  checked against it. It is the server's claim, and a client that has not
  pinned it by other means learns no more from it than the server says.
- Statement: `cyphr-server/receipt/tip` on an attestor.

**200, principal in Error** (SPEC §15.5: no single tip exists):

```json
{
  "v": 1,
  "payload": {
    "state": "error",
    "principal_id": "<bare PG>",
    "fork_point": { "height": 2, "pre": "SHA-256:…" },
    "heads": [
      { "commit_id": "SHA-256:…", "sequence": 2, "held_since": 1700000050 }
    ],
    "now": 1700000100
  },
  "statement": { "kind": "unsigned" }
}
```

`pre` is `null` at height 0; `held_since` is `null` when unrecorded.
Statement: `cyphr-server/receipt/held` on an attestor.

Other statuses:

| Status | When                                                                                                                     |
| :----- | :----------------------------------------------------------------------------------------------------------------------- |
| `404`  | No such principal.                                                                                                       |
| `409`  | Attestor only: the chain no longer holds the tip's commit at its position (a fork resolved during the read); read again. |
| `500`  | The fork state is unreadable from the index, or the re-derived roots disagree with the index (a genuine divergence).     |

In witness mode, a well-formed `pr` is synced from the authority before the
read.

Example: `tip_after_bootstrap` (`rs/cyphr-server/tests/e2e.rs`) for the
payload; `attestor_tip_response_carries_signed_tip_report`
(`rs/cyphr-server/tests/receipts.rs`) for the signed statement;
`tip_root_and_proof_answers_have_the_shapes_and_verify`
(`rs/cyphr-server/tests/head_certificates.rs`) for `root`; `error_heads` in
`rs/cyphr-server/tests/branches.rs` for the Error shape. An unknown
principal, `GET /tip?pr=nonexistent`, is `404` (`tip_unknown_principal`).

**Divergence from SPEC.** SPEC §13.7 (Gossip: "Clients may check
registration through `GET /tip?pr=<principal-root>`, which should return empty
if the principal isn't registered") says the route returns empty. The code
answers `404`.

### `GET /patch`

The principal's commits from a resync anchor, each as a bundle in the push
wire form. Semantics: `SPEC.md` §13.8 and the Resync section (the second `### 13. Resync`).

Query:

| Name   | Type          | Required | Meaning                                                                                |
| :----- | :------------ | :------- | :------------------------------------------------------------------------------------- |
| `pr`   | string        | yes      | Principal identifier.                                                                  |
| `from` | tagged digest | no       | Resync anchor. The response starts at the position after it. Omit to start at genesis. |
| `to`   | unsigned int  | no       | Last commit sequence to serve, inclusive. Omit for the tip.                            |

`from` is a content digest, never a sequence number. It must be held by
exactly one position of this principal's chain; a digest held only by
another principal is `404`, and one held at several positions is `409`.

**200:**

```json
{
  "v": 1,
  "payload": {
    "principal_id": "<bare PG>",
    "entries": [
      {
        "commit_id": "SHA-256:…",
        "sequence": 0,
        "pr": "SHA-256:…",
        "txs": [["<b64url coz>", "…"]],
        "keys": [{ "alg": "ES256", "pub": "<b64url>", "tmb": "<b64url>" }]
      }
    ],
    "actions": [{ "blobs": ["<b64url coz>"] }]
  },
  "statement": { "kind": "unsigned" }
}
```

- Each entry flattens a bundle: `txs` (transactions, each an array of
  base64url coz JSON, the commit transaction last), `keys` (omitted when
  empty), `actions` (omitted when empty; data actions recorded before the
  transactions).
- Top-level `actions` lists every action-only bundle held, whatever range
  the commits cover (SPEC 4.8.1).
- While the principal is in Error, `entries` stop below the fork point and
  two more payload fields appear: `fork_point` (`{height, pre}`) and
  `branches` (`[{head, canonical, entries:[…]}]`, one per branch).
- Statement: see "Signed statements". A bounded response (`to` present) is
  never signed in Active; in Error it is served unsigned when bounded.

| Status | When                                                                      |
| :----- | :------------------------------------------------------------------------ |
| `400`  | `from` is not a parseable digest.                                         |
| `404`  | No such principal, or `from` names no position of this principal's chain. |
| `409`  | `from` is held at several positions of the chain.                         |

Example: `patch_after_bootstrap` and `patch_with_range` in
`rs/cyphr-server/tests/e2e.rs` (`/patch?pr=<id>&to=0` returns one entry,
sequence 0).

**Divergences from SPEC** (§13.8, non-normative):

- SPEC lists `GET /patch?from=<pr>` and `?from=<pr>&to=…` with no `pr`, and
  says "`pr` is optional". The code requires `pr`; a request without it is
  `400`.
- SPEC writes `to=<target-pr>`, a root. The code's `to` is an integer
  commit sequence.

### `GET /branches`

Every branch head the store holds for a principal: the canonical tip and each
retained rival (a commit that verified at its `pre` but took a position the
chain already held). The push that produced a rival was refused (`409`);
`/tip` still reports the canonical chain.

Query: `pr` (string, required).

**200**, always `unsigned`:

```json
{
  "v": 1,
  "payload": {
    "branches": [
      {
        "tip": "SHA-256:…",
        "pre": "SHA-256:…",
        "sequence": 2,
        "canonical": true,
        "seen": 1700000050
      }
    ]
  },
  "statement": { "kind": "unsigned" }
}
```

Exactly one entry is `canonical`; `pre` is `null` at sequence 0; `seen` is
`null` when unrecorded. Entries sort by sequence, canonical first.

| Status | When               |
| :----- | :----------------- |
| `404`  | No such principal. |

Example: `fork_is_listed_under_every_pg_spelling` and
`unforked_principal_lists_only_its_chain_and_unknown_is_404` in
`rs/cyphr-server/tests/branches.rs`. No SPEC text defines this route.

### `GET /proof`

A certificate that a claim holds of the log of the principal's first `size`
commits (`SPEC.md` §4.4; design in `docs/specs/proof-portability.md`). The
server never signs this answer; the asker verifies the certificate against
an anchor it built itself (`cyphr::proof::verify`).

Query:

| Name    | Type         | Required | Meaning                                                            |
| :------ | :----------- | :------- | :----------------------------------------------------------------- |
| `pr`    | string       | yes      | Principal identifier.                                              |
| `size`  | unsigned int | yes      | Size in commits of the log the claim is about. Never defaulted.    |
| `claim` | string       | yes      | `member:<index>` or `extends:<from>`, both with unsigned integers. |

- `member:<i>`: the commit at position `i` is in the log. Payload is
  `{certificate, bundle}`; `bundle` is that commit in the push wire form,
  which the asker needs to compute the transaction root the certificate is
  checked against.
- `extends:<from>`: the log extends the log of the first `from` commits, to
  the root at `size` (the tip's `root` when `size` is the tip). Payload is `{certificate}`.

No other `claim` kind exists. The payload holds those keys and nothing else.

**200:**

```json
{
  "v": 1,
  "payload": { "certificate": {…}, "bundle": { "txs": [["<b64url coz>"]] } },
  "statement": { "kind": "unsigned" }
}
```

| Status | When                                                                                                                                                                                 |
| :----- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `400`  | `size` is not an unsigned integer; `claim` is absent, has no `:`, has a kind other than `member`/`extends`, or an argument that is not an unsigned integer.                          |
| `404`  | No such principal.                                                                                                                                                                   |
| `409`  | The principal is in Error (SPEC 15.5): it has no single log to prove against.                                                                                                        |
| `422`  | The log does not answer the question: `member:<i>` with no commit at `i`; `extends` with no root at `size`; a `size` past the log; a log whose last commit left no keys and no data. |
| `500`  | The log's store failed (`unavailable`), the index's fork state is unreadable, or a commit or certificate could not be encoded.                                                       |

Example: `tip_root_and_proof_answers_have_the_shapes_and_verify`
(`rs/cyphr-server/tests/head_certificates.rs`): `size` omitted is `400`;
`claim=member:1` returns exactly `bundle` and `certificate`; `claim=extends:1`
returns exactly `certificate`; `claim=bogus` and `claim=key:…` are `400`;
`member:<size>` and a `size` one past the log are `422`. The same test
asserts that `/head`, `/inclusion` and `/consistency` answer `404`: those
routes no longer exist.

No SPEC text defines this route.

### `GET /evidence`

Every principal fork the store holds, each item self-describing and
checkable offline by replaying the principal's chain to `height`, checking
its root is `pre`, then replaying each of `a` and `b` from there
(`cyphr_client::evidence`). No server signature takes part.

Query: `pr` (string, required): must parse as a tagged digest or a bare
canonical genesis identifier.

**200**, always `unsigned`:

```json
{
  "v": 1,
  "payload": {
    "items": [
      {
        "kind": "principal-fork",
        "pg": "<bare PG>",
        "height": 2,
        "pre": "SHA-256:…",
        "a": { "txs": [["<b64url coz>"]] },
        "b": { "txs": [["<b64url coz>"]] },
        "a_seen": 1700000050,
        "b_seen": 1700000051
      }
    ]
  },
  "statement": { "kind": "unsigned" }
}
```

`a` is the canonical commit at `height`, `b` the rival; both are bundles in
the push wire form. `pre` is `null` at height 0; `a_seen`/`b_seen` are
`null` when unrecorded. A principal never forked answers `{"items":[]}`. The
server keeps no peer-equivocation evidence.

| Status | When                                            |
| :----- | :---------------------------------------------- |
| `400`  | `pr` is not shaped like a principal identifier. |
| `404`  | No such principal.                              |

Example: `fork_evidence_is_served_and_verified_offline`
(`rs/cyphr-server/tests/evidence.rs`). No SPEC text defines this route.

### `GET /revoked`

The naked revokes this server holds for the named keys (`SPEC.md` §6.4). A
revoke mutates no chain, so a client that replays commits cannot learn of one
from `/patch`.

Query: `tmbs` (string, required): comma-separated base64url thumbprints, at
most 128; empty elements are ignored.

**200**, always `unsigned`: `{"revoked": [<envelope>, …]}`. Each element is
the stored self-signed `{pay, sig, key}`; a key with no revoke on record is
absent from the list. The reader re-verifies each element
(`cyphr_client::verify_naked_revoke`); the server is a mirror, not the
authority.

| Status | When                                                     |
| :----- | :------------------------------------------------------- |
| `400`  | More than 128 thumbprints, or one that is not base64url. |
| `500`  | The observation store failed.                            |

Example: `revoked_serves_the_accepted_naked_revoke_verifiably`
(`rs/cyphr-server/tests/revoked_route.rs`): after `POST /revoke` of
`golden/naked_revoke_valid.json`, `GET /revoked?tmbs=<tmb>,<unknown>`
returns one element; 200 thumbprints return `400`. SPEC §6.4 defines
the revoke; it names no route.

### `GET /e/{digest}`

Content-addressed lookup: the bytes held under a digest.

Path: `digest`, a tagged digest.

**200:** raw `application/octet-stream` bytes, not an envelope. A digest
may name several holders (SPEC 7.6); a coz or blob-hash digest names one
blob, while a state or auth root digest can differ between holders and the
first holder in canonical order is served. The server does not authenticate
the response; a client verifies what it fetches.

| Status | When                                                       |
| :----- | :--------------------------------------------------------- |
| `400`  | The path is not a parseable tagged digest (JSON envelope). |
| `404`  | A well-formed digest the store does not hold.              |

Example: `entity_bad_digest` (`rs/cyphr-server/tests/e2e.rs`):
`GET /e/not-a-valid-digest` is `400`.

**Divergence from SPEC.** SPEC §13.8 writes this as `GET /<digest-value>`.
The code serves it at `/e/{digest}`.

### `GET /server`

The server's identity and capability tier (`docs/specs/server-identity.md`).
No parameters. Always `200`, `unsigned`. The payload is tagged by `tier`:

```json
{
  "tier": "attestor",
  "pg": "<bare PG>",
  "alg": "Ed25519",
  "pub": "<b64url>",
  "tmb": "<b64url>",
  "genesis": {
    "alg": "Ed25519",
    "pub": "<b64url>",
    "tmb": "<b64url>",
    "first_seen": 1700000000
  }
}
```

```json
{ "tier": "witness", "mode": "witness", "now": 1700000100 }
```

```json
{ "tier": "repository" }
```

- `attestor`: keyed and bootstrapped. `alg`/`pub`/`tmb` are the _current_
  signing key; `genesis` is the genesis key, a hint for offline
  verification that a client trusts only after re-deriving the pinned `pg`.
- `witness`: a read-only server syncing from an authority.
- `repository`: no signing key, or a keyed process not yet bootstrapped.

Status `500` only if the signing key's thumbprint cannot be computed.
Examples: `keyed_bootstrapped_server_publishes_attestor_identity`,
`keyless_server_declares_repository_with_no_identity_fields`
(`rs/cyphr-server/tests/identity_publication.rs`);
`attestor_discovery_payload_carries_genesis_key_fields`
(`rs/cyphr-server/tests/receipts.rs`).

### `GET /healthz`

Whether the server can write: a probe write to its record directory, and
no store having lost a sync (a real write probe;
see `docs/guides/operating-a-server.md`, "What the server tells you"). Not
an envelope.

- `200` `{"status":"ok"}`
- `503` `{"status":"unavailable","error":"storage unavailable"}`: the
  probe write failed, or the engine, the invite spent set or the death set
  lost a sync (each then refuses every write until restart).

The body names no principal, path or cause. Examples:
`healthz_answers_200_on_a_healthy_peer_that_holds_data`,
`healthz_turns_503_when_storage_is_destroyed`
(`rs/cyphr-server/tests/healthz.rs`).

### `GET /metrics`

Prometheus text exposition, `200`, content type
`text/plain; version=0.0.4; charset=utf-8`. Counters and their labels are
listed in `docs/guides/operating-a-server.md` ("What the server tells
you"); example: `metrics_counters_move_exactly_with_traffic`
(`rs/cyphr-server/tests/metrics.rs`).

## Writes

### `POST /push`

Submit one commit bundle. Semantics: `SPEC.md` §13.8 (`POST /push`) and the
bundle wire form, §4.6.2.

Body: JSON object.

| Field          | Type                      | Required | Meaning                                                                                                          |
| :------------- | :------------------------ | :------- | :--------------------------------------------------------------------------------------------------------------- |
| `principal_id` | string                    | yes      | Principal identifier.                                                                                            |
| `txs`          | array of arrays of string | one of   | The commit's transactions, each an array of base64url coz JSON, the commit transaction last.                     |
| `keys`         | array of `{alg,pub,tmb}`  | no       | Public keys the cozies in `txs` introduce.                                                                       |
| `actions`      | array of string           | one of   | Data actions (base64url coz JSON) recorded before the transactions. A bundle of `actions` alone forms no commit. |
| `token`        | string                    | no       | A bearer token, for a carrier with no `Authorization` header (the Noise transport). The header wins.             |
| `parent`       | object                    | no       | The commit the bundle extends, in the same bundle wire form without `principal_id`. See below.                   |

An empty bundle (no `txs`, `keys` or `actions`) is `400`.

**`parent`.** A server keeps a bounded number of rival lines per principal
(a line is a rival commit and at most one commit over it). A rival the
quota refuses (`409`, `kind` `branch_limit`, or `423` while the principal is
in Error) can still be what makes the fork two extended branches, which
only its extension shows. A sender sends the extension with the refused
root as `parent`: the two are one offer, kept both or neither (a storage fault between the two writes can leave the root kept alone; it heals when the pair is offered again). The server
keeps the pair when its quotas allow it or when it changes the principal's
consensus state or fork point, and refuses it whole otherwise. A `parent`
the server already holds, or can admit alone, changes nothing about how the
bundle is answered. In Error a refused offer answers `423` (`errored`);
`409` applies only outside Error, or to a verified rival root the server retains while in Error; an offer the quotas refuse answers `423`
(`slots_one_key_cannot_crowd_out_another`, `rs/cyphr-server/tests/evidence.rs:412`). The field is additive and absent from the normative
specification of `POST /push`.

**Authentication.** No bearer token is required: the bundle's own signatures
are its authorization, including a new principal's genesis. A token is an
optional admission knob; if presented (header `Authorization: Bearer <token>`
or body `token`) it must verify, name the same principal as the target, be
bound to the channel it arrived on, and its login key must still be active
in that principal. Tests: `push_with_mismatched_token_pr_rejected`,
`push_with_matching_token_pr_succeeds`,
`push_for_existing_principal_with_no_token_succeeds`
(`rs/cyphr-server/tests/route_protection.rs`). The guide's admission policy
(`docs/guides/operating-a-server.md`, "Admission") may additionally gate a
new principal's genesis.

**201:**

```json
{
  "v": 1,
  "payload": {
    "blob_hashes": ["<hex>"],
    "commit_id": "SHA-256:…",
    "sequence": 0,
    "roots": { "pr": "SHA-256:…", "sr": "SHA-256:…", "ar": "SHA-256:…", "cr": "SHA-256:…" }
  },
  "statement": { "kind": "signed", "coz": { "pay": {…}, "sig": "…" } }
}
```

A `201` means the record was synced to disk before the answer was built
(`storage-engine.md` `[record-durable-first]`), for a commit, a retained
rival and an action-only bundle alike, so the receipt never signs over
state a power cut can erase. The sync costs one disk flush per push.

`sequence` is the accepted commit's 0-indexed position. `roots.cr` is
`null` when no commit root exists yet. Statement: `cyphr-server/receipt/commit`
on an attestor; a receipt that cannot be signed degrades the answer to
`unsigned` (the commit is already durable, and the answer stays `201`).

| Status | When                                                                                                                                                                                                                                                                   |
| :----- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `400`  | Empty bundle; body is not JSON of the expected shape (`kind` `malformed_body`); a malformed blob or invalid input; on an attestor, a `principal_id` that is not a canonical genesis identifier; a bundle that forms no commit for a principal with no committed state. |
| `401`  | A presented token fails verification, names another principal, is bound to another channel, or its login key is revoked or inactive; or the bundle is signed by a revoked key.                                                                                         |
| `402`  | The principal's durable commit count has reached the per-principal quota (default 1,000,000).                                                                                                                                                                          |
| `403`  | The invite admission policy refuses a new principal's genesis (payload `{"error":"admission required","policy":"invite"}`); or witness mode.                                                                                                                           |
| `409`  | State or commit mismatch (a stale `pre`, or a fork: a commit that verifies at its `pre` but takes a position the chain holds; the rival is retained as evidence); branch limit; ambiguous.                                                                             |
| `413`  | The body exceeds the cap (also while buffering for admission or quota).                                                                                                                                                                                                |
| `422`  | Any other protocol refusal, for example `genesis_incomplete` for an action-only push before any genesis.                                                                                                                                                               |
| `423`  | The principal is in Error: only a fork resolution is admitted (`kind` `errored`).                                                                                                                                                                                      |
| `500`  | A storage failure, including a failed sync of the record: that push is answered `500` and not indexed, and if the sync failed, every later write is refused the same way until restart.                                                                                |
| `503`  | The admission spent-set store is unavailable.                                                                                                                                                                                                                          |

Examples: `push_new_principal_happy_path` (`rs/cyphr-server/tests/e2e.rs`),
a genesis push returning `201`; `attestor_push_response_carries_signed_commit_receipt`
(`rs/cyphr-server/tests/receipts.rs`); a fork push returning `409` in
`fork_is_listed_under_every_pg_spelling`
(`rs/cyphr-server/tests/branches.rs`). The `402` body is shown in
`docs/guides/operating-a-server.md` ("The fences").

**Divergence from SPEC.** SPEC §13.8 says `POST /push` "accepts one or more
signed transactions (`tx_patch`)" and states no request or response shape.
The code accepts one commit bundle per request in the §4.6.2 wire form plus
`principal_id`, and answers `201` with the roots and (on an attestor) a
signed commit receipt. SPEC defines neither.

### `POST /revoke`

Submit a self-signed naked revoke (`SPEC.md` §6.4): an uncommitted
`key/revoke` coz signed by the key it names, with that key disclosed. The
server verifies it against the disclosed key (no principal load, no chain
replay), records it in the engine and the death set, and refuses the key
globally thereafter. It names no principal and touches no chain.

Body: JSON `{pay, sig, key}`.

| Field | Type         | Meaning                                                                                                    |
| :---- | :----------- | :--------------------------------------------------------------------------------------------------------- |
| `pay` | object       | The `key/revoke` payload, signed verbatim (`typ` `cyphr.me/cyphr/key/revoke`, `tmb`, `rvk`, `alg`, `now`). |
| `sig` | string       | Detached signature over `pay`, base64url.                                                                  |
| `key` | `{alg, pub}` | The disclosed public key (`pub` base64url). Required.                                                      |

**200**, always `unsigned` (the death record is server-local truth, not a
trust object a client replays):

```json
{
  "v": 1,
  "payload": { "revoked_tmb": "<b64url>", "recorded": true },
  "statement": { "kind": "unsigned" }
}
```

| Status | When                                                                                                                                                                 |
| :----- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `400`  | Body not JSON of the expected shape; `key` missing; malformed payload, bad `rvk`, oversize payload, wrong `typ`, or a disclosed key that does not hash to its `tmb`. |
| `401`  | The signature does not verify against the disclosed key.                                                                                                             |
| `500`  | The observation store failed, or the engine's record sync failed (every later write then answers `500` until restart).                                               |
| `507`  | The death set is at its ceiling (`[limits] max_dead_keys`) and no stored principal holds the key. A revoke of a held key is still recorded.                          |

Engine refusals while recording map as in "Engine error mapping".

**Divergence from SPEC.** SPEC §6.4 says both "Critically, the key signing a
revoke message must be the key itself" and "Third parties may sign a naked
revoke, declaring a key compromised, without any other knowledge of the
principal." The code accepts only the self-signed form: the signature must
verify against the disclosed key, which must hash to the payload's `tmb`, so a
revoke signed by any other key is refused (`401` for a bad signature, `400` for a
disclosed key that does not match `tmb`). The two SPEC sentences are not reconciled here.

Example: `revoked_serves_the_accepted_naked_revoke_verifiably`
(`rs/cyphr-server/tests/revoked_route.rs`) posts
`rs/cyphr-server/tests/golden/naked_revoke_valid.json` and gets `200`;
rejections are in `rs/cyphr-server/tests/naked_revoke.rs`. SPEC §6.4 names
no route.

## Authentication

Login follows `SPEC.md` §17.2. These three routes answer `501` when the
server has no signing key, or no configured `audience`; `GET /server` states
which tier the server declared.

### `POST /auth/challenge`

Issue a single-use 256-bit challenge, valid for 120 seconds. No body is
read.

**200:** payload `{"challenge": "<b64url>"}`, `unsigned`. Statuses: `501`
as above. Example: `login_challenge_flow_issues_valid_token`
(`rs/cyphr-server/tests/login.rs`).

### `POST /auth/login`

Exchange a signed login for a bearer token. Body: a coz, JSON `{pay, sig}`
(read as raw text; no content type is required).

`pay` fields:

| Field               | Required                | Meaning                                                                                    |
| :------------------ | :---------------------- | :----------------------------------------------------------------------------------------- |
| `typ`               | yes                     | `<audience>/cyphr/auth/login`. `<audience>` must equal the server's configured `audience`. |
| `alg`, `tmb`, `now` | yes                     | Signing algorithm, signing key thumbprint, signer's timestamp.                             |
| `pr`                | yes                     | The principal the signer claims. The key is looked up in that principal only.              |
| `challenge`         | challenge-response flow | A challenge from `/auth/challenge`, consumed once. Absent selects the timestamp flow.      |
| `h`                 | over Noise only         | The session's handshake hash, base64url. Must be present over Noise and absent over HTTP.  |

Timestamp flow: `now` must be within 60 seconds of server time.

**200:** payload `{"token": "<signed coz>"}`, `unsigned`. The token carries
`["read","write"]`, names the principal and the login key, and expires after
`session_ttl_secs` (clamped to 1 through 3600 seconds). Over Noise it is
bound to that session's handshake hash; over HTTP it is bound to the key.

| Status | When                                                                                                                                                                                                                                                                                                    |
| :----- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `400`  | The body is not a JSON coz, or its `pay` is not the expected shape.                                                                                                                                                                                                                                     |
| `401`  | Missing required field; `typ` is not a login; audience missing or not this server's; invalid signature; unknown principal; key not an active key of the claimed principal; principal not Active; key naked-revoked; timestamp outside the window; challenge unknown, used or expired; channel mismatch. |
| `501`  | No signing key or no audience configured.                                                                                                                                                                                                                                                               |
| `500`  | The token could not be issued.                                                                                                                                                                                                                                                                          |

Examples (all in `rs/cyphr-server/tests/login.rs`):
`login_timestamp_flow_issues_valid_token`,
`login_challenge_flow_issues_valid_token`, `login_rejects_replayed_challenge`.

**Divergences from SPEC** (§17.2 examples). The code requires `pr` in the
payload, which neither example carries (the code names the reason: a key can
belong to several principals, so a `tmb` alone is ambiguous). It requires
the `typ` to end in `/cyphr/auth/login`, so Option B's
`<authority>/<service>/auth/login` is accepted only when `<service>` is
`cyphr`. It adds `h` for Noise. The code's own header marks these field
choices as interim, pending the spec author's review.

### `POST /auth/session`

Report what a bearer token binds to. Body: the token string itself (raw
text, surrounding whitespace trimmed), not JSON-wrapped. The token is the
credential; no header is read.

**200**, `unsigned`:

```json
{
  "v": 1,
  "payload": {
    "pr": "<bare PG>",
    "key": "<login key tmb>",
    "binding": "key",
    "exp": 1700000900
  },
  "statement": { "kind": "unsigned" }
}
```

`binding` is `"key"` or `"noise-handshake-hash"`.

| Status | When                                                                                                                                                                                         |
| :----- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `401`  | The token fails verification or is expired; it is bound to another channel; names no login key; the login key is inactive, revoked or naked-revoked; the principal is unknown or not Active. |
| `501`  | No signing key or no audience configured.                                                                                                                                                    |

Example: `browser_session_is_bound_to_its_key` and
`token_is_refused_on_a_second_channel`
(`rs/cyphr-server/tests/session_binding.rs`). SPEC §17.4 describes the
token's fields; it names no session route.

## Carriers

The same router also serves over the opt-in Noise transport
(`transport_listen`); a request there carries the session's handshake hash,
which is what channel-bound tokens and logins are checked against. Over
that carrier a push may carry its token in the body (`token`).
