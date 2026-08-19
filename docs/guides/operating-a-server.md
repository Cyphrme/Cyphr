# Running a Cyphr server

A `cyphr-server` is one binary, one data directory, and an HTTP port. It
stores users' key histories, hands out signed receipts for what it stored,
and answers logins. There is no database to provision, no message broker,
and no clustering: a server is a single process that owns its directory
exclusively and refuses to start if another process already holds it.

What you are actually operating is closer to a git remote than to an
identity provider. Users' clients build their own key histories locally and
push commits; your server validates each commit against the protocol rules,
stores it, and can attest to what it holds. It is not the source of truth
about anyone's identity — it is a witness to it. That distinction sets the
whole operational posture: losing your server does not destroy your users'
identities, but losing your server's own signing key does destroy your
server's identity.

This guide covers standing one up, every knob it has, what it refuses and
why, what to back up, and what it will not tell you that you might expect it
to.

## Terms

| Term      | What it is                                                                                           |
| :-------- | :--------------------------------------------------------------------------------------------------- |
| Principal | A user's identity: a chain of commits adding and revoking keys over time. Not a key — a key history. |
| `pr`      | The identifier the server files a principal under.                                                   |
| PG        | Principal Genesis. Your server's own stable identifier, derived from its signing key.                |
| Tier      | What the server declares itself to be at `GET /server`: `attestor`, `repository`, or `witness`.      |
| Admission | The gate on a brand-new principal taking up residency. Off by default.                               |
| Fence     | A refuse-only resource limit — rate, body size, commit count. Always on, with defaults.              |
| Death-set | The server-local record of keys declared dead out of band. Durable, global by thumbprint.            |

## Start it

The shortest thing that runs:

```sh
cyphr-server serve --listen 127.0.0.1:3000 --data-dir ./data
```

```
listening on 127.0.0.1:3000
```

That line goes to stdout and everything else goes to stderr, so a supervisor
that wants to know the real port when you asked for `:0` can read it without
parsing logs. The defaults if you pass nothing at all are
`127.0.0.1:3000`, `./data`, pretty logs, and authority mode.

This server holds no key. It stores and serves commits, signs nothing, and
declares itself accordingly:

```sh
curl -s http://127.0.0.1:3000/server
```

```json
{
  "v": 1,
  "payload": { "tier": "repository" },
  "statement": { "kind": "unsigned" }
}
```

Give it a key and an audience and it becomes an attestor — a server that
signs receipts for what it stores and issues login tokens:

```sh
cyphr-server serve \
  --listen 127.0.0.1:3000 \
  --data-dir ./data \
  --signing-key-path ./signing-key.json \
  --audience login.example.com
```

```
INFO cyphr_server: server principal established pg=SHA-512:Aq8NJWSDFrFsjmcxQjFAZz5hKv4mtQ3u_RU25jX3Vay9...
INFO cyphr_server: server started listen=127.0.0.1:3000
```

The signing key is a JSON file holding a raw keypair, both fields base64url
without padding over raw key bytes:

```json
{
  "alg": "Ed25519",
  "pub_key": "y1xCqdKo0nTUHXpOnKOpw44VbKB9lvPmphkVULNnQbw",
  "prv_key": "4jl-rNm5WGFSDHTQM3cHmB5lVVs_eGzYFpmsOddUEno"
}
```

Generate one with Node:

```js
const crypto = require("crypto");
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
console.log(
  JSON.stringify({
    alg: "Ed25519",
    pub_key: publicKey
      .export({ format: "der", type: "spki" })
      .subarray(12)
      .toString("base64url"),
    prv_key: privateKey
      .export({ format: "der", type: "pkcs8" })
      .subarray(16)
      .toString("base64url"),
  }),
);
```

A configured-but-broken key path is a startup failure, not a quiet
downgrade to keyless. That is deliberate: a server that silently ran
unkeyed because of a typo would stop issuing logins with no signal.

### Every knob

Configuration merges from four layers, each overriding the one below: CLI
flags, then `CYPHR_*` environment variables, then a TOML file, then compiled
defaults. The TOML file is `./cyphr-server.toml` unless `--config` names
another, and a missing file is not an error.

That default is worth respecting: the file is looked up in the working
directory, not beside the binary or the data directory, and a stray
`cyphr-server.toml` left in a directory you happen to launch from is picked
up silently. It is the fastest way to get a server that behaves nothing like
its command line — the TOML-only settings especially, since no flag can
override them. Pass `--config` explicitly in anything you automate.

| Setting              | Flag                 | Environment              | What it buys                                                                     |
| :------------------- | :------------------- | :----------------------- | :------------------------------------------------------------------------------- |
| `listen`             | `--listen`           | `CYPHR_LISTEN`           | Bind address. `:0` picks a free port and reports it on stdout.                   |
| `data_dir`           | `--data-dir`         | `CYPHR_DATA_DIR`         | Where every durable store lives. Locked exclusively while running.               |
| `signing_key_path`   | `--signing-key-path` | `CYPHR_SIGNING_KEY_PATH` | The key the server signs receipts and tokens with. Absent means keyless.         |
| `audience`           | `--audience`         | `CYPHR_AUDIENCE`         | The name clients must sign into. Absent means logins are refused.                |
| `mode`               | `--mode`             | `CYPHR_MODE`             | `authority` (accepts writes) or `witness` (read-only, syncs from an authority).  |
| `log_format`         | `--log-format`       | `CYPHR_LOG_FORMAT`       | `pretty` for a terminal, `json` for a log pipeline.                              |
| `authority_url`      | `--authority-url`    | `CYPHR_AUTHORITY_URL`    | The upstream a witness pulls from.                                               |
| `authority_identity` | —                    | —                        | The upstream's public key, so a witness can verify what it pulls. **TOML only.** |
| `[admission]`        | —                    | —                        | The gate on new principals. **TOML only.**                                       |
| `[limits]`           | —                    | —                        | Rate, body size, and commit-count fences. **TOML only.**                         |

The last three have no flag and no environment variable. If you are
deploying from a unit file or a container spec that only sets environment,
the admission policy and every limit are unreachable — you need a config
file on disk. A full one:

```toml
listen = "0.0.0.0:3000"
data_dir = "/var/lib/cyphr"
mode = "authority"
log_format = "json"
signing_key_path = "/etc/cyphr/signing-key.json"
audience = "login.example.com"

[admission]
policy = "invite"
tokens_path = "/var/lib/cyphr/invites.txt"

[limits]
max_body_bytes = 2097152
count_quota = 1000000
per_ip = { per_second = 100, burst = 200 }
read = { per_second = 100, burst = 200 }
push = { per_second = 50, burst = 100 }
login = { per_second = 50, burst = 100 }
revoke = { per_second = 50, burst = 100 }
```

Three settings are rejected at startup rather than accepted into a broken
server. Each exits 1 before binding a port:

```
configuration error: limits.max_body_bytes is 0 -- this refuses every request body; set it to the intended cap in bytes (the default is 2 MiB)
configuration error: limits.count_quota is 0 -- this refuses every principal's first commit; set it to the intended per-principal commit cap
configuration error: admission pow difficulty 0 is invalid -- must be in 1..=256 leading zero bits (0 admits every nonce; blake3 digests are only 256 bits, so >256 admits none)
```

Each of those is a value that would silently brick the server rather than
fail visibly — a zero body cap refuses every request, a zero quota refuses
every principal's first commit, a zero difficulty turns the anti-spam gate
into a no-op while looking configured. They are checked because
`difficulty` and the `[limits]` fields all default when omitted, so
deserialization alone would not catch them.

A rate bucket of zero is treated differently. It starts, and clamps to the
tightest live bucket instead:

```toml
[limits]
read = { per_second = 0, burst = 0 }
```

```
req1: 404
req2: 429
req3: 429
```

One request gets through and everything after it is refused. The reasoning
is that a misconfigured rate should stay functional-but-strict rather than
refuse service outright — but from an operator's chair a bucket of zero is
indistinguishable from an outage, so do not use it as a way to "disable"
a route.

## Keyed or keyless

The tier at `GET /server` is the honest answer to what the server can do,
and it is worth choosing deliberately rather than by accident.

A **keyless server** (`repository`) stores and serves commits. It accepts
pushes, answers `/tip` and `/patch`, records naked revokes, and enforces
admission and every fence. What it cannot do is vouch: its responses carry
`"statement": {"kind": "unsigned"}`, and login is refused outright:

```sh
curl -s -X POST http://127.0.0.1:3000/auth/challenge
```

```json
{
  "v": 1,
  "payload": {
    "error": "this server runs without a signing identity; login is not offered -- see GET /server for the declared capability tier",
    "now": 1785872456
  },
  "statement": { "kind": "unsigned" }
}
```

`501`, not `500` — a declared capability absence, not a fault. This is a
reasonable thing to run if you want a durable, replicable store of key
history and you are not in the business of authenticating anyone.

A **keyed server** (`attestor`) additionally signs. On first keyed boot it
establishes its own principal — the server is an ordinary principal in its
own store — and publishes it:

```sh
curl -s http://127.0.0.1:3000/server | jq .payload
```

```json
{
  "tier": "attestor",
  "pg": "SHA-512:Aq8NJWSDFrFsjmcxQjFAZz5hKv4mtQ3u_RU25jX3Vay9sD_FgGs114dOBu4CXU4GfwIhDJfERsYSITvsWFJqHw",
  "alg": "Ed25519",
  "pub": "ll0VDGrwstQ4m2dKt-wMggEeC-uwAC18anqtPt96l08",
  "tmb": "Aq8NJWSDFrFsjmcxQjFAZz5hKv4mtQ3u_RU25jX3Vay9sD_FgGs114dOBu4CXU4GfwIhDJfERsYSITvsWFJqHw",
  "genesis": {
    "alg": "Ed25519",
    "pub": "ll0VDGrwstQ4m2dKt-wMggEeC-uwAC18anqtPt96l08",
    "tmb": "Aq8NJWSDFrFsjmcxQjFAZz5hKv4mtQ3u_RU25jX3Vay9sD_FgGs114dOBu4CXU4GfwIhDJfERsYSITvsWFJqHw",
    "first_seen": 0
  }
}
```

**`pg` is the number that matters operationally.** It is what clients pin on
first contact and check on every contact after. A client that sees a
different `pg` from the one it pinned is supposed to refuse loudly — it
cannot distinguish a redeployment from an attack. So the `pg` is a promise
you are making, and the rest of this guide's advice about backups exists to
let you keep it.

The `pg` is derived from the signing key. The same key in a completely
empty data directory produces the same `pg`, which is the property that
makes a rebuild survivable.

**The audience is separate from the key and equally required for login.**
Every login signature names the service the user believes they are signing
in to, and the server rejects anything naming something else. A keyed
server with no `--audience` still hands out challenges but fails every
login with a `500`. Configure both or neither.

Pick the host your users' clients actually address — `login.example.com`,
not `Example Inc`.

**Turning on login turns on one permission level, not a model.** Every
bearer token issued at login carries `["read", "write"]`, unconditionally --
there is no narrower grant for a client that only needs to read. In
practice this gates little: `POST /push` is the only route that checks a
presented token at all, and only to confirm it names the principal being
written to. Every other route, reads included, takes no token. Setting
`--audience` is a decision to start issuing tokens, not a decision about
what those tokens will be trusted to do.

## What lives in the data directory

After a keyed server has run once:

```
data/
├── blobs/           the commits themselves, and each principal's chain
├── index/           a derived projection, rebuildable from blobs
├── observations/    the key death-set
├── admission/       spent invite tokens (only under policy = "invite")
└── server-principal.json
```

Each directory is a separate embedded database. The split is not arbitrary
and it decides your backup policy:

| Path                    | Rebuildable?                  | Lose it and…                                |
| :---------------------- | :---------------------------- | :------------------------------------------ |
| `blobs/`                | No — this is the data         | Every principal you host is gone.           |
| `index/`                | Yes, from `blobs/`            | Nothing, after a rebuild.                   |
| `observations/`         | No                            | Every key declared dead comes back to life. |
| `admission/`            | No                            | Every spent invite token becomes reusable.  |
| `server-principal.json` | By hand, from the signing key | The server will not start. See below.       |

**The invite tokens file belongs in your backup plan even though it is not
in this table.** Under `policy = "invite"` it does not have to live inside
the data directory -- the example above uses `./invites.txt` -- and it is
not rebuildable. Lose it and every outstanding, unspent invite is dead; the
`data/admission/` spent-set backs up the tokens already used, not the ones
still good.

**`observations/` is separate precisely so a rebuild cannot erase it.** A
key declared dead by its holder is not recorded on anyone's chain — a naked
revoke mutates no principal — so if that record lived in the index, the next
reindex would silently wipe it. Delete the index outright and rebuild it,
and a key revoked beforehand is still refused afterward.

```sh
rm -rf data/index
cyphr-server rebuild-index --data-dir ./data
```

```
INFO cyphr_server: Starting total index rebuild in ./data
INFO cyphr_server: Index rebuild completed successfully
```

```sh
curl -s -X POST http://127.0.0.1:3000/push -H 'content-type: application/json' -d @commit.json
```

```json
{
  "v": 1,
  "payload": { "error": "push signing key was revoked", "now": 1785872826 },
  "statement": { "kind": "unsigned" }
}
```

**`server-principal.json` is the file nobody expects to matter.** It holds
the PG and the genesis key record. Delete it while leaving the blob store
intact, and the server refuses to start — but now names the problem:

```
ERROR cyphr_server: server exited with error error=missing data/server-principal.json for an already-established server principal (pg=SHA-256:…); see docs/guides/operating-a-server.md for the recovery procedure
```

That detection only works before the signing key's first rotation — it
recomputes the genesis key from the *current* key to check whether the
engine already has a chain there, which is the genesis key only pre-rotation.
After a rotation, a missing sidecar goes undetected: the server assumes a
fresh boot and creates a second, unrelated principal instead of erring.
Either way, you rebuild the sidecar by hand from two values: the public
key, which is `pub_key` in your signing key file, and the genesis
thumbprint, which is your PG with its hash-algorithm prefix stripped. The
server cannot tell you the second one — it will not start — so it has to
come from something you kept: the `server principal established pg=…` line
in an old log, or the value a client pinned.

Neither the `SHA-…:` prefix nor the `alg` field is a fixed value — both
come from the key's own algorithm, sitting right there in
`jq -r .alg signing-key.json` next to the `pub_key` line above. The prefix
tracks that algorithm's hash: SHA-256 for ES256, SHA-384 for ES384, and
SHA-512 for ES512 as well as Ed25519. The recipe reads both off the key
file, so it is not tied to one algorithm.

```sh
TMB=Aq8NJWSDFrFsjmcxQjFAZz5hKv4mtQ3u_RU25jX3Vay9sD_FgGs114dOBu4CXU4GfwIhDJfERsYSITvsWFJqHw
PUB=$(jq -r .pub_key signing-key.json)
ALG=$(jq -r .alg signing-key.json)
case "$ALG" in
  ES256)         HASH=SHA-256 ;;
  ES384)         HASH=SHA-384 ;;
  ES512|Ed25519) HASH=SHA-512 ;;
  *) echo "unrecognized alg: $ALG" >&2; exit 1 ;;
esac
jq -n --arg pg "$HASH:$TMB" --arg pub "$PUB" --arg tmb "$TMB" --arg alg "$ALG" \
  '{pg:$pg, genesis_key:{alg:$alg, pub_key:$pub, tmb:$tmb, first_seen:0}}' \
  > data/server-principal.json
```

That restores the original PG and the server starts, on one condition: the
index already has this principal's tip. If you are restoring from a
blobs-only backup, run `rebuild-index` first -- starting with a stale or
empty index makes the sidecar load fail with a different error,
`server principal genesis record does not match the configured key or its
chain`, because the server cannot confirm the chain it just described is
actually there. Back the sidecar file up anyway — this reconstruction also
leans on the genesis key still being the current key, which stops being
true after a rotation.

**Back up the signing key somewhere other than the data directory.** It is
the only irreplaceable thing you hold: with it and an empty disk you can
rebuild a server that clients still recognize, and without it you cannot,
no matter how complete your `blobs/` backup is.

The store is locked exclusively while the server runs, so a file-level
backup of a live directory is a copy of a moving target. A second process
pointed at the same directory refuses to start:

```
ERROR cyphr_server: server exited with error error=FjallError: Locked
```

There is no snapshot, dump, or online-backup command. `cyphr-server export`
appears in `--help` and does not work:

```sh
cyphr-server export "$PR" --data-dir ./data
```

```
error: export is not yet implemented
```

So a consistent backup today means stopping the server, copying the
directory, and starting it again. Say that out loud when you plan your
maintenance window, because it is the one operation that needs downtime.

## Admission: who may create a principal

Admission gates exactly one event — a principal the server has never seen
taking up residency — and nothing else. An already-resident principal
pushing its next commit never touches it. There are three policies.

**`open` is the default, and it means what it says.** No fence is installed
at all. Anyone who can reach the port can create principals without limit,
bounded only by the rate fences and the commit quota. For a public server
this is a decision, not a default to inherit by not thinking about it: the
namespace of principal identifiers is first-come-first-served.

**`invite` hands out single-use tokens.**

```toml
[admission]
policy = "invite"
tokens_path = "./invites.txt"
```

The tokens file must exist before the server starts, and issuing tokens is
what creates it. Issue first:

```sh
cyphr-server --config ./cyphr-server.toml invite new --count 2
```

```
12e94ee48b4fcc9e04e98580775d8614981e5a8dab85550e
422f0073f37631134662bac1b42886004925691c06a129aa
```

Those are the tokens to distribute. What lands in the file is their hashes,
one per line — the server never stores a token it could leak:

```
e06a65d68436b2d63ca8f66c3adc6c1e1a0ca560cf0438e0d35a113756bab7e5
893f2d40e90e55960053022ff9cc4b3d838a497313071c3ecd1c879fd44301d0
```

Start the server before the file exists and it exits:

```
ERROR cyphr_server: server exited with error error=reading invite tokens file ./invites.txt: No such file or directory
```

A client presents its token in a header. Without one:

```sh
curl -s -X POST http://127.0.0.1:3000/push -H 'content-type: application/json' -d @push.json
```

```json
{
  "v": 1,
  "payload": { "error": "admission required", "policy": "invite" },
  "statement": { "kind": "unsigned" }
}
```

`403` — the body names the policy so a client knows what it is missing.
With a valid token it is a `201`:

```sh
curl -s -X POST http://127.0.0.1:3000/push \
  -H 'content-type: application/json' \
  -H 'X-Cyphr-Invite: 12e94ee48b4fcc9e04e98580775d8614981e5a8dab85550e' \
  -d @push.json
```

Three behaviors are worth knowing before you hand tokens to users. Single
use is enforced durably — the same token on a second, different principal
is refused, and it is still refused after a restart, because the spent set
lives in `data/admission/`. A token is only spent on success; a push that
fails for a protocol reason refunds it. And once a principal is resident,
its later commits need no token at all, so a token buys a user an identity,
not a subscription.

An `invite` server whose `data/admission/` you restore from an older backup
un-spends every token issued since. There is no expiry and no revocation
list; a leaked token is live until someone uses it.

**`pow` asks for proof of work instead of a secret.**

```toml
[admission]
policy = "pow"
difficulty = 20
```

The refusal echoes the parameters:

```json
{
  "v": 1,
  "payload": {
    "error": "admission required",
    "policy": "pow",
    "difficulty": 20,
    "window": "utc-hour"
  },
  "statement": { "kind": "unsigned" }
}
```

The client finds a nonce, sends it as `X-Cyphr-Pow`, and gets its `201`.
The work binds to one principal identifier and one UTC hour, so a solution
cannot be amortized: the same nonce presented for a different principal is
refused. Solutions from the previous hour still verify, so a client that
solves just before the boundary is not punished; anything older is stale.
The server holds no state for any of this, and a check costs up to two
hashes -- one for the current hour and, since a solution from the previous
hour still verifies, one for that hour too.

**But no shipped client can compute that nonce.** The preimage — a domain
tag, the principal id length-prefixed, then the hour and nonce as
little-endian 64-bit integers, hashed with blake3 — is written down in the
server's source and in the server's own test, and nowhere else. There is no
client library, no CLI subcommand, and no specification a client author
could implement from. The `403` tells a client the difficulty but not the
thing it cannot guess. Turning this policy on today closes new-principal
onboarding to everyone; `invite` is the policy to reach for until that
changes.

## The fences

Three limits refuse service and never do anything else. They are always
installed, with defaults, so a server with no `[limits]` table is bounded
rather than unlimited. They know nothing about the protocol: they see
request rate, request size, and one number read from storage.

**Rate**, as token buckets. Each bucket refills at `per_second` up to a
`burst` ceiling, and the buckets are independent — a flood of pushes does
not drain the read bucket. Every bucket is keyed on the connection's real
peer address, which a client cannot choose or spoof at the TCP layer:

| Bucket   | Applies to                                 | Default          |
| :------- | :----------------------------------------- | :--------------- |
| `per_ip` | Every request, keyed on peer address       | 100/s, burst 200 |
| `read`   | `GET` routes                               | 100/s, burst 200 |
| `push`   | `POST /push`                               | 50/s, burst 100  |
| `login`  | `POST /auth/login`, `POST /auth/challenge` | 50/s, burst 100  |
| `revoke` | `POST /revoke`                             | 50/s, burst 100  |

```json
{
  "v": 1,
  "payload": { "error": "rate limit exceeded" },
  "statement": { "kind": "unsigned" }
}
```

`429`, with no `Retry-After` and no indication of which bucket fired -- the
`per_second`/`burst` pair above is the only knob either side has; there is
nothing computed for a client to back off against.

There is deliberately no per-principal rate bucket. Keying a rate limit on
the principal named in an unverified push body would let anyone throttle a
victim by naming them in a flood of garbage — the name is attacker-chosen
and unauthenticated at the point a fence would read it. The peer address
cannot be chosen that way, so that is what the write path is keyed on.

Each bucket's own memory is bounded at 100,000 resident keys, evicting the
coldest when full -- and that ceiling is per bucket. There are five buckets
(`per_ip`, `read`, `push`, `login`, `revoke`), each tracking its own set of
addresses, so size for five times that, not one. An evicted key gets a
fresh bucket on its next request, which only ever loosens; a key being
actively hammered is by definition not cold, so a flood of distinct
addresses cannot wash out the limiter entry for the address doing the
flooding.

**Size**, one cap for every route, refused by the fence like this:

```json
{
  "v": 1,
  "payload": { "error": "request body too large", "limit_bytes": 512 },
  "statement": { "kind": "unsigned" }
}
```

`413`, before any handler runs, on both the declared `Content-Length` and
the bytes actually read — a chunked body cannot lie its way past the header
check. The default is 2 MiB. Raise it if your users push large commit
bundles; it is the same number an active admission policy uses when it
buffers a push to peek at the principal id, so there is one cap, not two.

The cap is universal; that body is not. The fence weighs the declared
`Content-Length` on every route and the buffered bytes on `/push`, and both
produce the `limit_bytes` shape above. A chunked request that declares no
`Content-Length` to any route other than `/push` slips past the fence and
is stopped further in, by the framework's own limit, which answers `413`
with an `error` and a `now` and no `limit_bytes` field. Same code, same
cap, one field short. Most clients send `Content-Length`, so this is the
uncommon path — but do not key a client on that field always being there.

**Commit quota**, per principal:

```json
{
  "v": 1,
  "payload": {
    "error": "per-principal commit quota exhausted",
    "limit_commits": 1
  },
  "statement": { "kind": "unsigned" }
}
```

`402` — an unusual code, chosen so it is distinguishable from the other
refusals in a log. The default is 1,000,000 commits, high enough to bound
runaway growth without touching real use. It reads durable commit count, so
garbage pushes that never commit cannot inflate it. Concurrent pushes from
one principal can overshoot the cap by the in-flight burst; the fence bounds
growth, it does not enforce an exact ceiling.

**None of these refusals appear in the log — at any level.** Five requests
against a server with a burst of one — four of them refused — added zero
lines, and turning `RUST_LOG` up does not add them. A fence builds its
refusal and returns it without ever calling the code underneath, and the
request logging lives underneath. Budget for that when you plan
monitoring; it is covered below.

## TLS and reverse proxies

There is no TLS in the server itself -- no certificate configuration, and
`axum::serve` runs on a bare `TcpListener`. A real deployment terminates TLS
in front of it, in nginx, Caddy, an ALB, or similar, and forwards plain HTTP
to `cyphr-server`.

The server does not read `X-Forwarded-For` or any other proxy header. Every
bucket in the rate table above is keyed on the connection's peer address,
and behind a proxy that address is the proxy's, not the client's. The
moment TLS terminates in front of it, all five buckets collapse onto that
one address: the default `per_ip` 100/s stops bounding one client and starts
bounding everyone behind the proxy collectively, and the resulting `429`s
are invisible to request logging at any level, as covered above -- no
`RUST_LOG` setting recovers them. Size the fences for the proxy's aggregate
traffic, not for a single client, and count them at the proxy: it is the
one component in front of the server that actually sees the status codes
returned.

## Witness mode

A witness is a read-only replica that pulls state from an upstream
authority. It refuses every write itself:

```sh
curl -s -X POST http://127.0.0.1:3001/push -H 'content-type: application/json' -d @push.json
```

```json
{
  "v": 1,
  "payload": {
    "error": "write operations disabled in witness mode",
    "now": 1785872708
  },
  "statement": { "kind": "unsigned" }
}
```

`403` for every `POST`, `PUT`, `PATCH`, and `DELETE`, decided by method
rather than by route, so `/revoke` and `/auth/login` are refused on a
witness too.

Start one by naming its upstream:

```sh
cyphr-server serve \
  --listen 127.0.0.1:3001 \
  --data-dir ./witness-data \
  --mode witness \
  --authority-url http://127.0.0.1:3000
```

**Sync is pull-on-read, not a background loop.** A witness fetches a
principal's delta when someone asks it for that principal — `GET /tip` or
`GET /patch` triggers the fetch, applies what verifies, and then answers
from local state. There is no poller and no schedule. A principal nobody
asks about is never synced, and the first read after an upstream change
pays the latency of the fetch.

Each entry is validated in memory against the ordinary storage rules before
anything is persisted, and each entry stands on its own: one that fails to
decode or fails verification is skipped and counted, and the sync moves to
the next. That is deliberate. Aborting the whole response on the first bad
entry would make every genuine entry behind it permanently unreachable — a
witness keeps no progress marker, so the next read would refetch the same
response and fail on the same entry, forever.

The consequence is that **a witness can end up partially applied.** Nothing
unverifiable is ever persisted; every entry that lands passed the same
chain checks a direct push would. But the witness can be left short of the
authority's tip, and `GET /tip` serves whatever it holds without saying so.
The counts are in the log, at `cyphr_server=debug`: a
`witness sync applied entries` line carrying the principal alongside an
`applied` and a `rejected` count.

A non-zero `rejected` is the signal that this witness's answer is not the
authority's whole story. With an `[authority_identity]` configured, the
post-apply check compares what the witness now holds against what the
authority signed for, and fails the sync when they differ — but the entries
that already applied stay applied. Failing the sync does not roll anything
back.

### Authenticating the upstream

Out of the box the sync channel is not authenticated, and the server says so
loudly on startup — before the log subscriber is even installed, so it
reaches you regardless of log configuration:

```
WARNING: witness mode is configured with an authority_url but no [authority_identity] -- the sync channel is UNAUTHENTICATED (K10 disabled). An on-path party can forge, withhold, or substitute /patch entries with no verification. Configure an [authority_identity] table (alg + pub) in the TOML config file to enable the authenticated channel.
```

Fix it by pinning the upstream's key. Read it from the authority's own
discovery endpoint:

```sh
curl -s http://127.0.0.1:3000/server | jq -r .payload.pub
```

```
xzV0Vr3u_IB9KYe0P2nk5mWkLNKTQMDdRzcBTcpVEIM
```

and put it in the witness's config file — this setting has no flag and no
environment variable:

```toml
mode = "witness"
authority_url = "http://127.0.0.1:3000"

[authority_identity]
alg = "Ed25519"
pub = "xzV0Vr3u_IB9KYe0P2nk5mWkLNKTQMDdRzcBTcpVEIM"
```

The warning goes away and the witness now verifies two things: that the
signed report accompanying a delta came from that key and names the
principal it asked about, and that its own resulting local state matches
what the report attests. The second check is what catches truncation and
substitution — comparing the response's own fields against each other could
never do it, because a signature over the report says nothing about a
separate plaintext list of entries.

**What a wrong key looks like from the outside.** Point a witness at the
right upstream with the wrong `pub` and reads simply fail to find anything:

```json
{
  "v": 1,
  "payload": {
    "error": "principal AkQKBDXinn-_73V0UNuISr5n7pNVItqqrHI_6zcaYgA not found",
    "now": 1785872751
  },
  "statement": { "kind": "unsigned" }
}
```

`404` — the same answer as a principal that genuinely does not exist. The
real reason is a `WARN` in the log:

```
WARN cyphr_server::sync: witness sync authenticated-channel check failed principal=AkQK… reason=EnvelopeUnsignedOrMisSigned
```

A mis-keyed witness therefore looks like an empty one. If you run witnesses,
watch for that warning explicitly; nothing on the wire will tell you.

**One thing the authenticated channel does not close: replay of a genuine
response.** It authenticates the pairing of local state and signed report,
not the report's freshness. A response the authority genuinely signed at a
moment when its tip matched the witness's state matches that state forever,
so an on-path party can keep serving that captured response while the
authority advances, and the witness will keep concluding it is up to date.
Nothing is forged, so no comparison catches it. Closing it needs a freshness
property the channel does not currently provide.

A witness declares itself at `GET /server` and publishes no key material:

```json
{
  "v": 1,
  "payload": { "tier": "witness", "mode": "witness", "now": 1785872708 },
  "statement": { "kind": "unsigned" }
}
```

**Do not give a witness a signing key.** Nothing stops you, and what
happens if you do is worse than either alternative: the witness
bootstraps its own principal, signs the tips it serves —
`"statement": {"kind": "signed"}` — and still answers `GET /server` with
the payload above, because witness mode decides the tier before it looks
at any key. Clients get signatures with no published key to check them
against. Run witnesses keyless and let clients that need a verifiable
receipt ask the authority.

## The key death-set

Separately from any principal's chain, the server keeps a record of keys
whose holders have declared them compromised. This is the emergency lever:
it does not wait for a commit, does not need the principal's chain, and
takes effect the moment it is accepted.

A client posts a `key/revoke` payload the dying key signed about itself,
plus that key's public bytes so the server can check the signature against
the disclosed material alone:

```sh
curl -s -X POST http://127.0.0.1:3000/revoke \
  -H 'content-type: application/json' -d @revoke.json
```

```json
{
  "v": 1,
  "payload": {
    "revoked_tmb": "-DPfLkyhnJ5cfYtgPQVu_ptno5dtFXWfVBEdyivSduw",
    "recorded": true
  },
  "statement": { "kind": "unsigned" }
}
```

Thereafter that key is refused for everything, in every principal that
holds it:

```json
{
  "v": 1,
  "payload": { "error": "push signing key was revoked", "now": 1785872811 },
  "statement": { "kind": "unsigned" }
}
```

Three properties matter operationally.

**It is global by thumbprint, not scoped to a principal.** One key can be
active in several principals; a death record kills it in all of them. There
is no un-revoke.

**It survives anything short of losing the disk.** The record lives in
`data/observations/`, its own store, for the reason given in the backup
section: it is not derivable from any chain, so an index rebuild must not be
able to erase it.

**It cannot kill a genesis key.** The server only accepts a revoke naming a
key it has indexed, which in practice means a key introduced by a
`key/create` transaction. A principal's original key is not indexed:

```json
{
  "v": 1,
  "payload": {
    "error": "revoke names a key this server has not indexed",
    "now": 1785872792
  },
  "statement": { "kind": "unsigned" }
}
```

`400`. That is exactly the key a user is most likely to have on a device
they lost. If the clients on your service enroll a user with one key and
stop, your users have no kill switch — worth knowing before you are asked to
use one.

## What the server tells you

Logs go to stderr as a stream; nothing is written to a file and there is no
rotation to configure. `--log-format json` gives one object per line:

```json
{
  "timestamp": "2026-08-04T19:48:55.735648Z",
  "level": "INFO",
  "fields": { "message": "server started", "listen": "127.0.0.1:4023" },
  "target": "cyphr_server"
}
```

`RUST_LOG` controls filtering and defaults to
`cyphr_server=info,tower_http=info`. At that default there is no access log
at all — a request that succeeds, a request that 404s, and a request refused
by a fence are equally invisible. Turn requests on explicitly:

```sh
RUST_LOG=cyphr_server=info,tower_http=debug cyphr-server serve …
```

```json
{
  "timestamp": "2026-08-04T19:49:22.013997Z",
  "level": "DEBUG",
  "fields": {
    "message": "finished processing request",
    "latency": "1 ms",
    "status": 404
  },
  "target": "tower_http::trace::on_response",
  "span": {
    "method": "GET",
    "request_id": "f2a6264a-2209-4fc1-a461-c3bc96b91a77",
    "uri": "/tip?pr=nobody",
    "name": "request"
  }
}
```

Every request carries a generated `request_id` through its span, so a
failure and its handler's own log lines join up.

**There is no metrics endpoint and no health endpoint.** `/health`,
`/healthz`, `/metrics`, and `/readyz` all return the ordinary `404`:

```json
{
  "v": 1,
  "payload": { "error": "route not found", "now": 1785872935 },
  "statement": { "kind": "unsigned" }
}
```

Use `GET /server` as a liveness probe. It reads memory only, writes nothing,
touches no store, and its `tier` doubles as a check that the server came up
in the configuration you intended — a probe that starts answering
`repository` on a server you deployed as an attestor is telling you that
`signing_key_path` was never _seen_, not that it failed to load: a key file
that exists but is broken takes the whole server down at startup, so a live
server missing its key means the setting itself never reached the process --
the TOML wasn't in the working directory the server started from, or the
environment variable was left unset.

For anything beyond liveness you are counting log lines. The signals worth
extracting, given what is and is not emitted:

- `server principal established` with its `pg`, at every keyed start. A `pg` that changed is the loudest possible alarm — every client that pinned you will refuse.
- `witness sync failed` and `witness sync authenticated-channel check failed`, which say a witness's last sync did not complete. They do not cover the quieter case: a sync that succeeded with entries skipped, which is `witness sync applied entries` with a non-zero `rejected` at `cyphr_server=debug`. Watch that one too if you care whether a witness is complete, not merely alive.
- `configuration error:` on stderr with exit 1, which is a start that never happened.
- Response status counts from `tower_http=debug`, which covers every status a route handler produces — including a witness's `403` write refusal. It does not cover the fences; see below.

**The fence refusals cannot be logged, and no `RUST_LOG` setting changes
that.** The request tracing wraps the routes; the body-limit, rate-limit,
and admission layers wrap the tracing. A `429`, `413`, or `402` is built
and returned by the fence that caught the request, which never calls the
service beneath it, so the request never reaches the traced span and never
gets a line — not at `debug`, not at `trace`. Admission's `403` is refused
the same way. The one `413` that does get a line is the uncommon
chunked-body case above, which is refused from the handler side rather than
by the fence, so a `413` count scraped from logs undercounts by however
many the fence caught. Setting `RUST_LOG=tower_http=debug` to catch a
rate-limit storm buys you a line for every request that _succeeded_ and not
one for any that was throttled.

Witness mode's `403` is the confusing counter-example: it is refused by a
layer sitting _inside_ the tracing, so it does show up like any other
response. Seeing one `403` in the log is what makes it natural to assume
the `429`s are in there somewhere too. They are not.

That leaves the fences observable only from outside the process — from the
reverse proxy or load balancer in front of it, which sees the status codes
the server actually returned. If you want an alarm on rate-limit storms,
oversized bodies, or quota exhaustion, that is where the counter has to
live. There is nowhere inside the server to put it.

## Restarting and upgrading

**Stop with SIGINT or SIGTERM — both drain connections.** `Ctrl-C`,
`systemctl stop`, `docker stop`, and a bare `kill` all reach the same path:

```
INFO cyphr_server: shutdown signal received, draining connections
INFO cyphr_server: server stopped
```

A `kill -9` (SIGKILL) still bypasses this — no signal handler can catch
it — but the store is resilient to that hard kill too: a server restarted
after one opens its directory cleanly with no stale lock and no recovery
step. The cost of a hard kill is borne by in-flight requests, not the data.

An upgrade is therefore: stop the old process and wait for it to exit,
start the new binary against the same data directory. Nothing is versioned
in a way you configure, and there is no migration command. Because the
directory is locked exclusively, a rolling restart of two processes against
one directory is not possible — the second refuses to start. A blue-green
deployment needs two data directories and a resync, not a shared one.

Three things interact with a restart in ways worth planning for:

- **Login challenges** are in-memory and per-process. A client mid-login when you restart gets `login challenge is unknown, already used, or expired` and needs a fresh challenge. Harmless — clients retry — but it is a burst of login failures at every restart.
- **Witness registrations** (`POST /witness/register`) are in-memory. Every witness registered for push fanout is forgotten on restart and must register again. If you depend on fanout, that is a re-registration step in your restart procedure, not something the server recovers on its own.
- **Invite tokens issued to a running server** go the other way: they do nothing until the next restart. `invite new` durably records the new hashes in the tokens file, but the server reads that file once, at startup, and never rereads it. Hand out a token minted after boot and the holder gets a `403` until you restart. Every invite batch costs a restart, the same as the two hazards above.

`rebuild-index` is the one maintenance command that exists. It reconstructs
`index/` entirely from `blobs/`; use it after restoring a partial backup, or
if lookups start disagreeing with what you know is stored. Stop the server
first — it takes the same exclusive lock, so it cannot run against a live
one.

```sh
cyphr-server rebuild-index --data-dir ./data
```

The server also runs an incremental reindex at every startup, so you rarely
need the total rebuild.

## Capacity

There is no published benchmark and no capacity guidance grounded in
measurement, so treat what follows as the shape of the problem rather than
numbers to plan against.

The costs are not evenly distributed. A push validates every signature in
the bundle, re-derives the principal's roots, and — on a keyed server —
signs a receipt, which is why `push` has the tightest default bucket. A
`/tip` on a keyed server is not free either: it re-derives roots to sign its
attestation and refuses to answer if they disagree with the index. A witness
adds an upstream round-trip to the first read of any principal.

Storage grows with commits and never shrinks. Nothing prunes, compacts on a
schedule, or expires; a principal's history is append-only and the death-set
only ever gains rows. The per-principal `count_quota` is the only ceiling on
any single user's contribution, and at its default of a million commits it
is not a storage plan.

The one hard number the server enforces on itself is the rate limiter's
per-bucket ceiling of 100,000 resident keys -- five buckets, so 500,000
resident keys in the worst case, not 100,000. Everything else — memory per
principal, disk per commit, throughput per core — is unmeasured.

## What is not there yet

Named plainly, because finding these out during an incident is worse than
reading them here:

- **No replay protection on witness sync.** The authenticated sync channel (see "Authenticating the upstream" above) verifies a signed report's pairing with local state, not its freshness — a captured, genuinely-signed response can be replayed by an on-path party while the authority advances, and a witness has no way to tell. Tracked as issue #152, gated on an open specification question about what an attestation asserts about currency.
- **No key rotation you can perform.** The capability exists in the codebase and has no command, endpoint, or signal attached to it. A server whose signing key is compromised has no move except a new identity — which breaks every client's pin, because the `pg` changes with the genesis key.
- **No usable proof-of-work admission.** The policy works; nothing that could talk to it exists or is documented.
- **No metrics, no health endpoint, no access log by default.**
- **No backup command.** `cyphr-server export` is listed in `--help` and prints `error: export is not yet implemented`. Consistent backups mean stopping the server.
- **No token revocation and no invite expiry.** A leaked invite token is live until spent; a leaked bearer token is live until it expires, 15 minutes later.
- **No `Retry-After` on a `429`,** and no indication of which bucket refused, so a well-behaved client cannot back off intelligently.
- **No admission or limits configuration outside a TOML file.** Environment-only deployments cannot set them.
- **No permissions model.** Every bearer token the server issues carries `["read","write"]`, and bearer tokens gate almost nothing: `POST /push` checks that a presented token names the principal being written to, and no other route requires one.
- **No freshness guarantee on witness sync.** A captured, genuinely-signed upstream response can be replayed indefinitely to hold a witness at a stale state.
- **No coherent keyed witness.** A witness given a signing key signs what it serves while publishing no key to verify those signatures with.
