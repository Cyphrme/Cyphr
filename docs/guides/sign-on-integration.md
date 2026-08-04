# Adding Cyphr sign-in to an OIDC relying party

You already run OIDC. Your users click "Sign in with X", your app gets an
identity from a provider, and you turn that into a session. Adding Cyphr
sign-in replaces the provider with a signature the user's own device makes.
Everything downstream of "who is this?" stays where it is.

Concretely, you build three things:

- A **Cyphr server** your app can reach, or a pointer to one someone else
  runs. It holds users' key history and verifies logins.
- A **signing step in your client** — a few dozen lines. The user's key never
  leaves their device, so nothing on your side can do this for them.
- A **mapping from principal identifier to your account row**, which is the
  same table you already have for `sub`.

What you do not build: a password reset, an email verification loop, a
session-cookie scheme (keep yours), or an authorization model (keep yours).

The rest of this guide walks the exchange end to end with real requests, then
covers the case that makes this subject non-trivial: a user who has dropped
their phone in a lake and is signing in with a key your server has never seen.

## Terms you need

| Term      | What it is                                                                                                         |
| :-------- | :----------------------------------------------------------------------------------------------------------------- |
| Principal | A user's identity: a chain of commits that adds and revokes keys over time. Not a key — a key _history_.           |
| `pr`      | The identifier a Cyphr server files a principal under. This is what you store on your account row.                 |
| `tmb`     | A key's thumbprint. A hash of the key's algorithm and public key.                                                  |
| Coz       | The signed-message format: `{"pay": {...}, "sig": "..."}`. Login payloads and bearer tokens are both Coz messages. |
| Audience  | The identity your Cyphr server answers to, named inside every login signature.                                     |

## Stand up a server

Point the server at a data directory, give it a signing key, and tell it what
audience it answers to:

```sh
cyphr-server serve \
  --listen 127.0.0.1:3999 \
  --data-dir ./data \
  --signing-key-path ./signing-key.json \
  --audience localhost:3999
```

The equivalent environment variables are `CYPHR_LISTEN`, `CYPHR_DATA_DIR`,
`CYPHR_SIGNING_KEY_PATH`, and `CYPHR_AUDIENCE`; a `cyphr-server.toml` in the
working directory sets the same fields.

**The signing key** is what the server signs bearer tokens with. It is a JSON
file holding a raw keypair:

```json
{
  "alg": "Ed25519",
  "pub_key": "LNTO4mebHBg3YzWB2QwjXyETKcbvmmSnJ7hLMKGEElo",
  "prv_key": "-YSZ3MD_vmCxINuQHpTM3LkQ9zCdBVkYEVr1glDJp-Q"
}
```

Both fields are base64url without padding, over raw key bytes — for Ed25519,
32 bytes each. Generate one with Node:

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

Without a signing key the server refuses login entirely — it cannot issue a
token it cannot sign. `POST /auth/login` and `POST /auth/challenge` both
answer `501`:

```json
{
  "v": 1,
  "payload": {
    "error": "this server runs without a signing identity; login is not offered -- see GET /server for the declared capability tier",
    "now": 1785862749
  },
  "statement": { "kind": "unsigned" }
}
```

**The audience** is the part that stops a relay attack, and it is worth
understanding before you pick a value. Every login signature names the service
the user believes they are signing in to. Your server compares that name
against its own `--audience` and rejects anything else. Without it, a hostile
service could take a login a user signed for _it_, replay it to _you_, and
collect a session as that user. Pick the host your users' clients actually
address — `login.example.com`, not `Example Inc`.

Setting a signing key but forgetting `--audience` leaves the server in a state
where `POST /auth/challenge` still hands out nonces but every login fails with
a `500`. Configure both together.

Check what you got:

```sh
curl -s http://127.0.0.1:3999/server
```

```json
{
  "v": 1,
  "payload": {
    "tier": "attestor",
    "pg": "SHA-512:mRf9FF8DhlZs...",
    "alg": "Ed25519",
    "pub": "LNTO4mebHBg3YzWB2QwjXyETKcbvmmSnJ7hLMKGEElo",
    "tmb": "mRf9FF8DhlZs...",
    "genesis": {
      "alg": "Ed25519",
      "pub": "LNTO4mebHBg3YzWB2QwjXyETKcbvmmSnJ7hLMKGEElo",
      "tmb": "mRf9FF8DhlZs...",
      "first_seen": 0
    }
  },
  "statement": { "kind": "unsigned" }
}
```

`payload.pub` is the key you will verify bearer tokens against. `tier` reads
`repository` on a server with no signing key, and `attestor` on one that can
sign. Every response from this server is wrapped the same way: a version `v`,
your `payload`, and a `statement` slot that says explicitly whether the server
signed the response. Errors come back in the same envelope with
`payload.error`.

## Make a test principal

You need a user to sign in as, and in production your client creates one. To
get one now, use the `cyphr` CLI. It creates and mutates principals locally
but has no command that talks to a server, so the push is a `curl` you build
yourself.

```sh
PR=$(cyphr --output json key generate --algo ES256 | jq -r .tmb)
cyphr --output json key add --identity="$PR" --signer="$PR"
cyphr export --identity="$PR" --output ./export.jsonl
```

That leaves keys in `./cyphr-keys.json`, a principal in `./cyphr-data`, and a
JSONL file with one line per commit. Turn the newest commit into a push body
and send it:

```sh
jq -c --arg pid "$PR" -s '{principal_id: $pid, blobs: [.[-1].txs[]
  | tojson | @base64 | gsub("\\+";"-") | gsub("/";"_") | gsub("=";"")]}' \
  ./export.jsonl > ./push.json

curl -s -X POST http://127.0.0.1:3999/push \
  -H 'content-type: application/json' -d @push.json
```

`201`, with this `payload` (the response also carries a `statement` of kind
`signed` — a receipt the server signed over exactly these roots):

```json
{
  "blob_hashes": [
    "49e91e044083d384b2fa84b0d41179ca2c05de83c9f883379202205ec20437bc",
    "1aa0dc85394503326b22d940af233af03cd27bc6759361a3eacd279b3b972de2"
  ],
  "commit_id": "SHA-256:NK5GHZP2MEdzmH3b26xb5CDsEQZ7D1m5eyy_3I1di44",
  "sequence": 0,
  "roots": {
    "pr": "SHA-256:OVQOpDdSBKT4uyXvQMwqn15iOy3oK3zASO9tuLtU46g",
    "sr": "SHA-256:VtpqdWOesrfKmfpZF55VPCDg_mSP2pl-Re-NjULgyGg",
    "ar": "SHA-256:VtpqdWOesrfKmfpZF55VPCDg_mSP2pl-Re-NjULgyGg",
    "cr": "SHA-256:NK5GHZP2MEdzmH3b26xb5CDsEQZ7D1m5eyy_3I1di44"
  }
}
```

The `jq` rewrites each transaction as a base64url blob, which is the shape
`/push` wants; standard base64 will not do, which is what the `gsub` chain is
for. Use `.[-1]` to send only the newest commit — re-sending one the server
already holds is an error.

Use the genesis thumbprint as the principal id, as above. The write path
accepts an arbitrary string, but on a server that signs its responses a
non-thumbprint id makes the push return `500` with `commit receipt signing
unavailable` even though the commit was stored — a confusing state to debug
and one that gets worse on retry.

Two CLI limits to know before you lean on it: `key add` and `key revoke` fail
outright on Ed25519 principals (`digest length mismatch for SHA-256: expected
32 bytes, got 64`), so use ES256 for principals you create this way, and `key
revoke` refuses unless `--key` equals `--signer`, so it can only ever
self-revoke.

## The exchange

Five steps. Steps 2 and 3 are the only new code in your app.

1. Your app asks the Cyphr server for a challenge.
2. Your client signs a login payload naming the challenge, the audience, and
   which principal it is logging in as.
3. Your app posts that to the Cyphr server and gets a bearer token.
4. Your app verifies the token's signature against the server's public key.
5. Your app looks up the token's `pr` in your account table and starts its own
   session.

### 1. Get a challenge

```sh
curl -s -X POST http://127.0.0.1:3999/auth/challenge
```

```json
{
  "v": 1,
  "payload": { "challenge": "Ala4GzN1T25zOEmPYlXfQpm2jUmdhm9Qe5PemmLsbnM" },
  "statement": { "kind": "unsigned" }
}
```

A 256-bit nonce, good for one login and 120 seconds.

There is a second flow that skips this round-trip: sign a payload with a
current `now` timestamp and no challenge, and the server accepts it if `now`
is within 60 seconds of its own clock. It is cheaper and it is weaker —
**the same signed payload is accepted repeatedly for the whole window**.
Anyone who captures one has a minute to reuse it. Use the challenge flow for
sign-in; the timestamp flow suits a client that is re-authenticating its own
background traffic over a channel you already trust.

### 2. Sign the login payload

The payload carries six fields: the algorithm, the timestamp, the signing
key's thumbprint, a `typ` that carries your audience, the principal the signer
claims to be, and the challenge.

```json
{
  "pay": {
    "alg": "ES256",
    "now": 1785862430,
    "tmb": "M9wE8OFsu_LZweYWTnJn_ezJzb_VWyxfibuk03_dwbk",
    "typ": "localhost:3999/cyphr/auth/login",
    "pr": "M9wE8OFsu_LZweYWTnJn_ezJzb_VWyxfibuk03_dwbk",
    "challenge": "Ala4GzN1T25zOEmPYlXfQpm2jUmdhm9Qe5PemmLsbnM"
  },
  "sig": "57TBiuouH0xrMY7B_YsobElQ5BHljz61tqVYK98rkB50zL5OYrik9L15pkTBRUMcK1yi4AJiaD29OT0x6n5a9w"
}
```

`typ` is your audience followed by `/cyphr/auth/login`. The server splits on
that suffix and compares the front half to its own configured audience.

The `pr` field is the reason this looks different from OIDC. One key can be
active in several principals at once, so the server cannot look up "who is
this?" from the thumbprint — the answer might be three people. The signer
names the principal, and the server checks that this key is active in _that_
principal specifically. Your client therefore has to remember which principal
it is signing in as. Store it next to the key.

The signing code, in full:

```js
const crypto = require("crypto");

const b64 = (b) => Buffer.from(b).toString("base64url");
const unb64 = (s) => Buffer.from(s, "base64url");

// P-256 group order. Coz accepts only low-S ECDSA signatures; most libraries
// emit either half at random, so S has to be folded into the low half before
// the signature goes on the wire.
const N = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);

function lowS(sig) {
  const r = sig.subarray(0, 32);
  let s = BigInt("0x" + Buffer.from(sig.subarray(32, 64)).toString("hex"));
  if (s > N / 2n) s = N - s;
  return Buffer.concat([
    r,
    Buffer.from(s.toString(16).padStart(64, "0"), "hex"),
  ]);
}

function privateKey(prvRaw, pubRaw) {
  return crypto.createPrivateKey({
    format: "jwk",
    key: {
      kty: "EC",
      crv: "P-256",
      d: b64(prvRaw),
      x: b64(pubRaw.subarray(0, 32)),
      y: b64(pubRaw.subarray(32, 64)),
    },
  });
}

// A key's thumbprint is a hash of this exact canonical string — SHA-256 for
// ES256, SHA-512 for Ed25519.
function thumbprint(pubRaw) {
  return b64(
    crypto
      .createHash("sha256")
      .update(`{"alg":"ES256","pub":"${b64(pubRaw)}"}`)
      .digest(),
  );
}

function signLogin({ prv, pub, audience, pr, challenge }) {
  const pay = {
    alg: "ES256",
    now: Math.floor(Date.now() / 1000),
    tmb: thumbprint(pub),
    typ: `${audience}/cyphr/auth/login`,
    pr,
  };
  if (challenge) pay.challenge = challenge;

  const compact = Buffer.from(JSON.stringify(pay), "utf8");
  const sig = crypto.sign("sha256", compact, {
    key: privateKey(prv, pub),
    dsaEncoding: "ieee-p1363",
  });
  return JSON.stringify({ pay, sig: b64(lowS(sig)) });
}
```

Three details in there will cost you an afternoon if you meet them by
surprise:

**Field order is part of the signature.** The signature covers the compact
JSON of `pay` with its fields in the order you wrote them. Serialize once and
send those exact bytes. Whitespace does not matter — the server re-compacts —
but if anything reorders your keys between signing and sending, the signature
will not verify.

**ECDSA signatures have to be low-S.** A P-256 signature `(r, s)` is equally
valid as `(r, n − s)`, and Node picks whichever the RNG lands on. The server
rejects the high one outright. Fold it, or roughly half your logins will fail
with `login signature is invalid` and nothing about the failure will look
deterministic.

**Signatures are raw `r ‖ s`, not DER.** That is what `dsaEncoding:
"ieee-p1363"` is doing above.

Ed25519 works too, and its login payloads look identical apart from `alg`. It
differs in two places: the thumbprint hashes with SHA-512 rather than SHA-256,
and the signature is made over the SHA-512 digest of the compact payload
rather than over the payload itself. There is no low-S concern.

### 3. Post the login

```sh
curl -s -X POST http://127.0.0.1:3999/auth/login \
  -H 'content-type: application/json' \
  -d '{"pay":{"alg":"ES256","now":1785862430,"tmb":"M9wE8OFsu_LZweYWTnJn_ezJzb_VWyxfibuk03_dwbk","typ":"localhost:3999/cyphr/auth/login","pr":"M9wE8OFsu_LZweYWTnJn_ezJzb_VWyxfibuk03_dwbk"},"sig":"57TBiuouH0xrMY7B_YsobElQ5BHljz61tqVYK98rkB50zL5OYrik9L15pkTBRUMcK1yi4AJiaD29OT0x6n5a9w"}'
```

```json
{
  "v": 1,
  "payload": {
    "token": "{\"pay\":{\"alg\":\"Ed25519\",\"now\":1785862536,\"tmb\":\"mRf9FF8DhlZs...\",\"typ\":\"cyphr-server/auth/token\",\"pr\":\"M9wE8OFsu_LZweYWTnJn_ezJzb_VWyxfibuk03_dwbk\",\"exp\":1785863436,\"perms\":[\"read\",\"write\"]},\"sig\":\"efaRhdSMKMRCcmpbzZfBYbhqNImnZ-oRjvJ9wFKyeAoMuHD8y1EoDZOiWqaxAoVoGAEhvFpd04riNBZY_QWxDQ\"}"
  },
  "statement": { "kind": "unsigned" }
}
```

`payload.token` is a JSON string containing a Coz message the server signed.
It lives 15 minutes. Ignore `perms`: the server has no permissions model yet,
so every token it issues carries this same pair. Your own authorization stays
yours.

### 4. Verify the token

The token proves the Cyphr server vouched for this principal, so check the
signature rather than trusting the transport. You need `payload.pub` from
`GET /server`, fetched once at startup.

```js
const crypto = require("crypto");
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

function verifyToken(token, serverPubB64, now) {
  const { pay, sig } = JSON.parse(token);
  const compact = Buffer.from(JSON.stringify(pay), "utf8");
  const cad = crypto.createHash("sha512").update(compact).digest();
  const key = crypto.createPublicKey({
    format: "der",
    type: "spki",
    key: Buffer.concat([SPKI_ED25519, Buffer.from(serverPubB64, "base64url")]),
  });

  if (!crypto.verify(null, cad, key, Buffer.from(sig, "base64url"))) {
    throw new Error("token signature is invalid");
  }
  if (pay.typ !== "cyphr-server/auth/token") {
    throw new Error(`not a bearer token: typ=${pay.typ}`);
  }
  if (pay.exp <= now) throw new Error("token has expired");

  return { pr: pay.pr, perms: pay.perms, exp: pay.exp };
}
```

Check `typ`, not just the signature. The server's key signs other things —
commit receipts, tip reports — and every one of those is a genuine signature
by the same key. `typ` is what separates "the server said something" from "the
server issued a session".

There is no revocation list. A token is valid until it expires, full stop. If
you need to cut a session short, cut yours — do not expect the Cyphr server to
help.

### 5. Map `pr` to an account

```js
const claims = verifyToken(token, serverPub, Math.floor(Date.now() / 1000));
let account = await db.accountByPrincipal(claims.pr);
if (!account) account = await db.createAccount({ principal: claims.pr });
await session.start(account);
```

This is the same shape as your `sub` handling, with one difference worth
sitting with: `pr` is the identifier the Cyphr server files the principal
under, and the server accepts whatever identifier the client used when it
first pushed. It is first-come-first-served within that server's namespace,
not a value derived from the key material. On a server with open admission,
that namespace is open to anyone. If your deployment cares — and if you are
using someone else's Cyphr server, it should — run the server yourself with
`[admission] policy = "invite"` or `"pow"`, or scope your account table to the
specific server that vouched for the principal.

## The rejections you have to handle

The message text is the `payload.error` field verbatim. Every row except the
frozen-or-deleted one came from a running server; that one is exercised by the
server's own test suite rather than reproduced here, because no shipped tool
freezes a principal.

| Status | `payload.error`                                             | What happened                                         | What to do                                                                                                 |
| :----- | :---------------------------------------------------------- | :---------------------------------------------------- | :--------------------------------------------------------------------------------------------------------- |
| 400    | `failed to parse login body as JSON: ...`                   | The body is not JSON.                                 | Bug in your client.                                                                                        |
| 401    | ``login payload is missing required field `pr` ``           | No principal claimed.                                 | Bug in your client.                                                                                        |
| 401    | ``login payload `typ` is not a login request``              | `typ` does not end in `/cyphr/auth/login`.            | Bug in your client.                                                                                        |
| 401    | `login payload names no audience`                           | `typ` is the bare suffix.                             | Bug in your client.                                                                                        |
| 401    | `login audience does not name this server`                  | The signature names a different service.              | Either a config mismatch or a relayed login. Do not retry; log it.                                         |
| 401    | `login signature is invalid`                                | Signature does not verify.                            | Usually high-S, or reordered fields.                                                                       |
| 401    | `login: unknown principal`                                  | The server has never seen this `pr`.                  | See below — likely an unsynced client.                                                                     |
| 401    | `signing key is not an active key of the claimed principal` | The key is not active in that principal.              | See below — likely an unsynced client.                                                                     |
| 401    | `claimed principal is not in an active lifecycle state`     | Frozen or deleted.                                    | Tell the user their identity is frozen. A frozen principal is a deliberate act, often a response to theft. |
| 401    | `login challenge is unknown, already used, or expired`      | Nonce spent or older than 120 seconds.                | Fetch a fresh challenge and retry once.                                                                    |
| 401    | `login timestamp is outside the acceptance window`          | `now` more than 60 seconds from server time.          | Client clock skew.                                                                                         |
| 401    | `signing key was naked-revoked`                             | The key's holder declared it compromised out of band. | Never retry. This key is dead on this server for every purpose.                                            |
| 500    | `server is not configured to accept logins`                 | No audience configured.                               | Fix your deployment.                                                                                       |
| 501    | `this server runs without a signing identity; ...`          | No signing key.                                       | Fix your deployment.                                                                                       |

The two rows that say "see below" are the ones a legitimate user hits, and
they are the subject of the rest of this guide.

## When a user shows up with a new key

A user's phone goes into a lake. They buy a new one, generate a key on it, and
try to sign in. What happens next depends entirely on whether they still hold
_any_ key of their principal.

### They still hold a key: nothing breaks, but you have to sync

This is the ordinary case and the one to design for. The user had a backup key
— a hardware token, a second device, a paper key — so their principal is
intact. Their client signs a `key/create` transaction with the surviving key,
adding the new one. The principal is the same principal. `pr` does not change.
Your account row does not change.

But your Cyphr server does not know yet. It reconstructs each principal from
the commits it has been given, so until the client pushes that new commit, the
new key is a stranger:

```
POST /auth/login   (signed by the new key, claiming the same pr)
-> 401 {"error":"signing key is not an active key of the claimed principal"}
```

The client pushes its new commit — the same `export`, `jq`, and `POST /push`
sequence used to enroll the principal in the first place — and the server
answers `201`. The identical login then succeeds:

```
POST /auth/login   (same new key, same pr, fresh challenge)
-> 200  {"token": "..."}
```

**What this means for your integration:** treat `signing key is not an active
key of the claimed principal` as _maybe stale_, not _definitely wrong_. It is
the same response a genuine impostor gets, so do not weaken it — but the
recovery for a legitimate user is a push, not a support ticket. Have your
client push its pending commits and retry the login once before showing the
user an error. If you cannot make the client do that, at minimum make the
error message say "your device has changes this server has not seen yet"
rather than "invalid credentials", because the second one sends the user to
password-reset flows that do not exist here.

Retiring a key works the same way, one push later. Once the client pushes a
`key/revoke`, the retired key stops working:

```
POST /auth/login   (signed by the revoked key)
-> 401 {"error":"signing key is not an active key of the claimed principal"}
```

Note that both cases produce the same message. If you want to distinguish
"never seen" from "revoked" in your UI, you cannot do it from the login
response.

### Killing a stolen key immediately

A revocation pushed as a commit only takes effect on servers that receive the
commit. When a key is not merely retired but _compromised_, there is a faster
lever that does not need the principal's chain at all: `POST /revoke` takes a
self-signed `key/revoke` payload plus the public key it names, and marks that
key dead on that server for every purpose.

The request body is a `key/revoke` payload the dying key signs about itself,
plus that key's public bytes so the server can check the signature without
consulting anything. It reuses the signing helpers from step 2:

```js
function nakedRevoke({ prv, pub }) {
  const now = Math.floor(Date.now() / 1000);
  const pay = {
    alg: "ES256",
    now,
    rvk: now,
    tmb: thumbprint(pub),
    typ: "cyphr.me/cyphr/key/revoke",
  };
  const compact = Buffer.from(JSON.stringify(pay), "utf8");
  const sig = crypto.sign("sha256", compact, {
    key: privateKey(prv, pub),
    dsaEncoding: "ieee-p1363",
  });
  return JSON.stringify({
    pay,
    sig: b64(lowS(sig)),
    key: { alg: "ES256", pub: b64(pub) },
  });
}
```

```sh
curl -s -X POST http://127.0.0.1:3999/revoke \
  -H 'content-type: application/json' -d "$REVOKE_BODY"
```

```json
{
  "v": 1,
  "payload": {
    "revoked_tmb": "R5PV3JqMiUNSFdyjClRrNGNF7APWUUPB638wQoOQz4c",
    "recorded": true
  },
  "statement": { "kind": "unsigned" }
}
```

Logins by that key then fail with a message of their own, and no push, sync,
or principal state is involved:

```
-> 401 {"error":"signing key was naked-revoked"}
```

It is signed by the dying key itself, so the user needs to still hold it — this
is for "my laptop was stolen and I have the backup", not for a key that is
simply gone.

**One sharp limitation.** The server only accepts this for a key it has
indexed, which in practice means a key introduced by a `key/create`
transaction. A principal's _genesis_ key is not indexed, so the same request
naming a genesis key is refused:

```
-> 400 {"error":"revoke names a key this server has not indexed"}
```

That is precisely the key a user is most likely to have on the device they
lost. If your enrollment flow generates one key and stops, your users have no
emergency kill switch. Have the client add a second key at enrollment and use
_that_ one day to day, keeping genesis offline.

### They hold nothing: a new principal, and you have a stranger

If every key is gone, the principal cannot be extended — there is no key left
to sign the transaction that would add one. What the user creates on their new
phone is a genuinely different principal, with a different `pr`. There is no
cryptographic link between it and the old one. From your server's point of
view a new person just walked up.

This is where you have to build something, and it is worth being blunt: **the
protocol will not solve this for you and neither will the server.** Cyphr's
answer is a recovery agent — a backup key, a service, or a set of contacts the
principal designated in advance, who can sign a transaction into a new
principal that vouches for the link. That designation has to have happened
_before_ the loss, and today the Cyphr server implements none of it: there is
no recovery transaction type wired into the server, and no endpoint that
answers "is this new principal the successor of that old one?"

So the re-binding is your application's problem, exactly as account recovery
is your problem today with OIDC. Your options, and what each costs:

**Ask the old principal to authorize the swap.** If any old key still works,
the user signs in normally and adds the new principal to their account row.
Costs nothing, works only when the loss is partial — which means it is not
really the lockout case.

**Fall back to a second factor you already hold.** Email, phone, an existing
OIDC provider you have not turned off. Cheap and familiar, and it puts your
users' account security back on the weakest of those factors. If you are
adopting Cyphr to escape exactly that dependency, this option quietly
un-adopts it.

**Require the user to have designated a recovery path in advance.** Have your
client register a backup key at enrollment, kept somewhere the phone is not,
and treat sign-in by that key as authorization to bind a new principal. This
is the shape the protocol is built for and the only option that keeps the
security story intact. It costs you an enrollment step users will try to skip,
and it costs you a decision about what to do for the ones who skipped it.

**Manual review.** A human decides. Honest, does not scale, and worth having
anyway as the floor under the other three.

Whatever you pick, one design point holds across all of them: keep your
account row's link to `pr` one-to-many and mutable from the start. An account
that can hold two principal identifiers — the retired one and the current one
— makes every one of these paths a row update. An account with `pr` as its
primary key makes every one of them a migration.

## What is not there yet

Named plainly, because finding these out mid-integration is worse than reading
them here:

- **No client library.** There is no SDK for signing a login. The code in this
  guide is the reference; port it to your stack.
- **No CLI for the network.** `cyphr` creates and mutates principals locally
  and exports them; it has no command that talks to a server. The `jq` bridge
  above is what stands in for a push command, and you will want to replace it
  with something in your client.
- **`cyphr key add` and `cyphr key revoke` fail on Ed25519 principals.** Use
  ES256 for principals you create with the CLI. The server itself handles
  Ed25519 keys fine, and its own signing key in the examples above is Ed25519.
- **`cyphr key revoke` only self-revokes.** It requires `--key` to equal
  `--signer`, so you cannot use a surviving key to revoke a lost one from the
  command line. For the lost-device case — where the whole point is that you
  no longer hold the key you want to kill — this is the one operation you most
  need and cannot perform with shipped tooling. The protocol permits it; the
  CLI does not implement it.
- **`POST /revoke` cannot kill a genesis key**, as above.
- **No permissions.** Every token carries `["read","write"]`.
- **No token revocation.** Expiry only, 15 minutes.
- **No recovery transactions on the server.** Recovery agents, freeze, and
  thaw are specified; the server does not implement them.
- **Bearer tokens gate almost nothing.** `POST /push` accepts a token and
  checks it names the principal being written to, and rejects it otherwise.
  No other route requires one. The token's real job is telling your app who
  the user is.
