# Publishing a record and auditing it

A Cyphr server will sign a statement about what it just did, hand it to
you, and keep no copy. That receipt is the whole trust object. Everything
in this guide follows from it: what a publisher can get signed, what a
watcher can check later without asking the server again, and where the
chain of "check it yourself" runs out.

There are two jobs here and they belong to different people.

**Publishing** is pushing commits to a server and keeping what it hands
back. The commits are your own — your client builds and signs them, the
server validates and stores them. The receipt is the server's signature
over what it accepted.

**Auditing** is holding a server to those signatures. A server that tells
you one thing and someone else another has produced two statements it
signed and cannot take back, and a watcher who collected both is holding
proof. That is the entire enforcement mechanism: there is no quorum, no
consensus round, and nothing that stops a server from lying — only
evidence, after the fact, in the hands of whoever bothered to keep it.

Both halves work today, up to a point. This guide says where the point is.

## Terms

| Term       | What it is                                                                                                       |
| :--------- | :--------------------------------------------------------------------------------------------------------------- |
| Principal  | A user's identity: a chain of commits adding and revoking keys over time. Not a key — a key history.             |
| `pr`       | The identifier a server files a principal under.                                                                 |
| PG         | Principal Genesis. A server's own identifier, derived from its signing key. Tagged, like `SHA-512:wWKa…`.        |
| Coz        | The signed-message format, `{"pay": {…}, "sig": "…"}`. Transactions, receipts, and bearer tokens are all cozies. |
| Receipt    | A coz the server signs over what it accepted or currently sees. Two kinds: commit receipts and tip reports.      |
| Roots      | The four digests summarising a principal's state after a commit: `pr`, `sr`, `ar`, `cr`.                         |
| Split view | One server identity showing two different, irreconcilable answers about the same principal at the same position. |

## The setup this guide runs on

Two servers, one signing key. That is not a normal deployment — it is how
you manufacture a split view later, and it costs nothing to set up now.

Generate a key with Node:

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

Start two servers with that same key and two separate data directories:

```sh
cyphr-server serve --listen 127.0.0.1:4100 --data-dir ./data-a \
  --signing-key-path ./signing-key.json --audience localhost:4100 &
cyphr-server serve --listen 127.0.0.1:4101 --data-dir ./data-b \
  --signing-key-path ./signing-key.json --audience localhost:4101 &
```

Both derive the same identity from the key, and both say so:

```sh
curl -s http://127.0.0.1:4100/server | jq .payload
```

```json
{
  "tier": "attestor",
  "pg": "SHA-512:wWKaBAIFCCvRKbv7DbjsvoYrX986HwRMbtKgC2bwFlm0sVTjfi3aYCkZPVejOOap_Lar56XdaztAmjwL87uYyw",
  "alg": "Ed25519",
  "pub": "iQjl20zGarrf02bY-L-C5NeSb_wCPnb3DGHHK8BMXq4",
  "tmb": "wWKaBAIFCCvRKbv7DbjsvoYrX986HwRMbtKgC2bwFlm0sVTjfi3aYCkZPVejOOap_Lar56XdaztAmjwL87uYyw",
  "genesis": {
    "alg": "Ed25519",
    "pub": "iQjl20zGarrf02bY-L-C5NeSb_wCPnb3DGHHK8BMXq4",
    "tmb": "wWKaBAIFCCvRKbv7DbjsvoYrX986HwRMbtKgC2bwFlm0sVTjfi3aYCkZPVejOOap_Lar56XdaztAmjwL87uYyw",
    "first_seen": 0
  }
}
```

`4101` returns the identical `pg`. From the outside these are one server
with two addresses — which is the point. A server without a signing key
answers `{"tier": "repository"}` and signs nothing; nothing in the auditing
half of this guide applies to one.

Make something to publish. The `cyphr` CLI builds principals locally and
has no command that talks to a server, so the push is a `curl` you
assemble:

```sh
PR=$(cyphr --output json key generate --algo ES256 | jq -r .tmb)
cyphr --output json key add --identity="$PR" --signer="$PR"
cyphr export --identity="$PR" --output ./export.jsonl
```

```
Exported identity to ./export.jsonl
  identity: xljCYLjm22sWdMkW9vyGB8-fGLpaI-YjRQ9D4cM2pho
  commits: 1
```

## Publishing

### What a commit is, and what it leaves behind

A commit is a bundle of signed transactions that mutate a principal's key
history — adding a key, revoking one, creating or freezing the principal.
Push one and the server validates every signature, re-derives the four
roots, stores the blobs, and hands you a receipt.

Turn the newest exported commit into a push body and send it:

```sh
jq -c --arg pid "$PR" -s '{principal_id: $pid, blobs: [.[-1].txs[]
  | tojson | @base64 | gsub("\\+";"-") | gsub("/";"_") | gsub("=";"")]}' \
  ./export.jsonl > ./push.json

curl -s -X POST http://127.0.0.1:4100/push \
  -H 'content-type: application/json' -d @push.json
```

`201`:

```json
{
  "v": 1,
  "payload": {
    "blob_hashes": [
      "63db3adcb04fa00eb1dbe453f4bce474c67e229b7b3292d2417b4efc9e6e7a2c",
      "f0ce0e480d5550f9edea4b529ab9ce4db866daef4eadbdc932de33cfcb4d6cc8"
    ],
    "commit_id": "SHA-256:g9j_aS8iP8PSKzWFuJdUxqCuzcdaFVcrRQb6c-U-QNg",
    "sequence": 0,
    "roots": {
      "pr": "SHA-256:SLJTafFYjz-0JMAx5cPw_5DAfYzcr3b_CM9zlgme_aA",
      "sr": "SHA-256:M20zos467SonM7JqBoNUcvT47nCtkiMoSGg7Egf9svo",
      "ar": "SHA-256:M20zos467SonM7JqBoNUcvT47nCtkiMoSGg7Egf9svo",
      "cr": "SHA-256:g9j_aS8iP8PSKzWFuJdUxqCuzcdaFVcrRQb6c-U-QNg"
    }
  },
  "statement": {
    "kind": "signed",
    "coz": {
      "pay": {
        "alg": "Ed25519",
        "now": 1785879800,
        "tmb": "wWKaBAIFCCvRKbv7DbjsvoYrX986HwRMbtKgC2bwFlm0sVTjfi3aYCkZPVejOOap_Lar56XdaztAmjwL87uYyw",
        "typ": "cyphr-server/receipt/commit",
        "pr": "xljCYLjm22sWdMkW9vyGB8-fGLpaI-YjRQ9D4cM2pho",
        "sequence": 0,
        "commit_id": "SHA-256:g9j_aS8iP8PSKzWFuJdUxqCuzcdaFVcrRQb6c-U-QNg",
        "roots": {
          "pr": "SHA-256:SLJTafFYjz-0JMAx5cPw_5DAfYzcr3b_CM9zlgme_aA",
          "sr": "SHA-256:M20zos467SonM7JqBoNUcvT47nCtkiMoSGg7Egf9svo",
          "ar": "SHA-256:M20zos467SonM7JqBoNUcvT47nCtkiMoSGg7Egf9svo",
          "cr": "SHA-256:g9j_aS8iP8PSKzWFuJdUxqCuzcdaFVcrRQb6c-U-QNg"
        }
      },
      "sig": "IZUqweqL0RdMhssVsutUTjmK0uS9JdoGf9xSbIaG7OHgSqs4gwSF6AhJp7A8uJZD0-_VYGpEAONGabf_4XkTAg"
    }
  }
}
```

The `statement.coz` is the receipt, and it is the only part of that
response worth keeping. The `payload` is the server telling you what it
did; the `coz` is the server signing that it did it. The claims restate
the payload's `commit_id`, `sequence`, and `roots`, stamp them with the
server's key and clock, and mark them `cyphr-server/receipt/commit`.

**Keep the receipt, byte for byte — `pay` and `sig` together.** The server
persists nothing to issue one and holds no log of what it signed. If you
discard it, the fact that this server ever accepted this commit is gone
from everywhere except your side of the exchange.

Notice what the receipt does not carry: `blob_hashes`. It attests a chain
position, not the specific bytes you uploaded. For a commit that is a
distinction without a difference — `commit_id` and the roots are derived
from those exact transactions, so a different bundle could not produce
them. It stops being a distinction without a difference two sections
down, where a push moves the chain nowhere at all and the receipt says so
without saying so.

### Signing a payload `/push` will accept

**A payload's keys have to be sorted alphabetically before you sign it, at
every level of nesting.** Not before you send it — before you sign it.
This is the one rule most likely to cost you an afternoon, because nothing
in the error message points at it.

The same fields, signed over the compact JSON in the order a person would
naturally write them:

```json
{
  "alg": "ES256",
  "now": 1785880079,
  "tmb": "xljCYLjm22sWdMkW9vyGB8-fGLpaI-YjRQ9D4cM2pho",
  "typ": "example.com/note/create",
  "msg": "hello world"
}
```

```
422  payload.error: "protocol: invalid signature"
```

Every error arrives in the envelope every response uses: the message and a
`now` under `payload`, and an unsigned `statement`. Only the message
differs between them, so this guide quotes the message with the path to
it. The failed entity lookup and the failed tip report further down are
shown whole.

The same fields, signed over the alphabetically sorted form:

```json
{
  "alg": "ES256",
  "msg": "hello world",
  "now": 1785880211,
  "tmb": "xljCYLjm22sWdMkW9vyGB8-fGLpaI-YjRQ9D4cM2pho",
  "typ": "example.com/note/create"
}
```

```
201
```

And signed over the sorted form but transmitted with the keys back in
their original order — also `201`. The push path re-sorts every payload's
keys before it verifies, so the wire order is irrelevant and the signed
order is everything.

Nesting is where the rule bites, and both examples above are too flat to
show it. Objects inside arrays get sorted as well; array order itself is
left alone. Publish under a `typ` of your own and the payload acquires
nested structure immediately, which is how you end up staring at
`protocol: invalid signature` over something whose outer keys are plainly
in order:

```json
{
  "alg": "ES256",
  "now": 1785880211,
  "tmb": "xljCYLjm22sWdMkW9vyGB8-fGLpaI-YjRQ9D4cM2pho",
  "typ": "example.com/note/create",
  "note": { "title": "hello", "tags": ["b", "a"], "body": "world" }
}
```

Sign over this instead — `note`'s three keys sorted, `tags` untouched:

```json
{
  "alg": "ES256",
  "note": { "body": "world", "tags": ["b", "a"], "title": "hello" },
  "now": 1785880211,
  "tmb": "xljCYLjm22sWdMkW9vyGB8-fGLpaI-YjRQ9D4cM2pho",
  "typ": "example.com/note/create"
}
```

**This is the opposite of the rule that governs `/auth/login` and
`/revoke`,** both of which verify over the key order they receive. A login
payload signed and sent as `{alg, now, tmb, typ, pr, challenge}` is
accepted; sorted to `{alg, challenge, now, pr, tmb, typ}`, signed sorted
and sent sorted, it is also accepted. Login only requires that your signer
and your serialiser agree on the order. Push requires that both agree with
the sort.

It is key order that carries, not the literal bytes. Both paths re-compact
the payload after parsing it, so whitespace and string escaping are
normalised away on the way to the check — pretty-print your login payload
and it still verifies. Reorder its keys and it does not.

If you drive the CLI you will never meet this, because the transaction
payloads it emits — `{alg, id, now, tmb, typ}` and
`{alg, arrow, now, tmb, typ}` — happen to be alphabetical already. Write
your own client and you meet it immediately.

### Publishing content that is not key history

You can sign a coz with any `typ` you like and push it. The server
verifies the signature against the principal's active keys, answers `201`,
and signs a receipt. Then the content vanishes.

Push a bundle containing only that `example.com/note/create` cozy from
above. Everything in this section runs against `4101`, whose copy of the
principal is already at sequence 1 — the same tip the split-view section
below reports in full, so the numbers here and there match on purpose:

```json
{
  "v": 1,
  "payload": {
    "blob_hashes": [
      "43635be8a87f71b348d78b5b4e5ffde0b94eb46570631132faf9a5c51ea04e2e"
    ],
    "commit_id": "SHA-256:1TixInb1rAVG3xj4g2bXV0MRGt03sd2sKjS8uFM_-fM",
    "sequence": 1,
    "roots": {
      "pr": "SHA-256:MOldD2IVG-RWFVpN72_X3IECouOSNKDkrS7by-tedIU",
      "sr": "SHA-256:NdGwK05M5Lhi3xU5oiu3JIkGD--fh57WUvDcDilysYc",
      "ar": "SHA-256:NdGwK05M5Lhi3xU5oiu3JIkGD--fh57WUvDcDilysYc",
      "cr": "SHA-256:fzbJ1XCD8Pmcdy4pToIaatXz21UjY1N7KEaKEUE3vq0"
    }
  },
  "statement": {
    "kind": "signed",
    "coz": {
      "pay": {
        "alg": "Ed25519",
        "now": 1785880211,
        "tmb": "wWKaBAIFCCvRKbv7DbjsvoYrX986HwRMbtKgC2bwFlm0sVTjfi3aYCkZPVejOOap_Lar56XdaztAmjwL87uYyw",
        "typ": "cyphr-server/receipt/commit",
        "pr": "xljCYLjm22sWdMkW9vyGB8-fGLpaI-YjRQ9D4cM2pho",
        "sequence": 1,
        "commit_id": "SHA-256:1TixInb1rAVG3xj4g2bXV0MRGt03sd2sKjS8uFM_-fM",
        "roots": {
          "pr": "SHA-256:MOldD2IVG-RWFVpN72_X3IECouOSNKDkrS7by-tedIU",
          "sr": "SHA-256:NdGwK05M5Lhi3xU5oiu3JIkGD--fh57WUvDcDilysYc",
          "ar": "SHA-256:NdGwK05M5Lhi3xU5oiu3JIkGD--fh57WUvDcDilysYc",
          "cr": "SHA-256:fzbJ1XCD8Pmcdy4pToIaatXz21UjY1N7KEaKEUE3vq0"
        }
      },
      "sig": "1888gDSol2_nzuHSxjg_tXUY2Tv-PUkmwlgscVmNpsIrddg8wjACGGndNSiUsNmK8S7FnW92hQevo2Nc2vH4CA"
    }
  }
}
```

Every one of those values — `commit_id`, `sequence`, all four roots — is
identical to what the principal already had before the push. Nothing
moved. The receipt is a true, signed statement about a chain position your
content is not in.

The tip agrees that nothing happened:

```sh
curl -s "http://127.0.0.1:4101/tip?pr=$PR" | jq -c '.payload
  | {commit_count, commit_id, last_updated}'
```

```json
{
  "commit_count": 2,
  "commit_id": "SHA-256:1TixInb1rAVG3xj4g2bXV0MRGt03sd2sKjS8uFM_-fM",
  "last_updated": 1785879942
}
```

Unchanged, `last_updated` included. `GET /patch?pr=$PR` returns the same
two entries it did before. And nobody can fetch the content back — the
content-addressed lookup does not find it:

```sh
curl -s "http://127.0.0.1:4101/e/SHA-256:Sea6fBxGvclh1KlA9SVcOSc6gyRRmg_JkKYwT5Xf4rY"
```

```json
{
  "v": 1,
  "payload": {
    "error": "entity SHA-256:Sea6fBxGvclh1KlA9SVcOSc6gyRRmg_JkKYwT5Xf4rY not found",
    "now": 1785880272
  },
  "statement": { "kind": "unsigned" }
}
```

That digest is the cozy's own czd, computed the same way the server would.
A czd of any transaction from the same principal's stored commits resolves
`200` at the same endpoint, so the lookup works; this blob simply is not
in the index. A bundle carrying no chain transaction takes a separate path
that writes the blobs and skips indexing entirely, so no commit forms, no
root moves, and nothing points at what was stored.

**So Cyphr publishes key history, and nothing else, today.** If your
application needs to publish content, anchor it yourself: hash the
content, and put the hash somewhere the chain does cover — or keep the
content and its signature entirely on your own side and use Cyphr for what
it does do, which is telling a reader which keys were legitimately that
principal's at a given moment. Do not read the `201` as acceptance of the
content. It is acceptance of a blob.

### What the record proves, and what it does not

Once a commit is in, a reader who fetches it can establish, without
trusting anyone:

- The transactions were signed by keys active in that principal at that
  point in its history.
- The chain is unbroken from genesis to that commit.
- The roots the server reports are the roots those transactions produce.

A receipt adds one more thing, and only one: **that this server, holding
this key, made this claim at this time.** It is a statement about the
server, not about the world.

What none of it establishes:

- **That the server told anyone else the same thing.** That is the whole
  subject of the second half of this guide.
- **That the claim is current.** A receipt is true forever about the
  moment it names, which means a captured one stays true forever and can
  be replayed at you indefinitely. Nothing in the receipt or the protocol
  makes a stale one detectable.
- **That the server will still say it.** There is no undertaking to
  retain anything. Losing the server's data directory loses the record;
  what survives is what its users and watchers kept.
- **That the identifier is meaningful.** A `pr` is whatever the client
  used on its first push, first-come-first-served within that one server's
  namespace, not something derived from key material. Pushing a
  perfectly ordinary principal's commits under a randomly generated
  identifier gets a `201` and a signed receipt naming that identifier, and
  `GET /tip` then serves it. The only constraint an attestor imposes is
  shape: the identifier has to decode as base64url to 32, 48, or 64 bytes,
  because a receipt's `pr` claim will not compose otherwise. On an
  open-admission server, anyone can take any unused one.

## Auditing

### Where receipts come from

Three endpoints on a keyed server hand out a signed statement, and it is
worth knowing which, because the ones that do not are easy to mistake for
a failure.

| Request                      | Statement                                   |
| :--------------------------- | :------------------------------------------ |
| `POST /push`                 | `cyphr-server/receipt/commit`               |
| `GET /tip?pr=…`              | `cyphr-server/receipt/tip`                  |
| `GET /patch?pr=…`            | `cyphr-server/receipt/tip`, over the tip    |
| `GET /patch?pr=…&to=…`       | Unsigned                                    |
| `GET /server`                | Unsigned                                    |
| `POST /auth/login`           | Unsigned; the bearer token inside is signed |
| Anything on a keyless server | Unsigned                                    |

A bounded `/patch` goes unsigned deliberately: the attestation describes
the principal's current tip, and a response cut short by `to=` does not
reach it, so the server declines to attest a state it did not serve.

An unbounded `/patch` is the most useful request a watcher makes, because
it carries both halves at once — the chain data and a signed tip report
over it. Anchor it at the tip you already hold and you get a freshness
statement with no payload:

```sh
TIPPR=$(curl -s "http://127.0.0.1:4100/tip?pr=$PR" | jq -r .payload.pr)
curl -s "http://127.0.0.1:4100/patch?pr=$PR&from=$TIPPR" \
  | jq -c '{n: (.payload.entries|length), kind: .statement.kind}'
```

```json
{ "n": 0, "kind": "signed" }
```

One request, no data transferred, and a fresh signed claim about where the
server says the principal is.

One endpoint that does not work: **a server cannot report a tip about
itself.** The server is an ordinary principal in its own store, and
`/patch` serves its chain like anyone else's, but the tip report fails:

```sh
curl -s "http://127.0.0.1:4100/tip?pr=SHA-512:wWKaBAIFCCvRKbv7DbjsvoYrX986HwRMbtKgC2bwFlm0sVTjfi3aYCkZPVejOOap_Lar56XdaztAmjwL87uYyw"
```

```json
{
  "v": 1,
  "payload": {
    "error": "attestation root re-derivation failed: malformed blob: genesis blob must contain a 'key' field",
    "now": 1785879825
  },
  "statement": { "kind": "unsigned" }
}
```

`500`, on every keyed server, permanently. The server's own genesis cozy
carries no key material — that is why `GET /server` publishes the genesis
key separately — and the tip attestation path has no way to get it back.
Verification does not need this endpoint, but a monitor sweeping `/tip`
across a server's principals will find one that always fails with a
message that reads like store corruption.

### Verifying a receipt without trusting the server again

Six steps, and they are worth walking because the shape of the answer is
"most of this is portable, one part is not."

1. Pin `pg` and the `genesis` object from `GET /server`.
2. Re-derive the PG from that genesis key alone. If it does not match the
   pinned `pg`, stop — the published key does not back the identity.
3. Fetch the server's own chain: `GET /patch?pr=<pg>`, tagged form
   included. The bare thumbprint is a `404`; the tag is part of the
   identifier the server files itself under.
4. Replay every entry into a fresh, independent engine of your own,
   supplying that genesis key explicitly on each commit. The blobs carry
   no key material, so nothing recovers it from the chain itself.
5. Confirm the receipt's `tmb` is an active key of the chain you just
   replayed.
6. Verify the signature using the public key from that replayed chain.

Steps 1, 3, and 6 you can do in any language. Step 6, for an Ed25519
server key, is the same shape as verifying a bearer token — check the
signature against the SHA-512 digest of the compact `pay`:

```js
const crypto = require("crypto");
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

function verifyReceipt(coz, pubB64) {
  const compact = Buffer.from(JSON.stringify(coz.pay), "utf8");
  const cad = crypto.createHash("sha512").update(compact).digest();
  const key = crypto.createPublicKey({
    format: "der",
    type: "spki",
    key: Buffer.concat([SPKI_ED25519, Buffer.from(pubB64, "base64url")]),
  });
  return crypto.verify(null, cad, key, Buffer.from(coz.sig, "base64url"));
}
```

That code assumes the server signs with Ed25519, which it does in every
example here and need not in yours. An ECDSA server key changes both the
digest — SHA-256 for ES256, SHA-384 for ES384, SHA-512 for ES512 — and the
key construction. Read `alg` off the receipt's own `pay` and branch on it
rather than hard-coding either.

Step 2 is portable for the common case and not in general. A server whose
principal has exactly one genesis key has a PG that is just that key's
thumbprint with its hash algorithm prefixed — `SHA-512:` followed by
`genesis.tmb` in the discovery payload above. Recompute the thumbprint by
hashing the canonical string `{"alg":"<alg>","pub":"<pub>"}` built from
`genesis.alg` and `genesis.pub`, with the algorithm's own hash: SHA-512
for Ed25519 and ES512, SHA-256 for ES256, SHA-384 for ES384. For the
attestor above that reproduces `wWKaBAIF…` exactly.

That shortcut stops holding the moment a principal has more than one
genesis key, where the root is a tree over all of them rather than a
single thumbprint. If you cannot rule that out for the servers you watch,
do step 2 properly or do not claim you did it.

**Steps 4 and 5 have no portable implementation, and what blocks them is
getting the chain in, not replaying it.** Replay ships.
`cyphr tx verify --identity=<pr>` loads a principal out of a local store,
replays every commit through Cyphr's own validation — each signature
checked against the keys active at that point — and compares the principal
root it derives with the one the store recorded. That is step 4, running
today, against a chain that is already local.

Getting a server's chain to be local is the part with no route. Converting
the server's `/patch` response into the shape `cyphr import` reads, with
the genesis key from the discovery hint supplied alongside, gets:

```
error: cannot determine genesis keys from storage
```

`import` has two ways to find a genesis key — your local keystore, or key
material embedded in the chain's first commit — and a server's chain
offers neither, the same gap that breaks its own tip report. There is no
flag that feeds a genesis key in. And `import` does not round-trip
`export` either — `cyphr export`'s own output for an ordinary two-key
principal, imported into an empty store, gets
`error: protocol error: duplicate key`.

So a watcher today has two honest options. Link `cyphr` and
`cyphr-storage` and do the replay properly — a few dozen lines against
`StorageEngine` with an in-memory blob store and indexer, `submit_commit`,
`load_principal`, and `is_key_active`. Or skip steps 4 and 5, verify the
signature against the key `GET /server` publishes, and be clear with
yourself that you have then trusted the server's claim about its own
current key, which is exactly what those two steps exist to avoid.

The second option is not worthless. It still catches a forged receipt from
a third party and still detects a server signing two conflicting things
with one key. What it cannot catch is a server that rotates its published
key to one that never appeared in its chain.

### What to keep

Two things, and nothing else:

- **The receipts, byte-exact.** Both `pay` and `sig`, unmodified. What the
  signature actually depends on is the order of `pay`'s keys, so a round
  trip through anything that reorders them — most object-to-record
  mappings, some databases — destroys it silently. Keeping the bytes is
  the cheap way to keep the order.
- **Enough of the server's chain to bind the signing keys.** A receipt
  names its signing key by thumbprint; the chain is what proves that
  thumbprint was the server's at that moment. Two receipts a rotation
  apart need the segment spanning both keys, which is why the whole
  server chain from `GET /patch?pr=<pg>` is the simple thing to keep.

Nothing needs the server's cooperation afterwards, and nothing needs a
timestamp beyond what the receipts already carry.

### Detecting a split view

A split view is one server identity giving two different, irreconcilable
answers about the same principal at the same chain position. Produce one
with the two servers from the setup, which share a key and share nothing
else.

By design, a server that has a registered witness for a principal does
not leave this comparison to a reader: witness registration and push
fanout already deliver, as a byproduct of work the server does anyway,
each side's own signed tip report and a consistency proof to exchange
against — [the architecture page states the
mechanism](../architecture/equivocation-detection.md#the-exchange). A
finding from that exchange rides along in the server's next ordinary
answer about the principal, so its owner or anyone relying on it [learns
of a fork without going
looking](../use/detecting-a-split-view.md#you-find-out-without-looking).

That exchange does not run in the server this guide talks to — nothing
in `rs/cyphr-server` triggers it yet, a gap the end of this section
names precisely. And the two servers below were never registered as
each other's witness in the first place: sharing a signing key and
nothing else is what lets this setup manufacture a split view without
that registration. Gathering and checking two answers yourself, the way
the rest of this section does, is not only a stand-in for a missing
wire-up — the [pinned predicate](../specs/receipts.md#the-pinned-predicate)
is verifier-side and stateless by design, so a stranger with no witness
relationship to either server, [convinced by nothing but the
bytes](../use/detecting-a-split-view.md#convince-a-stranger), always
ends up running some form of it.

Push the same first commit to both, so they agree. Then build two
conflicting second commits: snapshot the client's local store, add one key,
export; restore the snapshot, add a different key, export.

```sh
cp -r cyphr-data snap && cp cyphr-keys.json snap-keys.json
cyphr --output json key add --identity="$PR" --signer="$PR"
cyphr export --identity="$PR" --output ./export-x.jsonl

rm -rf cyphr-data && cp -r snap cyphr-data && cp snap-keys.json cyphr-keys.json
cyphr --output json key add --identity="$PR" --signer="$PR"
cyphr export --identity="$PR" --output ./export-y.jsonl
```

Two commits with the same predecessor and different contents. Run each
export through the same `jq` that built `push.json` earlier, taking
`.[-1]` so only the newest commit goes out, and send one to each server.
Both take it:

```sh
curl -s -X POST http://127.0.0.1:4100/push \
  -H 'content-type: application/json' -d @push-x.json \
  | jq -c '{sequence: .payload.sequence, commit_id: .payload.commit_id}'
curl -s -X POST http://127.0.0.1:4101/push \
  -H 'content-type: application/json' -d @push-y.json \
  | jq -c '{sequence: .payload.sequence, commit_id: .payload.commit_id}'
```

```json
{ "sequence": 1, "commit_id": "SHA-256:DJ7mXgcMovELEH3QAIaNAaWFNFSQbDe6j6CyQWCrjBg" }
{ "sequence": 1, "commit_id": "SHA-256:1TixInb1rAVG3xj4g2bXV0MRGt03sd2sKjS8uFM_-fM" }
```

A single server does refuse the second branch. Send the other commit to
the server that already took one and it is a `409`:

```
409  payload.error: "protocol: state root mismatch"
```

That refusal is local bookkeeping, not fork detection. The server rejects
a commit that does not follow the state it holds; it does not conclude
anything happened, record the conflicting commit as evidence, or change
how it answers afterwards. Nothing about a fork exists in the server's
vocabulary.

Now ask each server where the principal is:

```sh
curl -s "http://127.0.0.1:4100/tip?pr=$PR" | jq -c '.statement.coz.pay'
curl -s "http://127.0.0.1:4101/tip?pr=$PR" | jq -c '.statement.coz.pay'
```

```json
{
  "alg": "Ed25519",
  "now": 1785879960,
  "tmb": "wWKaBAIFCCvRKbv7DbjsvoYrX986HwRMbtKgC2bwFlm0sVTjfi3aYCkZPVejOOap_Lar56XdaztAmjwL87uYyw",
  "typ": "cyphr-server/receipt/tip",
  "pr": "xljCYLjm22sWdMkW9vyGB8-fGLpaI-YjRQ9D4cM2pho",
  "sequence": 1,
  "commit_id": "SHA-256:DJ7mXgcMovELEH3QAIaNAaWFNFSQbDe6j6CyQWCrjBg",
  "roots": {
    "pr": "SHA-256:H7mluvygAqNaBwUSW7OWnlLxazcG6t_NNPALs3G6JlA",
    "sr": "SHA-256:eMFV9AUzzfnn8PLTd0sgfqj8vYZdwJN9TBgC1MlNZtc",
    "ar": "SHA-256:eMFV9AUzzfnn8PLTd0sgfqj8vYZdwJN9TBgC1MlNZtc",
    "cr": "SHA-256:Iz3NGqU7jCg3i6M6mwgeT_N_ww_ab_CWTquq3DNrwFo"
  },
  "commit_count": 2,
  "last_updated": 1785879941
}
```

```json
{
  "alg": "Ed25519",
  "now": 1785879960,
  "tmb": "wWKaBAIFCCvRKbv7DbjsvoYrX986HwRMbtKgC2bwFlm0sVTjfi3aYCkZPVejOOap_Lar56XdaztAmjwL87uYyw",
  "typ": "cyphr-server/receipt/tip",
  "pr": "xljCYLjm22sWdMkW9vyGB8-fGLpaI-YjRQ9D4cM2pho",
  "sequence": 1,
  "commit_id": "SHA-256:1TixInb1rAVG3xj4g2bXV0MRGt03sd2sKjS8uFM_-fM",
  "roots": {
    "pr": "SHA-256:MOldD2IVG-RWFVpN72_X3IECouOSNKDkrS7by-tedIU",
    "sr": "SHA-256:NdGwK05M5Lhi3xU5oiu3JIkGD--fh57WUvDcDilysYc",
    "ar": "SHA-256:NdGwK05M5Lhi3xU5oiu3JIkGD--fh57WUvDcDilysYc",
    "cr": "SHA-256:fzbJ1XCD8Pmcdy4pToIaatXz21UjY1N7KEaKEUE3vq0"
  },
  "commit_count": 2,
  "last_updated": 1785879942
}
```

Same `tmb`, same `pr`, same `sequence`, different `commit_id` and
different roots. Two statements one key signed, about one chain position,
that cannot both be true.

**Nothing detected this.** Neither server knows the other exists — they
were never registered as each other's witness — and no component
anywhere compared them; a registered pair would find nothing either,
since nothing in the running server triggers that exchange yet (above).
Detection is a thing a watcher does, with bytes it went and collected,
entirely outside the system.

### Checking the evidence

The predicate is short enough to write in whatever your watcher is written
in. Both statements have to be tip reports, both signatures have to verify
under their own key, both have to name the same principal and the same
sequence, and they have to differ in `commit_id` or in any root:

```js
function sameRoots(a, b) {
  return (
    a.pr === b.pr &&
    a.sr === b.sr &&
    a.ar === b.ar &&
    (a.cr ?? "") === (b.cr ?? "")
  );
}

function checkEquivocation(a, aPub, b, bPub) {
  const TIP = "cyphr-server/receipt/tip";
  if (a.pay.typ !== TIP || b.pay.typ !== TIP) return "WrongTyp";
  if (!verifyReceipt(a, aPub) || !verifyReceipt(b, bPub))
    return "InvalidSignature";
  if (a.pay.pr !== b.pay.pr) return "DifferentPrincipal";
  if (a.pay.sequence !== b.pay.sequence) return "DifferentSequence";
  if (
    a.pay.commit_id === b.pay.commit_id &&
    sameRoots(a.pay.roots, b.pay.roots)
  )
    return "IdenticalClaims";
  return "Proven";
}
```

`aPub` and `bPub` are the public keys those two receipts were signed with,
established the way the previous section describes — from a replay of the
server's chain if you did steps 4 and 5, or from `GET /server`'s `pub` if
you did not. Run it against the two reports above:

```
a signature verifies: true
b signature verifies: true
verdict: Proven
```

And against one report compared with itself, which is the control worth
having:

```
verdict: IdenticalClaims
```

**Two keys, not one.** The function takes a key per report, and they may
differ. A server's identity is its chain, not any single key, so two
receipts either side of a key rotation are still two statements by the
same server. Passing one key twice is the ordinary case, not the general
one.

**Compare the roots one named field at a time.** A whole-object
comparison — `JSON.stringify(a.pay.roots) === JSON.stringify(b.pay.roots)`
— is sensitive to the order the keys happen to sit in, so two honest
reports that serialise `roots` differently come out `Proven`: an
accusation against a server that did nothing. The server's own predicate
compares four separately parsed values, which no serialisation order can
disturb. `roots.cr` is an empty string on a principal with no data commit
yet, and the `??` keeps an absent `cr` from reading as a difference
against an empty one.

Two comparisons in that sketch are still looser than the version inside
the server, and they fail in opposite directions. The server parses
`sequence` from either a JSON number or a string of decimal digits, so `1`
and `"1"` are one position; the JavaScript reads them as different and
returns `DifferentSequence` on a genuine conflict. The server also decodes
each digest to bytes before comparing, so two spellings of one digest
cannot read as a difference; the JavaScript compares the strings, and two
spellings of one root come out `Proven`.

Those two costs are not the same. A missed conflict leaves you where you
started. A false `Proven` is an accusation you publish about a server that
never equivocated, which any careful reader can take apart — and which
costs you the credit you need the next time you are right. String
comparison holds only because a stock server emits one canonical spelling
of every digest. Decode before comparing, and accept both spellings of
`sequence`, if you take reports from a source you did not write.

There is a Rust implementation of this predicate — the same one [pinned
in the receipts spec](../specs/receipts.md#the-pinned-predicate) — plus
an all-pairs sweep across a set of reports and a formatter that renders
the conflicting pair as an evidence document. It lives in
`cyphr-server`'s library and has no HTTP route, no CLI subcommand, and
no caller in the server itself — every caller in the workspace is a
test. To use it you link the server crate; to avoid that, write the
predicate above.

### What you hold when you find one

Two cozies the server signed, and the chain segment binding the signing
keys. That is a complete, portable, self-contained proof, and it stays
valid for as long as the signatures do. The server can decline to explain
it, but cannot deny making both statements.

What you can do with it, inside Cyphr, is nothing today. No endpoint
accepts evidence, nothing propagates it, and no server behaves
differently for having seen it — not because that is how the design
ends, but because none of it is wired into the running server yet. Per
the [equivocation detection
architecture](../architecture/equivocation-detection.md#the-exchange), a
server that has run the exchange with a registered witness is supposed
to carry the resulting finding into its next ordinary answer; nothing in
`rs/cyphr-server` triggers that exchange today, so no server does.
SPEC's fuller design goes further still — witnesses that detect forks,
broadcast proof, transition a principal into an error state, and refuse
both branches until resolved ([SPEC
§15.7](../../SPEC.md#157-consensus-and-witnesses),
[§15.7.1](../../SPEC.md#1571-invalid-forks-fork-detection-and-duplicitous-behavior),
[§15.8](../../SPEC.md#158-fork-resolution)) — and none of that is built
either. There is no consensus state machine, no proof-of-error
retention, and no fork detection anywhere in the server. The only piece
of the resync design that exists is `/patch?from=<digest>`, an anchor
that lets a caller ask for everything after a state it already holds.

So the answer to "what do I do with it" is an application question, and
worth deciding before you need it rather than after:

**Stop trusting that server for that principal.** The cheapest response and
the one that always applies. You have proof it gave two answers; treat its
answers as unreliable and fall back to whatever else you have.

**Publish it.** The evidence verifies offline against nothing but the
server's own published identity, so anyone can check it. This is the
pressure the design actually relies on, and it needs somewhere to be
published — which is your problem, not the protocol's.

**Compare more servers.** Two conflicting reports tell you the identity
equivocated but not which answer is the odd one out. A third report
breaks the tie for you, by ordinary majority — nothing in Cyphr does that
reasoning. The all-pairs sweep in `cyphr-server`'s library returns the
first conflicting pair it finds and stops, so it proves misbehaviour
without mapping it; if you want the shape of the disagreement across a
set, collect the verdicts yourself.

**Ask the principal to resolve it.** A fork is resolved when the principal
publishes a commit whose predecessor is the tip of one branch, abandoning
the other. That much works, and because a resolving commit is a push
like any other, `POST /push` fans it out on its own to every server the
principal has registered as a witness — best-effort and asynchronous, no
follow-up action needed (`rs/cyphr-server/src/fanout.rs`'s
`spawn_fanout`, called from the push handler once a commit is accepted;
the mechanism [the architecture page
describes](../architecture/equivocation-detection.md#resolution)). A
server the principal never registered with gets nothing and keeps
serving the abandoned branch — which is exactly `4100` and `4101`'s
relationship here, so resolving this demo's fork means pushing to both
by hand. Building a third commit on the branch server `4101` holds and
pushing it to both:

```
4101  201
4100  409  payload.error: "protocol: state root mismatch"
```

The chosen branch advances and the abandoned one is stuck, which is the
outcome you want. But it is a convention between you and the user, not
something the server participates in: neither server records that a fork
happened, that one branch won, or that the other was abandoned. The `409`
looks the same as any stale push.

### Watching, in practice

A watcher is a loop, and a small one. For each principal you care about
and each server you are willing to ask, fetch the tip, keep the receipt,
and compare across servers. Anchoring at the tip you already hold makes
the steady-state request nearly free — no entries, one signed claim.

Two limits shape how you build it.

**A stale answer is indistinguishable from a current one.** The signature
proves the server said it, not that it is saying it now. An on-path party
holding a genuinely signed response can serve it to you indefinitely while
the real server moves on, and nothing in the receipt or in any comparison
catches it. Poll from more than one network position if that matters, and
treat a tip that has not moved as no information rather than as
confirmation.

**Silence is not evidence.** A server that stops answering, answers `404`,
or serves an old view has done nothing you can prove. Only two conflicting
signatures are provable. Everything else is a reason for suspicion and
nothing more.

## What is not there yet

Named plainly, because finding these out mid-integration is worse than
reading them here:

- **No content publishing.** A bundle with no chain transaction is stored
  and forgotten: no commit, no root movement, no index entry, no way to
  fetch it back — and a signed receipt attesting the unchanged tip anyway.
- **No agreement about what a signature covers.** `/push` verifies over
  the payload's recursively key-sorted form. `/push` is the only endpoint
  that canonicalizes before checking a signature — every other
  signature-verifying path, `/auth/login`, naked `/revoke`, and the
  witness-registration envelope among them, verifies over the key order
  as sent. Hand-build a payload against one assumption and post it to a
  path that holds the other, and the divergence is stated nowhere else:
  the failure it produces is a bare `protocol: invalid signature`.
- **No way to get a server's chain into the verifier that ships.**
  `cyphr tx verify` replays a local principal and re-derives its root, so
  the replay half is real; what is missing is the path in. `cyphr import`
  cannot ingest a server's chain — it fails with
  `cannot determine genesis keys from storage` — and cannot even
  re-import `cyphr export`'s own output, which fails with
  `protocol error: duplicate key`. The six steps end to end exist in full
  only as an integration test.
- **No automatic cross-witness exchange.** The predicate itself is meant
  to run this way — [verifier-side and
  stateless](../specs/receipts.md#equivocation-evidence) — so running it
  yourself, as this guide does, is not standing in for a missing
  feature. What is missing is the automation for a registered witness:
  `rs/cyphr-server/src/consistency.rs`'s
  `check_cross_witness_consistency`, `detect_fork_unverified`, and
  `format_disagreement_evidence` have no caller anywhere in the running
  server, only in its test suite, so [the exchange the architecture page
  describes](../architecture/equivocation-detection.md#the-exchange)
  never runs and no finding ever rides along in an answer.
- **No tip report about the server itself.** `GET /tip` on a server's own
  PG is a permanent `500`, though `/patch` on it works.
- **No fork detection beyond that predicate.** A server refuses a
  conflicting commit with a `409` and draws no conclusion. No consensus
  state machine, no proof-of-error retention, no state jumping — SPEC's
  own design for it ([§15.7](../../SPEC.md#157-consensus-and-witnesses),
  [§15.7.1](../../SPEC.md#1571-invalid-forks-fork-detection-and-duplicitous-behavior),
  [§15.8](../../SPEC.md#158-fork-resolution)) describes all of it and
  none of it is built. The one piece of the resync design that exists is
  `/patch`'s digest anchor.
- **Nowhere to file evidence.** No endpoint accepts it, nothing
  propagates it, and no server behaves differently for having seen it.
- **No freshness.** A genuinely signed response stays true about its
  moment forever and can be replayed at a reader or a witness
  indefinitely.
- **No key-inclusion proof endpoint.** A third party can verify that a key
  was included under a principal's root given the four proof hops, but no
  route serves those hops; whoever holds the chain has to generate them.
