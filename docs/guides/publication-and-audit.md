# Publishing a record and auditing it

A Cyphr server will sign a statement about what it just did, hand it to
you, and keep no copy of it. That receipt is the whole trust object. Everything
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
signed and cannot take back. That is the entire enforcement mechanism:
there is no quorum, no consensus round, and nothing that stops a server
from lying — only evidence, after the fact. No server is an authority
over anyone's record and none collects that evidence on your behalf: it
exists only if somebody went and collected it.

Both halves have real limits. This guide says where they are.

## Terms

| Term       | What it is                                                                                                       |
| :--------- | :--------------------------------------------------------------------------------------------------------------- |
| Principal  | A user's identity: a chain of commits adding and revoking keys over time. Not a key — a key history.             |
| `pr`       | The principal's identifier, derived from its genesis keys.                                                       |
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
  "pg": "SHA-512:lsraVr9sNuOtusTnvuVlQj5hbteg9LOBAsduqNE2bbQuZ0buuXMLg_QgNqVBpyxfy6NwCkV544kb98AuN7ng2Q",
  "alg": "Ed25519",
  "pub": "jPTSUUyNf2ZAQe77EsWmE0A6qXsuKkqfUDC5U87oJQk",
  "tmb": "lsraVr9sNuOtusTnvuVlQj5hbteg9LOBAsduqNE2bbQuZ0buuXMLg_QgNqVBpyxfy6NwCkV544kb98AuN7ng2Q",
  "genesis": {
    "alg": "Ed25519",
    "pub": "jPTSUUyNf2ZAQe77EsWmE0A6qXsuKkqfUDC5U87oJQk",
    "tmb": "lsraVr9sNuOtusTnvuVlQj5hbteg9LOBAsduqNE2bbQuZ0buuXMLg_QgNqVBpyxfy6NwCkV544kb98AuN7ng2Q",
    "first_seen": 0
  }
}
```

`4101` returns the identical `pg`. From the outside these are one server
with two addresses — which is the point. A server without a signing key
answers `{"tier": "repository"}` and signs nothing; nothing in the auditing
half of this guide applies to one.

Make something to publish. The `cyphr` CLI can push to a server itself
(`cyphr push --identity="$PR" --peer=http://127.0.0.1:4100`); this guide
builds the request by hand with `curl`, so that you hold the raw response
and its receipt. The CLI reports `status` `accepted` when it sent commits,
`up_to_date` when the peer already held everything, and `peer_in_error`
when the peer answered `423` because the principal is in Error there
(`rs/cyphr-cli/src/commands/network.rs:221-227`):

```sh
PR=$(cyphr --output json key generate --algo ES256 | jq -r .tmb)
cyphr --output json key add --identity="$PR" --signer="$PR"
cyphr export --identity="$PR" --output ./export.jsonl
```

```
Exported identity to ./export.jsonl
  identity: N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow
  commits: 2
```

## Publishing

### What a commit is, and what it leaves behind

A commit is a bundle of signed transactions that mutate a principal's key
history — adding a key, revoking one, creating or freezing the principal.
Push one and the server validates every signature, re-derives the four
roots, stores the blobs, and hands you a receipt.

Turn each exported commit into a push body and send them in order (a new
principal exports two: the genesis commit, then the key add, and the server
refuses a first push that is not a genesis commit):

```sh
jq -c --arg pid "$PR" '{principal_id: $pid, keys: .keys,
  txs: [.txs[] | map(tojson | @base64 | gsub("\\+";"-") | gsub("/";"_") | gsub("=";""))]}' \
  ./export.jsonl |
while IFS= read -r body; do
  curl -s -X POST http://127.0.0.1:4100/push \
    -H 'content-type: application/json' -d "$body"
  echo
done
```

`201`:

```json
{
  "v": 1,
  "payload": {
    "blob_hashes": [
      "b9532fd78782a4692144cca96239112c5fa56dfb38806b3cf58de463e25e019a",
      "68c7c8bc59eae3106483ef83de11b84d2fe5a6bcc7ae17c429eef387a7058276",
      "cdccf0ba6195f36a0cba78f72460e9f4c6e532e4e3e9a39035c0700f8720f61b"
    ],
    "commit_id": "SHA-256:eVZPpSYrDKvm8x-O1SyyvzXzqWJ6o3FSCIQloYP325Q",
    "sequence": 0,
    "roots": {
      "pr": "SHA-256:6GfLOb_VXaKMWz4it4iywYh4pgDgVnuM6dbvtbJKlXo",
      "sr": "SHA-256:N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
      "ar": "SHA-256:N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
      "cr": "SHA-256:eVZPpSYrDKvm8x-O1SyyvzXzqWJ6o3FSCIQloYP325Q"
    }
  },
  "statement": {
    "kind": "signed",
    "coz": {
      "pay": {
        "alg": "Ed25519",
        "now": 1795229090,
        "tmb": "lsraVr9sNuOtusTnvuVlQj5hbteg9LOBAsduqNE2bbQuZ0buuXMLg_QgNqVBpyxfy6NwCkV544kb98AuN7ng2Q",
        "typ": "cyphr-server/receipt/commit",
        "pr": "N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
        "sequence": 0,
        "commit_id": "SHA-256:eVZPpSYrDKvm8x-O1SyyvzXzqWJ6o3FSCIQloYP325Q",
        "roots": {
          "pr": "SHA-256:6GfLOb_VXaKMWz4it4iywYh4pgDgVnuM6dbvtbJKlXo",
          "sr": "SHA-256:N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
          "ar": "SHA-256:N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
          "cr": "SHA-256:eVZPpSYrDKvm8x-O1SyyvzXzqWJ6o3FSCIQloYP325Q"
        }
      },
      "sig": "IA7kUFeEi9g9TSI2vgAtUPntGU0YCKvyxjGnm4kDy_DCcxnpR8XXyh_hksGTjKOZCqT0dUgFFB492itJOlg3CQ"
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
persists nothing to issue one and holds no log of what it signed
(`docs/specs/receipts.md` `[receipts-r-stateless]`). If you discard it,
the fact that this server ever accepted this commit is gone from
everywhere except your side of the exchange.

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
  "now": 1795229209,
  "tmb": "N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
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
  "now": 1795229341,
  "tmb": "N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
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
  "now": 1795229341,
  "tmb": "N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
  "typ": "example.com/note/create",
  "note": { "title": "hello", "tags": ["b", "a"], "body": "world" }
}
```

Sign over this instead — `note`'s three keys sorted, `tags` untouched:

```json
{
  "alg": "ES256",
  "note": { "body": "world", "tags": ["b", "a"], "title": "hello" },
  "now": 1795229341,
  "tmb": "N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
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
and signs a receipt. Then the content is stored and forgotten.

Push a bundle containing only that `example.com/note/create` cozy from
above. Everything in this section runs against `4101`, whose copy of the
principal is already at sequence 1 — the same tip the split-view section
below reports in full, so the numbers here and there match on purpose:

```json
{
  "v": 1,
  "payload": {
    "blob_hashes": [
      "a1cc941d88447059c8db7a99f2c52b53f550ec7fe7f9b33c691c977c9c1be84a"
    ],
    "commit_id": "SHA-256:apy0Xxianj4kXkcshKoMRH2Ll5oHIErnEUnh2St1ZzY",
    "sequence": 2,
    "roots": {
      "pr": "SHA-256:SnPB2CXXZtisXfYf7u93-n49U33507l3hxiFh9Csh4c",
      "sr": "SHA-256:iy3JNs1dG7idi2IUMIcXSualYTtoRoTT70SD3YvLy_Q",
      "ar": "SHA-256:iy3JNs1dG7idi2IUMIcXSualYTtoRoTT70SD3YvLy_Q",
      "cr": "SHA-256:sjFnzyHCBQ3NwfHbDCwd3K7h_9P4gJMNH4N-eXQwF8g"
    }
  },
  "statement": {
    "kind": "signed",
    "coz": {
      "pay": {
        "alg": "Ed25519",
        "now": 1795229120,
        "tmb": "lsraVr9sNuOtusTnvuVlQj5hbteg9LOBAsduqNE2bbQuZ0buuXMLg_QgNqVBpyxfy6NwCkV544kb98AuN7ng2Q",
        "typ": "cyphr-server/receipt/commit",
        "pr": "N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
        "sequence": 2,
        "commit_id": "SHA-256:apy0Xxianj4kXkcshKoMRH2Ll5oHIErnEUnh2St1ZzY",
        "roots": {
          "pr": "SHA-256:SnPB2CXXZtisXfYf7u93-n49U33507l3hxiFh9Csh4c",
          "sr": "SHA-256:iy3JNs1dG7idi2IUMIcXSualYTtoRoTT70SD3YvLy_Q",
          "ar": "SHA-256:iy3JNs1dG7idi2IUMIcXSualYTtoRoTT70SD3YvLy_Q",
          "cr": "SHA-256:sjFnzyHCBQ3NwfHbDCwd3K7h_9P4gJMNH4N-eXQwF8g"
        }
      },
      "sig": "JJp5pt774DEO5YSdmkwKTq8pLXBviufyMzK8Th2oubZSaKkwZaVX7GeFw5mqF8j-0Dfl8QcYtwpcCRjWfyTYCg"
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
curl -s "http://127.0.0.1:4101/tip?pg=$PR" | jq -c '.payload
  | {commit_count, commit_id, last_updated}'
```

```json
{
  "commit_count": 3,
  "commit_id": "SHA-256:apy0Xxianj4kXkcshKoMRH2Ll5oHIErnEUnh2St1ZzY",
  "last_updated": 1795229090
}
```

Unchanged, `last_updated` included. `GET /patch?pg=$PR` returns the same
three entries it did before. And nobody can fetch the content back — the
content-addressed lookup does not find it:

```sh
curl -s "http://127.0.0.1:4101/e/SHA-256:Sea6fBxGvclh1KlA9SVcOSc6gyRRmg_JkKYwT5Xf4rY"
```

```json
{
  "v": 1,
  "payload": {
    "error": "entity SHA-256:Sea6fBxGvclh1KlA9SVcOSc6gyRRmg_JkKYwT5Xf4rY not found",
    "now": 1795229402
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

**So Cyphr publishes key history, and nothing else.** If your
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
- **That the principal is anyone in particular.** A `pr` is derived
  from the principal's genesis keys, not chosen: a push filed under any
  other identifier is refused with a `400` before anything is stored, so
  no one can claim another principal's identifier. The server stores the
  algorithm-labelled spelling and accepts the bare digest for the same
  principal. What the identifier does not tell you is who holds the keys.
  Who may create a principal on a server at all is its admission policy;
  on an open-admission server, anyone can.

## Auditing

### Where receipts come from

Three endpoints on a keyed server hand out a signed statement, and it is
worth knowing which, because the ones that do not are easy to mistake for
a failure.

| Request                      | Statement                                   |
| :--------------------------- | :------------------------------------------ |
| `POST /push`                 | `cyphr-server/receipt/commit`               |
| `GET /tip?pg=…`              | `cyphr-server/receipt/tip`                  |
| `GET /patch?pg=…`            | `cyphr-server/receipt/tip`, over the tip    |
| `GET /patch?pg=…&to=…`       | Unsigned                                    |
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
TIPPR=$(curl -s "http://127.0.0.1:4100/tip?pg=$PR" | jq -r .payload.pr)
curl -s "http://127.0.0.1:4100/patch?pg=$PR&from=$TIPPR" \
  | jq -c '{n: (.payload.entries|length), kind: .statement.kind}'
```

```json
{ "n": 0, "kind": "signed" }
```

One request, no data transferred, and a fresh signed claim about where the
server says the principal is.

A server is an ordinary principal in its own store, so its own chain
answers like any other's. `GET /tip` with the server's `pg` as `pr` returns
a signed tip report, and `GET /patch?pg=<pg>` returns its chain with a
signed tip report over it:

```sh
curl -s "http://127.0.0.1:4100/tip?pg=SHA-512:lsraVr9sNuOtusTnvuVlQj5hbteg9LOBAsduqNE2bbQuZ0buuXMLg_QgNqVBpyxfy6NwCkV544kb98AuN7ng2Q" | jq -c '.payload | {commit_count, commit_id}'
```

```json
{
  "commit_count": 1,
  "commit_id": "SHA-512:TOosR-0A10HFjb8bnfyD1UJ0BJY4A72rIgFtitq0Xd0L92bIF21KPKMnVvf7KkN5HxfJUYoPQDLbrjEbnJerlA"
}
```

The statement is a `cyphr-server/receipt/tip`, signed by the server about
its own chain. Treat it as the server's claim about itself, not as an
independent check on the server's key: the next section says what that
takes.

### Verifying a receipt without trusting the server again

No shipped command verifies a receipt: the `cyphr` CLI has no receipt
or audit command and never talks to a server. The check is six steps,
and every one of them is something you can write yourself, in any
language.

1. Pin `pg` and the `genesis` object from `GET /server`.
2. Re-derive the PG from that genesis key alone. If it does not match the
   pinned `pg`, stop — the published key does not back the identity.
3. Fetch the server's own chain: `GET /patch?pg=<pg>`. The tagged form
   and the bare digest after the `SHA-512:` label both work. The response
   carries a signed tip report over the chain, which is the server vouching
   for itself; do not rely on it for this check.
4. Replay every entry into a fresh, independent engine of your own,
   checking the genesis commit's key against the `genesis` object you pinned
   in step 1. Each entry carries the public keys its commit introduces, in
   `keys`; the transactions themselves name keys by thumbprint only.
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
attestor above that reproduces `lsraVr9s…` exactly.

That shortcut stops holding the moment a principal has more than one
genesis key, where the root is a tree over all of them rather than a
single thumbprint. If you cannot rule that out for the servers you watch,
do step 2 properly or do not claim you did it.

**Steps 4 and 5 are the part worth walking slowly.** Replaying a chain
means loading it into a second, independent engine — never the one you
are checking — and running every commit through the same validation
Cyphr always applies: each signature checked against the keys active at
that point, with the resulting principal root compared against what the
chain claims. In Rust, the `cyphr` and `cyphr-storage` crates are that
engine; in any other language, it is code you write or trust.

The alternative to all six steps — verify the signature against the key
`GET /server` publishes right now, and stop there — is weaker in one
specific way: it trusts the server's claim about its own current key
instead of the chain that key's history is supposed to answer for. It
still catches a forged receipt from a third party and still detects a
server signing two conflicting things with one key. What it cannot catch
is a server that rotates its published key to one that never appeared
in its chain — exactly what the full replay exists to rule out.

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
  server chain from `GET /patch?pg=<pg>` is the simple thing to keep.

Nothing needs the server's cooperation afterwards, and nothing needs a
timestamp beyond what the receipts already carry.

### Detecting a split view

A split view is one server identity giving two different, irreconcilable
answers about the same principal at the same chain position. Produce one
with the two servers from the setup, which share a key and share nothing
else.

No server runs this comparison for you. A server's tip report claims
only what that server holds; comparing two of them is the reader's job,
done with answers the reader kept. The
[equivocation detection architecture](../architecture/equivocation-detection.md)
states the model.

The two servers below share a signing key, so they are one server
identity with two data directories. That is what lets this setup
produce a split view on demand: it makes one identity sign two
conflicting views. The steps here gather and check the two answers by
hand.

Push the same two commits to both (the loop above, once per server), so
they agree. Then build two conflicting third commits: snapshot the client's local store, add one key,
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
export through the same `jq` filter as before (without the loop), keep
only the last line (`| tail -n 1 > push-x.json`, and `push-y.json` for the
other) so that only the newest commit goes out, since both servers already
hold the first two commits, and send one to each server.
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
{ "sequence": 2, "commit_id": "SHA-256:82H2RINvYeqEghpLkyeg9rOOY4LWkUk9glEs8Cm--0Y" }
{ "sequence": 2, "commit_id": "SHA-256:apy0Xxianj4kXkcshKoMRH2Ll5oHIErnEUnh2St1ZzY" }
```

Now ask each server where the principal is:

```sh
curl -s "http://127.0.0.1:4100/tip?pg=$PR" | jq -c '.statement.coz.pay'
curl -s "http://127.0.0.1:4101/tip?pg=$PR" | jq -c '.statement.coz.pay'
```

```json
{
  "alg": "Ed25519",
  "now": 1795229090,
  "tmb": "lsraVr9sNuOtusTnvuVlQj5hbteg9LOBAsduqNE2bbQuZ0buuXMLg_QgNqVBpyxfy6NwCkV544kb98AuN7ng2Q",
  "typ": "cyphr-server/receipt/tip",
  "pr": "N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
  "sequence": 2,
  "commit_id": "SHA-256:82H2RINvYeqEghpLkyeg9rOOY4LWkUk9glEs8Cm--0Y",
  "roots": {
    "pr": "SHA-256:TZ_yNik2MjrWwbOAtc3ytIZtUVXGcS41u9kOT_m0c7Y",
    "sr": "SHA-256:Yu10Am03qfFBLCc-A-Gg5vnR4t2dUVsXCGdqJKGwSg0",
    "ar": "SHA-256:Yu10Am03qfFBLCc-A-Gg5vnR4t2dUVsXCGdqJKGwSg0",
    "cr": "SHA-256:NiRFeyfe4RNjUuqME406ANsa1HG2AK4f5CywkE3YXLY"
  },
  "commit_count": 3,
  "last_updated": 1795229090
}
```

```json
{
  "alg": "Ed25519",
  "now": 1795229090,
  "tmb": "lsraVr9sNuOtusTnvuVlQj5hbteg9LOBAsduqNE2bbQuZ0buuXMLg_QgNqVBpyxfy6NwCkV544kb98AuN7ng2Q",
  "typ": "cyphr-server/receipt/tip",
  "pr": "N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
  "sequence": 2,
  "commit_id": "SHA-256:apy0Xxianj4kXkcshKoMRH2Ll5oHIErnEUnh2St1ZzY",
  "roots": {
    "pr": "SHA-256:SnPB2CXXZtisXfYf7u93-n49U33507l3hxiFh9Csh4c",
    "sr": "SHA-256:iy3JNs1dG7idi2IUMIcXSualYTtoRoTT70SD3YvLy_Q",
    "ar": "SHA-256:iy3JNs1dG7idi2IUMIcXSualYTtoRoTT70SD3YvLy_Q",
    "cr": "SHA-256:sjFnzyHCBQ3NwfHbDCwd3K7h_9P4gJMNH4N-eXQwF8g"
  },
  "commit_count": 3,
  "last_updated": 1795229090
}
```

Same `tmb`, same `pr`, same `sequence`, different `commit_id` and
different roots. Two statements one key signed, about one chain position,
that cannot both be true.

**Nothing detected this.** Neither server knows the other exists, and
no server compares its views with anyone's. Detection is a thing you do
yourself, with bytes you went and collected.

Two faults are present here, and they are different. The principal's
key signed two commits on the same predecessor: that is a fork in the
principal's record, and the two commits prove it with no server
signature involved. And one server identity signed two views that
cannot both be true: that is the server equivocating, and its two tip
reports prove it. With two servers that hold different keys, only the
first would be present — each would be telling the truth about what it
holds.

### Checking the evidence

No `cyphr` command runs this check. The comparison exists as a Rust
function, `check_equivocation` in the `cyphr-server` crate's `receipt`
module, which returns `Proven` or the specific reason a pair is not a
proven conflict (`WrongTyp`, `InvalidSignature`, `DifferentPrincipal`,
`DifferentSequence`, `IdenticalClaims`, `Malformed`). Call it from Rust,
or write the predicate in whatever your watcher is written in. Both
statements have to be tip reports, both signatures
have to verify under their own key, both have to name the same
principal and the same sequence, and they have to differ in `commit_id`
or in any root:

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

**Two keys, one server.** The function takes a key per report, and they
may differ. A server's identity is its chain, not any single key, so two
receipts either side of a key rotation are still two statements by the
same server. But the function does not check that both keys belong to
one server; you must, by binding each to the same server's chain as the
previous section describes. Two reports signed by two different servers
that hold different branches of a forked record come out `Proven`, and
neither server lied: each signed what it holds. That pair is evidence of
a fork in the principal's record, not of either server equivocating.

**Compare the roots one named field at a time.** A whole-object
comparison — `JSON.stringify(a.pay.roots) === JSON.stringify(b.pay.roots)`
— is sensitive to the order the keys happen to sit in, so two honest
reports that serialise `roots` differently come out `Proven`: an
accusation against a server that did nothing. The server's own predicate
compares four separately parsed values, which no serialisation order can
disturb. `roots.cr` is `null` on a principal with no data commit yet,
and the `??` makes two `null` values compare equal.

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

#### When the two positions differ

The predicate above requires the identical `sequence` on both sides, and
`DifferentSequence` is what it returns whenever that requirement is not
met — including two reports from a genuinely forked server, caught at
different sequences. A bare `DifferentSequence` is not an answer; it is
an unclosed question, and no shipped tool closes it.

[arch-behind-is-not-fork](../architecture/equivocation-detection.md#arch-behind-is-not-fork)
states how it closes. Take the report with the higher `sequence`, `n`,
and the one with the lower, `m`. Fetch the principal's chain from the
higher-sequence server — `GET /patch?pg=<pr>`, naming the principal the
two reports disagree about — and replay it into an engine of your own,
the way the previous section replays a server's chain. Check that the
replayed chain reaches the higher report's signed roots at `n`, then
read the Commit Root it had at `m`:

- Equal to the lower report's signed `cr`: the lower server is behind,
  not forked. No conflict.
- Different: the two reports fork at or before `m`. If one server
  identity signed both, that server equivocated; if two servers did,
  the principal's record forked.

### What you hold when you find one

Two cozies the server signed, and the chain segment binding the signing
keys. That is a complete, portable, self-contained proof, and it stays
valid for as long as the signatures do. The server can decline to explain
it, but cannot deny making both statements.

No server carries that proof to anyone. A server's answers say nothing
about what other servers hold, and nothing in Cyphr today passes
evidence between servers or readers: whoever gathered it holds it.

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
reasoning. If you want the shape of the disagreement across a set,
collect the verdicts yourself.

**Ask the principal to resolve it.** A fork is resolved when the principal
publishes a commit whose predecessor is the tip of one branch, and no
commit yet stands over the other. If both branches already have a commit
over them, the principal stays in Error whatever the heights, and a new
commit on either branch does not leave it. A branch the principal
abandoned re-opens the fork if anyone extends it later. Only the principal
can resolve it, and no server does it for them
([the architecture page states
why](../architecture/equivocation-detection.md#arch-principal-resolves)).
A resolving commit is a push like any other, and no server forwards a
push to other servers: it reaches exactly the servers the principal
pushes it to. A server they do not push it to keeps serving whatever
branch it holds. Building a third commit on the branch server `4101`
holds and pushing it to both. `4100` was never shown that branch, which
matters below:

```
4101  201
4100  409  payload.error: "protocol: state root mismatch"
```

The chosen branch advances and the abandoned one is stuck, which is the
outcome you want. The `409` looks the same as any stale push, because to
`4100` it is one: it never saw the branch the new commit builds on, and it
records nothing about the fork, the winner or the abandoned branch.

That `409` is what a server answers when it was never shown the branch the new
commit builds on: here `4100` has only seen the other branch. The next
section shows what changes when a server has seen both.

### What one server does with both branches

This section continues from the previous one, on the same two servers: `4100`
has refused the resolving commit and still holds only its own branch. Send
`4100` the commit that `4101` took (`push-y.json`). `4100` already holds the
other branch, so it refuses with a `409`:

```json
{
  "v": 1,
  "payload": {
    "error": "protocol: state root mismatch",
    "now": 1795229134,
    "kind": "commit_mismatch"
  },
  "statement": { "kind": "unsigned" }
}
```

The push is refused, but the server keeps the commit. It verified at its
predecessor and took a position the chain already holds, so the server
retains it as a rival branch and its answer about the principal changes:
`GET /tip` no longer reports a tip. It reports `state: "error"`, the
fork point, and both heads, and signs that as a `cyphr-server/receipt/held`
statement:

```sh
curl -s "http://127.0.0.1:4100/tip?pg=$PR" | jq '.payload'
```

```json
{
  "state": "error",
  "principal_id": "N6LMjHcpGOkCPkDLksty9fs3_lfTgRzoQQA9HnMRXow",
  "fork_point": {
    "height": 2,
    "pre": "SHA-256:038v6Co3KCUwmzGlaAGSv9wGK4_I30QF-HnmRS4ajj0"
  },
  "heads": [
    {
      "commit_id": "SHA-256:82H2RINvYeqEghpLkyeg9rOOY4LWkUk9glEs8Cm--0Y",
      "sequence": 2,
      "held_since": 1795229090
    },
    {
      "commit_id": "SHA-256:apy0Xxianj4kXkcshKoMRH2Ll5oHIErnEUnh2St1ZzY",
      "sequence": 2,
      "held_since": 1795229134
    }
  ],
  "now": 1795229134
}
```

`GET /branches?pg=$PR` lists the two heads and marks the one the server
still treats as canonical, and `GET /evidence?pg=$PR` returns both
branches whole. So a single server that is shown both branches does notice
the fork and says so. What it does not do is tell any other server, or
compare itself with one: the two servers of this guide still disagree with
each other, and nothing carries one's rival to the other. That comparison
is still yours.

Now push the resolving commit to `4100` again. It builds on one of the two
heads the server now holds, so it is accepted with a `201`: the server
settles on that branch, the principal leaves the `error` state, and the
other head stays on record as a non-canonical branch in `GET /branches`.
Which servers hold which branch when the principal resolves decides which
of them answer `201` and which `409`.

### Watching, in practice

A watcher is a loop, and a small one. For each principal you care about
and each server you are willing to ask, fetch the tip, keep the receipt,
and compare across servers.

No shipped command runs this loop. The fetch step is
`curl -s "<url>/tip?pg=<pr>"`, saving the response body byte-exact so
the receipt under `statement.coz` can be checked later. Anchoring at the
tip you already hold (the `from=` form [shown
earlier](#where-receipts-come-from)) makes the steady-state request
nearly free — no entries, one signed claim. A watcher's loop is this
fetch, repeated per principal and per server, feeding what it collects
into [the comparison](#checking-the-evidence).

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
