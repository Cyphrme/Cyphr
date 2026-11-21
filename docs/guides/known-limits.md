# Known limits

What the Cyphr implementation does not guarantee, written for the people
who run a server, build a client, or rely on what either one tells them.
Each limit says what the system does, what it does not promise, and what
to do about it. This is a reference: it describes the code as built, and
where the code and the specification differ it says so.

Section numbers refer to the specification at the spec author's branch tip
([`be0663f`](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md)).
The in-tree `SPEC.md` is not the reference for them.

## What is implemented

The implementation covers feature Levels 1 to 4: a static key, key
replacement, multi-key commits, and arbitrary data (`Level` in
`rs/cyphr/src/principal/mod.rs` stops at `L4`). Levels 5 (rules) and 6
(VM) do not exist. A principal can embed another principal and accept its
keys; two corners of that are refused, listed under "Embedded principals".

## Time and revocation

A revoke stops a key from now on. It does not reach back.

- **The cutoff is the receiving node's own clock.** A server, and a
  verifier that follows a peer, cut a revoked key off at the moment that
  node first received the revoke, never at the revoke's `now` or `rvk`
  (SPEC 14.12; forge #203). From then on a message the key signs is
  refused if its own `now` is at or after the cutoff. A later revoke of
  the same key changes nothing.
- **A held commit is never re-judged.** A commit the node already holds
  stays, whatever a later revoke says. A thief's commit that was accepted
  before the revoke arrived stays counted.
- **Backdating is not prevented.** The holder of a compromised key picks
  the `now` of what it signs. A commit's `now` may not be earlier than the
  latest `now` the principal already holds, and may not be more than 360
  seconds ahead of the verifier's clock, but inside that range a thief can
  date a commit below the cutoff and have it accepted. The remedy the
  specification gives is recovery, not prevention: the owner removes the
  key and mutates the principal forward (SPEC 6.4, 14.12). A server also
  records when it first saw each commit, so a backdated commit shows a gap
  between its `now` and its first-seen time.
- **Nodes can disagree about a late revoke.** Two nodes receive a revoke
  at different times. A message the dead key signed, dated between the two
  receipt times, is accepted by one and refused by the other, and nothing
  re-joins them (forge #203). A node that learns the revoke late, by
  relay, a later sync or as a verifier, judges by its own receipt time, so
  a commit the key made before that node learned of the revoke counts
  there. Convergence is guaranteed only for a revoked key being introduced
  to a principal, which is never refused.
- **A wrong clock is permanent.** A verifier fixes a key's cutoff at its
  own clock on the first revoke it accepts for that key
  (`PeerChain::observe_naked_revoke`). A wrong clock at that moment sets
  the cutoff for good. Run NTP on every server and verifier.
- **Data actions are judged at their own `now`.** An action counts if its
  signer was authorized at the action's `now` in the key history (SPEC
  6.2, 6.5). A key that can remove another key K2 dates the removal, so
  K2's later-dated actions that were already accepted stop counting when
  the data is read. A peer can also withhold actions undetectably: an
  action-only push forms no commit, so no signed root commits to an
  action until a later `ds/create` includes it (SPEC 4.8.2).

What to do: treat a revoke as the start of recovery. Remove the key with a
commit, check the commits dated near the revoke, and keep your servers'
clocks correct.

## Forks

- **A fork can split witnesses, each reporting Active.** Two branches fork
  at position n, and at n+1 each removes the other's key. Each witness
  accepts the removal on the branch it saw first and treats the other
  branch as signed by a removed key, so witnesses holding different
  branches each report Active and nobody is in Error (forge #203). Counting
  both removals as a fork instead would let the holder of an old, deleted
  key put a principal in Error at will, because nothing in the record says
  who holds a key. The specification does not yet say which reading is
  intended.
- **A deleted key can still fork the principal.** The owner removes a lost
  key K at position d. Whoever holds K can later sign a different commit
  at d, because K was active just before d. That is a real fork and the
  principal enters Error. A revoke of K must be signed by K, which the
  owner no longer holds, and K is already deleted, so no commit
  records an exit at Levels 1 to 4. The exit is the recovery strategy (SPEC 14), outside
  the chain (forge #203).
- **A thief can win a fork race.** A thief whose branch is accepted first
  can extend it with a deletion of the owner's key, and the owner's later
  contest stops counting. The specification treats this as the fork-
  resolution race (SPEC 15.8: the abandoned branch is permanently invalid).
- **A fork resolves only by a commit.** The proof-of-possession
  resolution (`resync/create`, SPEC 15.8 item 2) is not implemented: the
  Rust code has no coz kind for it.
- **An Active verdict means no fork was seen, not that none exists.** The
  verdict covers the peers that answered. A peer that serves one head is
  not asked for fork evidence (`sync.rs` asks only when a peer reports
  more than one head), and branch heads are hints, never proof. A peer
  can also bury genuine evidence under junk: a verifier reads at most 32
  evidence items per peer per pull, before checking them.
- **Retained rivals are capped.** An engine keeps at most 16 rivals per
  principal and 2 per signing key. A rival past the cap is refused with a
  `409` of kind `branch_limit` and is not retained, so a thief who adds
  keys can fill the 16. A relying party that cannot record a fork refuses
  sign-in until it is rebuilt from a fresh view.
- **A revoke never ends a fork already held.** It gates later arrivals
  only (SPEC 14.12), so a thief's commit held before the revoke stays
  counted. The owner exits by committing on the branch she chooses, or by
  recovery.

## Embedded principals

A principal can embed another and accept its keys (SPEC 10). The engine
stores such commits, replays them against the embedded principal's state
as it was at admission, and rebuilds the same result from blobs. Three
cases are refused as an unknown key, by design and under test
(`rs/cyphr-storage/tests/embedded_principals.rs`):

- an embedding created and used in one bundle: the engine follows the Key
  Tree that exists before the bundle is admitted;
- an embedded principal with no commits, unless its genesis state is held;
- a principal that embeds itself (SPEC 10.6).

A store holding embedded-signed objects is not readable by an earlier
build, which quarantines them as unreplayable rather than judge them
without their recorded state. Do not run an older binary on such a store.

## Storage and rebuild

- **A rebuild can quarantine a record.** A revoke record written by an
  earlier build over the Coz size limit, or in the first record version,
  which carried no receipt time, is quarantined on rebuild and logged. The
  engine then treats that key as alive until the owner posts a fresh
  revoke. Look for `revoke record quarantined on rebuild` after an
  upgrade.
- **A failed disk sync stops all writes until restart.** See "Durability"
  in the [operating guide](operating-a-server.md).
- **Reads and writes of one principal queue behind one lock.** The engine
  serializes a principal's reads and writes in one process, and one data
  directory belongs to one process. Nothing coordinates two servers on
  one directory.

## Promises the system does not keep

These are guarantees a reader might assume. None is provided today.

- **Tip currency.** A signed tip report says what the server holds, not
  that it is current. Nothing binds it to a request, so a genuine report
  can be replayed while the authority advances. A witness syncing from an
  authority cannot tell (forge #152, open on a specification question).
  The `cyphr verify` answer states how old its view is and never claims the
  view is current.
- **Timestamps.** The `now` in a receipt is the server's own clock, which
  no one else attests.
- **Bearer tokens.** A token lives 15 minutes and cannot be revoked. A
  server issues every token with read and write permission. No route
  requires a token. `POST /push` is authorized by the bundle's own
  signatures, and checks a token only when the request presents one.
- **Key custody.** A key stored by the CLI is software-held and
  unencrypted, and nothing can record how a key is held. See
  [key storage](key-storage.md).
- **Pairing replay.** `cyphr key accept` accepts a signed request whose
  `now` is within a window of the accepting device's clock: 300 seconds by
  default, set with `--window`. The specification leaves the window to the
  verifier (SPEC 17.2, 17.3). Within the window a captured request can be
  replayed after the owner removed the key, and re-adds it if the owner
  runs `accept` again; the request carries no nonce.

## Operator checklist

1. Keep every server and verifier clock correct.
2. Treat a revoke as the start of recovery, not its end.
3. Compare more than one peer before relying on an Active verdict.
4. Restart a server whose log says the record is not durable, after fixing
   the disk.
5. Back up `record/`, and read the log after an upgrade for quarantine
   lines.
