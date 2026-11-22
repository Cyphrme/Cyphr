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
  Rust code has no coz kind for it. A commit resolves a fork only by
  extending exactly one of its branches
  (`assessment`, `rs/cyphr/src/fork.rs:120`).
- **A fork with both branches extended locks until resolved.** Height
  does not decide it: the taller branch does not win, and a new commit on
  either branch leaves the principal in Error, because the walk still
  finds two extended branches (`rs/cyphr/src/fork.rs:120`). Holders of the
  same commits reach the same verdict. The explicit proof-of-possession exit is future work, so
  nothing at Levels 1 to 4 settles this state yet.
- **A resolved fork can re-open.** The verdict is a function of the
  commits held, so a fork the principal settled by extending one branch
  is Error again when anyone holding a key that was active at the
  parting point extends the abandoned branch. A stale offline device that
  wakes up and signs on the old branch does this without any attacker.
- **Any once-active key can backdate a commit to re-open or lock a
  principal.** A commit is checked against a key's revoke by its own
  `now` (`dead_key_in`, `rs/cyphr-storage/src/engine/mod.rs:3996`), so a
  holder of a key that was ever active can date a commit before the
  revoke cutoff, extend an abandoned branch, and put the principal back
  in Error. This is a liveness cost, not a forged history, and it is a
  known limit until the spec author rules on timestamp monotonicity.
- **The CLI sends a fork only as an answering pair.** `cyphr push`
  offers commits that part from a peer's tip only when at least two local
  commits lie past the parting point (`rs/cyphr-cli/src/commands/network.rs:107-130`).
  An owner with one commit past it must sign a second before the CLI will
  send the answer; a lone commit over a peer's tip is refused as stale,
  because it would move the peer to Error without settling anything.
- **An Active verdict means no fork was seen, not that none exists.** The
  verdict covers the peers that answered. A peer that serves one head is
  not asked for fork evidence (`sync.rs` asks only when a peer reports
  more than one head), and branch heads are hints, never proof. A peer
  can also bury genuine evidence under junk: a verifier reads at most 32
  evidence items per peer per pull, before checking them.
- **A witness does not check that entries past the cap chain.** A witness
  binds an attested head to the branch that names it and checks that the
  entries it holds chain to each other. Entries the authority holds past
  the retention cap are not held by the witness, so the binding does not
  check that they chain to each other.
- **Retained rivals are capped.** An engine keeps at most 16 rival
  lines per principal and 2 lines per signing key, and a line holds at
  most 2 commits (`BRANCH_LIMIT`, `BRANCH_PER_KEY`, `BRANCH_DEPTH`,
  `rs/cyphr-storage/src/engine/mod.rs:492-505`; the check is `has_slot`,
  `:703`). An offer past a cap is refused and not retained, with a `409`
  of kind `branch_limit` while the principal is Active and a `423` of kind
  `errored` while it is in Error. A refused offer, alone or as a root with
  its extension, is retained anyway when it changes the principal's
  standing or its fork point, so a thief who adds keys cannot keep out a
  commit that matters. What the store keeps by offer is bounded by
  32 + 2h commits, h the principal's chain length. A relying party that
  cannot record a fork refuses sign-in until it is rebuilt from a fresh
  view.
- **A revoke never ends a fork already held.** It gates later arrivals
  only (SPEC 14.12), so a thief's commit held before the revoke stays
  counted. The owner exits by extending exactly one branch, where that settles
  the fork, or by recovery.

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

- **A refused login can cost one replay.** `POST /auth/login` loads the
  claimed principal before it checks the signature, because the key that
  must have signed is found in that principal's state
  (`rs/cyphr-server/src/auth/login.rs`, `login`). A principal whose state
  the engine keeps costs a lookup. A cold or evicted one costs one replay
  of its history, then is kept. Two bounds apply: the kept-state cache,
  which makes the second refused login for the same principal cheap, and
  the per-IP request limit, which caps how fast one address can ask.
  Many addresses naming many cold principals can still force a replay
  each.

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
