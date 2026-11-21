# Detecting a split view

Ask a server for the current state of someone's record and an attestor
server answers with a signed statement, a **tip report**, naming exactly
which history it holds. A **split view** is what you have when two
answers about the same record disagree: one identity, two histories,
each answer signed and plausible to whoever received it.

This page says who needs a split view caught, what the disagreement can
mean, what you can do about it today, and what you cannot. The
[equivocation detection architecture](../architecture/equivocation-detection.md)
states the mechanism and its requirements.

## Who needs this

**You need split views caught if you act on what a server tells you
about someone's record, and may later have to defend that act to
someone with no reason to trust you.**

Noor is a reporter. A council member discloses a paid trip by filing a
report with the city and anchoring it to her own record: a commit whose
payload carries the filing's hash, so anyone holding a copy of the
filing can confirm it is the one she vouched for. Noor gets a copy of
the filing through the city's ordinary public-records process, hashes
it, and checks the council member's record for a commit anchoring that
hash. She finds none, and reports that the member never disclosed the
trip. A week later the member's office says the anchor was there all
along, and readers who check now find it, in a commit dated before
Noor's story ran. Whether Noor keeps her job turns on a question: did
the server show her one history and everyone else another, or did the
record itself change?

Noor is one bearer of the role. The record's owner is another: the
council member has her own stake in no one being able to show creditors
one history and auditors a second. So is a **relying service**, one that
answers for a user of its own on the strength of someone else's record.
What they share is the stake, not a job title: each has acted on a
served answer, and each faces an audience that will not take their word
for what that answer was.

## Nobody decides for you

No server, witness or peer is an authority over anyone's record. A
server's tip report claims only what that server holds. It does not
claim what the record is for anyone else, and nothing makes it so. The
record's owner is the authority over her own record
([SPEC §13.7](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#137-gossip):
"Principals are the authority over their own state").

So the verdict about a record is yours. You choose which servers to ask,
you compare what they signed, and what you conclude binds only you. No
server checks other servers on your behalf, and none pushes a record to
other servers for its owner: the owner publishes each commit to the
servers she chooses.

## What a disagreement can mean

Two different answers about one record have three possible causes, and
they call for different responses:

1. **One server is behind.** The older answer is a prefix of the newer
   one. Nothing is wrong.
2. **The owner's record forked.** The owner's keys signed two
   conflicting commits on the same predecessor, and different servers
   hold different branches. SPEC calls this an invalid fork
   ([§15.7.1](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#1571-invalid-forks-fork-detection-and-duplicitous-behavior)).
   Each server is telling the truth about what it holds. The fault is in
   the record, and the proof is the two commits the owner's keys signed.
3. **One server equivocated.** The same server signed two answers that
   cannot both be true. The fault is that server's, and the proof is
   its own two signatures.

Telling these apart is the whole job. Calling a behind server a liar, or
calling an honest server a liar because the record it holds forked, is
a false accusation anyone can take apart, and it costs you the
credibility you need the next time you are right. The architecture page
states the rule that separates them:
[arch-behind-is-not-fork](../architecture/equivocation-detection.md#arch-behind-is-not-fork).

## What you can do today

**Check that the server signs at all.** `GET /server` answers
`"tier": "attestor"` for a server that signs its answers, and
`"tier": "repository"` for a keyless one, which signs nothing. Each
answer also says so itself: its `statement.kind` is `signed` or
`unsigned`. An unsigned answer is a server's word with nothing behind
it, and none of what follows applies to it.

**Keep the signed answer.** A signed answer stays verifiable without the
server's cooperation for as long as you hold it, byte-exact. Not every
answer is signed: a bounded `/patch`, `GET /server`, a login, and
anything from a keyless server come back unsigned by design. The
[publication and audit guide](../guides/publication-and-audit.md),
section "Where receipts come from", lists which requests sign and which
do not.

**Get a second view.** One answer, however honestly signed, can never
show a split view. You need another view of the same record: a second
server, or the same server asked from a network position it does not
associate with you. A record only ever read in one place is a record
whose server cannot be caught.

**Compare them yourself.** The comparison is yours to run; no server
runs it for you and no `cyphr` command does it today. The publication
and audit guide, section "Checking the evidence", walks the check by
hand. Two limits apply to the check as it exists:

- `check_equivocation`, the comparison in the server library, decides
  only reports at the same sequence. For reports at different sequences
  it answers `DifferentSequence`, which settles nothing. Settling that
  case takes the prefix check the architecture page describes.
- It takes a key for each report and does not check that both keys
  belong to the same server. Feed it reports from two different servers
  and it can call a record fork a server's lie. Establish both keys from
  the same server's chain first.

## When the owner's record forked

Only the owner resolves a fork in her own record. She signs one more
entry on the branch she chooses: a commit whose `pre` is that branch's
tip, or a `resync/create` proof of possession re-asserting a tip (the Rust
implementation has no such message yet)
([SPEC §15.8](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#158-fork-resolution)).
No server, witness or reader resolves it for her. Until she does, SPEC
puts the record in the Error state: no new transactions are processed
([§15.5](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#155-principal-consensus-states)),
and both branches are kept as proof (§15.8).

A resolution is checked by signature, not by identity. When the fork
came from a stolen key, whoever holds that key can sign a resolution as
validly as the owner. Resolving does not settle that. The remedy is
revoking the stolen key and recovering the record onto one the thief
does not hold
([SPEC §14](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#14-recovery)).

A server does track a fork it is shown. It refuses a commit that
verifies on a predecessor its chain has already moved past, with a `409`,
and keeps that commit as evidence (up to 16 per record, at most 2 per
signing key). The record is then in Error: the server refuses everything
but a resolution with a `423`, answers `GET /tip` with a signed held
statement that names the tied heads and when each was first seen, and
lists the branches at `GET /branches` and `GET /evidence`. What a server
cannot do is see a branch it was never given. A server that took one
branch and a server that took the other each keep serving their own
record as Active until the two exchange commits, so a fork still shows
only to someone who compares the two. The owner's resolution reaches only
the servers she pushes it to.

What a verdict of Active does and does not mean is in
[Known limits](../guides/known-limits.md).

## What you hold when you find one

Two signed answers that conflict are proof that does not expire and
that needs nobody's testimony:

- For a server's equivocation: its two tip reports, plus the segment of
  that server's own chain that binds both signing keys to it. A server's
  currently published key is only a hint toward that chain; checking
  against it alone cannot catch a server that published a key that never
  appeared in its own chain.
- For a record fork: the two commits the owner's keys signed on the same
  predecessor, and the state they both extend. No server signature is
  part of it.

The server can decline to explain either kind. It cannot deny having
signed what it signed.

## What to do with it

**Detection buys a proof, and the proof has force only outside the
system.** Nothing in Cyphr today carries it to anyone who did not go and
collect it.

1. **Stop relying on an equivocating server.** Available immediately,
   needs nothing from anyone. Treat its answers as no answer.
2. **Make it known.** The proof is portable, so any venue works: a court
   filing, a news story, a page anyone can check. The venue is yours to
   find.
3. **Ask the owner to resolve a fork.** Only she can, and only by
   signing.
4. **Break the tie yourself.** Two conflicting answers convict without
   telling you which history the record's owner stands behind. More
   views, and the owner's own resolution, are what settle that; the
   reasoning is yours.

## Before the fact, or after?

**After the fact. Detection is an audit over signed answers already
held, never a check the moment of reading can wait on.**

A single answer can never show a split view: the conflict becomes
visible only across two, and the second usually arrives later or from
somewhere else. A conflict, once found, is proof forever; agreement at
any number of checks proves nothing about the next one. So keeping the
signed answer carries the load on this page. The proof, whenever it is
produced and whoever produces it, is built from what was kept.
