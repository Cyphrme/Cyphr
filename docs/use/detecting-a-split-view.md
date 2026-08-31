# Detecting a split view

Ask a server for the current state of someone's record and it answers
with a signed statement — a **tip report** — naming exactly which
history it stands behind. A **split view** is the lie this page is
about: the same server showing one version of a record to one reader
and a different version to another, each answer signed, each plausible,
neither audience aware of the other. The system's own name for the
underlying event is **equivocation**, and the protocol's own name for it
is a **fork**
([SPEC §15.7.1](../../SPEC.md#1571-invalid-forks-fork-detection-and-duplicitous-behavior)).
These are one thing under three names, not three things — a split view
is what a fork looks like from outside — and this page uses whichever
name the sentence needs.

That signed statement exists only if the server can sign at all. A
server that is an **attestor** — keyed and bootstrapped — signs a tip
report over every state it serves; a **keyless** server signs nothing,
and none of what follows applies to one. `GET /server` tells you which
you have: an attestor answers with `"tier": "attestor"`, a keyless
server with `"tier": "repository"`. Check that before going further.

This page says who needs that lie caught, how the system catches and
delivers it, and what you can do once it has. It states what the system
owes its users.

## Who needs this

**You need equivocation detected if you act on what a server tells you
about someone's record, and may later have to defend that act to
someone with no reason to trust you.**

Noor is a reporter. A council member discloses a paid trip by filing a
report with the city and anchoring it to her own record — a commit
whose payload carries the filing's hash, so anyone holding a copy of
the filing can confirm it is the one she vouched for. Noor gets a copy
of the filing through the city's ordinary public-records process,
hashes it, and checks the council member's record for a commit
anchoring that hash. She finds none, and reports that the member never
disclosed the trip. A week later the member's office says the anchor
was there all along — and readers who check now find it, in a commit
dated before Noor's story ran. Whether Noor keeps her job turns on a
question about a server: did it show her one history and everyone else
another?

Noor is one bearer of the role. The record's owner is another — the
council member has her own stake in a server that cannot show creditors
one history and auditors a second. So is a **relying service** — one
that answers for a user of its own on the strength of someone else's
record — and it learns of a conflict the same way anyone else does, by
[the ordinary answer it already gets](#a-service-relying-on-you-decides),
once a witness that does not depend on the answering server's goodwill
has exchanged views with it and found the conflict — not by watching
anything. So is a platform that acts on records and
answers to its users for those acts. What they share is the stake, not a
job title: each has done something on the strength of a served answer,
and each faces an audience that will not take their word for what that
answer was.

## What is being protected

**What equivocation detection protects is your ability to stand behind
an act you took on the strength of what a server showed you, or a
record it served under your name to someone else — when the server is
the one lying about what it showed.**

For Noor that act is a published story. For the council member it is
her own name — every statement served under it, to anyone. For the
relying service and the platform it is the trust their users place in
them. In every case the threat is the same: without detection, a server
can arrange for your audience and you to have seen different worlds,
and the word of the server is all anyone has.

## How detection reaches you

When a server already has both views — through a witness relationship
delivering the material automatically — comparing them for a conflict is
server-side work, not something you ask for; the
[architecture page](../architecture/equivocation-detection.md#detection-needs-no-watcher)
states that mechanism. The same comparison is also something you can run
yourself, by hand, over two answers you gathered on your own outside any
such relationship — [the publication and audit guide](../guides/publication-and-audit.md#checking-the-evidence)
walks that command. This page states what either path means for you, in
the order it happens. Most of the automatic path is not yours to do; the
sections below say which steps are.

### The server notices

A server exchanges tip reports and a consistency proof with a witness
for the same principal — an exchange that witness registration and push
fanout trigger as a byproduct of work it does anyway
([SPEC §13.5.1](../../SPEC.md#1351-witness-registration)). Neither side
needs to fetch or keep the other's chain to run it. No one asks the
server to check; no watcher, no schedule, no separate role exists to do
that asking.

### [fixed-rule-decides-conflict]

**Whether two kept answers conflict is decided by a fixed rule — never a
party's say-so, and only a genuine conflict decides as one.** For two
answers about the identical position, that rule needs nothing beyond the
two answers themselves:
[the receipts specification's pinned predicate](../specs/receipts.md#the-pinned-predicate).
For two answers about different positions, the same guarantee holds, but
settling it takes one more thing: the higher-sequence side's own claimed
Commit Root at the lower position, reconstructed and proven — not
asserted — by a consistency proof over its own history. That
reconstructed root is what gets checked against what the lower-sequence
side itself signed for that position — equal means simply behind, never
a lie; different is the fork — the
[architecture page states which](../architecture/equivocation-detection.md#arch-behind-is-not-fork).
A comparison that could call an honest server a liar is worse than
none: a false accusation is checkable by anyone, and being caught making
one costs the credibility needed the next time an accusation is true.

### You find out without looking

You do not request a check and wait for its result. The next ordinary
answer a server whose most recent exchange proved a fork gives you —
about your own record if you are its owner, about someone else's if you
are relying on it — already carries the proof, once a witness that does
not depend on this server's goodwill has exchanged views with it and
found the conflict. Reading your own record the way you always would is
the notice, once that witness relationship exists. Whether you can bring
that relationship about depends on who you are. If you are the record's
owner, running the comparison yourself is not the thing to go do; making
sure a witness is registered is — registering one is a signed act only
you can take
([SPEC §13.5.1](../../SPEC.md#1351-witness-registration)). If you are
not the owner — Noor, a relying service, a platform — you cannot
register a witness on someone else's record, so that act is not yours to
trigger. Your own move is gathering a second view yourself —
[the same server asked from a network position it does not associate
with you](#convince-a-stranger) — and running
[the comparison](../guides/publication-and-audit.md#checking-the-evidence)
over what you gathered.
This is a design choice the
[architecture page states and justifies](../architecture/equivocation-detection.md#the-answer-carries-the-finding):
the finding rides along in the answer you were already going to get,
rather than waiting behind a second address you would have to know to
ask.

### [the-conflict-record]

What you get is not a flag with no contents. The answer always carries
the two tip reports that disagree. When the two positions differed, it
carries one thing more: the higher side's own claimed Commit Root at the
lower position, authenticated by a consistency proof tying it to that
same side's claimed root at its current position — both roots belong to
the higher side alone, never one from each party. That reconstructed
root at the lower position is the value nothing else in the record
supplies, and the one the verdict actually turns on: it is what gets
checked against what the lower side itself signed for that position —
the object
[the architecture page names](../architecture/equivocation-detection.md#what-the-finding-contains).
You can hold onto it, hand it to someone else, or verify it yourself;
nothing about it depends on the server that showed it to you staying
honest a second time. Turning it into something that
[convinces a stranger](#convince-a-stranger) outright, rather than one
willing to trust the server's currently published key, takes one
further step only you can take: replaying the server's chain to bind
each report's signing key to it.

### [keep-the-signed-answer]

**An answer a server signs about a record's state can be kept, and the
kept answer keeps its meaning: it is signed, self-contained, and stays
verifiable without the server's cooperation, for as long as it is held.**
Not every answer is signed — a bounded patch, a bare discovery response,
a login, and anything from a keyless server all come back unsigned, by
design, and keeping one of those keeps nothing. Know which you have
before you rely on it: the [publication and audit guide's endpoint
table](../guides/publication-and-audit.md#where-receipts-come-from)
names exactly which requests attest and which do not.

This is what makes everything above possible, and it costs almost
nothing: a kept answer, when it is signed, is the answer that was
already given — no server cooperation is needed to keep it true. The
[publication and audit
guide](../guides/publication-and-audit.md) walks through what a kept
tip report looks like and how to verify one.

### Resolving takes a signature, not identity

If you are the record's owner, resolving the fork is yours to do, and it
takes exactly one act: sign the next entry on the branch you choose — a
commit whose `pre` names that branch's tip, or a `resync/create`
re-asserting the current tip
([SPEC §13, "Resync PoP"](../../SPEC.md#13-resync-pop)). Nobody's
agreement is needed, and no server or witness can produce that signature
in your place. But the check a server runs on it is a signature check,
not an identity check: it verifies against your currently-active key,
not against you, so anyone else who holds that key can sign the same
resolving commit exactly as you can. When a fork traces back to a
compromised key rather than a client retry, this is not hypothetical —
whoever holds the compromised key can resolve the fork in their own
favor the same way you resolve it in yours, and a server acts on
whichever resolving commit reaches it first: a server that receives
yours resolves to your chosen branch, a server that receives the
attacker's resolves to theirs, and each server's own signature check
accepts either one without being able to tell you apart. Until one such
act reaches it, a server that proved the fork refuses every OTHER push
you send for this principal —
[SPEC §15.5](../../SPEC.md#155-principal-consensus-states)'s Error
state — while accepting exactly that one: the resolving commit or PoP is
checked against the fork's own two branch tips rather than refused
outright, [the same way the architecture page states the
mechanism](../architecture/equivocation-detection.md#while-a-fork-stands).
It keeps answering everyone's ordinary queries about you meanwhile, fork
proof attached, and presents neither branch as settled. Because
a resolution is itself a commit, it reaches every server you have
registered as a witness, automatically, the same as any other push — and
no other server, since fanout only ever reaches a registered witness.
Once a server has processed a resolving commit, its answers about the
resolved sequence stop carrying the finding; the two tip reports that
proved the conflict remain valid proof regardless, for as long as
whoever kept them holds onto them. If the key is what is actually in
question, resolving the fork this way does not settle that: the remedy
is revoking the compromised key and recovering the principal onto one
the attacker does not hold
([SPEC §14, "Recovery"](../../SPEC.md#14-recovery)) — after that, only a
commit under the new key passes the same check.

### A service relying on you decides

A service authenticating a user against your identity right now needs
to know your record is contested, and it learns the same way you do: the
ordinary answer it was already going to get about your identity carries
the finding when one exists, once a witness that does not depend on the
answering server's goodwill has exchanged views with it and found the
conflict. What it does with that — refuse the
authentication, degrade it, ask for a second factor — is its own
decision, made with its own stakes in mind, not something this system
makes for it.

### [convince-a-stranger]

**A proven conflict convinces a stranger on its own, without anyone's
testimony.** What it takes is the two kept answers plus the segment of
the server's own chain that binds both signing keys as active — not the
server's bare published identity, which is only a hint toward that
chain, not a substitute for it. No one's word adds anything to the
proof, and the server's cooperation is not required. The server can
decline to explain the two statements. It cannot deny having made them.

You assemble the chain segment yourself, by replaying a copy of the
chain — the accused server's own, if it still answers, or any other
server that shares its signing identity, since a chain proves itself no
matter which copy you replay, which is exactly why no cooperation from
the accused party is needed to get one — [the publication and audit
guide walks the
steps](../guides/publication-and-audit.md#verifying-a-receipt-without-trusting-the-server-again).
Verifying against only the server's currently published key is weaker:
it cannot catch a server that rotated its published key to one that
never legitimately appeared in its own chain.

Comparing needs a second view, which means the record reaching more than
one place — another server registered as a witness and receiving the
push automatically, or the same server asked from a network position it
does not associate with you. A record only ever read in one place, one
way, is a record whose server cannot be caught. Witness registration
([SPEC §13.5.1](../../SPEC.md#1351-witness-registration)) is what
produces the first kind of second view.

## What to do when the answer is bad

**Detection buys you a proof, and the proof has force only outside the
system: nothing inside Cyphr spreads it to anyone who was not already
going to receive it as part of an ordinary answer.**

Three moves are open to you beyond
[resolving it, if it is yours to resolve](#resolving-takes-a-signature-not-identity), in
rising order of what they need.

1. **Stop relying on that server.** Available immediately, needs
   nothing from anyone. You hold proof it gave two answers; treat its
   answers as no answer at all.

2. **Make it known.** The proof is portable, so any venue works — a
   court filing, a news story, a page anyone can check. But the venue is
   yours to find: a server's own future answers about the principal
   carry a finding only when that server itself made or received it;
   there is no place inside the system for a stranger's
   independently-assembled proof to reach servers that never held the
   material to find it themselves.

3. **Break the tie.** Two conflicting answers convict the server without
   telling you which history is the honest one. A third view from
   somewhere else settles that by simple majority — reasoning that is
   yours to do, not the system's.

## Before the fact, or after?

**After the fact. Detection is an audit run over signed answers already
held, never a check the moment of reading can wait on.**

This is a property of the truth being checked, not a limitation of
tooling. A single answer, however honestly signed, can never show a
split view — the lie only becomes visible across two answers, and the
second one usually arrives later, or from somewhere else. The asymmetry
runs one way: a conflict, once found, is proof forever, but agreement at
any number of checks proves nothing about the next one. No amount of
diligence at reading time turns a server's answer into a safe one.

What follows from that: the comparing is not a job to time. Where a
witness relationship already exists, it is server-side work that
[runs automatically](../architecture/equivocation-detection.md#detection-needs-no-watcher)
on an exchange that relationship already delivers, never on a moment
you have to catch. Where none exists,
[running it yourself](#you-find-out-without-looking) is not tied to a
moment either — gather the second answer whenever you can get one, and
a comparison run then catches exactly what a comparison run at read
time would have.
[Keeping the signed answer](#keep-the-signed-answer) is what a
comparison has to work with regardless of when it runs, or who runs
it; nothing about when or how carefully you read changes whether a
conflict is ever caught. That is why keeping the signed answer carries
the load on this page — the proof, whenever it is produced, is built
from what was kept.

## Where the mechanics live

The [publication and audit guide](../guides/publication-and-audit.md)
walks the working parts. How the parts fit together — servers,
witnesses, and the comparison this page has been describing from the
outside — is stated in
[the equivocation detection architecture](../architecture/equivocation-detection.md).
