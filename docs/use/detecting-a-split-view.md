# Detecting a split view

Ask a server for the current state of someone's record and it answers
with a signed statement — a **tip report** — naming exactly which
history it stands behind. A **split view** is the lie this page is
about: the same server showing one version of a record to one reader
and a different version to another, each answer signed, each plausible,
neither audience aware of the other. The system's own name for that
lie is **equivocation**; this page uses both words for the same thing.

This page says who needs that lie caught, what catching it must make
possible, and what you can do once you have caught it. It states what
the system owes its users; where the system does not yet deliver, that
is marked plainly rather than papered over.

## Who needs this

**You need equivocation detected if you act on what a server tells you
about someone's record, and may later have to defend that act to
someone with no reason to trust you.**

Noor is a reporter. City officials publish their disclosure filings
under their own records, and a public server serves them. Noor checks a
council member's record and reports that it contains no filing for a
paid trip. A week later the member's office says the filing was always
there — and readers who look now see it. Whether Noor keeps her job
turns on a question about a server: did it show her one history and
everyone else another?

Noor is one bearer of the role. The record's owner is another — the
council member has her own stake in a server that cannot show creditors
one history and auditors a second. So is a service that watches servers
on behalf of readers who will not do it themselves, and so is a
platform that acts on records and answers to its users for those acts.
What they share is the stake, not a job title: each has done something
on the strength of a served answer, and each faces an audience that
will not take their word for what that answer was.

## What is being protected

**What equivocation detection protects is your ability to stand behind
an act you took on someone else's record, when the party that showed
you the record is the one lying about it.**

For Noor that act is a published story. For the council member it is
her own name — every statement served under it, to anyone. For the
watch service and the platform it is the trust their users place in
them. In every case the threat is the same: without detection, a server
can arrange for your audience and you to have seen different worlds,
and the word of the server is all anyone has.

## What must be possible

Three things, each stated as a claim the system answers for. The
fenced block under each is its machine-read form: whether a claim is
delivered is checked, not asserted in prose.

### [keep-the-signed-answer]

**Every answer a server gives about a record's state can be kept, and
the kept answer keeps its meaning: it is signed, self-contained, and
stays verifiable without the server's cooperation, for as long as you
hold it.**

```claim
kind: constraint
evaluator: example
```

This is what makes everything below possible, and it costs almost
nothing: the answer you keep is the answer you were already given. The
[publication and audit guide](../guides/publication-and-audit.md) walks
through what a kept tip report looks like and how to verify one.

### [decide-the-conflict-yourself]

**Holding two kept answers about the same position of the same record,
you can decide for yourself, offline, whether they conflict — and only
a genuine conflict decides as one.** A comparison that can call an
honest server a liar is worse than none: a false accusation is
checkable by anyone, and being caught making one costs you the
credibility you need the next time you are right.

```claim
kind: constraint
evaluator: example
```

### [convince-a-stranger]

**A conflict you found convinces a stranger. The two kept answers and
the server's published identity are enough; your testimony adds
nothing to the proof, and the server's cooperation is not required.**
The server can decline to explain the two statements. It cannot deny
having made them.

```claim
kind: constraint
evaluator: example
```

Comparing takes a second view, which means reaching the same record
from more than one place — another server holding a copy, or the same
server asked from a network position it does not associate with you. A
record you can only ever read in one place, one way, is a record whose
server cannot be caught. Making second views available is its own
story, told elsewhere; this page only names the dependency.

## When the answer is bad

**Detection buys you a proof, and today the proof has force only
outside the system: nothing inside Cyphr accepts it, spreads it, or
changes because of it.**

Four moves are open to you, in rising order of what they need.

1. **Stop relying on that server.** Available immediately, needs
   nothing from anyone. You hold proof it gave two answers; treat its
   answers as no answer at all.

2. **Make it known.** The proof is portable, so any venue works — a
   court filing, a news story, a page anyone can check. But the venue
   is yours to find. There is no place inside the system to lodge
   evidence, no way another reader of the same server learns what you
   found, and no server behaves differently for having been proven a
   liar. That is an unmet need this documentation records, not a
   defect in your proof.

3. **Break the tie.** Two conflicting answers convict the server
   without telling you which history is the honest one. A third view
   from somewhere else settles that by simple majority — reasoning you
   do yourself, because nothing in the system does it for you.

4. **Get it repaired.** The record's owner can end a split: publish
   the next entry on one branch, and the other branch can no longer
   advance. That much works today. But the repair leaves no mark:
   neither server records that a split happened, which branch won, or
   that anything was ever wrong. A reader who arrives later sees a
   record with no history of the incident — and that silence is also
   an unmet need this documentation records.

## Before the fact, or after?

**After the fact. Detection is an audit you run over answers you kept,
not a check the moment of reading can wait on.**

This is a property of the truth being checked, not a limitation of
tooling. A single answer, however honestly signed, can never show you a
split view — the lie only becomes visible across two answers, and the
second one usually arrives later, or from somewhere else. The
asymmetry runs one way: a conflict, once found, is proof forever, but
agreement at any number of checks proves nothing about the next one. No
amount of diligence at reading time turns a server's answer into a
safe one.

What follows for you: keep answers as you go, compare on a rhythm, and
act when proof appears. Asking several servers before you act narrows
the window a lying server can exploit — it is worth doing when the
stakes warrant it — but it cannot close the window, and nothing you do
in the moment should be designed to wait on a certainty that is not
for sale. What the system owes you instead is the audit path: the
answers you kept must still convict long after the fact. That is why
[keeping the signed answer](#keep-the-signed-answer) carries the load
on this page — the proof is built from what you kept.

## Where the mechanics live

The [publication and audit guide](../guides/publication-and-audit.md)
walks the working parts as they exist today, including exactly what is
and is not built. How the parties fit together — servers, witnesses,
and the watcher role this page has been describing from the inside —
is stated in
[the equivocation detection architecture](../architecture/equivocation-detection.md).
