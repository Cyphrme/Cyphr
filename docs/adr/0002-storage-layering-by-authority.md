# ADR-0002: Storage Layering by Authority

**Status:** ACCEPTED

**Date:** 2026-08-19

**Proposal:** `docs/proposals/storage-layering.md`, ratified at commit
`2121304`

---

## Context

The server's durable storage was grouped by storage technology — one
directory per embedded database (`blobs/`, `index/`, `observations/`,
`admission/`). `docs/proposals/storage-layering.md` proposed grouping it
by **authority** instead: whether the server was *told* a thing (and so
cannot recover it if lost) or *worked it out* (and so can always rebuild
it). The proposal asked three yes/no questions (§6); this ADR records
the answers and the decisions that follow from them.

Merging this PR is the ratification instrument for everything below.
The head had already agreed to the design at the document level; the
per-question answers, the wrap ruling, the ordering ruling, and a
correction to the proposal's own authority classification were not yet
recorded anywhere durable. Landing them here, in a document whose merge
the head consents to, closes that gap without a separate round-trip.

One of the eight decisions below is a **correction**, not an
endorsement: while working out the build shape that follows from the
proposal, a classification error in the proposal itself was found and
is fixed here rather than silently inherited. Decision 7 states it
plainly, against the document that carries it.

---

## Decision

### Decision 1 — Q1: cut storage by authority, corrected layout

**Yes**, with the layout as follows — corrected from the proposal's
own §1.1 diagram by Decision 6 below:

```text
data_dir/
├── record/                 what the server was told
│   ├── blobs/                  coz blobs, commit manifests, and every
│   │                           principal's EML commit-tree keyspaces
│   ├── observations/           the key death-set
│   ├── admission/              spent invite tokens
│   └── server-principal.json   the server's own genesis record
└── index/                  what the server works out; losing it costs
                             a rebuild
```

The proposal's §1.1 diagram nested the index under a `derived/` parent
(`derived/index/`), naming a general derived layer with one member. That
nesting is dropped: Decision 6 establishes the derived class has exactly
one member, and a wrapper directory for a one-member class buys nothing
— `index/` sits as a direct sibling of `record/`. Nothing else about the
proposed grouping changes: `observations/`, `admission/`, and
`server-principal.json` move beside `blobs/` under `record/`; `index/`
is regrouped, not changed; the EML commit-tree keyspaces stay co-located
inside the `blobs/` database.

That co-location is no longer a carved-out exception to the layering
rule (contrast the proposal's own framing in §1.1 and §5). Decision 6
establishes the EML commit tree as record data — co-locating it inside
`record/blobs/` is simply the correct placement, not a rule violated and
priced. Decision 4 separately prices *why* it stays co-located rather
than moving to its own database (single-batch atomicity).

### Decision 2 — Q2: sole-writer enforcement

**Yes.** The deriver — a pure function from record events to index
entries — becomes the only write path into the index; the raw accessors
are split by that: their WRITE half, which bypasses the deriver, is
removed, while their read half stays public, since a reader cannot
violate a write-path invariant. No future feature writes the index
directly; anything wanting durable memoization outside the record goes
into the record layer with a real durability story, or it does not
exist (proposal §5's standing tax, accepted).

### Decision 3 — Q3: generated registry, membership sharpened

**Yes.** The index registry becomes the deriver's generated output,
checked by rebuild-and-compare, replacing the hand-maintained
`index_meta` partition list.

One sharpening against the proposal's own §3.1 test: "reproducible from
the retained record" is necessary for index membership but not
sufficient, because recomputability does not discriminate authority — a
file's hash is recomputable from the file and remains authoritative
once signed. The discriminating question is whether principal-signed
content depends on the structure being what it is. Index membership is
therefore **reproducible from the retained record AND unattested** — no
principal-signed material references it. This is the same test Decision
6 applies to reclassify the EML commit tree; applied to the index it
confirms membership rather than changing it (nothing principal-signed
references the index).

### Decision 4 — Wrap: Cyphr implements `eml::Storage` over its own store

**Yes.** Cyphr's storage engine wraps the `eml` crate's `Storage` trait
over its own store rather than the two crates continuing to co-own one
physical database. Four grounds:

- **One shape-owner per database.** Today two crates in two
  repositories independently decide keyspace names, key encodings, and
  metadata shapes inside the database Cyphr's record lives in, held
  together only by both sides having independently chosen the same
  backend. Wrapping gives Cyphr sole ownership of the shape and
  lifecycle of every byte in its store.
- **The single-batch requirement becomes enforceable by the party that
  owns batches.** Today blob writes, the manifest, and EML's own
  internal write-batch are sequenced, not atomic across structures —
  nothing tests the cross-structure property, and either repository can
  silently change the behavior. Wrapping joins EML's writes into the
  engine's own commit batch, closing the crash window and making the
  property a testable wrapper contract in one repository.
- **Reversal costs are asymmetric.** Unwrapping later is a
  type-parameter swap. Wrapping later happens against live user data —
  a migration of every principal's commit tree. The cheap direction
  expires once the system has users.
- **The price is acknowledged, not absorbed.** Cyphr takes on a subtle
  storage contract (positional leaves, node encoding, atomic batch
  semantics) where a maintained upstream implementation exists today.
  This is priced against a differential test (identical roots through
  the wrapper and the current backend) and a crash-consistency test,
  both required before the wrapper ships.

Wrapping does not change what the EML data *is* — Decision 6 answers
that question independently — and does not by itself move where that
data lives; Decision 1's layout answers that.

### Decision 5 — Ordering: minted from record state, validated at two points

Chain order is not server-asserted in the trust-model sense: every
`commit/create` transaction carries `arrow = MR(pre, fwd, TMR)` inside
its signed content, where `pre` is the prior Principal Root
(`SPEC.md:587-588`). Two servers ingesting the same blobs cannot
disagree about chain order without one of them failing replay
verification. The server's `sequence` counter is availability
machinery — its assigned position for range scans — not a second source
of truth, and it must be built and checked as such:

- **Minting.** `sequence` is minted from record-side tip state — the
  last manifest's sequence, equivalently the replayed commit count,
  held under the per-principal lock the engine already takes — not from
  the indexer's own counter. Deriving a record value from derived-layer
  state inverts the authority relationship Decision 1 establishes; a
  rebuilt or lagging index must never become a correctness surface for
  new writes.
- **Validation at ingest.** The deriver validates `arrow`/`pre`
  continuity against the current record tip before accepting a write.
- **Validation at rebuild.** After the sequence sort, linkage continuity
  is asserted before the index accepts the chain, so a rebuild that
  disagrees with the links is caught mechanically rather than silently
  trusted.
- **Every field entering a server-signed artifact is sourced from or
  validated against record state.** The in-tree precedent is
  `sign_tip_attestation` (`rs/cyphr-server/src/routes.rs`): before
  signing a tip attestation, it re-derives PR/SR/AR/CR from the engine
  and rejects the request if the derived roots disagree with the
  index-served `TipState`, rather than signing whatever the index
  currently reports. New server-signed artifacts follow this pattern:
  the index may serve as a fast path, but the signed claim is checked
  against — never merely read from — derived state.

### Decision 6 — Corrected taxonomy: the EML commit tree is record, not derived

**The EML commit-tree keyspaces are record data. The derived class has
exactly one member: the index. There is no `derived/` directory —
`index/` sits directly under `data_dir/`, a sibling of `record/`
(Decision 1).**

The proposal's authority test asks whether a structure is *told* or
*worked out*. Applied to bytes, the EML commit tree is worked out — it
is a function of the record's blobs, and replay reconstructs it. But
recomputability from the record is not what the authority test is
actually discriminating, per Decision 3's sharpening: a signed file's
digest is also recomputable from the file, and the file remains
authoritative once signed. The discriminating question is whether
principal-signed content depends on the structure being what it is.

By SPEC construction, it does. The Commit Root is defined as the EML
root over the commit's transaction leaves — `CR = EMLR(TR₀, TR₁?, ...)`
(`SPEC.md:114`) — exactly what the EML keyspaces store. The Principal
Root binds it by construction: `PR = H(SR ∥ CR)` for every post-genesis
commit (`SPEC.md:333-339`). Every commit's signed `arrow` binds the
prior PR via `pre` (`SPEC.md:587-588`). So every commit's signature
attests the commit tree's root as of its predecessor, one hash away:
**the EML commit tree is the record's own structure, not a projection
of it.** (One precision that changes nothing in the classification: the
attestation of the tree's tip arrives with the *next* commit, since
`pre` in commit N+1 is what binds commit N's resulting root — the tree
is attested chainwise-retrospectively, not instantaneously, but it is
attested.)

The index has no such property: no principal-signed content references
it. It remains the sole derived-class member.

### Decision 7 — Correction against proposal §1.1, §4, and §5

This ADR corrects three places where `docs/proposals/storage-layering.md`
(left unedited at 2121304 per this PR's scope) misclassifies the EML
commit tree, so the correction is recorded here rather than silently
inherited:

- **§1.1's diagram and surrounding prose** label the EML keyspaces
  "derived EML keyspaces" and describe their co-location inside
  `blobs/` as "derived state inside the record layer, carried as a
  named exception." A reader who starts at §1.1 — the proposal's first
  substantive section — meets this misclassification before reaching
  §4 or §5; Decision 6 corrects it here too: the EML tree is record
  data, not derived state placed in the record layer by exception.
- **§4's table** lists the EML keyspaces' authority as "worked out from
  the chain," with a Regenerable note ("replay reconstructs principals
  from blobs"). This is true of the bytes and wrong as an authority
  classification, for the reason Decision 6 states: recomputability does
  not discriminate authority, attestation does, and the EML tree is
  attested.
- **§5** calls the EML co-location carve-out "a naming convention with
  better marketing" as the strongest case for a reasonable no on Q1.
  That self-criticism was a correct instinct pointed at the wrong
  target: there is no carve-out to defend or reject, because the EML
  tree was never derived-class data placed inside the record layer by
  exception. It is record data placed inside the record layer, plainly.
  Decision 4 still prices *why* it stays co-located in `blobs/` rather
  than moving to its own database — that is a real, separately-argued
  atomicity trade-off — but it is not payment for an exemption.

A reader of the proposal alongside this ADR should treat every "derived"
or "exception" reference to the EML keyspaces in §1.1, §4, and §5 as
superseded by Decision 6, not as a live characterization.

The proposal's Q1 condition ("the EML commit-tree keyspaces remain
inside the record's blob database") stands unchanged as *policy* — this
correction changes why it is right, not whether it is right.

### Decision 8 — `AGENTS.md` I1 rewritten

Root `AGENTS.md`'s I1 invariant reads (before this ADR):

> **I1 — Source of truth.** The BLAKE3 content-addressed blob store is
> the sole source of truth; the eml Merkle log and the index are
> rebuildable caches.

This is wrong per Decision 6: the EML Merkle log is not a rebuildable
cache, it is record structure. I1 is rewritten to:

> **I1 — Source of truth.** The BLAKE3 content-addressed blob store,
> including each principal's EML commit-tree keyspaces, is the record —
> the sole source of truth. The EML commit tree is record structure
> with a tested reconstruction property (disaster recovery from blob
> content, not disposability): its bytes can be rebuilt if lost, but
> losing them is a recovery event, not a routine operation, unlike the
> index. The index alone is a rebuildable cache: the sole derived-class
> member, safely and routinely disposable. Grounding: ADR-0002
> (`SPEC.md:114`, `:333-339`, `:587-588`). Signpost: any design that
> makes the index authoritative, or that treats deleting the EML
> keyspaces as a routine operation, violates this.

The distinction the rewrite draws — *reconstructible in principle* vs.
*disposable in practice* — is why the EML keyspaces sit in `record/`
while `index/` remains the one path safe for an operator's `rm -rf`.

---

## Consequences

### Positive

1. **The disposable/irrecoverable boundary is legible at the
   filesystem.** Today `observations/` (the key death-set, irrecoverable)
   sits as a directory sibling to `index/` (safely disposable), and
   nothing about the path distinguishes them. After Decision 1, every
   store an operator or backup tool can see under `record/` is
   irrecoverable if lost, and everything under `index/` is not.
2. **Index membership becomes a runnable test** (Decision 3) rather than
   a per-store judgment argued in module comments.
3. **The single-batch write requirement becomes deliverable and testable
   by the party that owns it** (Decision 4), closing a crash window
   nothing currently tests.
4. **Server-signed artifacts get a stated, checked provenance rule**
   (Decision 5), generalizing a pattern (`sign_tip_attestation`) that
   today exists only for tip attestations.
5. **The record/derived boundary is now grounded in what is
   cryptographically attested, not in what happens to be recomputable**
   (Decision 6) — a test that generalizes to future storage decisions
   without re-deriving it each time.

### Negative

1. **Migrating `observations/`, `admission/`, and
   `server-principal.json`** under `record/` touches the server's
   startup path (`rs/cyphr-server/src/lib.rs:112-127`) and is real work,
   priced by the proposal (§5) as a schedule item rather than a risk
   given no deployed users.
2. **Sole-writer enforcement (Decision 2) forecloses convenient durable
   memoization permanently** — proposal §5's standing tax, accepted
   here as the cost of the enforceability Decision 2 buys.
3. **The wrapper (Decision 4) takes on a subtle storage contract** where
   a maintained upstream implementation exists; mitigated by the
   differential and crash-consistency tests named there, not eliminated.
4. **`docs/specs/storage-engine.md`, `docs/specs/indexer.md`, and
   `docs/guides/operating-a-server.md`** need amendment to reflect
   Decisions 1-3 and the corrected taxonomy of Decision 6; that
   amendment is scoped to later work, not this PR.

---

## References

- Proposal: `docs/proposals/storage-layering.md` (full argument for
  Decisions 1-3; §4.2 alternatives considered; §5 costs).
- SPEC.md: `:108-117` (Commit Root definition), `:333-339` (PR
  construction), `:583-603` (Arrow, commit finality).
- `rs/cyphr-server/src/routes.rs` (`sign_tip_attestation`) — the
  record-cross-check precedent Decision 5 generalizes.
- `rs/cyphr-blob-fjall/src/lib.rs:70-82` — the single-WAL co-location
  Decision 4's wrap argument responds to.
- ADR-0001 — the format this ADR follows; establishes the adjacent
  Prover/Verifier vocabulary this ADR's storage layer sits beneath.
