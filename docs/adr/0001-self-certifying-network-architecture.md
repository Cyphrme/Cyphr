# ADR-0001: Self-Certifying Network Architecture

**Status:** PROPOSED

**Date:** 2026-05-11

**Plan:** `docs/plans/cyphr-server.md` (continuity from Phases 1-4)

---

## Context

During implementation of the Cyphr server (`cyphr-server`, Phases 1-4 of the
server plan), we discovered a persistent impedance mismatch between the
protocol's design and our network code. Despite the SPEC explicitly
designating the principal as sovereign over its own state (§13.7:
"Principals are the authority over their own state"), the server's write
path (`submit_commit`) was built as a full-replay pipeline — reconstructing
the entire principal from genesis on every push. This is the canonical
client/server reflex: treat the server as the authority, replay everything,
validate centrally.

This mismatch is not a bug in one function. It is a paradigm error. The Cyphr
protocol is not client/server with cryptographic signatures bolted on. It is
a fundamentally different architecture that requires its own mental model,
vocabulary, and design primitives. Without naming this model explicitly,
every new implementor will encounter the same friction and reach for the same
wrong abstractions.

### Scope of This ADR

This ADR governs the **authentication domain** — the Commit Tree (CT), which
is the MALT-backed append-only log of auth state transitions. The CT is the
mechanism that tracks key lifecycle (creation, revocation, replacement) and
derives the observable principal root (PR).

**The Data Tree (DT) is explicitly out of scope.** The SPEC (§2.3.3)
establishes that AT and DT have fundamentally different structural properties:

| Property     | Auth Tree (AT)                  | Data Tree (DT)              |
| :----------- | :------------------------------ | :-------------------------- |
| Mutability   | Append-only (immutable history) | Mutable (deletable content) |
| Chain        | Linked via `pre`                | No chain                    |
| Verification | Replay from genesis             | Point-in-time snapshot only |
| State type   | Monotonic sequence of commits   | Non-monotonic               |
| Semantics    | Full protocol semantics         | None (application-defined)  |

DT _may_ operate in MALT mode (§4.7.3: "Principals may construct DT in MALT
mode as an append only, verifiable data structure"), but this is an
application-level choice, not a protocol requirement. Different applications
will impose different structure on DT. The data domain requires its own
architectural treatment, informed by research into content-addressed storage
and networking (see "Future Work" below).

### Prior Art

The architecture Cyphr's auth domain implements has established precedent:

**Self-Certifying File System (SFS)** — David Mazières, 1999. Coined the
principle that data contains its own cryptographic authority, severing trust
from infrastructure. Cyphr's MALT-rooted identity chains are a direct
descendant of this concept.

**Certificate Transparency (RFC 9162)** — The direct structural precedent
for Cyphr's Commit Tree. CT defines append-only Merkle trees with inclusion
and consistency proofs as the verification mechanism for log integrity.
Cyphr's CT (§4.4) is architecturally equivalent to a CT log. RFC 9162's
`InclusionProofDataV2` and `ConsistencyProofDataV2` provide the model for
Cyphr's proof wire format.

**KERI (Key Event Receipt Infrastructure)** — Samuel M. Smith. Formalizes
the separation of identity control (Controllers) from infrastructure
(Witnesses/Watchers). KERI's controller/witness taxonomy parallels Cyphr's
principal/witness distinction, though Cyphr's use of MALT proofs diverges
from KERI's receipt-based approach.

**Git** — Useful analogy: the local repository is sovereign, remotes are
witnesses. Push/pull is state reconciliation, not RPC. However, Git requires
full history replay (O(n)), which is precisely what Cyphr's MALT proofs
avoid.

---

## Decision

Cyphr's auth-domain network architecture follows an established paradigm
that the transparency log literature (RFC 6962, RFC 9162) implements but
does not name as a unified model. We adopt the descriptive label
**SCADS** (Self-Certifying Authenticated Data Structures) for internal
architectural clarity.

> **Terminology provenance:** Nothing in this label is novel. Both
> constituent concepts are established prior art:
>
> - **Authenticated Data Structure (ADS)** — Tamassia (2003). A data
>   structure supporting efficient cryptographic proofs of membership,
>   consistency, and integrity. Merkle trees, including Cyphr's MALT, are
>   the canonical example.
> - **Self-Certifying** — Mazières (1999, Self-Certifying File System).
>   Data that carries its own proof of authenticity, severing trust from
>   infrastructure.
> - **Transparency Logs** — RFC 6962 (2013), RFC 9162 (2021). The closest
>   existing paradigm name in practice: append-only Merkle trees with
>   inclusion and consistency proofs. Certificate Transparency, Key
>   Transparency (CONIKS, Google KT), and KERI all implement variations
>   of this pattern.
>
> "SCADS" is our working label for this intersection as
> applied to Cyphr's identity domain. It is not a term of art from any
> RFC or paper.

All network-facing code — servers, clients, sync protocols — must be
designed from this paradigm, not from client/server conventions.

### Core Axioms

These are structural constraints derived from the SPEC. They are not design
preferences.

**1. Cryptographic Truth.** Auth state is valid because of its cryptographic
signature and placement in the Commit Tree (MALT), not because it was
returned by a particular server. A commit's TR (transaction root) is
self-certifying — its validity is derivable from the signed cozies it
contains and the Merkle path that chains it to prior state. A witness
stores and propagates this data; it does not produce it.

**2. Principal Sovereignty.** The principal is the sole authority over its own
auth state. No witness, service, or oracle may override, reject, or
reinterpret a cryptographically valid state mutation. A witness may _refuse
to store_ data (rate limits, policy, storage constraints), but it may not
alter the principal's chain.

> SPEC §13.7: "Principals are the authority over their own state."

**3. Partial Visibility as Normal Operating Condition.** A witness may hold
any subset of a principal's history — from a single tip root to the full blob
chain. Missing data is not an error; it is a trigger for state
synchronization. The protocol must function correctly regardless of witness
"fatness."

> SPEC §16.2: "Pruning: Services may discard irrelevant user data."

**4. Proof-Verifiable State.** Witnesses maintain local state (tip root,
active keys, tree size) as trust anchors. This state is not authoritative —
it is a _materialized view_ of events the witness has observed. Its integrity
is verifiable via MALT consistency proofs without replaying the full history.

> SPEC §16.4: "Enabling efficient verification of history without full
> chain replay."

### The Paradigm Shift

The fundamental conceptual reframe:

| Traditional Client/Server       | SCADS (Cyphr)                                                |
| :------------------------------ | :----------------------------------------------------------- |
| Server is source of truth       | Principal is source of truth                                 |
| Client requests mutations       | Principal declares mutations                                 |
| Server validates business logic | Witness validates cryptographic geometry                     |
| Missing data = error (404)      | Missing data = sync trigger                                  |
| Full state at server            | Partial views everywhere                                     |
| Auth: "Is this user allowed?"   | Auth: "Is this signature valid and does it chain correctly?" |

### Roles

The SPEC (§2.2.11) already defines the correct vocabulary. This ADR
reinforces it and adds two supplementary terms for the proof boundary:

| Role          | Definition                                                                                                                                                              | Source             |
| :------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------- |
| **Principal** | The identity itself — the cryptographic state tree rooted at PG. Sole source of truth for its own state.                                                                | SPEC §2.2.1        |
| **Witness**   | An infrastructure node that stores, verifies, and propagates principal state. Zero cryptographic authority. May hold partial history.                                   | SPEC §2.2.11       |
| **Oracle**    | A witness with delegated trust — the client trusts the oracle to have correctly processed commits it hasn't verified itself. Trust is explicitly granted, not inherent. | SPEC §2.2.11       |
| **Prover**    | The entity that generates MALT proofs. Typically the principal (on push) or a fat witness (on sync). Requires access to the tree's leaf data.                           | Adopted (this ADR) |
| **Verifier**  | The entity that checks MALT proofs against stored trust anchors. Requires only roots + proof paths. Any witness can be a verifier.                                      | Adopted (this ADR) |

**Rejected terminology:**

| External Term          | Source         | Rejection Rationale                                                                                                                                                            |
| :--------------------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "Controller"           | KERI / W3C DID | "Principal" names the identity itself, not merely the entity holding keys. Cyphr's principal encompasses the full state tree.                                                  |
| "Relay" / "Log Server" | KERI / CT      | "Witness" already defined in SPEC §2.2.11 with appropriate precision. Adding synonyms creates confusion.                                                                       |
| "Stateless Validation" | General        | Misleading. Witnesses maintain proof-verifiable state (tip, keys, tree size). They are not stateless; they are _proof-verifiable_. The distinction matters for implementation. |

### Verification Model

The network boundary is a **Prover-Verifier protocol** for auth state, not a
request-response API. The four fundamental network operations:

| Operation            | HTTP Mapping                 | Semantics                                                                               |
| :------------------- | :--------------------------- | :-------------------------------------------------------------------------------------- |
| **GetTreeHead**      | `GET /tip?pr=<PG>`           | Obtain the witness's latest trust anchor (CR, tree_size) for a principal                |
| **AppendTransition** | `POST /push`                 | Principal declares an auth state mutation with signed blobs + consistency proof         |
| **ProveConsistency** | Part of push/sync payload    | Mathematical proof that CR_new is a strict append-only extension of CR_old — O(log n)   |
| **ProveInclusion**   | Part of audit/query response | Mathematical proof that a specific commit (TR) exists in a tree with root CR — O(log n) |

**Full replay is one verification mode, not the verification model.** It is
appropriate for:

- **Bootstrap**: a new witness encountering a principal for the first time
  with full history available
- **Audit**: deliberate verification of entire chain integrity
- **Recovery**: reconstructing state after data loss

It is inappropriate as the default push acceptance path. A witness that
replays from genesis on every push implements O(n) verification where
O(log n) proof verification suffices.

### Proof Semantics (derived from RFC 9162)

The MALT implements two proof types, directly paralleling Certificate
Transparency:

**Inclusion Proof** (RFC 9162 §2.1.3): Given a leaf hash (TR), tree root
(CR), and Merkle path, proves that a specific commit is recorded in the tree.
Verifiable without the full leaf set — O(log n) nodes.

**Consistency Proof** (RFC 9162 §2.1.4): Given old root (CR_old, size m),
new root (CR_new, size n), and proof path, proves the new tree is a strict
extension of the old — no entries altered or removed. Verifiable with only
the two roots + proof — O(log n) nodes.

**Composition** (RFC 9162 §8.1.5): Both are used together. A witness:

1. Receives new root CR_new from the pushing principal
2. Verifies **consistency** from stored CR_old → CR_new (append-only guarantee)
3. Optionally verifies **inclusion** of specific commits (membership guarantee)

Neither requires the full leaf set. This is the property that enables thin
witnesses.

**Current `malt` crate API:**

```
Log::append(data)          → u64 (leaf index)
Log::root()                → Digest (current MALTR)
Log::inclusion_proof(i)    → InclusionProof { index, leaf, path }
Log::consistency_proof(m)  → ConsistencyProof { old_size, new_size, path }
verify_inclusion(...)      → bool
verify_consistency(...)    → bool
```

**Key asymmetry**: Proof _generation_ requires the full tree (all leaves).
Proof _verification_ requires only the proof path + roots. This is by design
(RFC 9162 §4) — the entity with the data generates proofs; lightweight
consumers verify them. The principal, as the authoritative chain holder,
is the natural proof generator on push.

### Witness Storage Tiers

The SPEC's thin/fat/full taxonomy (§16.1) applies to services, not just
clients. A witness's verification capabilities scale with its storage:

| Tier     | Stores                                | Can Verify                                             | Can Generate Proofs |
| :------- | :------------------------------------ | :----------------------------------------------------- | :------------------ |
| **Thin** | PG, CR, tree_size, active keys        | Consistency + inclusion (with client-supplied proofs)  | No                  |
| **Fat**  | Above + full commit chain (all TRs)   | Consistency + inclusion (self-generated) + full replay | Yes                 |
| **Full** | Above + all data actions + embeddings | Everything                                             | Yes                 |

The protocol must support all tiers. The push wire format must accommodate
thin witnesses by allowing the client to supply proof material alongside
commit blobs.

### What a Thin Witness Push Looks Like

When a principal pushes to a witness holding only `(PG, CR_old, tree_size,
active_keys)`, the request must carry:

1. The commit blobs (signed cozies)
2. A consistency proof: `(CR_old, tree_size) → (CR_new, new_size)`
3. The signer's public key (if not already known to the witness)
4. Optionally: inclusion proof for the new TR within CR_new

The witness verifies:

1. Signature on each coz is valid
2. `pay.tmb` is in active key set (local lookup)
3. Consistency proof verifies against stored CR_old
4. `pre` in the commit chains to stored tip PR
5. Timestamps within acceptable window
6. Update stored state: `CR_old ← CR_new`, `tree_size ← new_size`

> **SPEC gap (G1):** §13.4 says "verifies chain validity" without defining
> what validation is required. This ADR's verification list is our
> working model pending SPEC clarification.

---

## Consequences

### Positive

**For `cyphr-server`:**

1. **`submit_commit` supports proof-based verification** as the primary push
   acceptance path. Full replay remains as a configuration option or
   bootstrap mode. The fix is surgical — the storage layer (BlobStore,
   Indexer, read paths) is already paradigm-neutral and unaffected.

2. **`TipState` extends** with active key set, CR (MALT root), and tree_size
   to serve as the thin witness trust anchor. This makes the index
   sufficient for push verification without blob replay.

3. **`PushRequest` wire format** accommodates optional proof material
   (consistency proof, inclusion proof) from the client. A fat witness that
   holds full history can accept pushes without proof material (self-generated).

4. **`load_principal` remains** as the fat witness bootstrap/audit path. It
   is not removed — it is no longer the sole write path.

5. **O(log n) steady-state push** instead of O(n) genesis replay. For a
   principal with 10,000 commits, this is the difference between ~14 hash
   verifications and 10,000 full transaction replays.

**For implementors:**

6. **Named paradigm prevents regression.** Future features (sync, gossip,
   multi-witness) have an architectural reference that prevents defaulting to
   client/server patterns.

7. **Witness tier flexibility.** Deployments can choose their storage/compute
   tradeoff without architectural surgery.

**For the SPEC:**

8. **Gap inventory.** This ADR surfaces 6 gaps (G1-G6, documented in the
   sketch) where the SPEC's normative language is insufficient for
   implementors:

   | #   | Gap                                                                 | SPEC Section     |
   | :-- | :------------------------------------------------------------------ | :--------------- |
   | G1  | Push acceptance criteria ("verifies chain validity") underspecified | §13.4            |
   | G2  | No explicit verification tiers (full replay vs. proof-based)        | §13.2 vs §16.4   |
   | G3  | Service role in witness taxonomy not formalized                     | §2.2.11 vs §16.2 |
   | G4  | MALT proof serving/attachment direction unspecified                 | §4.4             |
   | G5  | Proof wire format undefined                                         | §4.4             |
   | G6  | Client proof generation obligation (SHOULD vs MUST)                 | —                |

   These are forwarded to Zami for SPEC augmentation.

### Negative

1. **Increased push payload size.** Proof material (consistency proofs) adds
   O(log n) hashes to each push request. For a tree with 10,000 commits this
   is ~14 × 32 bytes = ~448 bytes — negligible, but non-zero.

2. **Client complexity.** The principal must maintain a local `Log` instance
   to generate proofs on push. This shifts computational burden from server
   to client. This is architecturally correct (the principal is the source of
   truth), but it means client implementations must understand MALT proof
   generation, not just signature generation.

3. **Two verification paths to maintain.** The engine must support both
   proof-based (thin) and full-replay (fat/bootstrap) verification. The
   conditional logic is manageable but adds surface area to test.

4. **Data domain remains unaddressed.** This ADR intentionally does not cover
   Data Tree verification. Applications that need verifiable data actions
   will require separate architectural treatment (see "Future Work").

5. **SPEC gaps are blockers for wire format finalization.** G5 (proof wire
   format) and G6 (client proof generation obligation) must be resolved
   before the push wire format can be stabilized.

---

## Future Work: Data Domain and Content-Addressed Networking

While the Data Tree is out of scope for this ADR, active research is underway
on content-addressed storage and networking primitives that will inform
the data domain's architecture:

**tvix-castore** (TVL) — A generic, BLAKE3-addressed content store separating
blob storage from directory metadata. Relevant as a model for DT blob
management: the separation of content addressing (blobs) from structural
metadata (directory/tree service) parallels Cyphr's separation of BlobStore
from Indexer. Production-proven at Replit.

**iroh** (n0) — A Rust-based P2P networking toolkit using BLAKE3 verified
streaming for content-addressed data transfer. iroh-blobs enables
incrementally verified streaming — data is verified in ~16 KiB chunks as
it arrives, leveraging BLAKE3's tree hash structure. Relevant to Cyphr's
eventual sync protocol: rather than fetching entire commit chains, witnesses
could stream and verify individual blobs with incremental trust.

**DT MALT mode** (SPEC §4.7.3) — The SPEC notes that principals _may_
construct DT in MALT mode. If adopted, DT would benefit from the same
consistency/inclusion proof model documented in this ADR. This would unify
the verification model across auth and data domains, but the decision is
application-specific and cannot be mandated at the protocol level.

When the data domain requires its own ADR, these precedents should be
evaluated alongside the AT/DT duality table (§2.3.3) to determine whether
the proof-based model transfers or whether DT's mutable, non-monotonic
nature requires fundamentally different verification primitives.

---

## Alternatives Considered

| Alternative                                             | Reason Rejected                                                                                                                                                                                                                                      |
| :------------------------------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fix `submit_commit` without naming the paradigm         | The implementation fix is necessary but insufficient. Without the architectural model documented, the next feature (sync, gossip, multi-witness) will reproduce the same impedance mismatch. The ADR is cheap insurance against paradigm regression. |
| Adopt KERI terminology wholesale                        | The SPEC already has the correct vocabulary for roles (principal, witness, oracle). KERI's "Controller" is less precise than "principal" for Cyphr's model. Adopting external terminology would create unnecessary synonyms.                         |
| Wait for SPEC update before documenting                 | The architectural model is clear from existing SPEC sections. Waiting leaves implementors without guidance during the gap. The ADR can be revised when the SPEC update lands — that's what PROPOSED status means.                                    |
| Full event-sourcing model (Git-style replay everywhere) | Git requires O(n) replay because it lacks authenticated tree proofs. Cyphr has a MALT specifically to avoid this. Defaulting to full replay negates the MALT's raison d'être and creates a scalability ceiling.                                      |
| Unified AT/DT verification model now                    | Premature. AT and DT have fundamentally different properties (§2.3.3). DT is mutable, unchained, and non-monotonic. Forcing the MALT proof model onto DT without understanding application requirements would constrain flexibility.                 |

---

## References

- SPEC: §2.2.11 (Witnesses), §2.3.3 (AT/DT Duality), §4.4 (Commit Tree),
  §4.7.2-3 (Data Tree, DT Organization), §13.2 (Verification), §13.4 (MSS
  API), §13.7 (Gossip), §16.1-4 (Storage), §18 (State Jumping)
- RFC 9162 — Certificate Transparency v2 (§2.1 Merkle Trees, §4.11-4.12
  Proof structures, §8.1.5 Composition)
- Mazières, D. "Self-certifying File System" (1999)
- KERI (Key Event Receipt Infrastructure) — parallel architecture
- tvix-castore (TVL) — generic content-addressed blob + directory service
- iroh (n0) — BLAKE3 verified streaming, P2P content-addressed networking
- Sketch: `.sketches/2026-05-07-malt-proof-verification.md`
- Previous plan: `docs/plans/cyphr-server.md`
