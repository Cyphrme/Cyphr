# SPEC: Third-Party Key-Inclusion Proof Portability

<!--
  Implementation-domain design record closing issue #19's substance:
  making key-inclusion proof verification portable to a third party
  that never owns or trusts the principal being checked. This document
  does NOT replace SPEC.md; it sits alongside `docs/specs/receipts.md`
  (the trust anchor this design consumes) without editing it.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
  "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be
  interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
  when, they appear in all capitals.
-->

## Domain

**Problem Domain:** `Principal::verify_key_inclusion` (`rs/cyphr/src/principal.rs`)
only serves a caller that already owns and trusts a live `Principal` --
it reads its trusted roots from `self`. Issue #19 asks for the portable
alternative: a third party holding only a server's pinned PG and a
signed tip report can verify that a specific key was really included
under a _foreign_ principal's Principal Root, without ever owning,
replaying, or querying that principal directly.

**Target System:** `rs/cyphr/src/inclusion.rs`'s free function
`verify_key_inclusion` (pre-existing, genuinely `Principal`-free); the
one new accessor `Principal::sr_inclusion_proof`
(`rs/cyphr/src/principal.rs`) that makes hop 4 of the proof chain
reachable from outside the crate; and the end-to-end demonstration in
`rs/cyphr-server/tests/inclusion_portability.rs`.

**Scope boundary:** This document covers exactly how a portable
verifier assembles trusted roots from a signed tip report and proof
hops, and rules on whether a server-side proof-serving HTTP endpoint
ships now. It does not cover equivocation detection (a separate,
concurrent design) or any new persistence, caching, or batching of
proofs.

## The 4-hop chain and what a portable verifier needs

`Principal::verify_key_inclusion` chains four inclusion proofs,
top-down from a trusted Principal Root (PR):

1. **Hop 1 (KT)** -- the target key's thumbprint is included in the Key
   Root (KR).
2. **Hop 2 (AR-node)** -- KR is included in the Auth Root (AR).
3. **Hop 3 (SR-node)** -- AR is included in the State Root (SR).
4. **Hop 4 (PT)** -- SR is included in the Principal Root (PR).

Each hop is a self-contained `polydigest::LeafProof`, checked against
its own level's root, with a bridge check binding hop `i`'s proven leaf
value to hop `i-1`'s root (`NodePath::verify`,
`rs/cyphr/src/principal.rs`). All four hops and roots are generatable
from public APIs: `Principal::active_algs`/`active_keys`/`data_root`
feed `KeyTree`/`AuthTree`/`StateTree::build_tree` for hops 1-3 (all
`pub`), and the new `Principal::sr_inclusion_proof` accessor gives hop
4 without requiring the crate-internal `Principal.pt` field or the
non-portable `NodePath` type.

Implemented by `sr_inclusion_proof` and `key_inclusion_proof` in
`rs/cyphr/src/principal.rs`, `verify_key_inclusion` in
`rs/cyphr/src/inclusion.rs`, and exercised by
`rs/cyphr-server/tests/inclusion_portability.rs`.

## `[portability-r-kr-derivation]` Ruling: KR is derived, not trusted directly

`docs/specs/receipts.md`'s signed tip report carries `roots{pr, sr, ar,
cr}` -- there is no `kr` claim. A portable verifier therefore cannot
read a trusted KR straight from the tip report the way it can read AR,
SR, and PR.

This is **not a gap**: `roots[0]` (KR) is derived as `hops[1].leaf_hash`
instead of read from an independent source. This is cryptographically
sound because `verify_key_inclusion`'s bridge-and-hop-verify loop
checks hop 1 (the KT proof) against `roots[0]`, but hop 2 (the AR-node
proof) is _itself_ checked against `roots[1]` (AR) -- which IS an
independently-trusted tip claim. An attacker cannot substitute a forged
KR at `roots[0]` without also forging a valid Merkle proof for hop 2
against the real, tip-attested AR, which is infeasible under the same
collision-resistance assumption every other hop already relies on. Only
the outermost root in a chained inclusion proof needs independent
authentication; every interior root is transitively authenticated by
the hop that proves it sits under the next level up. AR, SR, and PR
happen to also be available directly from the tip report's claims, so
in practice only KR needs this derivation.

Exercised by `rs/cyphr-server/tests/inclusion_portability.rs`'s
`third_party_verify_key_inclusion` and
`third_party_rejects_tampered_ar_node_hop` (flips hop 2's leaf, leaving
hop 1's identity binding genuine, and confirms rejection -- exercising
exactly this ruling's argument: hop 1's proof no longer matches the
now-forged derived KR, and hop 2's own proof no longer matches the
tip-attested AR).

## `[portability-r-endpoint-deferred]` Ruling: no new HTTP endpoint ships here

A server-side proof-serving read handler (e.g. `GET
/proof/key-inclusion?pr=<pg>&tmb=<b64ut>&alg=<name>`, returning an
unsigned envelope carrying the 4 hops) was considered and is
**deferred**, not shipped, for three reasons:

1. **Not actually thin.** Materializing an arbitrary caller-named
   principal from the server's own storage requires
   `StorageEngine::load_principal(principal_id, genesis)`
   (`rs/cyphr-storage/src/engine/mod.rs`), which takes an explicit
   `Genesis` (the principal's original implicit key or explicit key
   set) as an input the handler does not yet have a public way to
   determine for an arbitrary `pr` -- unlike `/patch`, which serves raw
   chain data without needing to replay it. Wiring that lookup is new
   production surface, not a one-line addition to `routes.rs`.
2. **Out of this design's declared floor.** Its non-goals
   explicitly bar "proof caching, batching, or any performance
   machinery -- one proof, one verification, demonstrated." A
   production endpoint invites exactly those follow-on concerns
   (rate-limiting an arbitrary-`tmb` lookup, response caching,
   algorithm-selection validation) that a single demonstration e2e is
   not the right vehicle to settle.
3. **Not required to close #19's substance.** The delegated prover role
   ("anyone holding the chain -- e.g. the principal's owner or the
   server") is satisfied by
   `rs/cyphr-server/tests/inclusion_portability.rs`'s prover phase
   without any new server route: the free function
   `cyphr::verify_key_inclusion` is already fully portable, and the
   e2e already proves a verifier holding only the tip report and hops
   can use it. An HTTP endpoint would only change _who generates the
   hops_, not whether the verification itself is portable.

**Follow-up shape**, for whoever picks this up: `GET
/proof/key-inclusion?pr=<pg>&tmb=<b64ut>&alg=<name>` inside
`routes.rs`, returning `Envelope::unsigned` (no attestation claim is
needed -- the hops are self-verifying against a tip report the caller
fetches separately) carrying `{hops: [LeafProof; 4], tmb, alg}`. It
needs a way to resolve `Genesis` for an arbitrary `pr` first (the real
missing piece per reason 1 above); the hop-generation logic itself is a
direct lift of the prover phase in
`rs/cyphr-server/tests/inclusion_portability.rs`, which demonstrates
the alternative (no endpoint) path in full.

## Maintenance risk: prover-side hop 1-3 reconstruction duplicates internal ordering

The prover phase in `rs/cyphr-server/tests/inclusion_portability.rs`
rebuilds hops 1-3 by calling `KeyTree`/`AuthTree`/`StateTree::build_tree`
directly against a `Principal`'s `active_algs`/`active_keys`/`data_root`
-- the same sequence `Principal::key_inclusion_proof`
(`rs/cyphr/src/principal.rs`) runs internally, including KT's lexical
thumbprint sort. This is not accidental duplication within this test;
it is the only way to generate a portable proof today, since
`key_inclusion_proof` itself is `pub(crate)` and returns the
non-portable `NodePath` type.

The risk: if `KeyTree::build_tree`'s internal sort order, or the
KT/AR-node/SR-node construction sequence, ever changes, every external
caller reconstructing hops this way (this test, and any future
prover-side code following the same pattern) silently diverges from
what `key_inclusion_proof` produces, with no compiler or type-level
signal -- only a proof that fails to verify.

**Signpost for resolution:** a future, genuinely public "full-chain hop
generation" API on `Principal` -- e.g. `Principal::key_inclusion_hops(&self,
alg, tmb) -> Result<[LeafProof; 4]>`, mirroring `key_inclusion_proof`'s
body but returning the portable `Vec<LeafProof>` shape instead of the
crate-internal `NodePath` -- would let a prover call one function
instead of re-deriving the KT/AR-node/SR-node sequence, closing this
risk without widening any other crate-internal surface. This design did
not add that API because the scoped work here was limited to
exactly one accessor (`sr_inclusion_proof`, hop 4 only); a full-chain
generator is a larger, separately-justified addition.

Exercised by `build_fixture`'s hop 1-3 reconstruction in
`rs/cyphr-server/tests/inclusion_portability.rs`, which mirrors
`key_inclusion_proof`'s internal sequence in `rs/cyphr/src/principal.rs`.

## Roadmap: not built here

Equivocation detection is a separate, concurrent design
(`docs/specs/receipts.md`'s roadmap section). A server-side
proof-serving endpoint is deferred per
`[portability-r-endpoint-deferred]` above.
