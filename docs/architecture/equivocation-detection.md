# Equivocation detection

This page states how a fork in a principal's record, and a server that
shows different readers different records, are detected and handled. It
names the parts involved, says what the code does today, and states the
requirements the arrangement must meet. Definitions that live elsewhere
are cited, not restated.

The arrangement follows one model. No server, witness or peer is an
authority over a principal's state. Each party makes signed claims only
about itself. Every verifier chooses whose claims it collects and reaches
its own verdict. A conflict between claims is evidence, and only the
principal resolves a fork in its own record.

SPEC references are to `SPEC.md` at commit `be0663f` on the spec
author's `zami` branch, the normative text.

## Two faults that look alike

A reader who holds two different answers about one principal has seen a
**split view**. Two different faults produce one, and they must not be
confused:

- **Principal fork.** The principal's own keys signed two or more
  conflicting commits that reference the same `pre`. SPEC calls this an
  invalid fork
  ([§15.7](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#157-consensus-and-witnesses),
  [§15.7.1](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#1571-invalid-forks-fork-detection-and-duplicitous-behavior)).
  It is the principal's fault, or the fault of whoever holds its key.
- **Peer equivocation.** One server signed two views of the same
  principal that cannot both be true: neither is a prefix of the other.
  It is that server's fault.

Two different servers that hold different branches of a principal fork
are both telling the truth about themselves. Each holds what it says it
holds. Reading their disagreement as server misbehaviour accuses an
honest server. Two views can also differ with no fault at all, when one
server is simply behind the other.

## The model in SPEC

The model rests on these SPEC statements:

- "Principals are the authority over their own state"
  ([§13.7](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#137-gossip);
  that section is marked TODO in `be0663f`).
- Consensus rules favour "independent verifiability by any witness,
  without requiring global coordination"
  ([§15.1](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#151-consensus-philosophy)),
  and "witnesses independently track principal consensus states"
  ([§15.5](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#155-principal-consensus-states)).
- A witness may retain both conflicting transactions of an invalid fork
  as proof of error and broadcast them
  ([§15.2](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#152-proof-of-error)).
  The response to a fork "includes broadcast fork proof and rejection of
  both branches until resolved" (§15.7.1).
- "An invalid fork is resolved when the principal unambiguously selects
  one branch. Until resolved, witnesses hold both branches and the
  principal's consensus state is Error"
  ([§15.8](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#158-fork-resolution)).

## Parts

| Part      | What it claims, and about whom                                                                                                    |
| :-------- | :-------------------------------------------------------------------------------------------------------------------------------- |
| Principal | Its own state: each commit it signs says "this is my next state after `pre`".                                                     |
| Server    | Its own view: a signed tip report says which commit and roots this server holds for a principal. A keyless server signs nothing.  |
| Verifier  | Nothing to anyone else. It chooses which servers to ask, compares what they signed, and reaches a verdict that binds only itself. |

A server signs a tip report only if it is an attestor; the
[server receipts specification](../specs/receipts.md) defines the
attestor condition and the claim schema.

## What the code does today

These statements describe the code at this revision. Each names where
it can be checked.

- **No server delivers on a principal's behalf.** The server routes
  `/tip`, `/patch`, `/push`, `/revoke`, `/e/{digest}`, `/server`,
  `/auth/challenge` and `/auth/login` (`build_router` in
  `rs/cyphr-server/src/lib.rs`). There is no witness-registration
  endpoint, and accepting a push makes no outbound request
  (`rs/cyphr-server/tests/no_registration.rs`). A principal's client
  pushes its commits to the servers it chooses.
- **One server holds one branch.** A push whose `pre` the server's copy
  of the chain has already moved past is refused with `409` and not
  stored (`s2_3_2_push_on_a_stale_pre_is_refused_and_the_chain_stays_put`
  in `rs/cyphr-server/tests/spec_conformance.rs`). The server keeps no
  record of the refused branch. Nothing in the server records a fork,
  tracks a consensus state, or attaches evidence to an answer.
- **Witness mode pulls from one configured upstream.** A server started
  with `--mode witness` refuses writes and pulls `/patch` from the
  server named by `authority_url`, verifying each commit before it
  persists it (`rs/cyphr-server/src/sync.rs`). The
  [server operating guide](../guides/operating-a-server.md) describes
  the configuration.
- **The comparison exists as a library function.**
  `check_equivocation` in `rs/cyphr-server/src/receipt.rs` takes two tip
  reports and a public key for each. It returns `Proven` only when both
  verify, name the same principal and the same `sequence`, and differ in
  `commit_id` or in a root. Reports at different sequences return
  `DifferentSequence`, which settles nothing: the function makes no
  prefix check. It does not check that the two keys belong to one
  server; the receipts specification requires the caller to have
  established that. Only tests call it
  (`rs/cyphr-server/tests/equivocation.rs`); no server route and no
  `cyphr` CLI command runs it.

The requirements below that the code does not yet meet are stated as
requirements, not as behaviour. docket reports each one without a bound
test as `implementation-marker-absent`.

## Requirements

Each requirement below is a docket claim: a `[kebab-id]` heading
followed by a `claim` block whose `evaluator: test` says a test must
back it. `docs/AGENTS.md`, section "Docket — the documentation claim
gate", describes how a claim is bound to its test.

### [arch-verifier-chooses-peers]

A verifier, not a server, chooses which peers' views it collects. No
server enrols witnesses for a principal, and no server pushes a
principal's commits to other servers on its behalf. Publishing a commit
to a server is the principal's own act.

```claim
kind: requirement
evaluator: test
```

### [arch-detection-is-comparison]

Detection is comparison. It needs at least two independently obtained
views of the same principal, held together and checked against each
other. One view alone settles nothing, however trustworthy its source:
whether another party holds something different is information that
view does not carry.

```claim
kind: requirement
evaluator: test
```

### [arch-behind-is-not-fork]

Two views at different positions conflict only if the lower one is not
a prefix of the higher. Given views at sequences `m < n`, the check
establishes the higher view's own Commit Root at `m` and compares it with
the Commit Root the lower view signed at `m`. The higher view's root at
`m` is established either by replaying the commits from `m` to `n`, or
by a consistency proof from the higher side that binds its claimed root
at `m` to the root it signed at `n`
(`cyphr::commit_root::verify_consistency`).

- Equal roots: the lower view is behind, not in conflict.
- Different roots: the two views fork at or before `m`.
- A check that did not complete (a malformed proof, a fetch that
  failed) is no comparison. It is never reported as a conflict.

At `m == n` the check reduces to comparing the two signed roots
directly. A check that calls every pair of differing views a conflict
cannot tell a server that is behind from a forked one; a check that
calls every pair at different sequences consistent cannot tell a forked
server from one that is behind.

```claim
kind: requirement
evaluator: test
```

### [arch-principal-fork-evidence]

Evidence of a principal fork is two commits signed under the principal's
keys that reference the same `pre`, together with the state they both
extend. Anyone holding it checks it by replaying each commit from that
state. No server signature takes part in it, so it convicts no server.

```claim
kind: requirement
evaluator: test
```

### [arch-both-branches-kept]

A peer that learns of a principal fork keeps both branches and the
evidence, and shares them with any party that asks. It drops neither
branch and picks neither. Until the principal resolves the fork, it does
not present either branch as the principal's state: the principal's
consensus state is Error (SPEC §15.8). A peer may refuse further writes
for that principal; it keeps serving both branches and the evidence.

The server meets this: it refuses the second branch as the tip (`409`),
keeps it as a verified branch within a per-key quota, and serves both
branches at `GET /evidence`.

```claim
kind: requirement
evaluator: test
```

### [arch-evidence-is-portable]

Evidence verifies offline. A party that trusts neither the server nor
whoever collected the evidence checks it from the evidence alone, plus the
chain it names. A server's published key is a hint toward that chain,
not a substitute for replaying it. No verdict depends on a server's
cooperation or on anyone's word.

```claim
kind: requirement
evaluator: test
```

### [arch-principal-resolves]

Only the principal resolves its own fork, by one of the two acts SPEC
§15.8 names: a new commit whose `pre` is the tip of the chosen branch,
or a `resync/create` proof of possession re-asserting a tip. The
implementation takes both. A new commit resolves a fork only when it
leaves exactly one branch extended; a fork whose branches both have a
commit over them stays in Error at any heights. A proof of possession
is a coz of typ `<authority>/cyphr/resync/create`, signed by one key
active at the tip it names, with `now` required. At a contest the walk
follows the one child whose subtree holds an asserted tip, so a later
extension of the abandoned branch does not re-open the fork; proofs
into two children leave the principal in Error for good, and only
recovery ends it. A proof at or below the fork point changes nothing.
An abandoned branch extended after a commit resolution does re-open the
fork (`rs/cyphr/src/resync.rs`, `assessment` in `rs/cyphr/src/fork.rs`).
No server,
witness or verifier resolves a fork, and none chooses a branch on the
principal's behalf. After a resolution a verifier's verdict follows the
chosen branch, names the key that signed the resolution, and keeps the
abandoned branch as proof of error.

Resolution is checked by signature, not by identity. When a fork traces
back to a compromised key, whoever holds that key can sign a resolution
as validly as the owner can. That gap is closed outside detection, by
revoking the key and recovering the principal
([SPEC §14](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#14-recovery)).

```claim
kind: requirement
evaluator: test
```

### [arch-signing-stays-stateless]

Signing a tip report or commit receipt needs nothing from fork
bookkeeping: no stored evidence, no comparison, no record of prior
findings. A server produces the same valid signature whether or not it
holds evidence about the principal. The receipts specification states
issuance as stateless.

```claim
kind: requirement
evaluator: test
```

## Open questions for the spec author

These need a ruling in SPEC and are not decided here:

1. [SPEC §13.5.1](https://github.com/Cyphrme/Cyphr/blob/be0663f58086ac20131cc16a14944cf96c025609/SPEC.md#1351-witness-registration)
   has the principal sign a witness-registration message. Under this
   model a verifier chooses its own peers, and the server implements no
   registration. Does §13.5.1 stay in the protocol?
2. §15.7.1's "rejection of both branches until resolved" is read here
   as "neither branch is accepted as the principal's state", while both
   are kept and shared as proof of error (§15.2, §15.8). Is that the
   intended reading?
3. If a verifier holds two branches that each carry a resolution signed
   by an active key, does the principal stay in Error?
4. Is a server's view of a principal (today the server-defined tip
   report, `typ` `cyphr-server/receipt/tip`) a protocol object, or
   implementation detail?
