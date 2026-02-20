# MODEL: Cyphrpass Principal State

<!--
  Formal domain model of the Cyphrpass Principal, produced by the /model
  workflow in Apply mode against SPEC.md (Draft v0.1).

  See: .agent/workflows/model.md for the full protocol specification.
  See: .agent/personas/sdma.md for the applied modeling toolkit.
  See: .agent/axioms/formal-foundations.md for the mathematical foundations.
  See: .sketches/2026-02-13-spec-formal-model.md for the exploratory sketch.
-->

## Domain Classification

**Problem Statement:** Formalize the Cyphrpass principal's state space,
transition system, and multi-party protocols to expose gaps, ambiguities, and
unstated invariants in `SPEC.md` (Draft v0.1, 3182 lines).

**Source Document:** `SPEC.md` (Apply mode)

**Domain Characteristics:**

- **Evolving state with hidden variables** — a principal's internal state
  (key set, chain, data) is not fully observable; external parties see only
  the Merkle root (PS).
- **Multi-party protocols** — login, MSS synchronization, resync, and state
  jumping involve structured message exchange between clients, services, and
  witnesses.
- **Resource linearity** — keys are non-duplicable identities; revocation is
  permanent.
- **Hierarchical capability tiers** — six feature levels gate which state
  components exist and which operations are available.

---

## Formalism Selection

| Aspect                  | Detail                                                                                                                                                                   |
| :---------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Primary Formalism**   | Coalgebraic state machine                                                                                                                                                |
| **Supporting Tools**    | Session types, GADT (Curry-Howard)                                                                                                                                       |
| **Decision Matrix Row** | "Evolving state with hidden variables" → Coalgebra → Bisimilarity                                                                                                        |
| **Rationale**           | Principal behavior is observable but internal state is hidden (Merkle roots). Coalgebra is the natural model for systems characterized by observation, not construction. |

**Layering:** Session types (SDMA §4) are layered over the coalgebraic
base for multi-party protocol modeling. The lifecycle state model uses
GADTs (Curry-Howard from `formal-foundations.md`) to make invalid states
statically unrepresentable.

**Alternatives Considered:**

- **Ologs** — captures domain ontology but cannot express behavioral
  properties (transitions, guards, protocol sequencing). Deferred.
- **Linear Logic** — would surface resource linearity (key non-duplication)
  but coalgebra captured this via the state model. Not needed as primary.
- **Hyperdoctrines** — overkill for current constraint complexity.
  Level 5 rule system would benefit from this formalism in a future pass.

---

## Model

### 1. Coalgebraic Principal State Machine

#### 1.1 State Space

```
S = {
  KS    : Set(Key),         — Key State: set of active keys
  RS    : Set(Rule),         — Rule State: set of active rules (L5+)
  DS    : Bag(DataAction),   — Data State: mutable, application-agnostic
  Chain : Seq(Commit),       — Auth chain: append-only commit sequence
  PR    : Digest,            — Principal Root: genesis digest (immutable)
  Nonce : Set(Digest)        — Optional entropy values at any tree level
}

Key       = { pub: PublicKey, tmb: Digest, alg: Algorithm, rvk: Option(Timestamp) }
Commit    = { czds: Set(Digest), pre: Digest, cs: Digest, now: Timestamp }
```

**Derived quantities:**

```
as(s)    = MR(ks(s), rs(s)?)          — Auth State
cs(s)    = MR(as(s), commit_id)       — Commit State (post-mutation AS)
ps(s)    = MR(cs(s), ds(s)?, ...)     — Principal State
level(s) = see §1.3
life(s)  = see §1.2
```

#### 1.2 Lifecycle State

A principal's lifecycle is a product of two orthogonal components:

```
Lifecycle(s) = BaseState(s) × ErrorStatus(s)
```

`Errored` is an orthogonal flag — it annotates that something went wrong
(fork detected, chain invalid) but does not change which base state the
principal occupies. Any base state can be errored or non-errored.

**Condition channels** (each derived from state):

| Condition          | Definition                                          |
| :----------------- | :-------------------------------------------------- |
| `Errored(s)`       | Fork detected or chain invalid                      |
| `Deleted(s)`       | `principal/delete` transaction signed               |
| `Frozen(s)`        | `freeze/create` active ∧ `freeze/delete` not signed |
| `CanMutateAS(s)`   | Has keys meeting required thresholds to mutate AS   |
| `HasActiveKeys(s)` | `active_keys(s) ≠ ∅`                                |
| `CanDataAction(s)` | Can sign data actions (L4+, active key exists)      |

**Error status** (orthogonal to base state):

```
data ErrorStatus (s : State) where
  OK      : ¬Errored(s) → ErrorStatus s
  Errored : Errored(s)  → ErrorStatus s
```

**Base state** (GADT — invalid states are unconstructible):

```
data BaseState (s : State) where
  Active  : ¬Deleted(s) → ¬Frozen(s) → CanMutateAS(s)
            → HasActiveKeys(s) → BaseState s

  Frozen  : Frozen(s) → ¬Deleted(s) → CanMutateAS(s)
            → HasActiveKeys(s) → BaseState s

  Deleted : Deleted(s) → ¬Frozen(s) → BaseState s

  Zombie  : ¬CanMutateAS(s) → CanDataAction(s) → ¬Deleted(s)
            → BaseState s

  Dead    : ¬HasActiveKeys(s) → ¬CanDataAction(s) → BaseState s

  Nuked   : Deleted(s) → AllKeysRevokedOrDeleted(s) → BaseState s
```

**Refinement superstate** — `Unrecoverable` is a coarser observation for
when `CanDataAction` has not been determined:

```
data Unrecoverable (s : State) where
  MkUnrecoverable : ¬CanMutateAS(s) → ¬Deleted(s) → Unrecoverable s
  -- Refines to Zombie (CanDataAction) or Dead (¬CanDataAction)
```

In the observation lattice: `Unrecoverable ⊒ Zombie` and
`Unrecoverable ⊒ Dead`. An observer who can determine `CanDataAction` sees
the refined state; one who cannot sees `Unrecoverable`.

**Key properties:**

1. **`¬(Deleted ∧ Frozen)` is unconstructible** — no constructor accepts
   both proofs. Enforced by type structure, not runtime check.
2. **Nuked ⊂ Dead** — `Nuked` requires
   `Deleted ∧ AllKeysRevokedOrDeleted`, implying `¬HasActiveKeys ∧ ¬CanDataAction`.
3. **Product is total** — 6 base states × 2 error states = 12 combinations,
   all representable. No combinatorial explosion.
4. **Unrecoverable refines** — `Zombie ⊔ Dead = Unrecoverable` in the
   observation lattice. Classification is progressive, not all-or-nothing.

**Note:** `CanMutateAS` is not monotonic in key count at L5+. A principal
with active keys may still have `¬CanMutateAS` if no key combination meets
the threshold for AS mutation.

#### 1.3 Level Function

Cases are evaluated in priority order (first match wins):

```
level(s) =
  | 1  if  |s.KS| = 1  ∧  |s.Chain| = 0
  | 2  if  |s.KS| = 1  ∧  |s.Chain| ≥ 1
  | 3  if  |s.KS| > 1   ∧  s.RS = ∅  ∧  s.DS = ∅
  | 4  if  |s.KS| > 1   ∧  s.RS = ∅  ∧  s.DS ≠ ∅
  | 5  if  s.RS ≠ ∅
  | 6  if  s.RS ≠ ∅  ∧  has_advanced_features(s)
```

**Note:** A single-key principal with DS (`|KS| = 1 ∧ DS ≠ ∅`) matches L2,
not L4. This state is likely unreachable — DS requires L4+ per spec — but
the function is defined by priority order, not mutual exclusion.

**Level lattice:**

```
L1 ──→ L2 ──→ L3 ──→ L4 ──→ L5 ──→ L6    (upgrade: via state mutation)
                      │      │      │
                      └──────┴──────┘      (downgrade: L{4,5,6} → L3)
L1, L2: genesis-only; no return path
L3: floor for post-genesis principals
```

L4 → L3 is possible by clearing DS (data actions are mutable). L5 → L3 by
clearing RS + DS. The lattice is bidirectional above L3.

#### 1.4 Interface Functor

The principal coalgebra `(S, δ)` has interface functor:

```
F(X) = O × (Input → X + Error)
```

where `O` is the fixed observation type (digests, key sets, computed level
and lifecycle — see below). Observation is constant; it does not depend on
the type parameter.

**Observation:**

```
Obs(S) = {
  ps    : Digest,         — Principal State (Merkle root)
  as    : Digest,         — Auth State
  ks    : Set(Digest),    — active key thumbprints
  level : Level,          — computed
  life  : Lifecycle,      — computed
  tip   : Digest,         — latest CS
  pr    : Digest          — Principal Root (immutable)
}
```

**Input** (universal alphabet — not stratified by level):

```
Input = { key/create, key/delete, key/revoke, key/replace,
          principal/create, principal/delete,
          freeze/create, freeze/delete,
          data/*,           — stateless data actions
          rule/*,           — rule mutations (L5+)
          advanced/* }      — extensible (L6+)
```

Capability stratification belongs in the authorization predicate:

```
authorize(s, input) =
  signer(input).tmb ∈ active_keys(s)      — I1: pre-state key
  ∧ lifecycle_permits(life(s), input)      — lifecycle gate
  ∧ capability_permits(s, input)           — capability gate

where capability_permits(s, input) =
  | input ∈ {data/*}     → DS(s) exists
  | input ∈ {rule/*}     → RS(s) exists
  | input ∈ {advanced/*} → VM(s) exists
  | otherwise             → true
  ∧ rs_constraints(s, input)              — L5+ weight/timelock rules
```

#### 1.5 Transition Function

```
δ: S → F(S)
δ(s) = (observe(s), λ input.
  let auth = authorize(s, input) in
  if auth = Err(e) then Err(e)
  else
    let s' = apply(s, input) in
    let cs' = MR(as(s'), commit_id(input)) in
    (s' with { Chain = s.Chain ++ [commit(input, cs')] })
)
```

Authorization is evaluated against the **pre-state** — the signing key must
be active in `s`, not in `apply(s, input)`. The commit is atomic.

#### 1.6 Commit State Computation

```
CS_n = MR(AS_n, commit_id_n)

where:
  AS_n      = result of applying all transactions in commit_n to AS_{n-1}
  commit_id = MR(czd_1, czd_2, ..., czd_k)
  czd_i     = canonical digest of the i-th coz
```

AS computation is independent of CS. CS uses the **post-mutation** AS. No
circular dependency.

#### 1.7 `pre` Semantics

`pre` is always the digest of the previous Commit State (CS):

```
pre = digest of the previous CS
```

Due to implicit promotion, the _value_ of CS varies by level, but the
_semantic referent_ is always CS:

| Context                 | `pre` value    | Why                                    |
| :---------------------- | :------------- | :------------------------------------- |
| Genesis (L1/L2)         | `tmb`          | `tmb = KS = AS = CS` via promotion     |
| Genesis (L3+ bootstrap) | Incremental CS | AS = CS via promotion during bootstrap |
| Post-genesis (L3+)      | Previous CS    | Standard chain link                    |
| Naked revoke            | Omitted        | Only exception — explicitly optional   |
| Data actions            | N/A            | DS ops don't have `pre` (no chain)     |

**Naked revoke** is the only exception to the required `pre` rule. Data
actions do not participate in the commit chain and have no `pre` field.

#### 1.8 Observation Congruence (Promotion)

```
ps(s₁) = ps(s₂)  ⟹  s₁ ~_obs s₂
```

This is the **converse** of standard bisimulation: equal observations imply
behavioral equivalence (an observation-collapse, not an observation-
preservation property). Promotion intentionally collapses distinct internal
states into the same Merkle root. The observation functor is **not
injective** — this is a privacy property by design, but it means PS alone
is insufficient to reconstruct internal state.

---

### 2. Session Type Protocols

#### 2.1 Login (Challenge-Response)

```
LoginCR = Client ↔ Service where:

  Service → Client : Challenge(nonce: B256)
  Client → Service : Response(coz: SignedCoz {
    typ: "*/auth/login", tmb: Digest, challenge: B256
  })
  Service → Client : Result(
    | OK(token: BearerToken)
    | Err(InvalidSig | UnknownKey | ChallengeMismatch | KeyRevoked
         | PrincipalFrozen | PrincipalDeleted | PrincipalErrored)
  )
```

Login **must** reject non-Active principals. The `lifecycle_permits`
predicate from §1.4 applies — login is an authorization event.

#### 2.2 Login (Timestamp-Based)

```
LoginTS = Client ↔ Service where:

  Client → Service : LoginRequest(coz: SignedCoz {
    typ: "*/auth/login", tmb: Digest, now: Timestamp
  })
  Service → Client : Result(
    | OK(token: BearerToken)
    | Err(InvalidSig | UnknownKey | TimestampOutOfWindow | KeyRevoked
         | PrincipalFrozen | PrincipalDeleted | PrincipalErrored)
  )
```

One-round protocol (no challenge). Requires clock synchronization. Same
lifecycle gate as §2.1.

#### 2.3 MSS Synchronization

```
MSSSync = Client ↔ Service where:

  Client → Service : Tip(pr: Digest)
  Service → Client : TipResponse(
    | Synced(ps: Digest)
    | Behind(service_ps: Digest, client_ps: Digest)
    | Unknown(pr: Digest)
  )

  case Behind:
    Client → Service : Patch(delta: List(SignedCoz))
    Service → Client : PatchResult(
      | Applied(new_ps: Digest)
      | Rejected(reason: ChainBroken | InvalidSig | ForkDetected)
    )

  case ServiceAhead:
    Service → Client : PatchOffer(delta: List(SignedCoz))
    Client → Service : PatchAck(
      | Applied(new_ps: Digest)
      | Rejected(reason: ChainBroken | InvalidSig | ForkDetected)
    )
```

MSS is **bidirectional in state awareness** (both parties detect drift) but
**client-initiated in synchronization** (standard REST semantics).

#### 2.4 Resync

```
Resync = Witness ↔ Service where:

  Witness → Service : PatchRequest(
    from: Digest,          — trust anchor
    to: Option<Digest>     — target (None = tip)
  )
  Service → Witness : PatchResponse(
    | Delta(txs: List(SignedCoz))
    | AnchorUnknown(from: Digest)
    | NoPath(from: Digest, to: Digest)
  )

  Witness → (local) : Apply | Reject(reason: VerificationFailure)
```

**Fallback hierarchy** for `AnchorUnknown`:

1. Current trust anchor
2. Latest stored checkpoint
3. Genesis PR (always known — I3 guarantees this)
4. If genesis PR unknown → principal has no registration with service

Genesis PR is the universal fallback floor.

#### 2.5 State Jump

```
StateJump = Client ↔ Service where:

  Client → Service : JumpRequest(
    from: Digest, to: Digest, proof: JumpProof
  )
  Service → Client : JumpResponse(
    | Accepted(new_anchor: Digest, remaining_delta: List(SignedCoz))
    | Rejected(reason: InvalidJump | AnchorUnknown | ProofInvalid)
  )
```

State jumping composes with resync: `FullJump = StateJump ; Resync`.

---

### 3. Derived Invariants

These invariants are **consequences of the formal model**, not stated in the
spec. They should be confirmed and documented.

#### I1. Pre-State Authorization

```
∀ commit c, state s:
  valid(c, s) ⟹ signer(c).tmb ∈ active_keys(s)
```

The signing key must be active in the pre-state.

#### I2. Auth-State Monotonicity

```
∀ transition s → s':
  s.Chain ⊂ s'.Chain                    — commits never removed
  ∀ k ∈ s.KS: k.rvk = Some(_)
    ⟹ k ∈ s'.KS ∧ k.rvk = Some(_)    — revocations permanent
```

**AS/Chain is append-only. DS is not** — data actions can be deleted.

#### I3. PR Immutability

```
∀ transition s → s':
  pr(s) = pr(s')
```

The Principal Root is the genesis digest, preserved by all transitions
(coalgebraic coinvariant).

#### I4. Level Monotonicity (Partial)

```
∀ transition s → s':
  level(s) ∈ {1, 2} ⟹ level(s') ≥ level(s)    — L1/L2: up only
  level(s) ≥ 3      ⟹ level(s') ≥ 3            — floor at L3
  level(s) = 4      ⟹ level(s') ≥ 3            — L4 → L3 by clearing DS
  level(s) ∈ {5, 6} ⟹ level(s') ≥ 3            — L5/L6 → L3 by clearing RS+DS
```

#### I5. Observation Congruence

```
∀ s₁, s₂ ∈ S:
  ps(s₁) = ps(s₂) ⟹ s₁ ~_obs s₂
```

Promotion collapses distinct internal states into the same observable.
Privacy property — PS alone cannot reconstruct internal state.

#### I6. Fork Detection is Local

```
∀ witness w, state s:
  fork_detected(w, s) ⟺ ∃ c₁, c₂ ∈ observed(w):
    c₁.pre = c₂.pre ∧ c₁ ≠ c₂
```

Fork detection requires the witness to have seen both conflicting commits.
This is non-global — different witnesses may have different views.

---

### 4. AS/DS Duality

Auth State and Data State have fundamentally different properties:

| Property             | Auth State (AS/CS/Chain)        | Data State (DS)                   |
| :------------------- | :------------------------------ | :-------------------------------- |
| Mutability           | Append-only (immutable history) | Mutable (deletable content)       |
| Chain structure      | Hash-linked via `pre`           | No chain — ordered by `now`       |
| Verification         | Replay from genesis             | Point-in-time snapshot only       |
| Merkle computation   | Well-defined (§9)               | Stub (§4.2)                       |
| State type           | `Seq(Commit)` — monotonic       | `Bag(DataAction)` — non-monotonic |
| Prescribed semantics | Full protocol semantics         | None — application-defined        |

DS is a general-purpose data transaction ledger. Applications may impose
additional structure (including append-only chains) by referencing prior data
action digests in application-defined fields. The protocol does not mandate
any specific DS structure.

---

## Validation

### Internal Consistency

| Check                                          | Result  | Detail                                                    |
| :--------------------------------------------- | :------ | :-------------------------------------------------------- |
| Lifecycle — no invalid inhabitants             | PASS    | `¬(Deleted ∧ Frozen)` unconstructible by type structure   |
| Lifecycle — exhaustiveness                     | PASS    | 6 base states × 2 error states; product is total          |
| Level function — total, non-overlapping        | PARTIAL | L6 depends on undefined `has_advanced_features`           |
| Authorization predicate — well-defined         | PASS    | Three-part predicate is total and deterministic           |
| Transition function — pure                     | PASS    | `δ(s, input)` is a pure function                          |
| CS computation — acyclic                       | PASS    | No circular dependency                                    |
| Session type duality — all protocols terminate | PASS    | All 5 protocols terminate                                 |
| Session type branch completeness               | PASS    | Login includes lifecycle check; resync includes fallback  |
| Invariant I2 — AS-only monotonicity            | PASS    | Correctly captures AS/DS asymmetry                        |
| Observation congruence                         | PASS    | Promotion equivalence consistent with observation functor |
| `pre` semantics — consistent                   | PASS    | Always CS; promotion explains apparent variation          |

### External Adequacy

| Property            | Captured? | Detail                                               |
| :------------------ | :-------- | :--------------------------------------------------- |
| Principal lifecycle | ✓         | GADT with 9 constructors                             |
| Commit semantics    | ✓         | Pre-state auth, atomic transitions, CS order         |
| Level system        | ✓         | Universal input, level-gated auth, lattice           |
| Login protocol      | ✓         | Both variants with lifecycle rejection               |
| MSS protocol        | ✓         | Bidirectional awareness, unidirectional control      |
| Resync protocol     | ✓         | Fallback hierarchy with genesis PR floor             |
| State jumping       | ✓         | Composition with resync                              |
| `pre` semantics     | ✓         | Always CS; spec errata identified                    |
| DS semantics        | Partial   | Mutability captured; Merkle computation is spec stub |
| Recovery protocol   | ✗         | Not modeled — deferred                               |
| Level 5 rule system | ✗         | Needs constraint language formalism                  |
| Embedded principals | Partial   | Opaque-digest-at-boundary only                       |

### Minimality

The coalgebra + session types layering is minimal and sufficient. All
resolved issues were surfaced using only these two formalisms. The GADT
lifecycle refinement uses Curry-Howard from `formal-foundations.md` — the
natural extension when coalgebra reveals an under-constrained state space.

---

## Implications

### For the Spec

Seven remediation patches were drafted (see sketch `CONNECT` section):

1. **R1** (`pre` semantics) — Correct ~10 spec references from "AS" to "CS";
   add statement that `pre` is always CS; add missing `pre` at L500.
2. **R2** (lifecycle) — Replace narrative description in §10 with enumerated
   states and constraint table.
3. **R3** (level-gated auth) — Add authorization subsection to §3.
4. **R4** (login) — Mandate lifecycle check in §6.2.
5. **R5** (MSS) — Clarify "bidirectional" terminology in §10.1.
6. **R6** (resync fallback) — Document fallback hierarchy in §Consensus.
7. **R7** (AS/DS duality) — Add duality statement to §2 or §4.

### For Implementation

- The lifecycle GADT maps directly to a Rust `enum` or Go sum type via
  interface dispatch. Invalid states become unrepresentable in code.
- The authorization predicate (§1.4) is a composable three-part check
  suitable for middleware extraction.
- The level function (§1.3) is a pure computation suitable for property-based
  testing.
- AS/DS duality requires distinct storage strategies: append-only log for
  AS/Chain, mutable store for DS.

### For Testing

- **I1** (pre-state auth) — testable by attempting mutations with keys
  added/removed in the same commit.
- **I5** (observation congruence) — testable by constructing states with
  different internals that produce the same PS.
- **I6** (fork detection) — testable by presenting conflicting commits to
  witnesses with different observation histories.

### Open Questions

- **L6 boundary** — `has_advanced_features` is undefined. This blocks
  formalizing the L5→L6 transition.
- **Recovery protocol** — authority scope unbounded (deferred to
  implementation analysis).
- **DS Merkle computation** — spec stub (§4.2). Blocked on spec decision
  regarding ordering, deleted action handling, and checkpoint interaction.

### Mechanization Candidates

The following are candidates for mechanization in Lean 4:

- Lifecycle GADT → inductive type with dependent constructors
- I1 (pre-state auth) → lemma by case analysis
- I2 (AS monotonicity) → invariant by induction on chain
- I3 (PR immutability) → coinvariant by coinduction
- I5 (observation congruence) → requires observation relation proof
