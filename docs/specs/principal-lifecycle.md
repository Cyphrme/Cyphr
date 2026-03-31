# SPEC: Principal Lifecycle and Feature Levels

<!--
  SPEC document produced by /spec Apply mode.
  Source: SPEC.md §3, §11, §19
  Authority: SPEC.md (Zamicol and nrdxp) — this document does NOT replace SPEC.md.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Cyphrpass principal lifecycle — the feature levels that
determine capability, the lifecycle states a principal can occupy, and the
principal-level operations (close, merge, fork) that alter identity.

**Target System:** `SPEC.md` §3 (Feature Levels), §11 (Principal Lifecycle
States), §19 (Close, Merge, Fork).

**Model Reference:**
[`principal-state-model.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/models/principal-state-model.md)

**Criticality Tier:** High — lifecycle state errors can permanently lock users
out of their identities.

**Cross-references:**
[`transactions.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/specs/transactions.md)
— transaction semantics that produce lifecycle transitions.
[`state-tree.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/specs/state-tree.md)
— state computation underlying level-dependent structures.

## Constraints

### Type Declarations

```
TYPE Level          = 1 | 2 | 3 | 4 | 5 | 6
TYPE LifecycleState = Active | Frozen | Deleted | Zombie | Dead | Nuked
TYPE ErrorFlag      = Boolean                              -- orthogonal to base state

-- Lifecycle conditions (derived from state)
TYPE CanMutateAR    = Boolean   -- keys meet threshold to mutate Auth Root
TYPE HasActiveKeys  = Boolean   -- ≥1 active (non-revoked, non-deleted) key
TYPE CanDataAction  = Boolean   -- Level 4+, active key exists
TYPE IsFrozen       = Boolean   -- freeze/create active, freeze/delete not signed
TYPE IsDeleted      = Boolean   -- principal/delete signed
TYPE IsErrored      = Boolean   -- fork detected or chain invalid
```

### Invariants

#### Feature Level Capabilities

**[level-1-static]**: A Level 1 principal MUST have exactly one key that never
changes. No commit chain exists. `tmb` == KR == AR == SR == PR == PG via
implicit promotion. Level 1 does not have a commit chain.
`VERIFIED: agent-check — updated 2026-03-09 per B-2, SPEC §3.1/§5.1`

**[level-2-single-key]**: A Level 2 principal MUST have exactly one active key
at any time. Key changes are performed via `key/replace` (atomic swap) only.
No commit chain exists. `tmb` == KR == AR == SR == PR == PG via implicit
promotion. Level 2 does not have a commit chain.
`VERIFIED: agent-check — updated 2026-03-09 per B-2, SPEC §3.2/§5.1`

**[level-3-multi-key]**: A Level 3+ principal MUST support multiple concurrent
keys. PR = MR(SR, CR). Initial PR equals PG.
Any active key MAY perform `key/create`, `key/delete`, or `key/revoke` on any
other key (subject to Level 5+ rules).
`VERIFIED: agent-check — updated 2026-03-09 per A-3, SPEC §3.3`

**[level-4-data-tree]**: A Level 4+ principal MUST support Data Tree (DT) for
user actions. Data actions (AAA) are recorded in DT and signed by active keys.
`VERIFIED: agent-check`

**[level-not-authorization]**: Principal levels describe state composition
complexity and MUST NOT be used as an authorization input. Authorization is
determined by which state components exist and what rules govern them (per
`transactions.md` [authorization-triple], SPEC.md §3).
`VERIFIED: agent-check — citation updated 2026-03-09 per A-1`

#### Lifecycle State Definitions

**[lifecycle-derived-from-state]**: A principal's lifecycle state MUST be
deterministically derived from the following conditions: `IsDeleted`,
`IsFrozen`, `CanMutateAR`, `HasActiveKeys`, `CanDataAction`. No additional
inputs determine lifecycle state.
`VERIFIED: agent-check`

**[lifecycle-state-matrix]**: The mapping from conditions to base states MUST be:

| State       | IsDeleted | IsFrozen | CanMutateAR | HasActiveKeys               | CanDataAction |
| :---------- | :-------- | :------- | :---------- | :-------------------------- | :------------ |
| **Active**  | false     | false    | true        | true                        | —             |
| **Frozen**  | false     | true     | true        | true                        | —             |
| **Deleted** | true      | false    | —           | —                           | —             |
| **Zombie**  | false     | —        | false       | —                           | true          |
| **Dead**    | —         | —        | false       | false                       | false         |
| **Nuked**   | true      | —        | —           | false (all revoked/deleted) | —             |

`VERIFIED: agent-check`

**[errored-orthogonal]**: The `Errored` flag MUST be orthogonal to the base
lifecycle state. Any base state (Active, Frozen, Deleted, Zombie, Dead, Nuked)
MAY simultaneously be errored. `Errored` indicates fork detection or chain
invalidity (see `consensus.md`).
`VERIFIED: agent-check`

**[deleted-frozen-exclusive]**: `Deleted` and `Frozen` MUST be mutually
exclusive. A principal MUST NOT be both frozen and deleted simultaneously.
`VERIFIED: agent-check`

**[canmutate-non-monotonic]**: At Level 5+, `CanMutateAR` is NOT monotonic in
key count. A principal with active keys MAY have `¬CanMutateAR` if no key
combination meets the threshold for AR mutation. Implementations MUST NOT assume
that having active keys implies the ability to mutate AR.
`VERIFIED: agent-check`

### Transitions

#### Close (Principal Delete)

**[principal-delete]**: `principal/delete` (Level 3+) permanently closes the
principal. This transition is irreversible.

- **PRE**: Principal is Active or Frozen. Signing key MUST be active.
- **POST**: `IsDeleted` = true. No transactions or actions (including data
  actions) are possible. PR MAY be reused for a new principal only if the keys
  were not revoked.
  `VERIFIED: agent-check`

**[nuke-sequence]**: To ensure no aspect of a deleted principal can be reused,
the recommended sequence is: revoke all keys, delete all keys, sign
`principal/delete`. This results in the **Nuked** state.

- **PRE**: Principal is Active or Frozen.
- **POST**: All keys revoked and deleted, `IsDeleted` = true. No key reuse
  is possible for new principals.
  `VERIFIED: agent-check`

#### Merge

**[merge-requires-ack]**: A principal merge MUST require acknowledgement from
the target principal. Without acknowledgement, external accounts could attack
by merging in their state (merge attack).

- **PRE**: Source signs `principal/merge` with `merge_to_pr` = target's PR.
- **POST**: Merge is not complete until target signs `principal/merge-ack`
  with `merge_from_pr` = source's PR.
  `VERIFIED: agent-check`

**[merge-implicit]**: Alternatively, an implicit merge MAY be performed where
the source deletes all keys and both principals add each other's PR.
`VERIFIED: agent-check`

**[merge-key-transfer]**: If the target wants to reuse keys from the source,
it MUST explicitly add them via `key/create`. Key transfer is not automatic in
a merge.
`VERIFIED: agent-check`

#### Fork

**[fork-creates-new-pg]**: `principal/fork/create` (Level 3+) creates a new
principal from an existing one. The forked principal MUST have a new, distinct
PG. At least one key MUST be added to the forked principal.

- **PRE**: Source principal is Active. Signing key MUST be active on source.
- **POST**: New principal exists with its own PR and commit chain. Source
  principal is unaffected (its PR and state are preserved).
  `VERIFIED: agent-check`

**[fork-equivalent-to-genesis]**: The fork transaction bundle MUST be
equivalent to a genesis transaction — it establishes a new PG via the same
bootstrap model.
`VERIFIED: agent-check`

**[key-sharing-across-principals]**: Nothing in the protocol prevents multiple
principals from sharing keys, as long as genesis does not result in the same
PR. Any set of non-revoked keys MAY be used to create a new PG.
`VERIFIED: agent-check`

#### Freeze

**[freeze-blocks-mutations]**: When a principal is Frozen (`freeze/create`
signed, `freeze/delete` not signed), all mutations MUST be rejected until
the principal is unfrozen.

- **PRE**: Principal is Active. Signing key MUST be active.
- **POST**: `IsFrozen` = true. No mutations permitted.
  `VERIFIED: agent-check`

**[unfreeze]**: `freeze/delete` removes the freeze. After unfreezing, the
principal returns to Active (assuming keys still meet mutation thresholds).

- **PRE**: Principal is Frozen. Signing key MUST be active.
- **POST**: `IsFrozen` = false.
  `VERIFIED: agent-check`

### Forbidden States

**[no-deleted-and-frozen]**: A principal MUST NOT be simultaneously Deleted and
Frozen (per [deleted-frozen-exclusive]).
`VERIFIED: agent-check`

**[no-transactions-on-deleted]**: A Deleted principal MUST NOT accept any new
transactions or actions, including data actions. Any such attempt MUST be
rejected.
`VERIFIED: agent-check`

**[no-mutations-on-frozen]**: A Frozen principal MUST NOT accept any mutations
until unfrozen. Freeze is a full stop on all state changes.
`VERIFIED: agent-check`

**[no-level-1-recovery]**: A Level 1 principal that self-revokes MUST NOT have
a protocol-level recovery path. The result is permanent DEAD state. Recovery
requires sideband intervention.
`VERIFIED: agent-check`

> [!NOTE]
> **PLACEHOLDER — Level 5 Rules**: SPEC.md §10 describes Rule Root (RR) with
> weighted keys and timelocks (`CanMutateAR` depends on weight thresholds at
> Level 5+). The rules mechanics are in preview and not yet stable for full
> formalization. Key constraints: each key has weight (default 1), actions need
> threshold weight, timelocks may delay effects.

> [!NOTE]
> **PLACEHOLDER — Level 6 Programmable VM**: SPEC.md §3.6 describes Level 6
> (executable bytecode in RT, deterministic VM execution). This is
> research-stage and not implementation-ready.

### Behavioral Properties

**[lifecycle-deterministic]**: Given identical state conditions, the computed
lifecycle state MUST be identical across all implementations. The lifecycle is
a pure function of the condition set.

- **Type**: Safety
  `VERIFIED: agent-check`

**[delete-irreversible]**: Once `IsDeleted` = true, the principal MUST NOT
return to any non-deleted state. Deletion is a terminal, irreversible
transition.

- **Type**: Safety
  `VERIFIED: agent-check`

**[dead-terminal]**: The Dead state (¬HasActiveKeys, ¬CanDataAction) is
terminal absent recovery mechanisms. No protocol-level operation can restore
keys once all are revoked/deleted and no recovery path exists.

- **Type**: Safety
  `VERIFIED: agent-check`

## Formal Specification

<!-- Tier 2+ formalization is structured for but not populated in this pass. -->

## Verification

| Constraint                      | Method      | Result | Detail                               |
| :------------------------------ | :---------- | :----- | :----------------------------------- |
| [level-1-static]                | agent-check | pass   | SPEC.md §3.1, §5.1 (no chain)        |
| [level-2-single-key]            | agent-check | pass   | SPEC.md §3.2, §5.1 (no chain)        |
| [level-3-multi-key]             | agent-check | pass   | SPEC.md §3.3 (CR/PR formulas)        |
| [level-4-data-tree]             | agent-check | pass   | Explicit in SPEC.md §3.4             |
| [level-not-authorization]       | agent-check | pass   | SPEC.md §3 (relocated from §2.3.3)   |
| [lifecycle-derived-from-state]  | agent-check | pass   | Explicit in SPEC.md §11              |
| [lifecycle-state-matrix]        | agent-check | pass   | Explicit in SPEC.md §11.2            |
| [errored-orthogonal]            | agent-check | pass   | Explicit in SPEC.md §11.1            |
| [deleted-frozen-exclusive]      | agent-check | pass   | Explicit in SPEC.md §11.2            |
| [canmutate-non-monotonic]       | agent-check | pass   | Explicit in SPEC.md §11.3            |
| [principal-delete]              | agent-check | pass   | Explicit in SPEC.md §19.1            |
| [nuke-sequence]                 | agent-check | pass   | Explicit in SPEC.md §19.1            |
| [merge-requires-ack]            | agent-check | pass   | Explicit in SPEC.md §19.2            |
| [merge-implicit]                | agent-check | pass   | Explicit in SPEC.md §19.2            |
| [merge-key-transfer]            | agent-check | pass   | Explicit in SPEC.md §19.2            |
| [fork-creates-new-pg]           | agent-check | pass   | Explicit in SPEC.md §19.3            |
| [fork-equivalent-to-genesis]    | agent-check | pass   | Explicit in SPEC.md §19.3            |
| [key-sharing-across-principals] | agent-check | pass   | Explicit in SPEC.md §19.3            |
| [freeze-blocks-mutations]       | agent-check | pass   | Inferred from SPEC.md §11.2, §18.9   |
| [unfreeze]                      | agent-check | pass   | Inferred from SPEC.md §11.2          |
| [no-deleted-and-frozen]         | agent-check | pass   | Explicit in SPEC.md §11.2            |
| [no-transactions-on-deleted]    | agent-check | pass   | Explicit in SPEC.md §19.1            |
| [no-mutations-on-frozen]        | agent-check | pass   | Explicit in SPEC.md §11.2            |
| [no-level-1-recovery]           | agent-check | pass   | Explicit in SPEC.md §3.1             |
| [lifecycle-deterministic]       | agent-check | pass   | Follows from condition-derived state |
| [delete-irreversible]           | agent-check | pass   | Explicit in SPEC.md §19.1            |
| [dead-terminal]                 | agent-check | pass   | Follows from §11.2, §11.3            |

## Implications

### For Implementation (`/core`)

- **Lifecycle state machine**: The [lifecycle-state-matrix] is directly
  implementable as a match/switch on the five boolean conditions. Both
  implementations should derive lifecycle state identically.
- **Non-monotonic CanMutateAR**: At Level 5+, implementations MUST NOT assume
  having keys → can mutate. Weight thresholds can make mutation impossible
  even with active keys.
- **Merge two-phase**: Merge is a two-principal operation — both must cooperate.
  Implementation needs cross-principal coordination.
- **Fork = genesis**: Fork reuses the genesis bootstrap pattern. Implementations
  should share codec/validation between genesis and fork.

### For Testing

- **Lifecycle state coverage**: Test all 6 base states × errored flag (12 combinations).
- **Level upgrade paths**: Verify state tree composition changes correctly
  when a principal transitions from Level 1→2→3→4.
- **Delete finality**: Verify no operation succeeds after `principal/delete`.
- **Freeze/unfreeze cycle**: Verify mutations are rejected during freeze and
  accepted after unfreeze.
- **Merge handshake**: End-to-end test with source merge → target merge-ack.

### Open Questions (for Zami / sketch)

1. **Zombie → Dead transition**: Can a Zombie principal (can do data actions but
   not mutate AR) become Dead? What triggers that transition — key revocation?
2. **Freeze scope**: Does freeze block data actions too, or only AT mutations?
   §11.2 says "no mutations" but the Frozen state shows `CanMutateAR=true` —
   does freeze override this?
3. **Fork PG derivation**: §19.3 shows fork creating a new PG but the `fork_pr`
   field in the example says "which in this case is just KR" — is this always
   the case, or does it depend on the fork's key set?
