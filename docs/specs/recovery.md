# SPEC: Recovery and Account Freeze

<!--
  SPEC document produced by /spec Apply mode.
  Source: SPEC.md §18
  Authority: SPEC.md (Zamicol and nrdxp) — this document does NOT replace SPEC.md.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Cyphr recovery mechanisms — self-recovery, external
recovery (social recovery, third-party services), account freeze/unfreeze,
and retroactivity constraints. Recovery is the set of mechanisms for regaining
control of a principal when keys are lost, compromised, or inaccessible.

**Target System:** `SPEC.md` §18 (Recovery).

**Model Reference:**
[`principal-state-model.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphr/docs/models/principal-state-model.md)

**Criticality Tier:** High — recovery errors can permanently lock users out of
their identities or allow unauthorized parties to take over accounts.

**Cross-references:**
[`principal-lifecycle.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphr/docs/specs/principal-lifecycle.md)
— lifecycle states affected by recovery.
[`transactions.md`](file:///var/home/nrd/git/github.com/Cyphrme/Cyphr/docs/specs/transactions.md)
— key lifecycle transactions used in recovery.

## Constraints

### Invariants

#### Unrecoverable State

**[unrecoverable-definition]**: A principal is unrecoverable when: (1) no useful
active keys remain, (2) no designated recovery agents or fallback mechanisms are
present or able to act, (3) AR cannot be mutated, and (4) recovery is impossible
within the protocol (requires sideband intervention). All four conditions MUST
hold for the state to be classified as unrecoverable. Note: some data actions
MAY still be possible even in an unrecoverable state (SPEC.md §2.2.11).

> **Note:** "Unrecoverable" is a **descriptive classification** for human
> operators, not a protocol state flag that gates recovery transactions. Per
> SPEC.md §18.4.1, "the unrecoverable state may not be definitively known or
> verifiable by the protocol." Witnesses MUST accept valid recovery signatures
> from designated recovery agents regardless of whether the principal is
> considered unrecoverable.

`VERIFIED: agent-check — updated 2026-03-09 per A-5`

**[recovery-proactive]**: Self-recovery mechanisms MUST be established before
key loss or revocation. None of the protocol's recovery mechanisms can prevent
or reverse an unrecoverable state once it has occurred.
`VERIFIED: agent-check`

**[level-recovery-matrix]**: Recovery support by level:

- Level 1: No recovery. Sideband only.
- Level 2: Recovery via atomic swap (`key/replace`) only.
- Level 3+: Full recovery (can add new keys via `key/create`).
  `VERIFIED: agent-check`

#### Fallback

**[fallback-field]**: For single-key accounts, a `fallback` field MAY be
included at key creation to designate a recovery key. The `fallback` value is
`tmb` (Level 2) or external principal `PR` (Level 3+).
`VERIFIED: agent-check`

**[fallback-not-in-tmb]**: The `fallback` field MUST NOT be included in the
`tmb` calculation. This allows changing the fallback without changing the key's
identity.
`VERIFIED: agent-check`

**[level-2-fallback-restriction]**: Level 2 fallback MUST adhere to atomic swap
(`key/replace`) semantics. The fallback key replaces the lost key rather than
adding via `key/create`.
`VERIFIED: agent-check`

#### Recovery Agents

**[recovery-agent-registration]**: Recovery agents MUST be registered via
`cyphr/recovery/create` transaction, which includes `agent` (PR, tmb, or
array of contact PRs) and `threshold` (M-of-N, default 1).
`VERIFIED: agent-check`

**[recovery-agent-deletion]**: Recovery agents MAY be removed via
`recovery/delete`. After deletion, the agent MUST NOT be able to initiate
recovery.
`VERIFIED: agent-check`

**[recovery-agent-authorization]**: A designated recovery agent's `key/create`
MUST be accepted as valid even though no regular user key signed it — the
agent's authority derives from the `recovery/create` delegation.
`VERIFIED: agent-check`

#### Social Recovery

**[social-recovery-threshold]**: Social recovery requires M-of-N trusted
contacts to sign the same `key/create` transaction. When the threshold number
of signatures is collected, the transaction MUST be considered valid.
`VERIFIED: agent-check`

#### Freeze

**[freeze-global]**: Freeze MUST be global — it applies to the principal across
all services that observe the freeze state. Freezes halt all key mutations
(`key/*`) and MAY restrict other actions per service policy.
`VERIFIED: agent-check`

**[self-freeze]**: A principal MAY initiate a freeze by signing
`cyphr/freeze/create`. Self-freeze MAY be unfrozen by any active key.
`VERIFIED: agent-check`

**[external-freeze]**: A designated recovery authority MAY initiate a freeze
based on heuristics or out-of-band communication. External freeze requires the
recovery authority to thaw (or the principal after a configured timeout).
`VERIFIED: agent-check`

**[external-freeze-delegation]**: External freeze authority MUST be explicitly
delegated via `cyphr/recovery/create`. Without delegation, an external party
MUST NOT be able to freeze a principal.
`VERIFIED: agent-check`

#### Retroactivity

**[no-retroactive-undo]**: Cyphr does not support retroactivity (undoing
past actions to a given timestamp). Principals MUST mutate their state forward
using `create` and `delete` verbs to reach their targeted state. Past actions
MUST NOT be undone.
`VERIFIED: agent-check`

**[revoke-forward-only]**: Even though `key/revoke` can be postdated to the
time of an attack via `rvk`, Cyphr MUST interpret transactions based on
current `now`, not `rvk`. `rvk` is a declaration of compromise, not a request
for history rewriting.
`VERIFIED: agent-check`

**[disown-no-ar-mutation]**: A client MAY mark past actions as disowned
(expressing intent that the action was unintentional), but disowning MUST NOT
mutate AR. Disowning is bookkeeping only.
`VERIFIED: agent-check`

### Transitions

**[recovery-flow]**: The recovery flow MUST follow: (1) user generates a new
key/account, (2) user contacts recovery agent out-of-band, (3) agent verifies
identity (method varies), (4) agent signs `key/create` for the new key,
referencing `pre` = targeted PR.

- **PRE**: Principal is unrecoverable or compromised. Recovery agent is
  registered.
- **POST**: New key is added to KT. Principal transitions from Dead/Zombie
  to Active.
  `VERIFIED: agent-check`

**[freeze-transition]**: Account freeze transitions the principal from Active
to Frozen. All mutations are rejected until unfreeze.

- **PRE**: Principal is Active. Signing key MUST be active (or recovery
  authority with delegation).
- **POST**: `IsFrozen` = true.
  `VERIFIED: agent-check`

**[unfreeze-transition]**: `cyphr/freeze/delete` removes the freeze.

- **PRE**: Principal is Frozen.
- **POST**: `IsFrozen` = false. Principal returns to Active (if keys meet
  thresholds).
  `VERIFIED: agent-check`

### Forbidden States

**[no-retroactive-rewrite]**: History MUST NOT be rewritten through
retroactivity. The retrospection attack (attacker uses retroactivity to undo
legitimate actions) MUST be prevented by the forward-only mutation model.
`VERIFIED: agent-check`

**[no-unregistered-recovery]**: A party not registered via
`cyphr/recovery/create` MUST NOT be able to sign recovery transactions.
Attempts MUST fail with `RECOVERY_NOT_DESIGNATED`.
`VERIFIED: agent-check`

**[no-undelegated-freeze]**: An external party without explicit delegation MUST
NOT be able to freeze a principal (per [external-freeze-delegation]).
`VERIFIED: agent-check`

> [!NOTE]
> **PLACEHOLDER — Recovery Timelocks (Level 5+)**: SPEC.md §18.10 mentions
> recovery can have a "mandatory waiting period" (timelock) at Level 5+. The
> mechanics of timelocked recovery (how long, who sets it, interaction with
> freeze) are not fully specified. Deferred until Rule Root (RR) is
> formalized.

### Behavioral Properties

**[recovery-sovereignty]**: Recovery is designed to preserve self-sovereignty.
Self-recovery via backup keys, paper wallets, hardware keys, or airgapped
storage is the primary mechanism. External recovery delegates trust but remains
under the principal's control (via explicit delegation).

- **Type**: Design Property
  `VERIFIED: agent-check`

**[freeze-defensive]**: Freeze is a defensive mechanism for suspected compromise
scenarios. It is designed to stop the damage window while the principal
investigates, without irreversibly revoking keys.

- **Type**: Design Property
  `VERIFIED: agent-check`

## Formal Specification

<!-- Tier 2+ formalization is structured for but not populated in this pass. -->

## Verification

| Constraint                     | Method      | Result | Detail                                    |
| :----------------------------- | :---------- | :----- | :---------------------------------------- |
| [unrecoverable-definition]     | agent-check | pass   | SPEC.md §18, §2.2.11 (data action caveat) |
| [recovery-proactive]           | agent-check | pass   | Explicit in SPEC.md §18                   |
| [level-recovery-matrix]        | agent-check | pass   | Explicit in SPEC.md §18.2                 |
| [fallback-field]               | agent-check | pass   | Explicit in SPEC.md §18.4                 |
| [fallback-not-in-tmb]          | agent-check | pass   | Explicit in SPEC.md §18.4                 |
| [level-2-fallback-restriction] | agent-check | pass   | Explicit in SPEC.md §18.4                 |
| [recovery-agent-registration]  | agent-check | pass   | Explicit in SPEC.md §18.5.1               |
| [recovery-agent-deletion]      | agent-check | pass   | Explicit in SPEC.md §18.5.2               |
| [recovery-agent-authorization] | agent-check | pass   | Explicit in SPEC.md §18.6                 |
| [social-recovery-threshold]    | agent-check | pass   | Explicit in SPEC.md §18.8                 |
| [freeze-global]                | agent-check | pass   | Explicit in SPEC.md §18.9                 |
| [self-freeze]                  | agent-check | pass   | Explicit in SPEC.md §18.9.1               |
| [external-freeze]              | agent-check | pass   | Explicit in SPEC.md §18.9.2               |
| [external-freeze-delegation]   | agent-check | pass   | Explicit in SPEC.md §18.10                |
| [no-retroactive-undo]          | agent-check | pass   | Explicit in SPEC.md §18.12                |
| [revoke-forward-only]          | agent-check | pass   | Explicit in SPEC.md §18.12                |
| [disown-no-ar-mutation]        | agent-check | pass   | Explicit in SPEC.md §18.12                |
| [recovery-flow]                | agent-check | pass   | Explicit in SPEC.md §18.6                 |
| [freeze-transition]            | agent-check | pass   | Follows from §18.9                        |
| [unfreeze-transition]          | agent-check | pass   | Follows from §18.9.3                      |
| [no-retroactive-rewrite]       | agent-check | pass   | Follows from §18.12                       |
| [no-unregistered-recovery]     | agent-check | pass   | Follows from §18.5                        |
| [no-undelegated-freeze]        | agent-check | pass   | Follows from §18.10                       |
| [recovery-sovereignty]         | agent-check | pass   | Explicit in §18 design intent             |
| [freeze-defensive]             | agent-check | pass   | Explicit in §18.9 design intent           |

## Implications

### For Implementation (`/core`)

- **Recovery agent authority**: When evaluating a `key/create` signed by a non-
  member key, implementations must check whether the signer is a registered
  recovery agent. This is a special case in the authorization pipeline.
- **Fallback outside tmb**: The `fallback` field must be excluded from
  thumbprint computation — implementations must be careful not to include it.
- **Freeze is a state flag**: Freeze does not modify KR or AR directly — it sets
  a condition flag that gates all mutations. This is distinct from key lifecycle
  operations.
- **Forward-only mutations**: No undo, no rollback. The implementation must
  never provide a "revert to previous state" operation.

### For Testing

- **Recovery agent round-trip**: Register agent → lose all keys → agent signs
  key/create → verify principal is Active again.
- **Social recovery threshold**: 3-of-5 contacts sign → verify at exactly 3
  (passes) and 2 (rejects).
- **Freeze/unfreeze**: Self-freeze, external freeze, self-unfreeze, verify
  external freeze requires authority to thaw.
- **Fallback exclusion from tmb**: Create key with fallback, verify tmb is
  unchanged with and without fallback field.
- **Retroactivity prevention**: Attempt to undo a past action and verify it
  is rejected.

### Deferred Specifications (Level 6+)

> **Design Pending**: The exact implementation mechanisms for recovery validity checks, external freeze timeouts, and "action/disown" primitives are currently deferred. These components fall under Level 6 functionality (or potentially Level 5 if rule weights dictate them), and will be formalized when the specification expands beyond Level 4 structures.
