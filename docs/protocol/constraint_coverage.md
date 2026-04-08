# Constraint Coverage Matrix

Cross-reference of all 177 machine spec constraints against existing test coverage.

**Legend:**

- ✅ TESTED — Covered by existing `tests/intents/errors.toml` or `tests/e2e/error_conditions.toml`
- 🟡 TESTABLE — Reachable with current `OverrideIntent` fields or structural sequencing
- 🔶 NEEDS_OVERRIDE — Requires new `OverrideIntent` fields (Phase 2)
- ⬜ STRUCTURAL — Verified by state computation tests (golden fixtures)
- 🔵 RUNTIME — Behavioral/policy constraint; not a rejection test
- ⚪ OOS — Out of scope (Level 5+, consensus, recovery, not yet implemented)

---

## Transactions (49 constraints)

| Tag                             | Description                           | Status        | Evidence                                                                   |
| :------------------------------ | :------------------------------------ | :------------ | :------------------------------------------------------------------------- |
| `[coz-required-fields]`         | alg, tmb, now, typ required           | ⬜ STRUCTURAL | Implicitly tested by all golden fixtures                                   |
| `[transaction-pre-required]`    | Mutations must have `pre`             | ✅ TESTED     | `authentication_constraints.toml:err_transaction_missing_pre`              |
| `[data-action-no-pre]`          | Actions must NOT have `pre`           | ✅ TESTED     | `error_conditions.toml:err_data_action_with_pre`                           |
| `[authorization-triple]`        | tmb+sig+pre triple                    | ⬜ STRUCTURAL | Covered by golden verification                                             |
| `[pre-mutation-key-rule]`       | Auth checked against pre-mutation KR  | ⬜ STRUCTURAL | Implicit in verification flow                                              |
| `[commit-append-only]`          | Commits immutable after publish       | 🔵 RUNTIME    | Policy constraint, not rejection                                           |
| `[commit-one-or-more]`          | Commit must have ≥1 coz               | ✅ TESTED     | `structural_constraints.toml:err_empty_commit`                             |
| `[commit-pre-chain]`            | All cozies in commit ref same `pre`   | ✅ TESTED     | `errors.toml:pre_mismatch_fails`, `error_conditions.toml:err_broken_chain` |
| `[txs-list-of-lists]`           | txs is list of lists                  | ⬜ STRUCTURAL | Enforced by TOML schema                                                    |
| `[tx-grouping]`                 | No interlacing mutations              | ⬜ STRUCTURAL | Enforced by commit batch API                                               |
| `[tx-root-computation]`         | TR = MR(czds)                         | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[tmr-computation]`             | TMR = MR(mutation czds)               | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[tcr-computation]`             | TCR = MR(commit czds)                 | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[tr-computation]`              | TR = MR(TMR, TCR, SR)                 | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[commit-finality-arrow]`       | Arrow finalizes commit                | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[arrow-excludes-self]`         | Arrow covers everything except itself | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[pr-after-commit]`             | PR recomputed after commit            | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[typ-grammar]`                 | typ format: `authority/noun/verb`     | 🔵 RUNTIME    | Format validation                                                          |
| `[typ-verbs]`                   | Standard verbs                        | 🔵 RUNTIME    | Format validation                                                          |
| `[idempotent-transactions]`     | Mutations idempotent                  | 🔵 RUNTIME    | Policy constraint                                                          |
| `[create-uniqueness]`           | Create enforces uniqueness            | ✅ TESTED     | `errors.toml:duplicate_key_fails`, `e2e:err_duplicate_key`                 |
| `[transaction-id-required]`     | `id` required in pay                  | ⬜ STRUCTURAL | Enforced by payload construction                                           |
| `[wire-format-plurals]`         | JSON uses plural names                | 🔵 RUNTIME    | Serialization convention                                                   |
| `[key-sideband-optional]`       | Key material via sideband             | 🔵 RUNTIME    | Design guidance                                                            |
| `[timestamp-range]`             | `now` positive integer < 2^53         | 🔵 RUNTIME    | Enforced by JSON number                                                    |
| `[at-append-only]`              | AT history append-only                | 🔵 RUNTIME    | Architectural invariant                                                    |
| `[dt-mutable]`                  | DT permits mutation                   | 🔵 RUNTIME    | Design guidance                                                            |
| `[genesis-bootstrap]`           | Genesis uses explicit key/create      | ⬜ STRUCTURAL | Verified by golden genesis tests                                           |
| `[genesis-pre-bootstrap]`       | Genesis has no prior PR               | ⬜ STRUCTURAL | Verified by genesis tests                                                  |
| `[genesis-finality]`            | Genesis includes principal/create     | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[key-create]`                  | key/create adds key to KT             | ✅ TESTED     | `mutations.toml`, `multi_key.toml`                                         |
| `[key-delete]`                  | key/delete removes key                | ✅ TESTED     | `mutations.toml:key_delete_decreases_count`                                |
| `[key-replace]`                 | key/replace atomic swap               | ✅ TESTED     | `mutations.toml:key_replace_maintains_count`                               |
| `[key-revoke]`                  | key/revoke self-declaration           | ✅ TESTED     | `mutations.toml:self_revoke_decreases_count`                               |
| `[naked-revoke-error]`          | Naked revoke → Dead/Errored           | ✅ TESTED     | `errors.toml:last_key_revoke_fails`                                        |
| `[revoke-naked]`                | Naked revoke may omit `pre`           | 🔵 RUNTIME    | Design guidance                                                            |
| `[revoke-self-signed]`          | Revoke must be self-signed            | ✅ TESTED     | `e2e:err_revoke_non_self` uses `[no-revoke-non-self]` tag                  |
| `[key-active-period]`           | Key active when rvk unset or > now    | ⬜ STRUCTURAL | Implicit in revocation logic                                               |
| `[data-action-stateless]`       | Actions are stateless                 | ⬜ STRUCTURAL | Verified by action tests                                                   |
| `[dr-inclusion]`                | DR requires ds/create                 | ⬜ STRUCTURAL | Verified by action golden                                                  |
| `[nonce-path]`                  | Nonce typ specifies tree path         | ⚪ OOS        | Level 5+                                                                   |
| `[no-orphan-pre]`               | pre must reference valid PR           | ✅ TESTED     | `errors.toml:pre_mismatch_fails`                                           |
| `[no-unauthorized-transaction]` | Unknown signer rejected               | ✅ TESTED     | `errors.toml:unknown_key_fails`, `e2e:err_unknown_signer`                  |
| `[no-self-revoke-recovery]`     | L1 self-revoke = permanent            | ✅ TESTED     | `errors.toml:last_key_revoke_fails`                                        |
| `[no-revoke-non-self]`          | Revoke by non-self rejected           | ✅ TESTED     | `errors.toml:revoke_non_self_fails`, `e2e:err_revoke_non_self`             |
| `[intra-commit-ordering]`       | Commit order deterministic            | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[commit-deterministic]`        | Same cozies → same state              | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[genesis-irreversible]`        | PG immutable after genesis            | 🔵 RUNTIME    | Architectural invariant                                                    |
| `[revoke-propagation]`          | Revoke must be honored                | 🔵 RUNTIME    | Policy constraint                                                          |

### Transactions Summary

- ✅ TESTED: 15 (+5: `[revoke-self-signed]`, `[no-revoke-non-self]`, `[transaction-pre-required]`, `[data-action-no-pre]`, `[commit-one-or-more]`)
- 🟡 TESTABLE: 0
- 🔶 NEEDS_OVERRIDE: 0
- ⬜ STRUCTURAL: 18 (verified by existing golden/state computation tests)
- 🔵 RUNTIME: 13 (policy/design constraints, not rejection tests)
- ⚪ OOS: 1

---

## Authentication (24 constraints)

| Tag                                 | Status        | Notes                              |
| :---------------------------------- | :------------ | :--------------------------------- |
| `[pop-via-signature]`               | ⬜ STRUCTURAL | Implicit in all sig verification   |
| `[pop-types]`                       | 🔵 RUNTIME    | Taxonomy, not testable             |
| `[login-challenge-response]`        | ⚪ OOS        | Service-side, not in core          |
| `[login-timestamp-based]`           | ⚪ OOS        | Service-side                       |
| `[login-lifecycle-gate]`            | ⚪ OOS        | Service-side                       |
| `[replay-prevention]`               | ⚪ OOS        | Service-side                       |
| `[bearer-token-service-signed]`     | ⚪ OOS        | Service-side                       |
| `[bearer-token-fields]`             | ⚪ OOS        | Service-side                       |
| `[embedding-weight-default]`        | ⚪ OOS        | Level 5+                           |
| `[embedding-cyclic-stop]`           | ⚪ OOS        | Level 5+                           |
| `[embedding-conjunctive-auth]`      | ⚪ OOS        | Level 5+                           |
| `[embedding-tip-retrieval]`         | ⚪ OOS        | Level 5+                           |
| `[embedding-pinning]`               | ⚪ OOS        | Level 5+                           |
| `[verification-replay]`             | ⬜ STRUCTURAL | Core of golden test flow           |
| `[verification-timestamp-order]`    | ✅ TESTED     | `errors.toml:timestamp_past_fails` |
| `[checkpoint-self-contained]`       | ⬜ STRUCTURAL | `e2e.rs:e2e_checkpoint_load`       |
| `[checkpoint-genesis-foundational]` | ⬜ STRUCTURAL | `e2e.rs:e2e_checkpoint_load`       |
| `[checkpoint-declarative]`          | ⚪ OOS        | Not implemented                    |
| `[mss-bidirectional]`               | ⚪ OOS        | Architecture guidance              |
| `[mss-push-on-mutation]`            | ⚪ OOS        | Service-side                       |
| `[no-login-non-active]`             | ⚪ OOS        | Service-side                       |
| `[no-unsigned-bearer]`              | ⚪ OOS        | Service-side                       |
| `[aaa-over-bearer]`                 | ⚪ OOS        | Design guidance                    |
| `[sso-without-centralization]`      | ⚪ OOS        | Design guidance                    |

### Authentication Summary

- ✅ TESTED: 1
- ⬜ STRUCTURAL: 3
- ⚪ OOS: 16 (mostly service-side or Level 5+)
- 🔵 RUNTIME: 1

---

## State Tree (21 constraints)

| Tag                                 | Status        | Notes                                           |
| :---------------------------------- | :------------ | :---------------------------------------------- |
| `[digest-encoding]`                 | ⬜ STRUCTURAL | All golden fixtures use b64ut                   |
| `[identifier-is-cid]`               | ⬜ STRUCTURAL | All identifiers are CIDs                        |
| `[mr-sort-order]`                   | ✅ TESTED     | `edge_cases.toml:key_thumbprint_sort_order`     |
| `[pg-immutable]`                    | 🔵 RUNTIME    | Architectural invariant                         |
| `[alg-alignment]`                   | ⬜ STRUCTURAL | Enforced by MALT                                |
| `[digest-alg-from-coz]`             | ⬜ STRUCTURAL | Enforced by coz parsing                         |
| `[nonce-bit-length]`                | ⚪ OOS        | Level 5+                                        |
| `[nonce-indistinguishable]`         | ⚪ OOS        | Level 5+                                        |
| `[nonce-injection-bounds]`          | ⚪ OOS        | Level 5+                                        |
| `[mhmr-equivalence]`                | ⬜ STRUCTURAL | `multihash_coherence.toml`                      |
| `[implicit-promotion]`              | ⬜ STRUCTURAL | Verified by state computation                   |
| `[state-computation]`               | ✅ TESTED     | `state_computation.toml` (9 test cases)         |
| `[conversion]`                      | ⬜ STRUCTURAL | Cross-alg conversion in MALT                    |
| `[mhmr-computation]`                | ⬜ STRUCTURAL | `multihash_coherence.toml`                      |
| `[alg-set-evolution]`               | 🔵 RUNTIME    | Design guidance                                 |
| `[no-empty-mr]`                     | ✅ TESTED     | `structural_constraints.toml:err_empty_genesis` |
| `[no-circular-state]`               | 🔵 RUNTIME    | Architectural invariant                         |
| `[no-non-canonical-b64ut]`          | 🔵 RUNTIME    | Enforced by coz library                         |
| `[deterministic-state]`             | ✅ TESTED     | `edge_cases.toml:same_keys_different_order`     |
| `[promotion-recursive-termination]` | ⬜ STRUCTURAL | Implicit in MALT traversal                      |
| `[mhmr-no-rehash-children]`         | ⬜ STRUCTURAL | Verified by MALT impl                           |

### State Tree Summary

- ✅ TESTED: 4 (+1: `[no-empty-mr]`)
- ⬜ STRUCTURAL: 10
- 🔶 NEEDS_OVERRIDE: 0
- 🔵 RUNTIME: 4
- ⚪ OOS: 3

---

## Principal Lifecycle (30 constraints)

| Tag                               | Status        | Notes                                            |
| :-------------------------------- | :------------ | :----------------------------------------------- |
| `[level-1-static]`                | ⬜ STRUCTURAL | `genesis_load.toml`                              |
| `[level-2-single-key]`            | ⬜ STRUCTURAL | `mutations.toml:key_replace`                     |
| `[level-3-multi-key]`             | ⬜ STRUCTURAL | `multi_key.toml`                                 |
| `[level-4-data-tree]`             | ⬜ STRUCTURAL | `actions.toml`                                   |
| `[level-not-authorization]`       | 🔵 RUNTIME    | Design guidance                                  |
| `[lifecycle-derived-from-state]`  | 🔵 RUNTIME    | Architectural constraint                         |
| `[lifecycle-state-matrix]`        | 🔵 RUNTIME    | State machine spec                               |
| `[errored-orthogonal]`            | ⚪ OOS        | Not yet implemented                              |
| `[zombie-state-bounds]`           | ⚪ OOS        | Not yet implemented                              |
| `[freeze-mutation-lockout]`       | ⚪ OOS        | Freeze not implemented                           |
| `[fork-pg-derivation]`            | ⚪ OOS        | Fork not implemented                             |
| `[deleted-frozen-exclusive]`      | ⚪ OOS        | Not implemented                                  |
| `[canmutate-non-monotonic]`       | ⚪ OOS        | Level 5+                                         |
| `[principal-delete]`              | ⚪ OOS        | Not implemented                                  |
| `[nuke-sequence]`                 | ⚪ OOS        | Not implemented                                  |
| `[merge-requires-ack]`            | ⚪ OOS        | Not implemented                                  |
| `[merge-implicit]`                | ⚪ OOS        | Not implemented                                  |
| `[merge-key-transfer]`            | ⚪ OOS        | Not implemented                                  |
| `[fork-creates-new-pg]`           | ⚪ OOS        | Not implemented                                  |
| `[fork-equivalent-to-genesis]`    | ⚪ OOS        | Not implemented                                  |
| `[key-sharing-across-principals]` | 🔵 RUNTIME    | Design guidance                                  |
| `[freeze-blocks-mutations]`       | ⚪ OOS        | Freeze not implemented                           |
| `[unfreeze]`                      | ⚪ OOS        | Freeze not implemented                           |
| `[no-deleted-and-frozen]`         | ⚪ OOS        | Not implemented                                  |
| `[no-transactions-on-deleted]`    | ⚪ OOS        | Not implemented                                  |
| `[no-mutations-on-frozen]`        | ⚪ OOS        | Not implemented                                  |
| `[no-level-1-recovery]`           | ✅ TESTED     | `errors.toml:last_key_revoke_fails` maps to this |
| `[lifecycle-deterministic]`       | ⬜ STRUCTURAL | Verified by golden                               |
| `[delete-irreversible]`           | ⚪ OOS        | Not implemented                                  |
| `[dead-terminal]`                 | ✅ TESTED     | `errors.toml:last_key_revoke_fails`              |

### Lifecycle Summary

- ✅ TESTED: 2
- ⬜ STRUCTURAL: 5
- 🔵 RUNTIME: 4
- ⚪ OOS: 19

---

## Consensus (28 constraints)

Almost entirely ⚪ OOS — consensus/witness protocol not yet implemented.

Notable exceptions:

- `[error-reject-atomic]` — ⬜ STRUCTURAL (enforced by commit batch API)
- `[error-codes-transaction]` — Partially ✅ TESTED (the error codes listed map to our tested errors)
- `[no-backward-timestamp]` — ✅ TESTED (`errors.toml:timestamp_past_fails`)
- `[no-partial-apply]` — ⬜ STRUCTURAL (commit batch atomicity)

---

## Recovery (25 constraints)

Entirely ⚪ OOS — recovery protocol not yet implemented at Level 1-4.

---

## Phase 1 Actionable Gaps (🟡 TESTABLE)

These constraints can be tested **right now** with existing infrastructure:

1. **`[revoke-self-signed]`** — Attempt `key/revoke` where the `signer` is a _different_ key than the target. Should fail with `UnknownKey` (signer can't revoke another key's thumbprint).
2. **`[no-revoke-non-self]`** — Same as above; enforcement overlap.
3. **`[transaction-pre-required]`** — Override `pre` to empty string. Should fail with `InvalidPrior`.

These 3 constraints map to 2 new test cases (revoke-non-self covers both revoke constraints).
