# Constraint Coverage Matrix

Cross-reference of all 176 machine spec constraints against existing test coverage
(recomputed 2026-07-08: Transactions dropped from 49 to 48 tags after the
per-mutation-`pre` removal — see that section's note).

**Legend:**

- ✅ TESTED — Covered by existing `tests/intents/errors.toml` or `tests/e2e/error_conditions.toml`
- 🟡 TESTABLE — Reachable with current `OverrideIntent` fields or structural sequencing
- 🔶 NEEDS_OVERRIDE — Requires new `OverrideIntent` fields (Phase 2)
- ⬜ STRUCTURAL — Verified by state computation tests (golden fixtures)
- 🔵 RUNTIME — Behavioral/policy constraint; not a rejection test
- ⚪ OOS — Out of scope (Level 5+, consensus, recovery, not yet implemented)

---

## Transactions (48 constraints)

Re-audited 2026-07-08 against the current `transactions.md` (post
per-mutation-`pre` removal): `[transaction-pre-required]` and
`[commit-pre-chain]` no longer exist as tags — `pre` was removed from every
transaction-classified coz, so there is no `pre`-chaining constraint left to
test (their old evidence fixtures, `err_transaction_missing_pre` and
`pre_mismatch_fails`/`err_broken_chain`, no longer exist in the repo either).
`[transaction-classification]` is new — it replaces the old field-presence
discriminator with a `typ`-based one.

| Tag                             | Description                           | Status        | Evidence                                                                   |
| :------------------------------ | :------------------------------------ | :------------ | :------------------------------------------------------------------------- |
| `[coz-required-fields]`         | alg, tmb, now, typ required           | ⬜ STRUCTURAL | Implicitly tested by all golden fixtures                                   |
| `[transaction-classification]`  | Transaction vs. data action is by `typ`, not `pre` presence | ⬜ STRUCTURAL | `rs/cyphr-storage/src/import.rs::is_transaction_typ` |
| `[data-action-no-pre]`          | Actions must NOT have `pre`           | ✅ TESTED     | `error_conditions.toml:err_data_action_with_pre`                           |
| `[authorization-triple]`        | Antecedent (active-key) + lifecycle + capability gates, all three MUST hold | ⬜ STRUCTURAL | Covered by golden verification                                             |
| `[pre-mutation-key-rule]`       | Intra-commit: checked against live, incrementally-mutated key state as each tx applies; extra-commit: against last finalized commit only | ⬜ STRUCTURAL | Implicit in verification flow                                              |
| `[commit-append-only]`          | Commits immutable after publish       | 🔵 RUNTIME    | Policy constraint, not rejection                                           |
| `[commit-one-or-more]`          | Commit must have ≥1 coz               | ✅ TESTED     | `structural_constraints.toml:err_empty_commit`                             |
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
| `[revoke-naked]`                | SUPERSEDED — `pre`-presence no longer distinguishes a naked revoke (see transactions.md note); open question, not a tested constraint | 🔵 RUNTIME | Design guidance (stale)                                                    |
| `[revoke-self-signed]`          | Revoke must be self-signed            | ✅ TESTED     | `e2e:err_revoke_non_self` uses `[no-revoke-non-self]` tag                  |
| `[key-active-period]`           | Key active when rvk unset or > now    | ⬜ STRUCTURAL | Implicit in revocation logic                                               |
| `[data-action-stateless]`       | Actions are stateless                 | ⬜ STRUCTURAL | Verified by action tests                                                   |
| `[dr-inclusion]`                | DR requires ds/create                 | ⬜ STRUCTURAL | Verified by action golden                                                  |
| `[nonce-path]`                  | Nonce typ specifies tree path         | ⚪ OOS        | Level 5+                                                                   |
| `[no-orphan-pre]`               | Commit's arrow `pre` component must match the actual known PR (no per-mutation `pre` field remains — see transactions.md note) | ✅ TESTED | `rs/cyphr/tests/properties.rs` (arrow/CommitMismatch property tests); citation was stale (`errors.toml:pre_mismatch_fails` no longer exists) |
| `[no-unauthorized-transaction]` | Unknown signer rejected               | ✅ TESTED     | `errors.toml:unknown_key_fails`, `e2e:err_unknown_signer`                  |
| `[no-self-revoke-recovery]`     | L1 self-revoke = permanent            | ✅ TESTED     | `errors.toml:last_key_revoke_fails`                                        |
| `[no-revoke-non-self]`          | Revoke by non-self rejected           | ✅ TESTED     | `errors.toml:revoke_non_self_fails`, `e2e:err_revoke_non_self`             |
| `[intra-commit-ordering]`       | Commit order deterministic            | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[commit-deterministic]`        | Same cozies → same state              | ⬜ STRUCTURAL | Verified by golden fixtures                                                |
| `[genesis-irreversible]`        | PG immutable after genesis            | 🔵 RUNTIME    | Architectural invariant                                                    |
| `[revoke-propagation]`          | Revoke must be honored (description no longer conditions on `pre` presence) | 🔵 RUNTIME | Policy constraint                                                          |

### Transactions Summary

Recomputed 2026-07-08 by direct count of the table above (48 rows; the
prior counts here did not sum to the stated total even before the
per-mutation-`pre` removal, an independent staleness from the dead-tag
issue).

- ✅ TESTED: 13
- 🟡 TESTABLE: 0
- 🔶 NEEDS_OVERRIDE: 0
- ⬜ STRUCTURAL: 22 (verified by existing golden/state computation tests)
- 🔵 RUNTIME: 12 (policy/design constraints, not rejection tests)
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
| `[alg-alignment]`                   | ⬜ STRUCTURAL | Enforced by EMT (SPEC.md's current name; was "MALT") |
| `[digest-alg-from-coz]`             | ⬜ STRUCTURAL | Enforced by coz parsing                         |
| `[nonce-bit-length]`                | ⚪ OOS        | Level 5+                                        |
| `[nonce-indistinguishable]`         | ⚪ OOS        | Level 5+                                        |
| `[nonce-injection-bounds]`          | ⚪ OOS        | Level 5+                                        |
| `[mhmr-equivalence]`                | ⬜ STRUCTURAL | `multihash_coherence.toml`                      |
| `[implicit-promotion]`              | ⬜ STRUCTURAL | Verified by state computation                   |
| `[state-computation]`               | ✅ TESTED     | `state_computation.toml` (9 test cases)         |
| `[conversion]`                      | ⬜ STRUCTURAL | SUPERSEDED description — no per-child conversion step exists; see state-tree.md's resolution note (raw-byte fold under target alg, not per-child re-hash) |
| `[mhmr-computation]`                | ⬜ STRUCTURAL | `multihash_coherence.toml`                      |
| `[alg-set-evolution]`               | 🔵 RUNTIME    | Design guidance                                 |
| `[no-empty-mr]`                     | ✅ TESTED     | `structural_constraints.toml:err_empty_genesis` |
| `[no-circular-state]`               | 🔵 RUNTIME    | Architectural invariant                         |
| `[no-non-canonical-b64ut]`          | 🔵 RUNTIME    | Enforced by coz library                         |
| `[deterministic-state]`             | ✅ TESTED     | `edge_cases.toml:same_keys_different_order`     |
| `[promotion-recursive-termination]` | ⬜ STRUCTURAL | Implicit in EMT traversal (SPEC.md's current name; was "MALT") |
| `[mhmr-no-rehash-children]`         | ⬜ STRUCTURAL | `rs/cyphr/src/multihash.rs` (`MultihashDigest::arrow_component_bytes`); see state-tree.md's resolution note |

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

## Phase 1 Actionable Gaps — RESOLVED (2026-07-08)

This section listed 3 constraints as 🟡 TESTABLE gaps to close. All 3 are
now moot: `[revoke-self-signed]` and `[no-revoke-non-self]` are already
✅ TESTED per the Transactions table above (`e2e:err_revoke_non_self`,
`errors.toml:revoke_non_self_fails`); the third item's tag,
`[transaction-pre-required]`, no longer exists — `pre` was removed from
every transaction-classified coz (see the Transactions section note). No
open gap remains from this list.
