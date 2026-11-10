# SPEC conformance map

This page maps the normative statements of the protocol specification in
sections 2 through 12, 15.2, 15.8, 15.9, 17.2 and 19.5 to a test that fails
when the requirement breaks, and says plainly where no such test exists. It
covers those sections only: sections 13, 14, 15.1 and 15.3-15.7, 16, 17.1 and
17.3-17.5, 18 and 19.1-19.4 are outside it. It exists so a reader can answer
"is this requirement of the specification enforced, and what would tell us if
it stopped being?" without reading the test suite.

The source is `SPEC.md` as it stands at commit `be0663f` on the `zami`
branch, the spec author's branch, which governs. The copy of `SPEC.md` on the
integration branch has drifted from it; the rows where that matters are listed
under [Drift in the in-tree SPEC.md](#drift-in-the-in-tree-specmd).
This page never edits or reinterprets the specification: an ambiguous or
contradictory sentence is recorded as a question for the spec author, not
resolved.

## How to read a row

A row is one specification line, keyed by its line number at `be0663f`. Rows
come from two sources. `rule` rows are every line in the sections above that contains the
lowercase word `must`, `shall` or `never` (or the uppercase `MUST` or
`SHALL`); `rs/cyphr/tests/spec_conformance.rs` re-extracts them from the
specification and fails if a line has no row or a row has no line. The
keyword rule misses requirements phrased another way (the lifecycle table and
the fork-resolution prose use "rejects", "no mutations", "become permanently
invalid"), so `supplement` rows add those statements by hand; the same test
checks each supplement's quoted text sits on its line.

Each row carries one disposition:

| Disposition    | Meaning                                                                                      |
| :------------- | :------------------------------------------------------------------------------------------- |
| `covered`      | A test in the default suite fails when the requirement breaks.                               |
| `red-existing` | A test already written by an earlier node covers it and is ignored as red.                   |
| `red-new`      | Nothing covered it; a new test in this node's files fails today and is ignored as red.       |
| `not-testable` | No behaviour can fail for it today, with the reason stated (ambiguity, contradiction, none). |
| `out-of-scope` | Above Level 4, or with no implementation surface in the Rust crates.                         |

A red test is `#[ignore = "RED(<id>): SPEC <section>"]`. The map test also
checks each row against its tests' source: a `covered` row whose test is
ignored, or a red row with no ignored test, fails the check, so a row cannot
go stale when a fix lands. Each test name resolves in the named file; a
`[vector]` suffix names a golden vector under `tests/golden/`.

## Summary

| Disposition    | Rows |
| :------------- | ---: |
| `covered`      |   56 |
| `red-existing` |    0 |
| `red-new`      |    0 |
| `not-testable` |   11 |
| `out-of-scope` |    6 |
| `total`        |   73 |

## Rows

### [sc-l119]

SPEC 2.2.2, line 119. Disposition: `covered`.

- spec-line: 119
- source: supplement
- disposition: covered
- spec-text: base64 URL alphabet and encoding method, errors on non-canonical encodings, and
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s2_2_2_non_canonical_b64ut_is_rejected`
- fails when: a non-canonical b64ut spelling of a thumbprint is accepted as the same key (two valid spellings, two cozies).

```claim
kind: requirement
evaluator: test
```

### [sc-l127]

SPEC 2.2.3, line 127. Disposition: `covered`.

- spec-line: 127
- source: rule
- disposition: covered
- spec-text: object. Following Coz semantics, all digest identifiers inside a coz must
- tests:
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_algorithm_diversity[algorithm_diversity/ed25519_account_adds_es256_key]`
- fails when: a `key/create` of a key of another algorithm is rejected. Resolved: the sentence aligns digests with `alg` 'unless explicitly labeled'; a key's `tmb` is the digest under the key's own `alg` (Coz), so an Ed25519 coz introducing an ES256 key carries a SHA-256 `id`. The corpus vector is right and pins it.

```claim
kind: requirement
evaluator: none
```

### [sc-l129]

SPEC 2.2.3, line 129. Disposition: `covered`.

- spec-line: 129
- source: rule
- disposition: covered
- spec-text: the algorithm for the `id` of the new key must be `SHA256`, aligning with alg
- tests:
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_algorithm_diversity[algorithm_diversity/ed25519_account_adds_es256_key]`
- fails when: same sentence pair as line 127; the example is the same-algorithm case and the cross-algorithm vector pins the other.

```claim
kind: requirement
evaluator: none
```

### [sc-l203]

SPEC 2.2.13, line 203. Disposition: `covered`.

- spec-line: 203
- source: rule
- disposition: covered
- spec-text: made transparent. Public keys must be revealed for verification; embeddings,
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s2_2_13_key_create_without_revealed_pub_is_rejected`
- fails when: a `key/create` with no revealed `pub` is accepted, so a key becomes active that nothing can verify.

```claim
kind: requirement
evaluator: test
```

### [sc-l226]

SPEC 2.3.1, line 226. Disposition: `covered`.

- spec-line: 226
- source: rule
- disposition: covered
- spec-text: Cyphr requires specific Coz semantics. All cozies must have the fields:
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s2_3_1_coz_missing_tmb_now_or_typ_is_rejected`
  - `rs/cyphr/tests/spec_conformance.rs::s2_3_1_coz_missing_alg_is_rejected`
  - `rs/cyphr-server/tests/error_parity.rs::missing_alg_is_malformed_on_push_import_and_replay`
  - `rs/cyphr-server/tests/error_parity.rs::wrong_alg_is_alg_mismatch_on_push_and_import`
- fails when: a coz missing `tmb`, `now` or `typ` is accepted (green test), a coz missing `alg` is accepted or refused as anything but `MalformedPayload` on core apply, server push, import or replay, or a present `alg` that differs from the signing key's is refused as anything but `AlgMismatch` (green tests).

```claim
kind: requirement
evaluator: none
```

### [sc-l237]

SPEC 2.3.2, line 237. Disposition: `covered`.

- spec-line: 237
- source: rule
- disposition: covered
- spec-text: 1. **Commits are append-only**: Commits are never removed from the chain and
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s2_3_2_second_commit_on_a_stale_pre_is_rejected`
  - `rs/cyphr-server/tests/spec_conformance.rs::s2_3_2_push_on_a_stale_pre_is_refused_and_the_chain_stays_put`
  - `rs/cyphr-server/tests/e2e.rs::submit_commit_concurrent_same_principal_serializes_and_conflicts`
- fails when: a second, fully authorized commit on a `pre` the chain has moved past is appended (core replay), stored over HTTP (server), or two racing writers both land.

```claim
kind: requirement
evaluator: test
```

### [sc-l240]

SPEC 2.3.2, line 240. Disposition: `covered`.

- spec-line: 240
- source: supplement
- disposition: covered
- spec-text: 2. **Principal Genesis (PG) is immutable**: No operation can change a PG.
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s2_3_2_no_operation_changes_the_principal_genesis`
- fails when: a second `principal/create` overwrites the PG (the only writer; it must fail with `StateMismatch`), or a key create, replace, delete or revoke changes it.

```claim
kind: requirement
evaluator: test
```

### [sc-l246]

SPEC 2.3.2, line 246. Disposition: `covered`.

- spec-line: 246
- source: rule
- disposition: covered
- spec-text: apply an action (keys, rules) must already be active before the transaction
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s2_3_2_inactive_key_cannot_authorize_its_own_admission`
  - `rs/cyphr/tests/signer_seam.rs::signer_outside_principal_is_unknown_key`
- fails when: a key that is not yet active signs a `key/create` for itself, or closes a commit, and is accepted.

```claim
kind: requirement
evaluator: test
```

### [sc-l248]

SPEC 2.3.2, line 248. Disposition: `covered`.

- spec-line: 248
- source: rule
- disposition: covered
- spec-text: 2. **Capability gate**: The principal must have the components required for an
- tests:
  - `rs/cyphr-server/tests/data_root.rs::data_root_enters_pr_only_by_a_signed_ds_create`
  - `rs/cyphr/tests/negative_vectors.rs::forged_action_spliced_before_delete_commit_breaks_replay`
- fails when: a data action reaches PR without DT commit inclusion: the core records it in DT, and only a signed `cyphr/ds/create` whose `id` is the computed DR = MR(DT) puts DR into PR (SPEC 4.8.2, row [sc-l689](#sc-l689)), so the test turns red if an action alone moves PR or a `ds/create` is accepted for a DT it does not name. "Principal genesis is required for commits" is §3.3's rule: a key-only principal's first commit is its genesis. The RT constraints in the sentence are Level 5.

```claim
kind: requirement
evaluator: test
```

### [sc-l252]

SPEC 2.3.2, line 252. Disposition: `covered`.

- spec-line: 252
- source: rule
- disposition: covered
- spec-text: 3. **Lifecycle gate**: The principal's current lifecycle state must permit the
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s11_2_frozen_principal_rejects_key_mutations`
  - `rs/cyphr/tests/spec_conformance.rs::frozen_principal_rejects_data_actions_until_thawed`
  - `rs/cyphr/src/principal/tests/lifecycle.rs::key_create_on_deleted_principal_is_rejected`
  - `rs/cyphr/src/principal/tests/lifecycle.rs::data_action_on_deleted_principal_is_rejected`
- fails when: a frozen principal accepts a key mutation or a data action (its lifecycle cozies freeze/delete, freeze/create, principal/delete and the commit finalizer are the only transactions it takes), or a deleted principal accepts any transaction or action.

```claim
kind: requirement
evaluator: none
```

### [sc-l295]

SPEC 3.1, line 295. Disposition: `not-testable`.

- spec-line: 295
- source: rule
- disposition: not-testable
- spec-text: - Single key, never changes
- tests: none
- reason: Descriptive of the Level 1 feature set; §3.0 says a principal's level is not an authorization input, so there is no level-based rejection to test. The related last-key self-revoke requirement is line 298.

```claim
kind: requirement
evaluator: none
```

### [sc-l298]

SPEC 3.1, line 298. Disposition: `covered`.

- spec-line: 298
- source: supplement
- disposition: covered
- spec-text: - Self-revoke results in permanent lockout (in lieu of sideband intervention)
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s3_1_last_key_self_revoke_is_accepted_and_leaves_the_principal_dead`
  - `rs/cyphr/tests/spec_conformance.rs::s3_1_dead_principal_after_last_key_revoke_records_no_action`
  - `rs/cyphr/tests/spec_conformance.rs::dead_principal_roots_are_absent_and_pr_is_cr_without_data`
  - `rs/cyphr/tests/spec_conformance.rs::dead_principal_roots_state_root_is_the_data_root`
  - `rs/cyphr/tests/spec_conformance.rs::dead_principal_roots_hash_under_the_pre_commit_algorithm_set`
  - `rs/cyphr/tests/spec_conformance.rs::dead_principal_roots_key_delete_of_the_last_key_leaves_dead`
  - `rs/cyphr/tests/spec_conformance.rs::dead_principal_roots_are_final_no_further_commit`
  - `rs/cyphr/tests/nonce.rs::dead_principal_roots_keep_the_nonces_that_remain`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_lifecycle[lifecycle/last_key_revoke_leaves_dead]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_lifecycle[lifecycle/dead_principal_rejects_commit]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_lifecycle[lifecycle/last_key_delete_leaves_dead]`
  - `rs/cyphr-server/tests/transport.rs::a_never_pushed_level_one_key_can_be_naked_revoked`
- fails when: a self-revoke of a principal's only key is refused (it was, with `NoActiveKeys`), or deleting the last key is refused, or the dying commit's roots are not the ruled ones (KR and AR derived from the nonces that remain and absent without any, SR equal to DR or absent, PR equal to CR when SR is absent, hashed under the pre-commit algorithm set), or the Dead principal accepts anything further. SPEC governs: §3.1 'permanent lockout', §11 Dead 'a consequence of any condition that leaves the principal with no keys', §14.1 services that ignore revokes are out of compliance. Refusing the revoke leaves Mallory, who copied Alice's only key, a usable key after Alice's revoke.
- note: the commit-borne tests above are the Level 3 case (a principal with a genesis commit revokes its last key in a commit). A Level 1 principal makes no commit (3.1 "No commit", 5.1 "No commit or PG exists"), so its self-revoke is a naked revoke (6.4: "signed outside of a commit"): the server records it with no prior knowledge of the key, and the key is then locked out (`a_never_pushed_level_one_key_can_be_naked_revoked`). A `key/revoke` in a commit on a principal that never committed is refused `GenesisIncomplete`.

```claim
kind: requirement
evaluator: test
```

### [sc-l463]

SPEC 4, line 463. Disposition: `covered`.

- spec-line: 463
- source: rule
- disposition: covered
- spec-text: Merkle tree primitive must support n-arity.
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s4_key_tree_supports_more_than_256_keys`
  - `rs/cyphr/tests/spec_conformance.rs::key_tree_arity_growth_past_256_and_delete_restores_the_key_root`
- fails when: the Key Tree refuses a key set beyond 256 keys, does not make all 257 keys active, or a `key/delete` back to 256 keys does not restore the 256-key Key Root.
- note: SPEC section 4 requires only that the tree "must support n-arity". Past 256 items the shape is the arity-256 rebalanced skeleton the implementation inherits from its Merkle library; roots at 256 items or fewer are unchanged by it. That shape is provisional and an open question for the spec author.

```claim
kind: requirement
evaluator: none
```

### [sc-l468]

SPEC 4.1, line 468. Disposition: `covered`.

- spec-line: 468
- source: supplement
- disposition: covered
- spec-text: of PT. All cozies for a particular transaction contain an identical `typ`, which
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s4_1_transaction_cozies_must_share_one_typ`
- fails when: a transaction holding cozies of different `typ` is applied.

```claim
kind: requirement
evaluator: none
```

### [sc-l535]

SPEC 4.3, line 535. Disposition: `not-testable`.

- spec-line: 535
- source: supplement
- disposition: not-testable
- spec-text: field "seq" is required in the format `"seq": "0/1"`. For example, for two
- tests: none
- reason: The `seq` field exists only for a commit transaction made of several cozies. The core has no multi-coz commit transaction (the finalizer is one `commit/create` coz) and `seq` appears nowhere in the Rust crates, so there is no behaviour to fail. Open point O3.

```claim
kind: requirement
evaluator: none
```

### [sc-l554]

SPEC 4.5, line 554. Disposition: `not-testable`.

- spec-line: 554
- source: rule
- disposition: not-testable
- spec-text: The transactions that must actually be fetched and verified to move from ARₐ to
- tests: none
- reason: A definition of `tx_patch` (what a client fetches between two Auth Roots), with no rejected input of its own; the verification it implies is the portable-proof surface covered by the inclusion tests, not by a sentence-specific test.

```claim
kind: requirement
evaluator: none
```

### [sc-l592]

SPEC 4.6.2, line 592. Disposition: `covered`.

- spec-line: 592
- source: rule
- disposition: covered
- spec-text: must be last.
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s4_6_commit_coz_must_be_last_in_txs`
- fails when: a commit whose `commit/create` coz is not last is accepted.

```claim
kind: requirement
evaluator: test
```

### [sc-l689]

SPEC 4.8.2, line 689. Disposition: `covered`.

- spec-line: 689
- source: supplement
- disposition: covered
- spec-text: to be implicitly promoted to PR. To explicitly include DR into PR, a DR
- tests:
  - `rs/cyphr-server/tests/data_root.rs::data_root_enters_pr_only_by_a_signed_ds_create`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_actions[actions/action_alone_leaves_pr]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_actions[actions/single_action_promotes_ds]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_actions[actions/multiple_actions_sorted]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/ds_create_wrong_id_fails]`
- fails when: a data action alone changes PR, a `cyphr/ds/create` naming the computed DR = MR(DT) does not put DR into PR, or one naming any other DR (a stale one over HTTP, an arbitrary one in the vector) is accepted instead of refused with `StateMismatch`.

```claim
kind: requirement
evaluator: test
```

### [sc-l860]

SPEC 5.1, line 860. Disposition: `not-testable`.

- spec-line: 860
- source: supplement
- disposition: not-testable
- spec-text: order is not provided, clients should throw error `TRANSACTION_ORDER_UNKNOWN`.
- tests: none
- reason: `TRANSACTION_ORDER_UNKNOWN` is a 'should throw' for a wire format that omits order; the core wire format always carries order and no error variant of that name exists. The storage engine's order retention (forge U1) is pinned by `manifest_retains_ingest_order_without_search`, a different sentence. Open point O3.

```claim
kind: requirement
evaluator: none
```

### [sc-l944]

SPEC 6, line 944. Disposition: `covered`.

- spec-line: 944
- source: rule
- disposition: covered
- spec-text: "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA" // Private component, never transmitted
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s6_no_wire_form_carries_private_key_material`
  - `rs/cyphr-server/tests/spec_conformance.rs::s6_exported_commits_carry_no_private_key_material`
  - `rs/cyphr-server/tests/spec_conformance.rs::s6_no_http_response_carries_private_key_material`
- fails when: any serialized coz, any exported commit entry (cozies and key sidecars), or any HTTP response of an attestor (push, server identity, tip, patch and its decoded blobs) carries a private component. Two properties over random key sets of both algorithms (core: cozies; server tier: `export_commits`, which the core crate cannot import) and one end-to-end scenario whose needles include the attestor's own private signing bytes. They check the wire forms the protocol and server emit, not the client keystore.

```claim
kind: requirement
evaluator: test
```

### [sc-l997]

SPEC 6.2, line 997. Disposition: `not-testable`.

- spec-line: 997
- source: rule
- disposition: not-testable
- spec-text: device) when the key was never compromised. Clients should store the public key
- tests: none
- reason: Descriptive use of 'never' (a key 'that was never compromised'), not a requirement.

```claim
kind: requirement
evaluator: none
```

### [sc-l1001]

SPEC 6.2, line 1001. Disposition: `covered`.

- spec-line: 1001
- source: supplement
- disposition: covered
- spec-text: When a key is deleted, actions signed after it has been removed are ignored.
- tests:
  - `rs/cyphr/tests/negative_vectors.rs::deleted_key_action_dated_after_delete_is_rejected`
- fails when: an action signed by a key after its delete commit is accepted.

```claim
kind: requirement
evaluator: none
```

### [sc-l1002]

SPEC 6.2, line 1002. Disposition: `covered`.

- spec-line: 1002
- source: supplement
- disposition: covered
- spec-text: Only actions signed while a ley is active in KT are interpreted. Past signatures
- tests:
  - `rs/cyphr/tests/negative_vectors.rs::deleted_key_action_backdated_into_old_active_period_is_rejected`
- fails when: the genuine pre-delete action is dropped after the delete, or a forged action backdated into the old active period is accepted. Rejection stands: a verdict is fixed by chain position, so a later commit cannot change an old one (the spec author on forge issue #200).

```claim
kind: requirement
evaluator: none
```

### [sc-l1005]

SPEC 6.2, line 1005. Disposition: `not-testable`.

- spec-line: 1005
- source: rule
- disposition: not-testable
- spec-text: deleted and one that was never added except that a deleted key may have a
- tests: none
- reason: Descriptive use of 'never' (a key 'that was never added'), not a requirement.

```claim
kind: requirement
evaluator: none
```

### [sc-l1006]

SPEC 6.2, line 1006. Disposition: `covered`.

- spec-line: 1006
- source: supplement
- disposition: covered
- spec-text: duration of legitimate past signatures. Deleted keys may be re-added later (via
- tests:
  - `rs/cyphr/tests/key_auth.rs::d3_control_deleted_key_may_be_readded`
- fails when: a deleted key cannot be re-added by `key/create`.

```claim
kind: requirement
evaluator: none
```

### [sc-l1058]

SPEC 6.4, line 1058. Disposition: `covered`.

- spec-line: 1058
- source: rule
- disposition: covered
- spec-text: A revoke is a self-signed declaration that a key is compromised and should never
- tests:
  - `rs/cyphr/tests/key_auth.rs::d3_revoked_key_cannot_be_readded_by_key_create`
  - `rs/cyphr/tests/key_auth.rs::d3_revoked_key_cannot_be_readded_by_key_replace`
  - `rs/cyphr/tests/key_auth.rs::d3_revoked_key_cannot_sign_after_readd_attempt`
  - `rs/cyphr/tests/signer_seam.rs::revoked_signer_is_key_revoked`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/revoked_key_fails]`
- fails when: a revoked key is re-added by `key/create` or `key/replace` or still signs a commit or action (all green).

```claim
kind: requirement
evaluator: none
```

### [sc-l1059]

SPEC 6.4, line 1059. Disposition: `covered`.

- spec-line: 1059
- source: rule
- disposition: covered
- spec-text: be trusted again. Critically, the key signing a revoke message must be the key
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s6_4_one_key_cannot_revoke_another`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/revoke_non_self_fails]`
- fails when: a key other than the revoked one signs, or is credited with, a `key/revoke`.

```claim
kind: requirement
evaluator: test
```

### [sc-l1067]

SPEC 6.4, line 1067. Disposition: `covered`.

- spec-line: 1067
- source: rule
- disposition: covered
- spec-text: > `rvk` and `now` must be a positive integer less than 2^53 – 1
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s6_4_revoke_rvk_must_be_a_positive_bounded_integer`
  - `rs/cyphr/tests/spec_conformance.rs::s6_4_revoke_now_must_be_a_positive_bounded_integer`
- fails when: an in-commit `key/revoke` with `rvk` of 0, a negative value or 2^53, or `now` of 0 or 2^53, is accepted; 2^53-1 is in range for both.

```claim
kind: requirement
evaluator: none
```

### [sc-l1069]

SPEC 6.4, line 1069. Disposition: `covered`.

- spec-line: 1069
- source: rule
- disposition: covered
- spec-text: > IEEE754 minus one. Revoke checks must error if `rvk` is not an integer or
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s6_4_revoke_rvk_must_be_a_positive_bounded_integer`
  - `rs/cyphr-server/tests/naked_revoke.rs::rejects_malformed_rvk`
- fails when: a revoke check accepts a non-integer or oversized `rvk`: checked on the naked-revoke path (`rejects_malformed_rvk`) and the in-commit path.

```claim
kind: requirement
evaluator: none
```

### [sc-l1075]

SPEC 6.4, line 1075. Disposition: `covered`.

- spec-line: 1075
- source: rule
- disposition: covered
- spec-text: naked revoke does not mutate PR, but further use of the revoked key must be
- tests:
  - `rs/cyphr/tests/signer_seam.rs::revoked_signer_is_key_revoked`
  - `rs/cyphr-server/tests/naked_revoke.rs::revoked_key_refused_at_push`
  - `rs/cyphr-server/tests/naked_revoke.rs::revoked_key_refused_at_login_sibling_survives`
  - `rs/cyphr-server/tests/transport.rs::a_never_pushed_level_one_key_can_be_naked_revoked`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/action_revoked_key_fails]`
- fails when: a revoked key signs a commit, a push, a login or an action and is accepted. The in-tree copy has drifted here (see the drift table).
- note: a naked revoke needs no prior knowledge of its key: a Level 1 key signs nothing a peer could have seen, so the revoke route verifies only the self-signature against the disclosed key and its thumbprint bind; revokes of keys no stored principal holds are bounded by the operator's `[limits] max_dead_keys` (refused `507` past it) and the `/revoke` rate buckets, while a held key's revoke is recorded even past it (`the_ceiling_never_refuses_a_held_keys_revoke`); residual: while the set is full, an unseen Level 1 key's revoke is refused. Third-party revokes stay refused.

```claim
kind: requirement
evaluator: none
```

### [sc-l1266]

SPEC 7.6, line 1266. Disposition: `covered`.

- spec-line: 1266
- source: supplement
- disposition: covered
- spec-text: All actions are idempotent. For data actions, replaying an previously applied
- tests:
  - `rs/cyphr/tests/properties.rs::prop_data_action_replay_is_idempotent`
- fails when: replaying a previously applied data-action coz changes state.

```claim
kind: requirement
evaluator: none
```

### [sc-l1268]

SPEC 7.6, line 1268. Disposition: `covered`.

- spec-line: 1268
- source: supplement
- disposition: covered
- spec-text: particular principal is prohibited and results in error `COZ_REUSE`. The first
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s7_6_transaction_coz_reuse_by_the_same_principal_is_rejected`
  - `rs/cyphr/tests/spec_conformance.rs::s7_6_reuse_is_typed_and_scoped_to_one_principal`
  - `rs/cyphr/tests/spec_conformance.rs::multihash_replay_of_an_es384_signed_coz_is_reuse`
  - `rs/cyphr/tests/spec_conformance.rs::every_active_algorithms_cr_variant_advances_with_every_commit`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/coz_reuse_fails]`
- fails when: a transaction coz already included by a principal is applied again.
- limit: a principal restored from a checkpoint starts with no record of earlier cozies, so it accepts reuse of a coz included before the checkpoint; the restore path owns closing this.

```claim
kind: requirement
evaluator: none
```

### [sc-l1278]

SPEC 7.6, line 1278. Disposition: `covered`.

- spec-line: 1278
- source: supplement
- disposition: covered
- spec-text: principal) already exists, the operation fails with error `DUPLICATE`.
- tests:
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/duplicate_key_fails]`
- fails when: a `key/create` for a key already in the key set is accepted. Only keys exist at Levels 1-4; `DUPLICATE` for rules and principals is Level 5 or has no creating transaction.

```claim
kind: requirement
evaluator: none
```

### [sc-l1287]

SPEC 7.7, line 1287. Disposition: `covered`.

- spec-line: 1287
- source: rule
- disposition: covered
- spec-text: must be performed in exactly one canonical, atomic representation with no
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s7_7_fork_create_does_not_create_a_principal`
  - `rs/cyphr-server/tests/explicit_genesis.rs::genesis_omitting_a_key_create_is_refused`
  - `rs/cyphr-server/tests/explicit_genesis.rs::a_created_genesis_key_may_create_the_next`
  - `rs/cyphr-server/tests/explicit_genesis.rs::a_first_commit_without_principal_create_is_refused`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/principal_create_without_genesis_key_create_fails]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/genesis_not_opened_by_self_create_fails]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/mutation_after_principal_create_fails]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/uncreated_genesis_key_signs_fails]`
- fails when: a `principal/fork/create` is accepted as, or changes state like, a principal creation (Example 2, line 1300); or a `principal/create` is accepted while a genesis key has no `key/create` (Example 1: the genesis commit carries a `key/create` for every genesis key, SPEC 5.1 step 1, 5.2, 5.3); or a genesis commit opens with anything but the genesis key's own `key/create`; or a commit is finalized before its principal's `principal/create`.
- note: the genesis signer rule is SPEC 5.1 steps 1-2 ("The genesis key (the first key) is explicitly added"; "Adding additional keys, rules, or any other AR components require additional transactions") read with 13.2 step 3 ("`tmb` belongs to a key in current KR"): before any `key/create` the KR is empty, so the first genesis transaction can only be the genesis key's own `key/create`, and every later one is signed by a key already created in that commit (any key may `key/create` another, 3.3). The `principal/create` names the future SR (5.1 step 3, 5.2 "ID == PG == SR"), the state every genesis transaction before it reached, so only the `commit/create` may follow it. A commit chain begins with this commit: there is no committed state without a PG. Refusals: `UnknownKey` for a signer not yet created, `GenesisIncomplete` for a `principal/create` with a genesis key uncreated, a transaction after it, or a commit finalized without it (`rs/cyphr/src/principal/apply.rs`).

```claim
kind: requirement
evaluator: test
```

### [sc-l1300]

SPEC 7.7, line 1300. Disposition: `covered`.

- spec-line: 1300
- source: supplement
- disposition: covered
- spec-text: Example 2: A principal may only be created using `principal/create`. A
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s7_7_fork_create_does_not_create_a_principal`
- fails when: `principal/fork/create` is accepted as a creation.

```claim
kind: requirement
evaluator: test
```

### [sc-l1515]

SPEC 9.1, line 1515. Disposition: `out-of-scope`.

- spec-line: 1515
- source: rule
- disposition: out-of-scope
- spec-text: keys must be signed for a valid transaction:
- tests: none
- reason: Level 5 (rules and weights); `rs/cyphr` has no weight or rule tree.

```claim
kind: requirement
evaluator: none
```

### [sc-l1588]

SPEC 9.3, line 1588. Disposition: `out-of-scope`.

- spec-line: 1588
- source: rule
- disposition: out-of-scope
- spec-text: Unlike other nodes, all top level rules must be content-revealed. Top level
- tests: none
- reason: Level 5 (rules); `rs/cyphr` has no rule tree.

```claim
kind: requirement
evaluator: none
```

### [sc-l1673]

SPEC 10.2, line 1673. Disposition: `covered`.

- spec-line: 1673
- source: rule
- disposition: covered
- spec-text: - The nonce's bit length must match the declared algorithm's output size (e.g.,
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s10_2_nonce_bit_length_must_match_the_declared_algorithm`
- fails when: a nonce whose width differs from the output size of the algorithm it declares (a SHA-256 nonce of anything but 32 bytes, likewise SHA-384 and SHA-512) is accepted at the PR, AT or KT path, or a correct-width nonce is refused.

```claim
kind: requirement
evaluator: test
```

### [sc-l1674]

SPEC 10.2, line 1674. Disposition: `covered`.

- spec-line: 1674
- source: rule
- disposition: covered
- spec-text: a nonce declared as SHA-256 must be 256 bits). Bit-checking is the only
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s10_2_nonce_bit_length_must_match_the_declared_algorithm`
- fails when: same sentence as line 1673 (nonce bit length); the same test covers both lines.

```claim
kind: requirement
evaluator: test
```

### [sc-l1676]

SPEC 10.2, line 1676. Disposition: `not-testable`.

- spec-line: 1676
- source: rule
- disposition: not-testable
- spec-text: - Nonce values should be cryptographic randomly generated values must match the
- tests: none
- reason: A 'should' on whoever generates the nonce: randomness cannot be checked by a verifier, and the bit-length check is the previous bullet. The sentence is ungrammatical (editorial note E2).

```claim
kind: requirement
evaluator: none
```

### [sc-l1704]

SPEC 10.3, line 1704. Disposition: `out-of-scope`.

- spec-line: 1704
- source: rule
- disposition: out-of-scope
- spec-text: retrieval is performed. However, any node of these types must be revealed
- tests: none
- reason: Embedded principals (Level 5+); no embedding type in `rs/cyphr`.

```claim
kind: requirement
evaluator: none
```

### [sc-l1799]

SPEC 10.5, line 1799. Disposition: `out-of-scope`.

- spec-line: 1799
- source: rule
- disposition: out-of-scope
- spec-text: To sign/act as a primary principal, an embedded principal must produce a valid
- tests: none
- reason: Conjunctive authorization of embedded principals (Level 5+); no embedding type in `rs/cyphr`.

```claim
kind: requirement
evaluator: none
```

### [sc-l1803]

SPEC 10.5, line 1803. Disposition: `out-of-scope`.

- spec-line: 1803
- source: rule
- disposition: out-of-scope
- spec-text: - The action must be valid according to the embedded principal’s own rules (its
- tests: none
- reason: Embedded principals (Level 5+).

```claim
kind: requirement
evaluator: none
```

### [sc-l1805]

SPEC 10.5, line 1805. Disposition: `out-of-scope`.

- spec-line: 1805
- source: rule
- disposition: out-of-scope
- spec-text: - The embedded principal's action must be authorized by the primary principal’s
- tests: none
- reason: Embedded principals (Level 5+).

```claim
kind: requirement
evaluator: none
```

### [sc-l1862]

SPEC 11.2, line 1862. Disposition: `covered`.

- spec-line: 1862
- source: supplement
- disposition: covered
- spec-text: unfrozen via `freeze/delete`. No mutations until unfrozen.
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s11_2_frozen_principal_rejects_key_mutations`
  - `rs/cyphr/tests/spec_conformance.rs::frozen_principal_rejects_data_actions_until_thawed`
- fails when: a frozen principal accepts a key mutation or a data action (the same gate as line 252).

```claim
kind: requirement
evaluator: none
```

### [sc-l1863]

SPEC 11.2, line 1863. Disposition: `covered`.

- spec-line: 1863
- source: supplement
- disposition: covered
- spec-text: - **Deleted**: The principal signed `principal/delete`. No new transactions or
- tests:
  - `rs/cyphr/src/principal/tests/lifecycle.rs::key_create_on_deleted_principal_is_rejected`
  - `rs/cyphr/src/principal/tests/lifecycle.rs::key_delete_on_deleted_principal_is_rejected`
  - `rs/cyphr/src/principal/tests/lifecycle.rs::data_action_on_deleted_principal_is_rejected`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_lifecycle[lifecycle/freeze_after_delete_is_rejected]`
- fails when: a deleted principal accepts a key mutation, a data action, or a freeze.

```claim
kind: requirement
evaluator: none
```

### [sc-l1869]

SPEC 11.2, line 1869. Disposition: `covered`.

- spec-line: 1869
- source: supplement
- disposition: covered
- spec-text: - **Dead**: No transactions or actions possible at all. No active keys remain.
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s11_2_dead_principal_accepts_no_transaction_or_action`
- fails when: a principal with no active key still takes a transaction or an action.

```claim
kind: requirement
evaluator: test
```

### [sc-l1875]

SPEC 11.2, line 1875. Disposition: `covered`.

- spec-line: 1875
- source: supplement
- disposition: covered
- spec-text: `Deleted` and `Frozen` are mutually exclusive (a principal cannot be frozen and
- tests:
  - `rs/cyphr/src/principal/tests/lifecycle.rs::principal_delete_from_frozen_succeeds_and_clears_frozen`
  - `rs/cyphr/src/principal/tests/lifecycle.rs::freeze_create_on_deleted_is_rejected`
- fails when: a principal can be both frozen and deleted: a delete leaves `frozen` set, or a freeze is accepted on a deleted principal.

```claim
kind: requirement
evaluator: none
```

### [sc-l1898]

SPEC 11.4, line 1898. Disposition: `covered`.

- spec-line: 1898
- source: supplement
- disposition: covered
- spec-text: Delete, Level 3+). Closed principals are permanently closed and cannot be
- tests:
  - `rs/cyphr/src/principal/tests/lifecycle.rs::later_commit_bare_finalizer_on_already_deleted_is_rejected`
  - `rs/cyphr/src/principal/tests/lifecycle.rs::self_revoke_on_deleted_principal_is_rejected`
- fails when: a later commit, including a bare finalizer, is accepted on a closed principal.

```claim
kind: requirement
evaluator: none
```

### [sc-l1951]

SPEC 11.5.1, line 1951. Disposition: `covered`.

- spec-line: 1951
- source: rule
- disposition: covered
- spec-text: Note the target account must explicitly add keys from the source account (if the
- tests:
  - `rs/cyphr/tests/merge.rs::a_merge_and_its_matching_ack_are_accepted`
- fails when: a merge or its ack adds the source's keys to the target, or changes the target's actions.

```claim
kind: requirement
evaluator: none
```

### [sc-l1953]

SPEC 11.5.1, line 1953. Disposition: `covered`.

- spec-line: 1953
- source: rule
- disposition: covered
- spec-text: must be explicitly added to the target. Also note that the source principal is
- tests:
  - `rs/cyphr/tests/merge.rs::a_merge_and_its_matching_ack_are_accepted`
- fails when: a merge deactivates or deletes the source, or imports AT into the target.

```claim
kind: requirement
evaluator: none
```

### [sc-l2095]

SPEC 12.2, line 2095. Disposition: `not-testable`.

- spec-line: 2095
- source: rule
- disposition: not-testable
- spec-text: A MHMR must prescribe how commits sign the MHMR. The reference implementation
- tests: none
- reason: An obligation on the choice of MHMR scheme ('must prescribe how commits sign'), not a rejected input; the reference scheme's behaviour is pinned by the arrow and root tests, which are not this sentence.

```claim
kind: requirement
evaluator: none
```

### [sc-l2117]

SPEC 12.3, line 2117. Disposition: `covered`.

- spec-line: 2117
- source: rule
- disposition: covered
- spec-text: only for operations where the service must interpret. If such an operation is
- tests:
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/unsupported_algorithm_fails]`
- fails when: a principal using an unsupported algorithm is accepted instead of refused as incompatible (the vector `unsupported_algorithm_fails` expects `UnknownAlg` at genesis; the `key/create` path returns `UnsupportedAlgorithm` and is untested).

```claim
kind: requirement
evaluator: none
```

### [sc-l2814]

SPEC 15.8, line 2814. Disposition: `not-testable`.

- spec-line: 2814
- source: supplement
- disposition: not-testable
- spec-text: An invalid fork is resolved when the principal unambiguously selects one
- tests: none
- reason: Witness-side consensus states (Error until the principal resolves its own fork) have no implementation in `rs/cyphr` or `rs/cyphr-server`; the text stands and the work belongs to the consensus nodes (D1 and the gossip nodes).

```claim
kind: requirement
evaluator: none
```

### [sc-l2822]

SPEC 15.8, line 2822. Disposition: `not-testable`.

- spec-line: 2822
- source: supplement
- disposition: not-testable
- spec-text: - **2. PoP assertion** - The principal signs a `resync/create` message
- tests: none
- reason: Depends on `resync/create`, which `rs/cyphr` has no coz kind for; the same witness-side surface as line 2814.

```claim
kind: requirement
evaluator: none
```

### [sc-l2827]

SPEC 15.8, line 2827. Disposition: `covered`.

- spec-line: 2827
- source: supplement
- disposition: covered
- spec-text: In both cases, the abandoned branch's transactions become permanently invalid.
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s2_3_2_second_commit_on_a_stale_pre_is_rejected`
- fails when: an abandoned branch's commit is accepted onto the chosen chain (core replay; the witness-side half is line 2814).

```claim
kind: requirement
evaluator: test
```

### [sc-l2828]

SPEC 15.8, line 2828. Disposition: `covered`.

- spec-line: 2828
- source: supplement
- disposition: covered
- spec-text: Keys that were only added in the abandoned branch are not part of KR. Witnesses
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s2_3_2_second_commit_on_a_stale_pre_is_rejected`
- fails when: a key added only in the abandoned branch becomes active on the chosen chain (the test asserts it stays inactive).

```claim
kind: requirement
evaluator: test
```

### [sc-l2829]

SPEC 15.8, line 2829. Disposition: `not-testable`.

- spec-line: 2829
- source: supplement
- disposition: not-testable
- spec-text: transition the principal's consensus state from Error back to Active upon
- tests: none
- reason: The Error-to-Active transition on resolution is witness-side consensus state with no implementation surface; same as line 2814.

```claim
kind: requirement
evaluator: none
```

### [sc-l2835]

SPEC 15.9, line 2835. Disposition: `covered`.

- spec-line: 2835
- source: supplement
- disposition: covered
- spec-text: includes comparing now to witness time on receipt and rejecting outside ±360 s
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s15_9_future_dated_message_is_rejected_by_default`
- fails when: a message dated a day ahead is accepted by a default principal (the verifier clock plus a 360 s tolerance bounds every coz and action; the far extremes and push are covered in `rs/cyphr-server/tests/now_range.rs`). The backdated half (far in the past relative to witness time) is not tested because the corpus uses fixed 2023 timestamps; Open point O1.

```claim
kind: requirement
evaluator: none
```

### [sc-l2837]

SPEC 15.9, line 2837. Disposition: `covered`.

- spec-line: 2837
- source: supplement
- disposition: covered
- spec-text: recent valid message, rejecting any now earlier than latest known timestamp to
- tests:
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/timestamp_past_fails]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/action_timestamp_past_fails]`
- fails when: a commit or action with `now` earlier than the principal's latest known timestamp is accepted.

```claim
kind: requirement
evaluator: none
```

### [sc-l2838]

SPEC 15.9, line 2838. Disposition: `covered`.

- spec-line: 2838
- source: supplement
- disposition: covered
- spec-text: prevent history rewriting, and rejecting future-dated messages.
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s15_9_future_dated_message_is_rejected_by_default`
- fails when: future-dated messages are accepted (same defect as line 2835).

```claim
kind: requirement
evaluator: none
```

### [sc-l3054]

SPEC 17.2, line 3054. Disposition: `covered`.

- spec-line: 3054
- source: supplement
- disposition: covered
- spec-text: 1. Service generates a 256-bit cryptographic challenge (nonce)
- tests:
  - `rs/cyphr-server/tests/spec_conformance.rs::s17_2_challenge_is_256_bits_and_unique`
- fails when: a challenge is not 32 bytes or repeats.

```claim
kind: requirement
evaluator: test
```

### [sc-l3057]

SPEC 17.2, line 3057. Disposition: `covered`.

- spec-line: 3057
- source: supplement
- disposition: covered
- spec-text: - Signature is valid
- tests:
  - `rs/cyphr-server/tests/login.rs::login_rejects_invalid_signature`
- fails when: a login with an invalid signature gets a token.

```claim
kind: requirement
evaluator: none
```

### [sc-l3058]

SPEC 17.2, line 3058. Disposition: `covered`.

- spec-line: 3058
- source: supplement
- disposition: covered
- spec-text: - `tmb` belongs to an active key in principal's KR
- tests:
  - `rs/cyphr-server/tests/login.rs::login_rejects_key_revoked_in_claimed_principal`
  - `rs/cyphr-server/tests/login.rs::login_binds_key_to_claimed_principal_not_thumbprint`
  - `rs/cyphr-server/tests/login.rs::login_rejects_unknown_principal`
- fails when: a key that is not active in the claimed principal (revoked, or active only elsewhere) gets a token.

```claim
kind: requirement
evaluator: none
```

### [sc-l3059]

SPEC 17.2, line 3059. Disposition: `covered`.

- spec-line: 3059
- source: supplement
- disposition: covered
- spec-text: - Principal lifecycle state is Active (reject Frozen, Deleted, Errored,
- tests:
  - `rs/cyphr-server/tests/login.rs::login_rejects_frozen_principal`
  - `rs/cyphr-server/tests/login.rs::login_rejects_deleted_principal`
- fails when: a Frozen or Deleted principal gets a token. The Errored case has no test: `Principal::is_errored` is never set by any detector today, so no principal can be Errored (line 2814).

```claim
kind: requirement
evaluator: none
```

### [sc-l3061]

SPEC 17.2, line 3061. Disposition: `covered`.

- spec-line: 3061
- source: supplement
- disposition: covered
- spec-text: - Challenge matches the one issued (prevents replay)
- tests:
  - `rs/cyphr-server/tests/login.rs::login_rejects_replayed_challenge`
- fails when: a consumed or unissued challenge gets a token.

```claim
kind: requirement
evaluator: none
```

### [sc-l3081]

SPEC 17.2, line 3081. Disposition: `covered`.

- spec-line: 3081
- source: supplement
- disposition: covered
- spec-text: - Signature is valid
- tests:
  - `rs/cyphr-server/tests/login.rs::login_rejects_invalid_signature`
- fails when: a login with an invalid signature gets a token.

```claim
kind: requirement
evaluator: none
```

### [sc-l3082]

SPEC 17.2, line 3082. Disposition: `covered`.

- spec-line: 3082
- source: supplement
- disposition: covered
- spec-text: - `tmb` belongs to an active key in principal's KR
- tests:
  - `rs/cyphr-server/tests/login.rs::login_rejects_key_revoked_in_claimed_principal`
  - `rs/cyphr-server/tests/login.rs::login_binds_key_to_claimed_principal_not_thumbprint`
  - `rs/cyphr-server/tests/login.rs::login_rejects_unknown_principal`
- fails when: a key that is not active in the claimed principal (revoked, or active only elsewhere) gets a token.

```claim
kind: requirement
evaluator: none
```

### [sc-l3083]

SPEC 17.2, line 3083. Disposition: `covered`.

- spec-line: 3083
- source: supplement
- disposition: covered
- spec-text: - Principal lifecycle state is Active (reject Frozen, Deleted, Errored,
- tests:
  - `rs/cyphr-server/tests/login.rs::login_rejects_frozen_principal`
  - `rs/cyphr-server/tests/login.rs::login_rejects_deleted_principal`
- fails when: a Frozen or Deleted principal gets a token. The Errored case has no test: `Principal::is_errored` is never set by any detector today, so no principal can be Errored (line 2814).

```claim
kind: requirement
evaluator: none
```

### [sc-l3085]

SPEC 17.2, line 3085. Disposition: `covered`.

- spec-line: 3085
- source: supplement
- disposition: covered
- spec-text: - `now` is within acceptable window (e.g., ±60 seconds of server time)
- tests:
  - `rs/cyphr-server/tests/login.rs::login_rejects_out_of_window_timestamp`
- fails when: a timestamp-flow login outside the window gets a token.

```claim
kind: requirement
evaluator: none
```

### [sc-l3350]

SPEC 19.5, line 3350. Disposition: `covered`.

- spec-line: 3350
- source: rule
- disposition: covered
- spec-text: **Implementations must:**
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s19_5_failed_commit_leaves_no_partial_state`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/duplicate_key_fails]`
- fails when: a rejected transaction is accepted, or leaves state behind (the two rules below are this line's items).

```claim
kind: requirement
evaluator: test
```

### [sc-l3352]

SPEC 19.5, line 3352. Disposition: `covered`.

- spec-line: 3352
- source: supplement
- disposition: covered
- spec-text: - Reject transactions with any error condition
- tests:
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/unknown_key_fails]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/revoked_key_fails]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/timestamp_past_fails]`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/duplicate_key_fails]`
- fails when: a transaction with an error condition (unknown or revoked key, past timestamp, duplicate key) is accepted.

```claim
kind: requirement
evaluator: none
```

### [sc-l3353]

SPEC 19.5, line 3353. Disposition: `covered`.

- spec-line: 3353
- source: supplement
- disposition: covered
- spec-text: - Not apply partial state changes (atomic)
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s19_5_failed_commit_leaves_no_partial_state`
  - `rs/cyphr/src/principal/tests/tree.rs::abandoned_commit_scope_does_not_leak_state`
- fails when: the first transaction of a failed commit is visible in the principal.

```claim
kind: requirement
evaluator: test
```

## Editorial notes for the spec author

The earlier open questions were settled against `be0663f`, the code, the
corpus and the Coz reference implementations. Three leave a note on the text;
none changes a verdict.

- **E1 (lines 127 and 129).** Add a cross-algorithm example: an Ed25519 coz
  introducing an ES256 key carries a SHA-256 `id`, the key's own digest.
- **E2 (line 1676).** The sentence "Nonce values should be cryptographic
  randomly generated values must match the target strength" is ungrammatical.
- **E3 (lines 1067 and 1069).** "Less than 2^53 - 1" and "larger than
  2^53 - 1" disagree at the boundary. The Coz references accept 2^53 - 1 and
  reject only above it, and the tests follow them.

Open points this node raised that the resolved set did not cover:

- **O1 (line 2835).** Is the "witness time on receipt" comparison a core rule
  or a witness rule? The corpus uses fixed 2023 timestamps, so a strict
  backdating check would reject every golden vector. Only the future side is
  tested.
- **O2 (line 1287), closed.** Example 1 says genesis does not implicitly
  create the genesis key. Every commit chain begins with a genesis commit
  carrying a `key/create` for every genesis key, the genesis key's own
  first, and `principal/create` refuses while one is missing (row
  `sc-l1287`). Implicit genesis (Levels 1 and 2) makes no commit; an
  implicit principal's first commit is its genesis commit.
- **O3 (lines 535 and 860).** `seq` for multi-coz commit transactions and
  `TRANSACTION_ORDER_UNKNOWN` have no counterpart in the Rust wire format; are
  they still wanted at Levels 1-4?

## Drift in the in-tree SPEC.md

The `zami` branch governs. These are places where the integration branch's
`SPEC.md` has drifted from it, compared line by line at the base of this node,
so whoever syncs the in-tree copy knows what to bring across. They are not
open questions. Rows whose `be0663f` sentence does not appear verbatim in the
in-tree file:

| Row  | `be0663f`                                                   | In-tree                                                                                                                     |
| :--- | :---------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------- |
| 463  | "must support n-arity"                                      | "must be able to support arity"                                                                                             |
| 1059 | "Critically, the key signing a revoke message must be ..."  | "The key signing the revoke message must be the key itself."                                                                |
| 1075 | "further use of the revoked key must be rejected"           | sentence removed; "Cyphr must appropriately interpret this event" and a naked revoke "puts the principal in an error state" |
| 1803 | "The action must be valid according to ..."                 | "Transaction must be valid according to ..."                                                                                |
| 1805 | "The embedded principal's action must be authorized by ..." | "The act of using that embedded principal must be authorized by ..."                                                        |
| 2095 | "A MHMR must prescribe how commits sign the MHMR."          | sentence absent                                                                                                             |
| 2117 | "where the service must interpret"                          | "Compatibility is strictly required only for operations where the service must interpret"                                   |

Normative lines present only in the in-tree file, in the same sections, that
no row covers: "Cyphr must appropriately interpret this event" (naked
revoke), "cells are never re-sorted" (PT, AT and ST ordering), "Implementors
must be aware that inner nodes may have different security levels" and the
KT and DR ordering note. No mapped test depends on them.

- **Q9 (line 2835).** Is the "witness time on receipt" comparison a core
  rule or a witness rule? The corpus uses fixed 2023 timestamps, so a strict
  backdating check would reject every golden vector. Only the future side is
  tested.
- **Q10 (line 1287).** Example 1 says genesis does not implicitly create the
  genesis key and every key needs a `key/create`, but implicit and explicit
  genesis both hold keys with no `key/create`.
- **Q11 (lines 535 and 860).** `seq` for multi-coz commit transactions and
  `TRANSACTION_ORDER_UNKNOWN` have no counterpart in the Rust wire format;
  are they still wanted at Levels 1-4?
