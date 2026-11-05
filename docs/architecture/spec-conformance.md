# SPEC conformance map

This page maps every normative `must`, `must not`, `shall` and `never` on the
security path of the protocol specification to a test that fails when the
requirement breaks, and says plainly where no such test exists. It exists so a
reader can answer "is this requirement of the specification enforced, and what
would tell us if it stopped being?" without reading the test suite.

The source is `SPEC.md` as it stands at commit `be0663f` on the `zami`
branch (the spec author's working copy), sections 2 through 12 plus 15.2 and
15.8. The copy of `SPEC.md` on the integration branch differs from it; every
row where that matters is listed under
[Differences from the in-tree SPEC.md](#differences-from-the-in-tree-specmd).
This page never edits or reinterprets the specification: an ambiguous or
contradictory sentence is recorded as a question for the spec author, not
resolved.

## How to read a row

A row is one specification line, keyed by its line number at `be0663f`. Rows
come from two sources. `rule` rows are every line in scope that contains the
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
| `covered`      |   15 |
| `red-existing` |    1 |
| `red-new`      |    6 |
| `not-testable` |   17 |
| `out-of-scope` |    8 |
| `total`        |   47 |

Fixing ids on red rows: `KA1` is the key-authentication node
(`pay.alg == key.alg` must treat an absent `alg` as a mismatch, and revoked
keys must not be re-added). `SC1-F1` (frozen principals reject mutations),
`SC1-F2` (in-commit `rvk` and `now` bounds) and `SC1-F3` (Key Tree arity) have
no fixing node yet; they are tracking ids until one is assigned.

## Rows

### [sc-l127]

SPEC 2.2.3, line 127. Disposition: `not-testable`.

- spec-line: 127
- source: rule
- disposition: not-testable
- spec-text: object. Following Coz semantics, all digest identifiers inside a coz must
- tests: none
- reason: Ambiguous against the corpus: read strictly, every digest identifier in a coz is computed with the algorithm named by that coz's `alg`, but the golden vector `algorithm_diversity/ed25519_account_adds_es256_key` has an Ed25519 coz whose `id` is a SHA-256 thumbprint. Question Q1.

```claim
kind: requirement
evaluator: none
```

### [sc-l129]

SPEC 2.2.3, line 129. Disposition: `not-testable`.

- spec-line: 129
- source: rule
- disposition: not-testable
- spec-text: the algorithm for the `id` of the new key must be `SHA256`, aligning with alg
- tests: none
- reason: Same sentence pair as line 127: the example (`id` of the new key is SHA256 under `ES256`) is the same-algorithm case and says nothing about a cross-algorithm `key/create`. Question Q1.

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

SPEC 2.3.1, line 226. Disposition: `red-new`.

- spec-line: 226
- source: rule
- disposition: red-new
- spec-text: Cyphr requires specific Coz semantics. All cozies must have the fields:
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s2_3_1_coz_missing_tmb_now_or_typ_is_rejected`
  - `rs/cyphr/tests/spec_conformance.rs::s2_3_1_coz_missing_alg_is_rejected`
- fails when: a coz missing `tmb`, `now` or `typ` is accepted (green test), or a coz missing `alg` is accepted (red today: `verify_coz` never reads `pay.alg`).

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

SPEC 2.3.2, line 248. Disposition: `not-testable`.

- spec-line: 248
- source: rule
- disposition: not-testable
- spec-text: 2. **Capability gate**: The principal must have the components required for an
- tests: none
- reason: No operation-to-component pair the sentence names has an observable rejection at Levels 1-4: its own example ('principal genesis is required for commits') conflicts with Level 1 having no commit while an implicit-genesis principal commits today; 'data actions require DT commit inclusion' names no rejected input; the RT constraints it mentions are Level 5. Question Q2.

```claim
kind: requirement
evaluator: none
```

### [sc-l252]

SPEC 2.3.2, line 252. Disposition: `red-new`.

- spec-line: 252
- source: rule
- disposition: red-new
- spec-text: 3. **Lifecycle gate**: The principal's current lifecycle state must permit the
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s11_2_frozen_principal_rejects_key_mutations`
  - `rs/cyphr/src/principal.rs::key_create_on_deleted_principal_is_rejected`
  - `rs/cyphr/src/principal.rs::data_action_on_deleted_principal_is_rejected`
- fails when: a frozen principal accepts a key mutation (red today: `frozen` is recorded but never consulted by the apply gate), or a deleted principal accepts any transaction or action (green).

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
- reason: Descriptive of the Level 1 feature set, and §3.0 says a principal's level is not an authorization input, so there is no level-based rejection to test. Question Q3 (with line 298).

```claim
kind: requirement
evaluator: none
```

### [sc-l298]

SPEC 3.1, line 298. Disposition: `not-testable`.

- spec-line: 298
- source: supplement
- disposition: not-testable
- spec-text: - Self-revoke results in permanent lockout (in lieu of sideband intervention)
- tests: none
- reason: Contradicts the implementation and the corpus: SPEC says a Level 1 self-revoke 'results in permanent lockout', while `principal.rs::self_revoke_last_key_prevented` and the golden vector `errors/last_key_revoke_fails` reject the last-key revoke with `NoActiveKeys`. Not resolved here. Question Q3.

```claim
kind: requirement
evaluator: none
```

### [sc-l463]

SPEC 4, line 463. Disposition: `red-new`.

- spec-line: 463
- source: rule
- disposition: red-new
- spec-text: Merkle tree primitive must support n-arity.
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s4_key_tree_supports_more_than_256_keys`
- fails when: the Key Tree refuses a key set beyond 256 keys (`CollectionArityExceeded`, a documented deferred gap in `error.rs`).

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

### [sc-l944]

SPEC 6, line 944. Disposition: `not-testable`.

- spec-line: 944
- source: rule
- disposition: not-testable
- spec-text: "prv": "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA" // Private component, never transmitted
- tests: none
- reason: A comment on `prv` in a key-file example; no protocol message carries a private component and no rejected input exists to test. The client keystore is the surface that owns it.

```claim
kind: requirement
evaluator: none
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
- fails when: the genuine pre-delete action is dropped after the delete, or a forged action backdated into the old active period is accepted. The test pins the implementation's fail-closed reading; the spec's position is open (forge issue #200). Question Q7.

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

SPEC 6.4, line 1058. Disposition: `red-existing`.

- spec-line: 1058
- source: rule
- disposition: red-existing
- spec-text: A revoke is a self-signed declaration that a key is compromised and should never
- tests:
  - `rs/cyphr/tests/key_auth.rs::d3_revoked_key_cannot_be_readded_by_key_create`
  - `rs/cyphr/tests/key_auth.rs::d3_revoked_key_cannot_be_readded_by_key_replace`
  - `rs/cyphr/tests/key_auth.rs::d3_revoked_key_cannot_sign_after_readd_attempt`
  - `rs/cyphr/tests/signer_seam.rs::revoked_signer_is_key_revoked`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/revoked_key_fails]`
- fails when: a revoked key is re-added by `key/create` or `key/replace` (red today, KA1T), or still signs a commit or action (green).

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

SPEC 6.4, line 1067. Disposition: `red-new`.

- spec-line: 1067
- source: rule
- disposition: red-new
- spec-text: > `rvk` and `now` must be a positive integer less than 2^53 – 1
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s6_4_revoke_rvk_must_be_a_positive_bounded_integer`
  - `rs/cyphr/tests/spec_conformance.rs::s6_4_revoke_now_must_be_a_positive_bounded_integer`
- fails when: an in-commit `key/revoke` with `rvk` of 0, a negative value or 2^53, or `now` of 0 or 2^53, is accepted (red today: both fields are plain `i64`; the naked-revoke path in the server bounds `rvk`).

```claim
kind: requirement
evaluator: none
```

### [sc-l1069]

SPEC 6.4, line 1069. Disposition: `red-new`.

- spec-line: 1069
- source: rule
- disposition: red-new
- spec-text: > IEEE754 minus one. Revoke checks must error if `rvk` is not an integer or
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s6_4_revoke_rvk_must_be_a_positive_bounded_integer`
  - `rs/cyphr-server/tests/naked_revoke.rs::rejects_malformed_rvk`
- fails when: a revoke check accepts a non-integer or oversized `rvk`: green on the naked-revoke path (`rejects_malformed_rvk`), red on the in-commit path.

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
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_errors[errors/action_revoked_key_fails]`
- fails when: a revoked key signs a commit, a push, a login or an action and is accepted. Differs in the in-tree SPEC.md: Q4.

```claim
kind: requirement
evaluator: none
```

### [sc-l1287]

SPEC 7.7, line 1287. Disposition: `not-testable`.

- spec-line: 1287
- source: rule
- disposition: not-testable
- spec-text: must be performed in exactly one canonical, atomic representation with no
- tests: none
- reason: A design principle ('each operation in exactly one canonical representation'), with no rejected input of its own.

```claim
kind: requirement
evaluator: none
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

SPEC 10.2, line 1673. Disposition: `out-of-scope`.

- spec-line: 1673
- source: rule
- disposition: out-of-scope
- spec-text: - The nonce's bit length must match the declared algorithm's output size (e.g.,
- tests: none
- reason: Nonces and embedding (Level 5+): no API in `rs/cyphr` accepts a nonce from outside (`derive` helpers take `Option<&[u8]>` and every caller passes none).

```claim
kind: requirement
evaluator: none
```

### [sc-l1674]

SPEC 10.2, line 1674. Disposition: `out-of-scope`.

- spec-line: 1674
- source: rule
- disposition: out-of-scope
- spec-text: a nonce declared as SHA-256 must be 256 bits). Bit-checking is the only
- tests: none
- reason: Same sentence as line 1673 (nonce bit length).

```claim
kind: requirement
evaluator: none
```

### [sc-l1676]

SPEC 10.2, line 1676. Disposition: `not-testable`.

- spec-line: 1676
- source: rule
- disposition: not-testable
- spec-text: - Nonce values should be cryptographic randomly generated values must match the
- tests: none
- reason: The sentence is ungrammatical ('should be cryptographic randomly generated values must match the target strength'), so which of should/must is intended is unknown. Question Q5. Nonces are also Level 5+.

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

SPEC 11.2, line 1862. Disposition: `red-new`.

- spec-line: 1862
- source: supplement
- disposition: red-new
- spec-text: unfrozen via `freeze/delete`. No mutations until unfrozen.
- tests:
  - `rs/cyphr/tests/spec_conformance.rs::s11_2_frozen_principal_rejects_key_mutations`
- fails when: a frozen principal accepts a key mutation (the same defect as line 252).

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
  - `rs/cyphr/src/principal.rs::key_create_on_deleted_principal_is_rejected`
  - `rs/cyphr/src/principal.rs::key_delete_on_deleted_principal_is_rejected`
  - `rs/cyphr/src/principal.rs::data_action_on_deleted_principal_is_rejected`
  - `rs/cyphr/tests/golden_fixtures.rs::test_golden_lifecycle[lifecycle/freeze_after_delete_is_rejected]`
- fails when: a deleted principal accepts a key mutation, a data action, or a freeze.

```claim
kind: requirement
evaluator: none
```

### [sc-l1875]

SPEC 11.2, line 1875. Disposition: `covered`.

- spec-line: 1875
- source: supplement
- disposition: covered
- spec-text: `Deleted` and `Frozen` are mutually exclusive (a principal cannot be frozen and
- tests:
  - `rs/cyphr/src/principal.rs::principal_delete_from_frozen_succeeds_and_clears_frozen`
  - `rs/cyphr/src/principal.rs::freeze_create_on_deleted_is_rejected`
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
  - `rs/cyphr/src/principal.rs::later_commit_bare_finalizer_on_already_deleted_is_rejected`
  - `rs/cyphr/src/principal.rs::self_revoke_on_deleted_principal_is_rejected`
- fails when: a later commit, including a bare finalizer, is accepted on a closed principal.

```claim
kind: requirement
evaluator: none
```

### [sc-l1951]

SPEC 11.5.1, line 1951. Disposition: `not-testable`.

- spec-line: 1951
- source: rule
- disposition: not-testable
- spec-text: Note the target account must explicitly add keys from the source account (if the
- tests: none
- reason: No explicit merge transaction exists in `rs/cyphr` (`CozKind` has no `principal/merge` or `merge-ack`), so there is no behaviour to fail; a red test cannot be written without inventing the API. Question Q6.

```claim
kind: requirement
evaluator: none
```

### [sc-l1953]

SPEC 11.5.1, line 1953. Disposition: `not-testable`.

- spec-line: 1953
- source: rule
- disposition: not-testable
- spec-text: must be explicitly added to the target. Also note that the source principal is
- tests: none
- reason: Same merge feature as line 1951: no implementation surface. Question Q6.

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
- fails when: a principal using an unsupported algorithm is accepted instead of refused as incompatible (the vector covers genesis; the `key/create` path returns `UnsupportedAlgorithm` untested).

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
- reason: Witness-side consensus states (Error, then Active on resolution) have no implementation in `rs/cyphr` or `rs/cyphr-server`, and the sovereignty-model rewrite of the consensus spec (campaign node D1) is open. Question Q8.

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
- reason: Depends on `resync/create`, which `rs/cyphr` has no coz kind for; the same witness-side surface as line 2814. Question Q8.

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
- fails when: an abandoned branch's commit is accepted onto the chosen chain (core replay; the witness-side half is Q8).

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
- reason: The Error-to-Active transition on resolution is witness-side consensus state, with no implementation surface; same as line 2814. Question Q8.

```claim
kind: requirement
evaluator: none
```

## Questions for the spec author

Each of these is a requirement the walk could not close without choosing a
reading, so it was left open.

- **Q1 (lines 127 and 129).** "All digest identifiers inside a coz must
  aligned with algorithm (`alg`) in `pay` unless explicitly labeled." The
  golden vector `algorithm_diversity/ed25519_account_adds_es256_key` has an
  Ed25519 coz introducing an ES256 key whose `id` is a SHA-256 thumbprint. Is
  a key's `id` computed under the signer's `alg` or the new key's own?
- **Q2 (line 248).** The capability gate's example says principal genesis is
  required for commits, but Level 1 has no commit and an implicit-genesis
  principal commits today. Which operations are rejected, at which levels,
  for lack of which component?
- **Q3 (lines 295 and 298).** Level 1 "never changes" and a self-revoke
  "results in permanent lockout", but §3.0 says a principal's level is not an
  authorization input, and the implementation and the corpus reject a
  last-key revoke with `NoActiveKeys` at every level. Which governs?
- **Q4 (line 1075).** At `be0663f`, "further use of the revoked key must be
  rejected." The in-tree text drops that sentence and says a naked revoke puts
  the principal in an error state. Was the removal deliberate? The tests that
  reject a revoked key stay green either way.
- **Q5 (line 1676).** "Nonce values should be cryptographic randomly
  generated values must match the target strength": should or must?
- **Q6 (lines 1951 and 1953).** Explicit merge has no transaction kind in the
  Rust crates. Is it in the Level 1-4 scope that the node list assumes?
- **Q7 (line 1002).** Does "past signatures from previous active periods
  remain valid" admit an action whose own `now` claims a past period but
  which arrives after the key was deleted? The implementation rejects it;
  forge issue #200 is open with the spec author.
- **Q8 (lines 2814, 2822 and 2829).** Witness-side fork resolution (the
  Error and Active consensus states, the `resync/create` transaction) has no
  implementation. The node that rewrites the consensus specification to the
  sovereignty model is open; is §15.8 still the requirement?
- **Q9 (lines 1067 and 1069).** "`rvk` and `now` must be a positive integer
  less than 2^53 - 1" and "must error if `rvk` is ... larger than 2^53 - 1":
  is 2^53 - 1 itself in range? The tests avoid the boundary value.

## Differences from the in-tree SPEC.md

Compared line by line against the in-tree `SPEC.md` at the base of this
node. Rows whose `be0663f` sentence does not appear verbatim in the in-tree
file:

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
KT and DR ordering note. Whether any of these supersede a mapped row is for
the spec author; no mapped test depends on them.
