# Record verification

This page names twelve rules a replay of a principal's record enforces, says
where each one lives in the code, and binds each to the test that fails when
the rule breaks. It also lists the further checks a replay makes that the
twelve do not cover. Where a claim has no bound test for part of what it says,
the page says so. It is a
reference: it describes the code at this revision, and it records two things
it cannot settle itself, a question for the spec author and a deferred
format decision.

SPEC references are to `SPEC.md` at commit `be0663f` on the spec author's
`zami` branch, the normative text.

## What a replay checks

A verifier that holds a trust anchor (SPEC §4.5) and a principal's commits
replays the commits in order and either accepts every one or stops at the
first that fails a check. A record is **honest** when its replay from the
anchor to the tip accepts every commit. Honesty is a property of the record
against its commitment. It does not depend on how the record reached the
verifier or on what any server would have admitted. The twelve rules below
are the ones this page classifies and binds. Replay makes further checks, listed
under [Further checks a replay makes](#further-checks-a-replay-makes), so
passing the twelve is necessary for honesty and is not shown to be sufficient.

Two scoping facts come from SPEC, not from this page:

- The rules range over the auth chain. SPEC §2.3.3 makes the Auth Tree
  append-only, `pre`-chained and replayed from genesis, and the Data Tree
  mutable and chainless. Data content has no rules of its own. Only its digest
  (DR) takes part, through rule 7.
- Tip currency, fork resolution and witness exchange sit above the record.
  They decide whether a view is current and unique, never whether a record is
  honest. Their text is in the Extended part of SPEC (from §13), which is in
  flux; no rule below depends on it, except as the question under
  [Question for the spec author](#question-for-the-spec-author) records.

## The twelve rules

Each rule carries a **class** that names the shape of its check:

- **A**: commit-local. The check reads one coz, or the cozies of one commit,
  and nothing from earlier commits.
- **B**: adjacent pair. The check compares a commit with the one before it.
- **C**: bounded backward reference. The check reads state, or key material,
  built by earlier commits, such as a key's registration or whether a value
  was already written. A succinct verifier can certify it only incrementally,
  forward from a verified checkpoint.
- **D**: keyed. The check asks whether a value already occurs in this
  principal's record.

| #   | Rule                                                              | SPEC           | Class | Error                                  | Claim                                           |
| :-- | :---------------------------------------------------------------- | :------------- | :---- | :------------------------------------- | :---------------------------------------------- |
| 1   | A coz carries `tmb`, `now`, `typ` and `alg`; encodings canonical  | §2.2.2, §2.3.1 | A     | `MalformedPayload`, `AlgMismatch`      | [rv-coz-wellformed](#rv-coz-wellformed)         |
| 2   | `pay.alg` equals the signing key's algorithm; `czd` recomputes    | §2.2.3, §12    | C     | `AlgMismatch`, `CzdMismatch`           | [rv-alg-alignment](#rv-alg-alignment)           |
| 3   | The signature verifies under the key named by `tmb`               | §7.1           | C     | `InvalidSignature`                     | [rv-sig-verifies](#rv-sig-verifies)             |
| 4   | A self-revoke's `now` is a positive integer within 2^53 - 1       | §6.4           | A     | `MalformedPayload`                     | [rv-timestamp-range](#rv-timestamp-range)       |
| 5   | A coz's `now` is never earlier than the principal's latest        | §13.2, §15.9   | B     | `TimestampPast`                        | [rv-timestamp-monotone](#rv-timestamp-monotone) |
| 6   | An `arrow` binds a commit to the prior PR                         | §4.2, §4.3     | B     | `CommitMismatch`                       | [rv-arrow-chain](#rv-arrow-chain)               |
| 7   | The `arrow` binds the recomputed forward state                    | §3.7, §4.2     | C     | `CommitMismatch`                       | [rv-state-recomputed](#rv-state-recomputed)     |
| 8   | The signer is an active key when the coz is applied               | §2.3.2, §6     | C     | `UnknownKey`, `KeyRevoked`             | [rv-key-active-gate](#rv-key-active-gate)       |
| 9   | A frozen principal takes no mutation; a deleted one takes nothing | §2.3.2, §11.2  | C     | `Frozen`, `AlreadyDeleted`             | [rv-lifecycle-gate](#rv-lifecycle-gate)         |
| 10  | The Principal Genesis is written once                             | §2.3.2, §5     | C     | `StateMismatch`                        | [rv-genesis-immutable](#rv-genesis-immutable)   |
| 11  | The commit coz is last; a grouped transaction shares one `typ`    | §4.1, §4.6     | A     | `CommitNotLast`, `MixedTransactionTyp` | [rv-intra-commit-shape](#rv-intra-commit-shape) |
| 12  | A coz this principal already included is refused or ignored       | §7.6           | D     | `CozReuse` (transactions); none (data) | [rv-no-coz-reuse](#rv-no-coz-reuse)             |

Rules 8 and 9 read the state that rule 7 recomputes, and each names a
distinct way a record can be dishonest, so each has its own claim and its own
test. A principal whose last key is revoked is Dead (SPEC §11.2). The code has
no gate for that state: such a principal's coz is refused by rule 8, because
its only signer is revoked. The error names are variants of `cyphr::Error`
(`rs/cyphr/src/error.rs`).

### Reading a claim

Each claim below is a docket claim: a `[kebab-id]` heading followed by a
`claim` block. `evaluator: test` means a test is bound to the claim through an
`@docket:` marker at the test and an entry in `scripts/docket-run`, and
`scripts/docket-run <id>` runs every test the rule rests on. All twelve
claims are bound this way.

The binding is narrower than the rule in places. Each claim ends with what
its tests do not check, and says which tests carry a control (a variant of the
scenario that must succeed, so the rejection can only be the rule).

### Coz shape and signature

#### [rv-coz-wellformed]

A coz that omits `tmb`, `now` or `typ` is rejected as `MalformedPayload`, and
one that omits `alg` is rejected as `AlgMismatch`. A rejected coz leaves the
principal's state untouched. A `key/create` whose `id` is a non-canonical
base64url spelling of the new key's thumbprint is rejected, so one key has one
spelling.

```claim
kind: requirement
evaluator: test
```

Backed by `s2_3_1_coz_missing_tmb_now_or_typ_is_rejected`,
`s2_3_1_coz_missing_alg_is_rejected` and
`s2_2_2_non_canonical_b64ut_is_rejected` in
`rs/cyphr/tests/spec_conformance.rs`. Each is an end-to-end scenario (sign,
verify, apply, finalize). The first and third carry a control that accepts the
well-formed coz; the `alg` test has no control. All three assert only that the
coz is rejected, not which error. The error names come from the code:
`ParsedCoz::from_pay` (`rs/cyphr/src/parsed_coz.rs`) checks `tmb`, `now` and
`typ`, and `verify_coz` and the data-action path return `AlgMismatch` for an
absent or different `alg`. Not checked: non-canonical encoding in fields other
than `id`, and the error type of any of these rejections.

#### [rv-alg-alignment]

A coz whose `pay.alg` differs from the signing key's algorithm is rejected on
both the data-action path and the commit-coz path, and a caller-supplied `czd`
that is not the digest of the signed bytes is never recorded.

```claim
kind: requirement
evaluator: test
```

Backed by `d4_action_pay_alg_must_equal_key_alg`,
`d4_commit_coz_pay_alg_must_equal_key_alg`, their ES256 variants,
`d4_wrong_caller_czd_is_not_recorded_for_actions` and
`d4_wrong_caller_czd_is_not_recorded_for_commit_cozies`, all in
`rs/cyphr/tests/key_auth.rs`; the marker sits at the commit-coz test and the
runner entry runs all six. `d4_control_es256_matching_alg_action_accepted` is
the control for the action path and is not in the runner entry. The rule is
class C because it compares the coz with the registered key. Not checked by
these tests: the SPEC §2.2.3 statement that the digest algorithm of a new key's
`id` follows its `alg`, which a golden vector (`ed25519_account_adds_es256_key`)
pins.

#### [rv-sig-verifies]

A signature has one accepted encoding, and one that does not verify is
rejected with `InvalidSignature`. An ES256 signature with a high `S`, and an
Ed25519 signature whose `s` is shifted by the group order, both verify
mathematically; both are rejected, because the coz digest `czd` covers the
signature and a second encoding would give one signed action two identities.

```claim
kind: requirement
evaluator: test
```

Backed by `es256_high_s_signature_is_rejected` and
`ed25519_non_canonical_s_is_rejected` in `rs/cyphr/tests/negative_vectors.rs`,
byte-level vectors built from the group orders that assert
`InvalidSignature`. They pin the encoding rule. The signature check itself is
in `verify_coz` and the data-action path. Not bound here: the property test
`any_non_verifying_signature_never_commits` in
`rs/cyphr/tests/signer_seam.rs`. It covers arbitrary bytes and bit flips from a
faulty signer on the finalize path only, so it does not back this claim for
other paths.

### Timestamps

#### [rv-timestamp-range]

A self-revoke whose `now` is zero, negative or above 2^53 - 1 is rejected, and
`now` equal to 2^53 - 1 is accepted. SPEC §6.4 states the bound for `rvk` and
`now` on a revoke; the code reads the bound as inclusive, which SPEC §6.4 does
not state consistently (see
[Question for the spec author](#question-for-the-spec-author)).

```claim
kind: requirement
evaluator: test
```

Backed by `s6_4_revoke_now_must_be_a_positive_bounded_integer` in
`rs/cyphr/tests/spec_conformance.rs`, which tests zero, a negative, and 2^53,
with controls at `T` and 2^53 - 1. It asserts rejection, not the error type.
This is narrower than a general "timestamp in range" rule. SPEC §4.1 states no
range for the `now` of other cozies, and the code bounds only the revoke
(`ParsedCoz::from_pay`). SPEC §15.9 gives a default tolerance of 360 seconds
against witness time; the implementation leaves its future-dated check off by
default (`max_clock_skew` is 0), and the test that would require it is ignored
as `RED(SC1-F5)` in `spec_conformance.rs`. Not checked: `now` on any coz other
than a self-revoke, and the future-dated check.

#### [rv-timestamp-monotone]

A coz whose `now` is earlier than the latest timestamp the principal has
recorded is rejected with `TimestampPast`, on both the transaction path and
the data-action path. A coz whose `now` equals the latest is accepted by this
rule.

```claim
kind: requirement
evaluator: test
```

The code is `apply_transaction_internal` in
`rs/cyphr/src/principal/apply.rs` and `record_action` in
`rs/cyphr/src/principal/data.rs`; both compare `now` with `latest_timestamp`
using a strict `<`. Two golden vectors pin the rejection, `timestamp_past_fails`
and `action_timestamp_past_fails` in `tests/golden/errors/`. The marker sits at
`test_golden_errors` in `rs/cyphr/tests/golden_fixtures.rs`, and the runner
entry runs that whole test. It runs every vector in `tests/golden/errors/`, not
only the two timestamp ones, so the binding fails if any error vector fails; the
two timestamp vectors are the part that backs this claim. Equal `now` is
accepted, and two things pin it: in `timestamp_past_fails` the first commit's
`commit/create` coz carries the same `now` as its transaction and the commit
applies; and the rule 12 reuse scenario replays a coz at the same `now` and is
refused as `CozReuse`, not `TimestampPast`. Not checked by any bound test: that
a coz rejected for `TimestampPast` leaves state unchanged (the golden vectors
assert only the error). The SPEC wording that governs the boundary is the
subject of [Question for the spec author](#question-for-the-spec-author).

### Chain and state

#### [rv-arrow-chain]

The finalizing `commit/create` coz carries an `arrow` over the prior PR
(`pre`), the forward SR and the transactions. A replayer recomputes the
`arrow`, and a commit whose `arrow` does not match is rejected with
`CommitMismatch`. A second commit built on a `pre` the chain has already moved
past is therefore refused, and the chain keeps its first branch.

```claim
kind: requirement
evaluator: test
```

Backed by two tests. `test_finalize_commit_rejects_tampered_arrow` in
`rs/cyphr/tests/properties.rs` is a property test: for a genuinely signed
commit coz whose `arrow` has one byte changed, signature verification
succeeds and only `finalize()` catches the change.
`s2_3_2_second_commit_on_a_stale_pre_is_rejected` in `spec_conformance.rs` is
the two-peer scenario: two authorized commits branch from one ancestor, and a
replayer that applied the first rejects the second with `CommitMismatch` and
keeps its state; it carries controls. The check lives in `finalize_commit`
(`rs/cyphr/src/principal/apply.rs`). Fork evidence tests in
`rs/cyphr/tests/fork_evidence.rs` show that each branch of a fork verifies
alone from the ancestor; they back the equivocation page, not this claim, and
the linear replayer there fails on `UnknownKey`, not on the arrow. Not checked:
that commits are never removed from the chain (append-only), and replay through
the durable storage in `rs/cyphr-storage`; these tests use the core principal
alone.

#### [rv-state-recomputed]

A replay recomputes the forward state the `arrow` commits to, the data root
included, and a commit whose signed `arrow` was made over different state is
rejected. A forged data action spliced into the history before a commit cannot
be hidden by replaying the commit's own cozies.

```claim
kind: requirement
evaluator: test
```

Backed by `forged_action_spliced_before_delete_commit_breaks_replay` in
`rs/cyphr/tests/negative_vectors.rs`. The scenario replays one real delete
commit twice, once without and once with a forged action inserted before it;
every coz verifies on its own, the honest replay (the control) finalizes, and
the forged one fails with `CommitMismatch`. The same `arrow` check as rule 6
closes it, and the two claims differ in the component each pins: `pre` for
rule 6, the forward state for rule 7. Not checked by a named test: a
root-by-root comparison of replayed SR, AR, KR, CR and PR with roots a server
published.

### Authorization and lifecycle

#### [rv-key-active-gate]

A coz is accepted only if its signer is an active key in the principal at the
position the coz is applied, with two exceptions the code makes. A
`commit/create` coz skips the active check in `apply_transaction_internal`,
because the finalizer is authorized against the key set from before the
commit, and an earlier mutation in the same commit may have replaced its
signer. A self-revoke also skips it, since the key revokes itself. A deleted
key's action is rejected whether dated after the delete or backdated into the
key's old active period, and a key that is not active cannot authorize its own
admission.

```claim
kind: requirement
evaluator: test
```

Backed by `deleted_key_action_dated_after_delete_is_rejected` and
`deleted_key_action_backdated_into_old_active_period_is_rejected` in
`rs/cyphr/tests/negative_vectors.rs`, and
`s2_3_2_inactive_key_cannot_authorize_its_own_admission` in
`spec_conformance.rs`. Only the last carries a control (an active key may admit
the same key); the two negative-vector tests have none. The backdated case pins
the implementation's fail-closed reading, which tests the signer against
current key membership and ignores the payload `now`. SPEC §6.2 says past
signatures from earlier active periods remain valid but does not say whether a
signer-dated action claiming such a period is accepted on replay, so that test
pins behaviour, not a ruling. Not bound here: the two exceptions themselves,
that a replaced signer of the finalizer is accepted, the `KeyRevoked` path
(`revoked_signer_is_key_revoked` in `rs/cyphr/tests/signer_seam.rs`) and the
revoked-key re-add refusals in `rs/cyphr/tests/key_auth.rs`.

#### [rv-lifecycle-gate]

A frozen principal refuses key mutations and data actions until it is thawed,
and thawing restores it. The freeze, thaw, close and finalizer cozies are
exempt from the frozen gate. A principal whose last key is revoked, a Dead
principal, takes no transaction or action, and a Deleted principal (after
`principal/delete`) takes nothing but its close and lifecycle cozies.

```claim
kind: requirement
evaluator: test
```

The gates are in `apply_transaction_internal`
(`rs/cyphr/src/principal/apply.rs`): `AlreadyDeleted` for the Deleted state and
`Frozen` for the Frozen state, plus the data-action path in
`verify_and_record_action`. Backed by
`s11_2_frozen_principal_rejects_key_mutations` and
`frozen_principal_rejects_data_actions_until_thawed`, each with a control that
shows the refusal is the freeze, and by
`s11_2_dead_principal_accepts_no_transaction_or_action` in
`rs/cyphr/tests/spec_conformance.rs`. Three limits on that last test. There is
no Dead gate: a Dead principal's coz is refused by the revoked-signer check of
rule 8 (`active_signer` returns `KeyRevoked`). The test has no control. It
asserts only that the key/create and the data action are refused, not which
error. Not checked by any bound test: refusal after `principal/delete`, which
the code reports as `AlreadyDeleted` and no test bound here exercises.

#### [rv-genesis-immutable]

The Principal Genesis, once written by `principal/create`, is never changed. A
second `principal/create` is refused with `StateMismatch`, and key creation,
replacement, deletion of a genesis key and revocation leave the recorded PG
as it was.

```claim
kind: requirement
evaluator: test
```

Backed by `s2_3_2_no_operation_changes_the_principal_genesis` in
`rs/cyphr/tests/spec_conformance.rs`, which asserts `StateMismatch` for the
second create. The rule is class C because it depends on whether a PG was
already written. Not bound here: that a genesis is well-formed.
`d1_implicit_genesis_rejects_unbound_key` and its siblings in
`rs/cyphr/tests/key_auth.rs` pin that a genesis key must bind its own
thumbprint.

### Commit structure and reuse

#### [rv-intra-commit-shape]

The `commit/create` coz must be the last coz of a commit, and a commit with
the finalizer elsewhere is rejected with `CommitNotLast`. Cozies grouped into
one transaction through `CommitScope::apply_tx` must carry an identical `typ`,
and a mixed group is rejected with `MixedTransactionTyp`. Both statements hold
for the code as it is; the known defect below says what replay does not do.

```claim
kind: requirement
evaluator: test
```

Backed by `s4_6_commit_coz_must_be_last_in_txs` and
`s4_1_transaction_cozies_must_share_one_typ` in
`rs/cyphr/tests/spec_conformance.rs`. The first asserts `CommitNotLast`; the
second asserts `MixedTransactionTyp` and has a control (a same-typ group
applies). The finalizer-position check is in `finalize_commit`, so it holds on
every path that finalizes a commit.

**Known defect.** The implementation does not honour transaction grouping.
SPEC §4.6.2 makes grouping part of the wire format (`txs` is a list of lists),
and SPEC §3.7.5 makes it a hash input: `TX = MR(czd₀, czd₁?, …)` and
`TR = MR(TXₘ₀?, …, TX꜀)`. Ingest drops the grouping and applies each coz as its
own transaction, through `verify_and_apply`, which groups nothing. For any
transaction with more than one coz, the computed TR, and therefore CR and PR,
differ from the values the specification defines. The shared-`typ` rule of
SPEC §4.1 is likewise not enforced at replay: it is checked only by
`CommitScope::apply_tx`, which has no production caller
(`git grep -n "apply_tx(" -- rs` finds only the definition and tests in
`spec_conformance.rs`). The bound tests therefore pin the `apply_tx` API
behaviour, not replay, and no bound test shows the grouping defect. Not
checked: that the order of transactions inside a commit survives storage and
replay unchanged. That is a property of the storage engine
(`rs/cyphr-storage`), outside these tests.

#### [rv-no-coz-reuse]

A transaction coz this principal already included is rejected with the typed
`CozReuse`, whatever its timestamp or the principal's state, and the first
inclusion stays authoritative. The check is per principal: another principal
that shares the keys may apply the same coz. It compares the whole `czd`, so a
coz signed under a wider digest (ES384) is recognised. The other half of SPEC
§7.6 differs in kind: a replayed data action is ignored and produces no state
change, and `verify_and_record_action` returns `Ok` for it (`data.rs`, the
`included_czds` check after the `czd` is proven).

```claim
kind: requirement
evaluator: test
```

Backed by `s7_6_transaction_coz_reuse_by_the_same_principal_is_rejected`,
`s7_6_reuse_is_typed_and_scoped_to_one_principal` and
`multihash_replay_of_an_es384_signed_coz_is_reuse` in
`rs/cyphr/tests/spec_conformance.rs`, and, for the data-action half,
`prop_data_action_replay_is_idempotent` in `rs/cyphr/tests/properties.rs`. The
reuse test replays with equal timestamps so the timestamp rule cannot be the
rejecter, and a cross-principal control catches a process-global set. The
property test asserts that replaying a data action changes no state, and it
accepts `Ok` or `Err`, so the `Ok` return is read from the code and not pinned
by a test. The server maps the error to a refusal
(`rs/cyphr-server/tests/coz_reuse.rs`), which this claim does not bind. The set
is `included_czds` on the principal's core, filled as each coz is applied. It is
not part of any committed root in this code, so a verifier that holds only a
commitment cannot check reuse without the history.

## Further checks a replay makes

The twelve are not everything replay enforces. These checks also reject a
record. They have no docket claim; the last column names the test that exercises
each, found by search, not bound to a claim here. "None found" means no test
turned up for that check.

| Check                                                         | Error                             | Where                                    | Test that exercises it                                                                       |
| :------------------------------------------------------------ | :-------------------------------- | :--------------------------------------- | :------------------------------------------------------------------------------------------- |
| `key/create` of a key already in the key set                  | `DuplicateKey`                    | `apply_transaction_internal`             | golden vector `duplicate_key_fails`                                                          |
| `key/create` or `key/replace` of a revoked key                | `KeyRevoked`                      | `apply_transaction_internal`             | `d3_revoked_key_cannot_be_readded_by_key_create` and `_by_key_replace` in `key_auth.rs`      |
| Removing or self-revoking the last key                        | `NoActiveKeys`                    | `remove_key`, `revoke_key`               | golden vectors `delete_last_key_fails`, `last_key_revoke_fails`                              |
| `rvk` outside 1 to 2^53 - 1, or `id` present on a revoke      | `MalformedPayload`                | `ParsedCoz::parse_kind`                  | `s6_4_revoke_rvk_must_be_a_positive_bounded_integer`; golden vector `revoke_non_self_fails`  |
| The revealed `pub` does not hash to the signed `id`           | `MalformedPayload`, `TmbMismatch` | `apply_transaction_internal`, `Key::new` | `d1_key_create_rejects_victim_tmb_with_attacker_pub` in `key_auth.rs`                        |
| A lifecycle coz's `id` is not the current PR                  | `StateMismatch`                   | `apply_transaction_internal`             | none found                                                                                   |
| `freeze/create` when frozen; `freeze/delete` when not frozen  | `AlreadyFrozen`, `NotFrozen`      | `apply_transaction_internal`             | unit tests in `rs/cyphr/src/principal/tests/lifecycle.rs`                                    |
| A commit with only a finalizer, or without a terminal `arrow` | `EmptyCommit`, `MissingCommit`    | `finalize_commit`                        | unit tests in `rs/cyphr/src/commit.rs`                                                       |
| A `pre` field on a data action                                | `MalformedPayload`                | `verify_and_record_action`               | intent `data_action_constraints.toml` (tag `[data-action-no-pre]`) through the golden runner |
| A `typ` the parser does not know                              | `MalformedPayload`                | `ParsedCoz::parse_kind`                  | `parse_unknown_typ_fails` in `rs/cyphr/src/parsed_coz.rs`                                    |
| A durable leaf at a commit's position differs from its new TR | `DurableLeafMismatch`             | `finalize_commit`                        | `rs/cyphr-storage/tests/durable_commit_trees.rs`                                             |

## Rules by proof form

The rules do not all admit the same succinct proof. This is analysis of the
rules' shape from the classes above; no code builds these proofs, and no test
in this repository checks the cost figures. `n` is the number of commits.

| Rules             | Form                    | What a verifier can hold                                                         |
| :---------------- | :---------------------- | :------------------------------------------------------------------------------- |
| 1, 4, 5, 6, 11    | one-shot fold           | the whole record in `O(log n)` against the commitment, given committed summaries |
| 2, 3, 7, 8, 9, 10 | incremental certificate | `O(log n)` per root transition forward of a verified checkpoint                  |
| 12                | keyed index             | `O(log n)` per lookup against a committed keyed-tree root                        |

- A **one-shot fold** has a commit-local or adjacent-pair measure, so a
  summary of a range can be combined associatively.
- An **incremental certificate** cannot be cold-succinct: rule 7's composed
  state grows with the state, not with the log of the range, and rules 2, 3, 8,
  9 and 10 read state or key material at each position. What holds is a proof
  bounded up to a verified checkpoint (SPEC §8.3). The distance a verifier
  replays is bounded by its checkpoint interval, never by the chain length.
- A **keyed index** answers "is this value already included" in `O(log n)`
  once its root is committed. The protocol commits no such root today, and
  the global negative, that no duplicate occurs anywhere, costs a linear
  replay without it.

Replay today is the cold stance: `O(n)` once, each commit checked against the
rules above and the further checks.

## What is outside the rules

Besides the further checks above, these fall outside the record rules:

- **Server admission policy**: clock-skew tolerance, rate limits, the error
  taxonomy, atomic rejection. A record does not become dishonest because a
  server would have refused it, nor honest because one admitted it.
- **Wire and API shape**: envelopes, plural forms, bearer tokens, login.
- **Liveness**: proof of possession, witnesses, fork detection and
  resolution, gossip. They are non-monotone. The record-layer residue of a
  fork, two commits naming one `pre`, is caught by rule 6.
- **Data-tree content**: application-defined (SPEC §2.3.3).

Per-verb authority statements and lifecycle-matrix rows restate rules 8 and 9
at finer grain.

An embedded principal (SPEC §10.3) is not verified by the rules above alone.
SPEC §10.3 requires the tip of the referenced principal to be retrieved at
verification time for PG, PR and AR nodes, which is a retrieval across logs and
sits in the liveness group. Whether the referenced principal's own record is
honest is the same question applied to that log. No code or test in this page
covers embedding.

Known gap: recovery and merge (SPEC §11.4, §11.5) add record-layer rules once
their text settles. The merge acceptance tests in `rs/cyphr/tests/merge.rs`
are ignored as red today, and no merge rule is among the twelve.

## Question for the spec author

**Where should timestamp monotonicity live?** Rule 5 is the one rule that
other mechanisms lean on: an adjacent-pair timestamp argument and any
timestamp-based lease are sound only if `now` never decreases along the
chain. The implementation enforces it (`TimestampPast`). The SPEC text that
states it is in the Extended part: SPEC §15.9 ("rejecting any now earlier than
latest known timestamp") and the replay list in SPEC §13.2 ("`now` is after
previous transaction"), both in sections marked as in flux. The core commit
rules (SPEC §4) do not mention it.

1. Should the rule be promoted into §4 so the core record rules state it?
2. The two statements differ at equality. §15.9 rejects only a `now` earlier
   than the latest, which the code does with a strict comparison. §13.2's "is
   after" reads as strictly later. Which is intended for two cozies with the
   same `now`? The code accepts them.
3. SPEC §4.1 states no range for `now`, while §6.4 bounds it on a revoke
   (rule 4) and §15.9 gives a default tolerance against witness time. Is a
   general positive-and-bounded rule for `now` intended?

4. SPEC §6.4 states the revoke bound twice: "a positive integer less than
   2^53 – 1" and "must error if `rvk` is not an integer or larger than
   2^53 - 1". The first excludes 2^53 - 1 and the second allows it. The code
   reads the bound as inclusive (`coz::is_valid_rvk`: positive and at most
   2^53 - 1), and a bound test accepts 2^53 - 1. Which is intended?

Until the spec author answers, this page states rule 5 as the code and the
Extended text describe it and treats the equality case as unspecified.

## Deferred: where fold summaries are committed

Every `O(log n)` figure above assumes that summaries of ranges of the record
are committed where a verifier can authenticate them: in an interior slot of
the Merkle structure, or as summary claims appended to the record. The
format of that commitment is **deferred**: no code or SPEC text defines it,
and nothing here depends on it, because replay needs no summary. The
placement decides the shape of every succinct proof, and a rule-12 keyed
root would need the same decision.

**Signpost.** Decide the format before the 1.0 hash-format freeze or before
the first consumer of an `O(log n)` proof, whichever comes first. A committed
format cannot change without changing the roots it feeds, so a decision after
the freeze costs a protocol version.
