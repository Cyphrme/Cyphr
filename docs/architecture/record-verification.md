# Record verification

This page names twelve rules a replay of a principal's record enforces, says
where each one lives in the code, and binds each to the test that fails when
the rule breaks. It also lists, for every error the core can raise, the claim that
governs it. The page is complete for errors, not for checks: a check that
raises an error listed under another claim appears, if at all, as a sentence in
the claim that governs that error. The completeness has two caveats: the
`Coz` error variant, which wraps `coz::Error`, is classified outside the core
paths and has no row, and which errors are reachable on the core paths is
classified by hand in the test, not derived from the code. Where a claim has no bound test for part of what it says,
the page says so. It is a reference: it describes the code at this revision,
and it records a question for the spec author, a known defect and a deferred
format decision.

**Scope.** The rules and claims describe the core apply, finalize and record
paths of the `cyphr` crate: `CommitScope::verify_and_apply`, `finalize` and
`Principal::verify_and_record_action`. Every bound test uses the core
principal directly. Replay from storage reaches the same core paths but differs
before and around them; [Storage replay](#storage-replay) points to where
that is specified.

SPEC references are to `SPEC.md` at commit `be0663f` on the spec author's
`zami` branch, the normative text.

## What a replay checks

A verifier that holds a trust anchor (SPEC §4.5) and a principal's commits
replays the commits in order and either accepts every one or stops at the
first that fails a check. A record is **honest** when its replay from the
anchor to the tip accepts every commit. Honesty is a property of the record
against its commitment. It does not depend on how the record reached the
verifier or on what any server would have admitted. The twelve rules below
are the ones this page classifies; further claims cover the other checks the
core makes, and [Errors by claim](#errors-by-claim) maps every error to one.
Passing the twelve is necessary for honesty and is not shown to be sufficient.

Two scoping facts come from SPEC, not from this page:

- The rules range over the auth chain. SPEC §2.3.3 makes the Auth Tree
  append-only, `pre`-chained and replayed from genesis, and the Data Tree
  mutable and chainless. Data content is application-defined, but a data
  action is a coz and is bound by the coz rules: 1, 2, 3, 5, 8, 9 and 12 apply to
  it, and its digest (DR) takes part in rule 7.
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

| #   | Rule                                                              | SPEC           | Class | Claim                                           |
| :-- | :---------------------------------------------------------------- | :------------- | :---- | :---------------------------------------------- |
| 1   | A coz carries `tmb`, `now`, `typ` and `alg`; encodings canonical  | §2.2.2, §2.3.1 | A     | [rv-coz-wellformed](#rv-coz-wellformed)         |
| 2   | `pay.alg` equals the signing key's algorithm; `czd` recomputes    | §2.2.3, §12    | C     | [rv-alg-alignment](#rv-alg-alignment)           |
| 3   | The signature verifies under the key named by `tmb`               | §7.1           | C     | [rv-sig-verifies](#rv-sig-verifies)             |
| 4   | A self-revoke's `now` is a positive integer within 2^53 - 1       | §6.4           | A     | [rv-timestamp-range](#rv-timestamp-range)       |
| 5   | A coz's `now` is never earlier than the principal's latest        | §13.2, §15.9   | B     | [rv-timestamp-monotone](#rv-timestamp-monotone) |
| 6   | An `arrow` binds a commit to the prior PR                         | §4.2, §4.3     | B     | [rv-arrow-chain](#rv-arrow-chain)               |
| 7   | The `arrow` binds the recomputed forward state                    | §3.7, §4.2     | C     | [rv-state-recomputed](#rv-state-recomputed)     |
| 8   | The signer is an active key when the coz is applied               | §2.3.2, §6     | C     | [rv-key-active-gate](#rv-key-active-gate)       |
| 9   | A frozen principal takes no mutation; a deleted one takes nothing | §2.3.2, §11.2  | C     | [rv-lifecycle-gate](#rv-lifecycle-gate)         |
| 10  | The Principal Genesis is written once                             | §2.3.2, §5     | C     | [rv-genesis-immutable](#rv-genesis-immutable)   |
| 11  | The commit coz is last; transaction grouping (known defect)       | §4.1, §4.6     | A     | [rv-intra-commit-shape](#rv-intra-commit-shape) |
| 12  | A coz this principal already included is refused or ignored       | §7.6           | D     | [rv-no-coz-reuse](#rv-no-coz-reuse)             |

Rules 8 and 9 read the state that rule 7 recomputes, and each names a
distinct way a record can be dishonest, so each has its own claim and its own
test. A principal whose last key is revoked is Dead (SPEC §11.2). The code has
no gate for that state; replay reaches it, because revoking the last key is
accepted (SPEC §3.1). A Dead principal's coz is refused by rule 8, because its
only signer is revoked. Error names are
variants of `cyphr::Error` (`rs/cyphr/src/error.rs`).

### Reading a claim

Each claim below is a docket claim: a `[kebab-id]` heading followed by a
`claim` block. `evaluator: test` means a test is bound to the claim through an
`@docket:` marker at the test and an entry in `scripts/docket-run`, and
`scripts/docket-run <id>` runs every test the rule rests on. All twelve
claims are bound this way.

The binding is narrower than the rule in places. Each claim ends with what
its tests do not check, and names a control (a variant of the scenario that must
succeed, so the rejection can only be the rule) where it knows of one.

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
absent or different `alg`. The data-action path
(`verify_and_record_action`) reads `tmb`, `now` and `typ` and returns
`MalformedPayload` when one is absent, and checks `alg` the same way as
`verify_coz`; no bound test sends a data action with a field missing. Also
refused as `MalformedPayload`, with no bound test: a data action that carries
`pre`, a `typ` the parser does not know, and an `id` on a self-revoke
(`verify_and_record_action` and `ParsedCoz::parse_kind`). An unknown `typ` is
refused only on the transaction path (`parse_kind`); a data action accepts any
`typ`. Tests that exercise these exist elsewhere: the `t2_f15_*` cases in
`tests/e2e/e2e_features.toml`, which run through storage replay and not the
core path, `parse_unknown_typ_fails` in `rs/cyphr/src/parsed_coz.rs`, and the
golden vector `revoke_non_self_fails`. Not checked: non-canonical encoding in fields
other than `id`, the data-action path, and the error type of any of these
rejections.

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
runner entry runs all six. The bound commit-coz tests send a `key/create`
through `verify_and_apply`; none sends a `commit/create` finalizer whose `pay.alg`
differs from its signer's, and the finalizer's `alg` is taken from the stored
key, so that case has no test. `d4_control_es256_matching_alg_action_accepted` is
the control for the action path and is not in the runner entry. The rule is
class C because it compares the coz with the registered key. Not checked by
these tests: SPEC §2.2.3's statement that digest identifiers in a coz align
with its `alg`. How that applies to a key of another algorithm is a question
for the spec author (see below); the golden vector
`ed25519_account_adds_es256_key` records what the implementation does and
settles nothing.

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
`InvalidSignature`. Each has a control: the canonical encoding of the same payload is
accepted. They cover ES256 and Ed25519 only; no bound test covers the encoding
rule of another algorithm. Both feed `verify_and_record_action`, so they
exercise the data-action path only: no bound test exercises `verify_coz` or the
transaction path, where the same check lives. Not bound here: the property test
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
against witness time; the implementation applies it by default
(`max_clock_skew` is 360, and 0 means no tolerance, not "off"). Every coz and
action `now` is also bounded to `1..2^53-1` and by the verifier clock, covered
in `spec_conformance.rs` and `rs/cyphr-server/tests/now_range.rs`.

#### [rv-timestamp-monotone]

A coz whose `now` is earlier than the latest timestamp the principal has
recorded is rejected with `TimestampPast`, on both the transaction path and
the data-action path. A coz whose `now` equals the latest is accepted by this
rule. The latest timestamp is the chain's: its commits' cozies and the data
actions a `ds/create` included. A pending action also bounds later actions,
which stay in `now` order (SPEC 4.8.1), but bounds no commit, and an action a
`ds/create` left out bounds nothing.

```claim
kind: requirement
evaluator: test
```

The code is `apply_transaction_internal` in
`rs/cyphr/src/principal/apply.rs` and `record_action` in
`rs/cyphr/src/principal/data.rs`; both compare `now` with a strict `<`, the
first against `latest_timestamp`, the second against `latest_now` (that and
the pending actions' newest `now`). `left_out_action_does_not_bound_time` in
`rs/cyphr-storage/tests/action_inclusion.rs` pins that a left-out action
bounds no later commit. Two golden vectors pin the rejection, `timestamp_past_fails`
and `action_timestamp_past_fails` in `tests/golden/errors/`. The marker sits at
`test_golden_errors` in `rs/cyphr/tests/golden_fixtures.rs`, and the runner
entry runs that whole test. It runs every vector in `tests/golden/errors/`, not
only the two timestamp ones, so the binding fails if any error vector fails; the
two timestamp vectors are the part that backs this claim. Equal `now` is
accepted, and two accepted scenarios pin it: in `timestamp_past_fails` the first
commit's `commit/create` coz carries the same `now` as its transaction and the
commit applies, and the rule 12 reuse fixture applies several cozies at one
`now` before the replay. The reuse refusal itself says nothing about `<`,
because the reuse check runs before the timestamp check
(`apply_transaction_internal`). Not checked by any bound test: that
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
enter the commit's state: the commit's `ds/create` names DR = MR(DT) over the
action bundles its signer included (SPEC 4.8.2), so a replay includes exactly
the pending bundles whose root is that `id` and leaves the spliced one out. A
`ds/create` whose `id` no subset of the pending bundles reaches is refused with
`StateMismatch`. All the pending bundles together are tried first, with no
limit; only when that fails are subsets searched, and a search over more
pending bundles than it tries is refused with `TooManyPendingBundles`.

```claim
kind: requirement
evaluator: test
```

Backed by `forged_action_spliced_before_delete_commit_is_left_out` in
`rs/cyphr/tests/negative_vectors.rs`. The scenario replays one real delete
commit twice, once without and once with a forged action inserted before it;
every coz verifies on its own, the honest replay (the control) finalizes, and
the forged one finalizes to the same PR with the forged action marked not
included. Rule 6 pins `pre`; this rule pins the forward state, DR included.
Not checked by a named test: a root-by-root comparison of replayed SR, AR, KR,
CR and PR with roots a server published.

### Authorization and lifecycle

#### [rv-key-active-gate]

A coz is accepted only if its signer is an active key in the principal at the
position the coz is applied. `CommitScope::verify_and_apply` resolves the
signer against the key set from before the commit, and also accepts a key that
an earlier mutation in the same commit added (the projected key set). The code
makes two exceptions to the active check in `apply_transaction_internal`: a
self-revoke, which skips only that inner check (`resolve_signer` in
`CommitScope::verify_and_apply` still requires its signer to be active), and a
`commit/create` coz submitted through `verify_and_apply`, which is how storage
replay supplies the finalizer. On the path that builds a commit,
`prepare_commit` resolves the finalizer's signer with `resolve_signer`, which
accepts a key active in either the pre-commit key set or the projected one
(an earlier mutation in the same commit may have replaced it), and
`finish_commit` pushes the finalizer with `push_tx`, so it does not pass
through `apply_transaction_internal` at all. A deleted
key's action is rejected whether dated after the delete or backdated into the
key's old active period, and a key that is not active cannot authorize its own
admission. A `key/create` or `key/replace` of a revoked key is refused with
`KeyRevoked`; only a deleted key may be re-added.

```claim
kind: requirement
evaluator: test
```

Backed by `deleted_key_action_dated_after_delete_is_rejected` and
`deleted_key_action_backdated_into_old_active_period_is_rejected` in
`rs/cyphr/tests/negative_vectors.rs`, and
`s2_3_2_inactive_key_cannot_authorize_its_own_admission` in
`spec_conformance.rs`. The last carries an explicit control (an active key may admit
the same key). The two negative-vector tests have no explicit control, but the
fixture records an accepted action from the same key before the delete, which
serves as one. The backdated case pins
the implementation's fail-closed reading, which tests the signer against
current key membership and ignores the payload `now`. SPEC §6.2 says past
signatures from earlier active periods remain valid but does not say whether a
signer-dated action claiming such a period is accepted on replay, so that test
pins behaviour, not a ruling. Not bound here: the two exceptions themselves, that a replaced
signer of the finalizer is accepted, that a key added earlier in the commit may
sign later cozies, and the `KeyRevoked` path. Tests for the last exist outside
the bound set: the golden vectors `revoked_key_fails` and
`action_revoked_key_fails` (both expect `KeyRevoked`), run by
`test_golden_errors`; `revoked_signer_is_key_revoked` in
`rs/cyphr/tests/signer_seam.rs`; and the revoked-key re-add refusals in
`rs/cyphr/tests/key_auth.rs`.

#### [rv-lifecycle-gate]

A frozen principal refuses key mutations and data actions until it is thawed,
and thawing restores it. The freeze, thaw, close and finalizer cozies are
exempt from the frozen gate. After the close commit (`principal/delete`) the
principal is Deleted and every coz is refused: `AlreadyDeleted` for most
cozies and for a second `principal/delete` or `freeze/create`, and `NotFrozen`
for `freeze/delete`, because closing clears the frozen flag. The one exemption
is the close commit's own `commit/create` coz, which is exempt only while the
close is pending (`deleted_pending`).

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
shows the refusal is the freeze. Not checked by any bound test: refusal after
`principal/delete`, which no test bound here exercises.

The bound runner also runs
`s11_2_dead_principal_accepts_no_transaction_or_action` in
`rs/cyphr/tests/spec_conformance.rs`, which is about Dead, not Deleted, and has
two limits. There is no Dead gate: a Dead principal's coz is refused by the
revoked-signer check of rule 8 (`active_signer` returns `KeyRevoked`). The
test builds the state with `pre_revoke_key`, which exists only for tests; the
dying commit itself, and the Dead principal's refusal of a further commit, are
covered by `dead_principal_roots_are_final_no_further_commit` in the same file.
The test has no control, and it asserts only that the `key/create` and the
data action are refused, not which error.

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
second create. The first `principal/create`, which is accepted before the
second is refused, is its only control. `principal/create` signed by a key other
than the genesis key (the first) is refused with `UnknownKey`, and one whose
`id` is not the future SR (the state at the `principal/create`, SPEC 5.1 step 3)
with `StateMismatch`; no bound test exercises either. `StateMismatch`,
whose row in the error table is under
[rv-state-recomputed](#rv-state-recomputed) (an `id` naming a state the
principal is not in), is also raised for an `id` that is not the current PR on `principal/delete`,
`freeze/create` and `freeze/delete`; see
[rv-lifecycle-transitions](#rv-lifecycle-transitions). The rule is class C because it depends on whether a PG was
already written. Not bound here: that a genesis is well-formed.
`d1_implicit_genesis_rejects_unbound_key` and its siblings in
`rs/cyphr/tests/key_auth.rs` pin that a genesis key must bind its own
thumbprint. A PG is written only by a complete genesis commit:
`GenesisIncomplete` refuses a commit finalized before its `principal/create`
and a `principal/create` while a genesis key has no `key/create` (SPEC 5.1);
the golden error vectors pin both, and no test bound here exercises them.

### Commit structure and reuse

#### [rv-intra-commit-shape]

The `commit/create` coz must be the last coz of a commit, and a commit with
the finalizer elsewhere is rejected with `CommitNotLast`. Separately,
`CommitScope::apply_tx` rejects cozies grouped into one transaction with
different `typ` values (`MixedTransactionTyp`); replay does not use it, as the
known defect below says.

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
`CozReuse`, and the first inclusion stays authoritative. The check precedes the
timestamp and state checks in `apply_transaction_internal`. The check is per principal: another principal
that shares the keys may apply the same coz. It applies to cozies that pass
through `apply_transaction_internal`; a finalizer pushed by `finish_commit`
does not, and its `czd` is not added to `included_czds`, while a `commit/create`
coz submitted through `verify_and_apply` is checked and recorded like any other. It compares the whole `czd`, so a
coz signed under a wider digest (ES384) is recognised. The check runs after the
signer is resolved and the coz is verified (alg, signature, `czd`), so a replay
whose signer is active in neither the pre-commit nor the projected key set
returns `UnknownKey` or `KeyRevoked`, not `CozReuse`. A replay whose signer was
removed earlier in the same commit still resolves through the pre-commit set,
reaches the reuse check first, and returns `CozReuse`. The other half of SPEC
§7.6 differs in kind: a replayed data action is ignored and produces no state
change, and `verify_and_record_action` returns `Ok` for it, but only after the `pre`,
deleted, frozen and active-signer gates and the alg, signature and `czd`
checks have passed (`data.rs`, the `included_czds` check).

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
(`rs/cyphr-server/tests/coz_reuse.rs`), which this claim does not bind. Not checked: a replay by a signer that is no longer active (it returns
`UnknownKey` or `KeyRevoked`), the data-action half's `Ok` return, and any replay through storage. The
set is `included_czds` on the principal's core, filled as each coz is applied. It is
not part of any committed root in this code, so a verifier that holds only a
commitment cannot check reuse without the history.

## Further record checks

The checks below are not among the twelve rules. Each claim is either bound to
a test or declares itself unbound and says what binding it needs. "Unbound"
means no test in the bound set closes the claim; tests that exercise it
elsewhere are named.

### Keys, algorithms and digests

#### [rv-key-set]

A `key/create` of a key already in the key set is refused with `DuplicateKey`.
Revoking or deleting the last key is accepted and leaves the principal Dead
(SPEC §3.1, §11.2), so a replay can empty the key set; a genesis with no key is
still refused with `NoActiveKeys`. Deleting or revoking a key outside the
active set is refused with `UnknownKey`.

```claim
kind: requirement
evaluator: test
```

Backed by the golden vectors `duplicate_key_fails` and
`delete_unknown_key_fails` in `tests/golden/errors/`. They cover a duplicate
create and deleting an unknown key; none covers revoking an unknown key,
though the code refuses it with `UnknownKey`. The accepted removal of the last
key is pinned by `last_key_revoke_leaves_dead` and `last_key_delete_leaves_dead`
in `tests/golden/lifecycle/`.
The marker sits at `test_golden_errors` in
`rs/cyphr/tests/golden_fixtures.rs` and the runner entry runs that whole test,
which runs every vector in the directory, so the binding fails if any error
vector fails; these two are the part that backs this claim. The vectors are
byte-exact fixtures that assert the error name; none has a control. Not checked: that a rejected
coz leaves the principal unchanged.

#### [rv-nonce-ledger]

A nonce is an opaque digest held per level (Principal Root, AT and KT). A
`nonce/create` whose `id` is not a digest of its algorithm's width, bare under
the signing key's hash or labelled with its own, is refused with
`MalformedPayload`. A `nonce/create` of a value the level already holds is
refused with `DuplicateNonce`, and a `nonce/delete` of a value the level does
not hold is refused with `UnknownNonce`. A value held at one level is a
separate nonce at another. A refused nonce leaves every root unchanged.

```claim
kind: requirement
evaluator: test
```

Backed by `nonce_created_twice_at_one_level_is_refused` and
`nonce_delete_removes_only_the_named_nonce_at_the_named_path` in
`rs/cyphr/tests/nonce.rs`, and `s10_2_nonce_bit_length_must_match_the_declared_algorithm`
in `rs/cyphr/tests/spec_conformance.rs`. The first two are end-to-end scenarios
with controls that accept the valid create or delete; they assert that the coz
is refused and the roots are unchanged, not which error. The third refuses
every width off by one, double or another algorithm's, at each level, with a
control at the correct width, and also asserts only the refusal. The error
names come from the code (`NonceSets` and `Nonce::parse` in
`rs/cyphr/src/nonce.rs`) and from the golden vectors
`nonce_create_twice_at_one_level_fails`, `nonce_delete_absent_fails` and the
`nonce_*_fails` width vectors in `tests/golden/errors/`, which
`test_golden_errors` runs but this claim's runner entry does not. Not checked:
a nonce created in a commit that also deletes it; and the error type of any
refusal through the bound tests.

#### [rv-key-material]

A key introduced by `key/create` or `key/replace` must come with its public key
revealed, and that public key must hash to the signed `id`. A `key/create` with
no revealed key is refused, and the thumbprint does not become active. A
revealed key whose thumbprint differs from the signed `id` is refused with
`MalformedPayload`, and `Key::new` refuses a thumbprint that is not the
thumbprint of its public key with `TmbMismatch`.

```claim
kind: requirement
evaluator: test
```

Backed by `s2_2_13_key_create_without_revealed_pub_is_rejected` in
`rs/cyphr/tests/spec_conformance.rs`, a scenario that asserts the coz is
rejected and the key not active; it has no control and does not assert the
error type. Not bound here: the `TmbMismatch` and mismatched-`id` refusals.
`d1_key_create_rejects_victim_tmb_with_attacker_pub` and its siblings in
`rs/cyphr/tests/key_auth.rs` exercise them.

#### [rv-alg-support]

A key algorithm the core does not know is refused with `UnknownAlg`
(`hash_alg_from_str` in `rs/cyphr/src/state.rs`, and `Key::new`). An algorithm
that has no digest function where one is needed is refused with
`UnsupportedAlgorithm`.

```claim
kind: requirement
evaluator: test
```

Backed, for `UnknownAlg`, by the golden vector `unsupported_algorithm_fails`,
which expects `UnknownAlg`, not `UnsupportedAlgorithm`. The marker sits at
`test_golden_errors` in `rs/cyphr/tests/golden_fixtures.rs` and the runner
entry runs that whole test, so the binding fails if any error vector fails;
this vector is the part that backs the claim. Not checked: the
`UnsupportedAlgorithm` refusal. Only unit tests outside the core paths reach
it: `tagged_digest_unknown_algorithm` and
`compute_dr_errors_on_ambiguous_component_length` in `rs/cyphr/src/state.rs`.
No bound test does, so the second sentence of the claim has no backing.

#### [rv-digest-wellformed]

A tagged digest string with no `:` separator is refused with `MalformedDigest`,
one with an unknown algorithm tag with `UnsupportedAlgorithm`, one with invalid
base64 with `MalformedDigest`, and one with the wrong length for its algorithm
with `DigestLengthMismatch`, up to 64 decoded bytes; parsing arbitrary input
never panics. Above 64 decoded bytes the parser's fixed buffer overflows and
the error is `MalformedDigest("invalid base64")`, not `DigestLengthMismatch`. A multihash
built from a digest of the wrong length is refused.

```claim
kind: requirement
evaluator: test
```

Backed by `test_tagged_digest_parsing_roundtrip`,
`test_tagged_digest_invalid_parsing_does_not_panic` and
`test_multihash_digest_validation` in `rs/cyphr/tests/properties.rs`, property
tests over random digests and strings. They assert that a wrong length fails
and that parsing does not panic; they do not assert the error type. Unit tests
in `rs/cyphr/src/state.rs` assert the types for a missing separator, an unknown
tag and a wrong length; no test asserts the error type for invalid base64 or for input above
64 bytes. The roundtrip property test draws up to 99 bytes, so it reaches the
above-64 branch, and asserts only that parsing fails. Not
checked on a coz-borne digest: the path that parses an `arrow` out of a coz.

#### [rv-internal-invariants]

A digest container that lacks a variant the code expects raises
`EmptyMultihash` or `MissingVariant`. The code raises these for an internal
fault, not for a property of a record.

```claim
kind: requirement
evaluator: none
```

Unbound. No scenario that reaches either error from a valid or invalid record
is known. Binding needs such a scenario to exist first.

#### [rv-key-arity]

A principal can hold any number of keys. The code meets this: the Key Tree
adds a level of 256 children per fold as it grows, and no error bounds the
key count.

```claim
kind: requirement
evaluator: none
```

Unbound. The tests `s4_key_tree_supports_more_than_256_keys` and
`key_tree_arity_growth_past_256_and_delete_restores_the_key_root` in
`rs/cyphr/tests/spec_conformance.rs` cover it, but this claim's runner entry
does not name them yet.

### Time, lifecycle transitions and commit completeness

#### [rv-timestamp-future]

A coz whose `now` exceeds verifier time plus the skew is refused with
`TimestampFuture`. The default skew is 360 seconds (SPEC §15.9); setting it to
0 removes the tolerance and does not disable the check.

```claim
kind: requirement
evaluator: none
```

Unbound. The test that would require the check on by default,
`s15_9_future_dated_message_is_rejected_by_default` in
`rs/cyphr/tests/spec_conformance.rs`, is ignored as `RED(SC1-F5)`. No test
enables a skew and checks the refusal. Binding needs a test that configures a
skew.

#### [rv-lifecycle-transitions]

`freeze/create` on a principal that is already frozen is refused with
`AlreadyFrozen`, and `freeze/delete` on one that is not frozen is refused with
`NotFrozen`. A `principal/delete`, `freeze/create` or `freeze/delete` whose `id`
is not the current PR is refused with `StateMismatch`.

```claim
kind: requirement
evaluator: none
```

Unbound. Unit tests in `rs/cyphr/src/principal/tests/lifecycle.rs` assert both
errors; no test for the `StateMismatch` case was found. They live in the crate's source tree. Binding needs a change whose file
surface includes that file.

#### [rv-commit-nonempty]

A commit that holds only its finalizer is refused with `EmptyCommit`, and a
commit whose last coz carries no `arrow` is refused with `MissingCommit`.

```claim
kind: requirement
evaluator: none
```

Unbound. Unit tests in `rs/cyphr/src/commit.rs` assert both errors. Binding
needs a change whose file surface includes that file.

### Collaborators of the core

#### [rv-signer-faults]

A failure of the signing backend while finalizing a commit surfaces as
`Error::Signer` and records no commit.

```claim
kind: requirement
evaluator: none
```

Unbound. `faulty_signers_yield_typed_errors_and_no_commit` in
`rs/cyphr/tests/signer_seam.rs` exercises it. Binding needs a change whose
file surface includes that file.

#### [rv-storage-backend]

A failure of the backing storage while reading or writing commit trees
surfaces as `Error::Storage`. A durable leaf at a commit's position that
differs from the commit's TR, the signature of a crash-window orphan, is
refused with `DurableLeafMismatch`.

```claim
kind: requirement
evaluator: none
```

Unbound. `storage_backend_failure_surfaces_as_storage_error` in
`rs/cyphr/tests/storage_error_taxonomy.rs` and the orphan-leaf scenario in
`rs/cyphr-storage/tests/durable_commit_trees.rs` exercise them. Binding needs
a change whose file surface includes those files.

## Errors by claim

Every error the core apply, finalize and record paths can raise has one row,
naming the claim that governs it. A claim may govern errors raised for several
rules; the claim's text says which. The table is checked for consistency with
the classification in `rs/cyphr/tests/record_verification.rs`, which is the
reachability judgement of its author and is not itself proved. That test classifies every `cyphr::Error`
variant with an exhaustive `match`, and fails if a reachable variant has no
row, a row names no variant or one classified outside the core paths, a row
points to a different claim than the classification, or a claim is neither
bound nor declared unbound. Variants the test classifies as outside the core
paths have no row; its source gives the reason for each.

| Error                   | Claim                      |
| :---------------------- | :------------------------- |
| `Signer`                | `rv-signer-faults`         |
| `InvalidSignature`      | `rv-sig-verifies`          |
| `UnknownKey`            | `rv-key-active-gate`       |
| `UnknownAlg`            | `rv-alg-support`           |
| `TimestampPast`         | `rv-timestamp-monotone`    |
| `TimestampFuture`       | `rv-timestamp-future`      |
| `KeyRevoked`            | `rv-key-active-gate`       |
| `MalformedPayload`      | `rv-coz-wellformed`        |
| `TmbMismatch`           | `rv-key-material`          |
| `AlgMismatch`           | `rv-alg-alignment`         |
| `CzdMismatch`           | `rv-alg-alignment`         |
| `DuplicateKey`          | `rv-key-set`               |
| `DuplicateNonce`        | `rv-nonce-ledger`          |
| `UnknownNonce`          | `rv-nonce-ledger`          |
| `CozReuse`              | `rv-no-coz-reuse`          |
| `StateMismatch`         | `rv-state-recomputed`      |
| `TooManyPendingBundles` | `rv-state-recomputed`      |
| `EmptyMultihash`        | `rv-internal-invariants`   |
| `MissingVariant`        | `rv-internal-invariants`   |
| `NoActiveKeys`          | `rv-key-set`               |
| `AlreadyDeleted`        | `rv-lifecycle-gate`        |
| `AlreadyFrozen`         | `rv-lifecycle-transitions` |
| `NotFrozen`             | `rv-lifecycle-transitions` |
| `Frozen`                | `rv-lifecycle-gate`        |
| `EmbeddedErrored`       | `rv-key-active-gate`       |
| `MixedTransactionTyp`   | `rv-intra-commit-shape`    |
| `UnsupportedAlgorithm`  | `rv-alg-support`           |
| `Storage`               | `rv-storage-backend`       |
| `EmptyCommit`           | `rv-commit-nonempty`       |
| `GenesisIncomplete`     | `rv-genesis-immutable`     |
| `CommitNotLast`         | `rv-intra-commit-shape`    |
| `MissingCommit`         | `rv-commit-nonempty`       |
| `CommitMismatch`        | `rv-arrow-chain`           |
| `DurableLeafMismatch`   | `rv-storage-backend`       |
| `MalformedDigest`       | `rv-digest-wellformed`     |
| `DigestLengthMismatch`  | `rv-digest-wellformed`     |

## Storage replay

Replay from storage reaches these core paths through its own import and
submission code. Whether it gives the same result as applying the same record
through the core is the subject of a separate equivalence criterion, "storage
replay equals core apply". This page makes no claim about storage replay, and
none of its bound tests exercises it. Known differences are not listed here,
because a list written by hand goes stale; the criterion's own checks are where
they are found.

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

Known gap: recovery (SPEC §14) and merge and fork (SPEC §11.5) add
record-layer rules once their text settles. The merge acceptance tests in `rs/cyphr/tests/merge.rs`
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

5. SPEC §2.2.3 requires digest identifiers inside a coz to align with the
   coz's `alg` "unless explicitly labeled", and gives as an example that the
   `id` of a new key must be SHA-256, aligning with `ES256`. A key's thumbprint
   is a digest under the key's own algorithm. When an Ed25519 key signs a
   `key/create` for an ES256 key, the `id` is a SHA-256 digest while the coz's
   `alg` is Ed25519. Does the sentence require the `id` to follow the coz's
   `alg`, the new key's, or either?

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
