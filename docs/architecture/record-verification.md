# Record verification

This page names the twelve rules a replay of a principal's record enforces,
says where each one lives in the code, and binds each to the test that fails
when the rule breaks. Where no test is bound, the page says so. It is a
reference: it describes the code at this revision, and it records two things
it cannot settle itself, a question for the spec author and a deferred
format decision.

SPEC references are to `SPEC.md` at commit `be0663f` on the spec author's
`zami` branch, the normative text.

## What a replay checks

A verifier that holds a trust anchor (SPEC §4.5) and a principal's commits
replays the commits in order and either accepts every one or stops at the
first that fails a rule. A record is **honest** when its replay from the
anchor to the tip accepts every commit. Honesty is a property of the record
against its commitment. It does not depend on how the record reached the
verifier or on what any server would have admitted.

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

- **A**: leaf-local. The check reads one coz and nothing else.
- **B**: adjacent pair. The check compares a commit with the one before it.
- **C**: bounded backward reference. The check reads state, or key material,
  built by earlier commits. A succinct verifier can certify it only
  incrementally, forward from a verified checkpoint.
- **D**: keyed. The check asks whether a value already occurs in this
  principal's record.

| #   | Rule                                                           | SPEC           | Class | Error                                  | Claim                                           |
| :-- | :------------------------------------------------------------- | :------------- | :---- | :------------------------------------- | :---------------------------------------------- |
| 1   | A coz carries `alg`, `tmb`, `now`, `typ`; encodings canonical  | §2.2.2, §2.3.1 | A     | `MalformedPayload`                     | [rv-coz-wellformed](#rv-coz-wellformed)         |
| 2   | `pay.alg` equals the signing key's algorithm; `czd` recomputes | §2.2.3, §12    | A     | `AlgMismatch`, `CzdMismatch`           | [rv-alg-alignment](#rv-alg-alignment)           |
| 3   | The signature verifies under the key named by `tmb`            | §7.1           | C     | `InvalidSignature`                     | [rv-sig-verifies](#rv-sig-verifies)             |
| 4   | A self-revoke's `now` is a positive integer below 2^53         | §6.4           | A     | `MalformedPayload`                     | [rv-timestamp-range](#rv-timestamp-range)       |
| 5   | A coz's `now` is never earlier than the principal's latest     | §13.2, §15.9   | B     | `TimestampPast`                        | [rv-timestamp-monotone](#rv-timestamp-monotone) |
| 6   | An `arrow` binds a commit to the prior PR                      | §4.2, §4.3     | B     | `CommitMismatch`                       | [rv-arrow-chain](#rv-arrow-chain)               |
| 7   | The `arrow` binds the recomputed forward state                 | §3.7, §4.2     | C     | `CommitMismatch`                       | [rv-state-recomputed](#rv-state-recomputed)     |
| 8   | The signer is an active key when the coz is applied            | §2.3.2, §6     | C     | `UnknownKey`, `KeyRevoked`             | [rv-key-active-gate](#rv-key-active-gate)       |
| 9   | A frozen principal takes no mutation; a dead one takes nothing | §2.3.2, §11.2  | C     | `Frozen`, `AlreadyDeleted`             | [rv-lifecycle-gate](#rv-lifecycle-gate)         |
| 10  | The Principal Genesis is written once                          | §2.3.2, §5     | A     | `StateMismatch`                        | [rv-genesis-immutable](#rv-genesis-immutable)   |
| 11  | The commit coz is last; a transaction's cozies share one `typ` | §4.1, §4.6     | A     | `CommitNotLast`, `MixedTransactionTyp` | [rv-intra-commit-shape](#rv-intra-commit-shape) |
| 12  | A transaction coz this principal already included is refused   | §7.6           | D     | `CozReuse`                             | [rv-no-coz-reuse](#rv-no-coz-reuse)             |

Rules 8 and 9 read the state that rule 7 recomputes, and each names a
distinct way a record can be dishonest, so each has its own claim and its own
test. The error names are variants of `cyphr::Error`
(`rs/cyphr/src/error.rs`).

### Reading a claim

Each claim below is a docket claim: a `[kebab-id]` heading followed by a
`claim` block. `evaluator: test` means a test is bound to the claim through an
`@docket:` marker at the test and an entry in `scripts/docket-run`, and
`scripts/docket-run <id>` runs every test the rule rests on. `evaluator: none`
means no bound test closes the claim yet, and the claim's text says why and
names the existing tests it would bind.

The binding is narrower than the rule in places. Each claim ends with what
its tests do not check.

### Coz shape and signature

#### [rv-coz-wellformed]

A coz that omits `alg`, `tmb`, `now` or `typ` is rejected, and the rejection
leaves the principal's state untouched. A `key/create` whose `id` is a
non-canonical base64url spelling of the new key's thumbprint is rejected, so
one key has one spelling.

```claim
kind: requirement
evaluator: test
```

Backed by `s2_3_1_coz_missing_tmb_now_or_typ_is_rejected`,
`s2_3_1_coz_missing_alg_is_rejected` and
`s2_2_2_non_canonical_b64ut_is_rejected` in
`rs/cyphr/tests/spec_conformance.rs`. Each is an end-to-end scenario (sign,
verify, apply, finalize) with a control that accepts the well-formed coz. The
code path is `ParsedCoz::from_pay` in `rs/cyphr/src/parsed_coz.rs`. Not
checked: non-canonical encoding in fields other than `id`.

#### [rv-alg-alignment]

A coz whose `pay.alg` differs from the signing key's algorithm is rejected on
both the data-action path and the commit-coz path, and a caller-supplied `czd`
that is not the digest of the signed bytes is never recorded.

```claim
kind: requirement
evaluator: none
```

Tests that fail when this breaks exist:
`d4_action_pay_alg_must_equal_key_alg`,
`d4_commit_coz_pay_alg_must_equal_key_alg`, their ES256 variants,
`d4_wrong_caller_czd_is_not_recorded_for_actions` and
`d4_wrong_caller_czd_is_not_recorded_for_commit_cozies`, all in
`rs/cyphr/tests/key_auth.rs`. The claim is `none` only because a docket
marker must sit at the test and that file lies outside the files the work that
wrote this page could change. A change that adds
`// @docket: rv-alg-alignment :: scripts/docket-run rv-alg-alignment` to
`d4_commit_coz_pay_alg_must_equal_key_alg` and a `scripts/docket-run` entry
for those tests binds it. Not covered by any test: the SPEC §2.2.3 statement
that the digest algorithm of a new key's `id` follows its `alg`, which a
golden vector (`ed25519_account_adds_es256_key`) pins.

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
byte-level vectors built from the group orders. These pin the encoding rule.
The wider statement, that no signature which fails verification ever commits,
is checked by the property test `any_non_verifying_signature_never_commits` in
`rs/cyphr/tests/signer_seam.rs`, which carries no marker here.

### Timestamps

#### [rv-timestamp-range]

A self-revoke whose `now` is zero, negative or at least 2^53 is rejected, and
`now` equal to 2^53 - 1 is accepted. SPEC §6.4 states the bound for `rvk` and
`now` on a revoke.

```claim
kind: requirement
evaluator: test
```

Backed by `s6_4_revoke_now_must_be_a_positive_bounded_integer` in
`rs/cyphr/tests/spec_conformance.rs`. This is narrower than a general
"timestamp in range" rule. SPEC §4.1 states no range for the `now` of other
cozies, and the code bounds only the revoke (`ParsedCoz::from_pay`). SPEC
§15.9 gives a default tolerance of 360 seconds against witness time; the
implementation leaves its future-dated check off by default
(`max_clock_skew` is 0), and the test that would require it is ignored as
`RED(SC1-F5)` in `spec_conformance.rs`.

#### [rv-timestamp-monotone]

A coz whose `now` is earlier than the latest timestamp the principal has
recorded is rejected with `TimestampPast`, on both the transaction path and
the data-action path. A rejected coz changes no state.

```claim
kind: requirement
evaluator: none
```

The code is `apply_transaction_internal` in
`rs/cyphr/src/principal/apply.rs` and `record_action` in
`rs/cyphr/src/principal/data.rs`; both compare `now` with `latest_timestamp`.
Two golden vectors pin the rejection, `timestamp_past_fails` and
`action_timestamp_past_fails` in `tests/golden/errors/`, run by
`test_golden_errors` in `rs/cyphr/tests/golden_fixtures.rs`. That runner covers
the whole error directory, and its file is outside the files the work that
wrote this page could change, so no marker binds this claim. The comparison
is strict (`<`), so a coz with a `now` equal to the latest is accepted; no
test pins that. The SPEC wording that governs the boundary is the subject of
[Question for the spec author](#question-for-the-spec-author).

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
succeeds and only `finalize()` catches the change. `s2_3_2_second_commit_on_a_stale_pre_is_rejected` in
`spec_conformance.rs` is the two-peer scenario: two authorized commits branch
from one ancestor, and a replayer that applied the first rejects the second
with `CommitMismatch` and keeps its state. The check lives in
`finalize_commit` (`rs/cyphr/src/principal/apply.rs`). Fork evidence tests
in `rs/cyphr/tests/fork_evidence.rs` show that each branch of a fork verifies
alone from the ancestor; they back the equivocation page, not this claim, and
the linear replayer there fails on `UnknownKey`, not on the arrow.

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
every coz verifies on its own, the honest replay finalizes, and the forged one
fails with `CommitMismatch`. The same `arrow` check as rule 6 closes it, and
the two claims differ in the component each pins: `pre` for rule 6, the
forward state for rule 7. Not checked by a named test: a root-by-root
comparison of replayed SR, AR, KR, CR and PR with roots a server published.

### Authorization and lifecycle

#### [rv-key-active-gate]

A coz is accepted only if its signer is an active key in the principal at the
position the coz is applied. A deleted key's action is rejected whether the
action is dated after the delete or backdated into the key's old active
period, and a key that is not active cannot authorize its own admission.

```claim
kind: requirement
evaluator: test
```

Backed by `deleted_key_action_dated_after_delete_is_rejected` and
`deleted_key_action_backdated_into_old_active_period_is_rejected` in
`rs/cyphr/tests/negative_vectors.rs`, and
`s2_3_2_inactive_key_cannot_authorize_its_own_admission` in
`spec_conformance.rs`, each a scenario with a control. The backdated case pins
the implementation's fail-closed reading, which tests the signer against
current key membership and ignores the payload `now`. SPEC §6.2 says past
signatures from earlier active periods remain valid but does not say whether a
signer-dated action claiming such a period is accepted on replay, so that test
pins behaviour, not a ruling. Not bound here: the `KeyRevoked` path
(`revoked_signer_is_key_revoked` in `rs/cyphr/tests/signer_seam.rs`) and the
revoked-key re-add refusals in `rs/cyphr/tests/key_auth.rs`.

#### [rv-lifecycle-gate]

A frozen principal refuses key mutations and data actions until it is thawed,
and thawing restores it. A dead principal, one whose last key is revoked,
refuses every transaction and action.

```claim
kind: requirement
evaluator: test
```

Backed by `s11_2_frozen_principal_rejects_key_mutations`,
`frozen_principal_rejects_data_actions_until_thawed` and
`s11_2_dead_principal_accepts_no_transaction_or_action` in
`rs/cyphr/tests/spec_conformance.rs`. Each is a scenario with a control that
shows the refusal is the lifecycle state and not a general failure. The code
gates in `apply_verified_internal` and `verify_and_record_action`. Not
checked: refusal after `principal/delete`. The code returns
`AlreadyDeleted` for it, and no test bound here exercises that path.

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
`rs/cyphr/tests/spec_conformance.rs`. Not bound here: that a genesis is
well-formed. `d1_implicit_genesis_rejects_unbound_key` and its siblings in
`rs/cyphr/tests/key_auth.rs` pin that a genesis key must bind its own
thumbprint.

### Commit structure and reuse

#### [rv-intra-commit-shape]

The `commit/create` coz must be the last entry of a commit, and all cozies of
one transaction carry an identical `typ`. A commit with the finalizer first, or
a transaction that mixes `key/create` with `key/delete`, is rejected.

```claim
kind: requirement
evaluator: test
```

Backed by `s4_6_commit_coz_must_be_last_in_txs` and
`s4_1_transaction_cozies_must_share_one_typ` in
`rs/cyphr/tests/spec_conformance.rs`. The first asserts `CommitNotLast`; the
second asserts only that the mixed transaction is rejected, not which error.
`MixedTransactionTyp` is the variant the code raises (`rs/cyphr/src/commit.rs`).
Not checked here: that the order of transactions inside
a commit survives storage and replay unchanged. That is a property of the
storage engine (`rs/cyphr-storage`), outside these tests.

#### [rv-no-coz-reuse]

A transaction coz this principal already included is rejected with the typed
`CozReuse`, whatever its timestamp or the principal's state, and the first
inclusion stays authoritative. The check is per principal: another principal
that shares the keys may apply the same coz. It compares the whole `czd`, so a
coz signed under a wider digest (ES384) is recognised.

```claim
kind: requirement
evaluator: test
```

Backed by `s7_6_transaction_coz_reuse_by_the_same_principal_is_rejected`,
`s7_6_reuse_is_typed_and_scoped_to_one_principal` and
`multihash_replay_of_an_es384_signed_coz_is_reuse` in
`rs/cyphr/tests/spec_conformance.rs`. The reuse test replays with equal
timestamps so the timestamp rule cannot be the rejecter, and a cross-principal
control catches a process-global set. The server maps the error to a refusal
(`rs/cyphr-server/tests/coz_reuse.rs`), which this claim does not bind. The
set is `included_czds` on the principal's core, filled as each coz is
applied. It is not part of any committed root in this code, so a verifier that
holds only a commitment cannot check reuse without the history.

## Rules by proof form

The rules do not all admit the same succinct proof. This is analysis of the
rules' shape; no code builds these proofs, and no test in this repository
checks the cost figures. `n` is the number of commits.

| Rules                 | Form                    | What a verifier can hold                                                         |
| :-------------------- | :---------------------- | :------------------------------------------------------------------------------- |
| 1, 2, 4, 5, 6, 10, 11 | one-shot fold           | the whole record in `O(log n)` against the commitment, given committed summaries |
| 3, 7, 8, 9            | incremental certificate | `O(log n)` per root transition forward of a verified checkpoint                  |
| 12                    | keyed index             | `O(log n)` per lookup against a committed keyed-tree root                        |

- A **one-shot fold** has a leaf-local or adjacent-pair measure, so a
  summary of a range can be combined associatively.
- An **incremental certificate** cannot be cold-succinct: rule 7's composed
  state grows with the state, not with the log of the range, and rules 3, 8
  and 9 read state at each position. What holds is a proof bounded up to a
  verified checkpoint (SPEC §8.3). The distance a verifier replays is bounded
  by its checkpoint interval, never by the chain length.
- A **keyed index** answers "is this value already included" in `O(log n)`
  once its root is committed. The protocol commits no such root today, and
  the global negative, that no duplicate occurs anywhere, costs a linear
  replay without it.

Replay today is the cold stance: `O(n)` once, rules 1 to 12 applied to each
commit in order.

## What is outside the twelve

Every other constraint falls in one of five groups; the group, not the tag
list, is the durable content.

- **Server admission policy**: clock-skew tolerance, rate limits, the error
  taxonomy, atomic rejection. A record does not become dishonest because a
  server would have refused it, nor honest because one admitted it.
- **Wire and API shape**: envelopes, plural forms, bearer tokens, login.
- **Liveness**: proof of possession, witnesses, fork detection and
  resolution, gossip. They are non-monotone. The record-layer residue of a
  fork, two commits naming one `pre`, is caught by rule 6.
- **Derived restatements**: per-verb authority statements refine rule 8,
  and lifecycle-matrix rows refine rule 9.
- **Data-tree content**: application-defined (SPEC §2.3.3).

An embedded principal (SPEC §10.3) is verified by applying the same rules to
its own record. The rules compose per log and never become a query across
logs.

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
