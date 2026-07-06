# docs/ — Documentation Status & Traps

**Alignment to parent:** documentation serves the root goal only when it
is true. As of 2026-07-06 (full spec-drift survey), parts of this tree
assert things the implementation does not do. Until the truth-restoration
pass lands, calibrate trust as below.

## Trust calibration (verified 2026-07-06)

- **Do not trust `VERIFIED`/`pass` annotations in `docs/specs/*.md`.**
  They have no single meaning. Worst offenders: `consensus.md` (27/27
  "pass", zero implementation), `authentication.md` (24/24, no
  login/bearer/embedding code), `principal-lifecycle.md` (25/25, no
  lifecycle state machine; `level()` cannot return L2). The storage-layer
  specs are closer to reality but `storage-engine.md` still claims the
  reindex permutation search was removed — it was not.
- **Section citations are broken repo-wide.** SPEC.md was renumbered
  2026-07-02; most `docs/specs/*.md` headers and some rustdoc cite the old
  §-numbers, and five specs cite dead `.sketches/` paths (content lives in
  `.ledger/log/`). Check the current `SPEC.md` TOC before following any
  §-reference.
- **`docs/plans/` is legacy.** Never plan-of-record (root I6); campaign
  workflow supersedes. Same for `docs/protocol/constraint_coverage.md`
  tag-counts (stale ~3 months, still says "MALT") and ADR-0001's
  "PROPOSED" status (its design landed).
- **`SPEC.md` in-tree ≠ implemented design** until PR #5 lands on `zami`
  (Principal-Tree-as-EMT amendment). The working copy may be checked out
  to the PR branch for reference — do not commit it (root I3).
- Decision records here can be superseded by forge rulings: the in-repo
  ledger records KV→SQLite for the index; the settled direction is
  KV-not-SQL (root R3). When docs and forge issues conflict, the forge +
  root `AGENTS.md` win.

## Invariants

- **I1 — Truthful status or none.** A verification/status annotation that
  cannot name its evaluator must be corrected or removed, not propagated.
  Grounding: the 2026-07-06 spec-drift findings above (verifiable against
  the named files and `rs/`). Signpost: new docs copying `VERIFIED:
  agent-check` style claims without an evaluator.

## Unknowns

- **U1 — `VERIFIED` semantics.** What the annotation must mean
  (implementation-verified vs spec-internally-consistent) is undefined;
  resolves when the documentation-repair work is scoped. Grounding: the
  contradictory usage documented above.

## Spec Pointers

- Root spec: `/SPEC.md` · machine specs: `docs/specs/` · ADRs: `docs/adr/`
- Corpus/spec traceability: `docs/protocol/constraint_coverage.md`
  (stale — see above)
