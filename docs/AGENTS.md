# docs/ — Documentation Status & Traps

**Alignment to parent:** documentation serves the root goal only when it
is true. As of 2026-07-06 (full spec-drift survey), parts of this tree
assert things the implementation does not do. Until the truth-restoration
pass lands, calibrate trust as below.

## Layout & how to work here

| Path | What it is / how to approach |
| :--- | :--- |
| `specs/` | Machine specs with `[tag]`-anchored constraints; behavior contracts for `rs/`. Edit alongside the code they govern; keep tags stable (tests and `protocol/constraint_coverage.md` reference them) |
| `adr/` | Architecture decision records |
| `models/` | Formal models (self-flagged staleness applies) |
| `protocol/` | Constraint→test traceability matrix |
| `charters/`, `audit/`, `plans/` | Historical; `plans/` is legacy (root I6) — read for archaeology only |
| `sites/` | Published websites — see below |
| `level_2.5.md` | Orphaned; not linked from any spec — verify with nrd before relying on it |

Markdown is formatted by `treefmt` (prettier) from the repo root; the
pre-commit hook audits local links in touched files. Follow the
predicate documentation conventions when editing prose.

## Doc sites (`sites/`)

Two static sites built with **sukr** (https://sukr.io), deployed via
Netlify; each site's `netlify.toml` is the build authority:

- `sites/docs/` → docs.cyphr.me. **Injects `/SPEC.md` at build time**
  (prepends front matter, writes `content/specification.md`) — the spec
  page is generated, never edited in `content/`.
- `sites/blog/` → the blog; posts live in `content/posts/`.
- `sites/theme/` — shared CSS copied into each site's `public/theme/` at
  build; edit theme here, not per-site.

Local build: run `sukr` inside the site directory (config: `site.toml`;
output: `public/`, gitignored), then copy `../theme/*.css` into
`public/theme/` to mirror the Netlify step. There is no CI job for the
sites; Netlify builds on push.

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

## Protocol model — tenets for any spec-touching work

Learned the hard way (a spec-amendment proposal was withdrawn after review
by the spec's author; see closed PR #39). Internalize before proposing any
SPEC.md change:

- **The spec's domain ends at structures, digests, and the wire format.**
  The wire format is the disclosure channel: it carries full information
  (including transaction order, via the `txs` array) when a principal
  chooses to authenticate to a party. Storage, indexing, and persistence
  are implementation domain — never propose a spec change to solve an
  implementation persistence problem.
- **Digests are commitments.** Whoever needs to re-prove a pre-image
  (order included) is responsible for retaining it. If the implementation
  received data and discarded it, that is an implementation bug; the
  protocol owes no second carrier for data a digest already commits to.
- **Obfuscation-by-digest is an intentional privacy property.** That
  reconstructing undisclosed information from digests is O(n!)-hard is the
  design working, not a smell or a DoS vector — the spec directs clients
  to error (`TRANSACTION_ORDER_UNKNOWN`) rather than search. Nobody is
  obligated to brute-force; an implementation that does so volunteered.
- **Succinctness is heavily weighted.** Do not propose new signed fields
  when an existing digest already commits to the data. Redundant fields in
  signed pays are bloat, and AI-authored proposals systematically
  underweigh this.
- **Authority order: SPEC.md prose outranks everything downstream.** The
  derived specs (`docs/specs/*.md`) and the reference implementation can
  and do encode stale draft designs; their constraint tags and MUST
  language make them LOOK more normative than SPEC.md, and treating them
  as protocol intent is the single failure mode that has repeatedly
  produced wrong spec proposals. Canonical example (spec author, PR #39
  thread, 2026-07-06): per-mutation `pre` in signed transaction pays is
  a rejected old draft — commit atomicity, bundling, and order all ride
  in the commit transaction's `arrow`, and only commit cozies need it —
  yet the implementation requires `pre` on every mutation,
  `transactions.md` mandates it ([transaction-pre-required],
  [commit-pre-chain]), and a golden fixture asserts its absence errors.
  When SPEC.md and downstream artifacts disagree, the default reading is
  "downstream is stale," and the resolution is a question to the spec
  author, never a spec amendment to match downstream.
- **Two authorization contexts — never mix their rules.** *Intra-commit*:
  transactions within a commit apply sequentially ("one-by-one using a
  given order as dictated by the principal", SPEC §4); a key activated by
  an earlier transaction may authorize a later one, a key revoked earlier
  is barred (spec author, PR #39 thread). *Extra-commit*: external
  authenticators see only commits — intra-commit transactions are
  ephemeral to them, so external authorization is evaluated against
  committed state. Rules stated for one context are not contradictions of
  the other; `transactions.md`'s [pre-mutation-key-rule] conflated the
  two and needs rewriting with the contexts distinguished.

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
