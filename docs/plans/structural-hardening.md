# PLAN: Pre-Release Structural Hardening

Six structural findings from the Hickey×Löwy architectural review, all judged
correctable within the release window. This plan addresses protocol naming
consistency, duplicated logic, type-system alignment, and a concrete typ-path
decision that governs every fixture and every generated coz.

---

## Goal

Harden the Go and Rust implementations against the structural findings from the
pre-release review before v0.1.0 ships. All six findings produce cleaner,
safer, or more correct code without changing observable protocol semantics. No
backwards-compatibility concern applies (pre-alpha, per AGENTS.md).

---

## Constraints

- Release window is a few days; scope must be bounded and realistic.
- Both implementations must stay in parity — every structural change applies to
  both unless the finding is language-specific.
- Golden fixtures must be regenerated via `fixture-gen` whenever typ strings
  change; hand-editing fixture JSON is prohibited.
- No commits are made by the agent; all boundaries are reported as commit
  messages for human review.

---

## Decisions

| Decision                       | Choice                                                 | Rationale                                                                                                                                                                                                                                                                                                                                |
| :----------------------------- | :----------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **typ grammar**                | `<authority>/cyphr/<noun(s)>/<verb>`                   | Per SPEC §7.2: authority is the domain only (`cyphr.me`); `cyphr` is the protocol segment; noun/verb follow. Third-party deployments use `example.com/cyphr/key/create`.                                                                                                                                                                 |
| **protocol segment**           | `cyphr`                                                | `cyphrpass` is the old name; `cyphr` is canonical post-rename.                                                                                                                                                                                                                                                                           |
| **Rust typ constants**         | Suffix-only, protocol-qualified (`"cyphr/key/create"`) | The suffix includes the protocol segment but not the authority. Authority (`cyphr.me`) is prepended at call-site. Aligns with `ends_with()` dispatch.                                                                                                                                                                                    |
| **Rust `COMMIT_CREATE` fix**   | `"cyphr/commit/create"` suffix (was a half-path)       | The current constant `"cyphr/commit/create"` already has the right value — it's a suffix if authority is NOT included. The bug is that other key/create etc. constants are bare (`"key/create"`) while this one is `"cyphr/commit/create"`. All suffixes must be uniformly qualified: `"cyphr/key/create"`, `"cyphr/commit/create"` etc. |
| **Go TxRevoke → TxSelfRevoke** | Rename in Go, no wire change                           | Struct-level alignment with Rust `SelfRevoke` variant. Wire format stays `cyphr/key/revoke`.                                                                                                                                                                                                                                             |
| **Checkpoint loading gap**     | Descoped                                               | Rust `load_from_checkpoint` has no Go equivalent. This requires protocol-level decisions outside the hardening window; defer to post-release roadmap.                                                                                                                                                                                    |
| **State derivation helper**    | Single helper per impl                                 | Each language gets a `recomputeState`/`recompute_state` function covering KR → AR → SR → PR with optional DR and CR inputs.                                                                                                                                                                                                              |

---

## Risks & Assumptions

| Risk / Assumption                                                               | Severity | Status                  | Mitigation / Evidence                                                                                                                                                                                         |
| :------------------------------------------------------------------------------ | :------- | :---------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| typ grammar confirmed: `<auth>/cyphr/<noun>/<verb>`                             | HIGH     | **Confirmed**           | SPEC §7.2 defines the grammar; `cyphr.me` is authority only; `cyphr` is protocol segment                                                                                                                      |
| All source + intent files use `"cyphr.me/key/create"` (missing `cyphr` segment) | CRITICAL | **Validated**           | Grep confirms: zero occurrences of `"cyphr.me/cyphr/key/create"` anywhere in source or fixtures. Phase 3 must update **all** intent files, all source-level typ string literals, and regenerate all fixtures. |
| Rust typ constants are non-uniform (bare suffixes vs. protocol-qualified)       | HIGH     | **Validated**           | `KEY_CREATE = "key/create"` (bare) vs `COMMIT_CREATE = "cyphr/commit/create"` (protocol-qualified). Must be normalised to protocol-qualified suffixes: `"cyphr/key/create"`, `"cyphr/commit/create"` etc.     |
| SPEC.md itself uses stale `cyphrpass` in all examples                           | MEDIUM   | **Validated**           | SPEC.md is nrd/Zami territory — not modified in this plan; however Phase 3 is blocked on coherence with implementation                                                                                        |
| Fixture regeneration is atomic                                                  | MEDIUM   | **Assumed valid**       | `fixture-gen` must be updated before regeneration; run tests immediately after                                                                                                                                |
| State derivation helper introduces subtle bugs                                  | MEDIUM   | **Mitigated by review** | Calling conventions differ per site; helper must be parameterised correctly; existing tests catch regressions                                                                                                 |
| Go TxSelfRevoke rename breaks external callers                                  | LOW      | **Not applicable**      | Pre-alpha, no external consumers                                                                                                                                                                              |
| Checkpoint loading gap                                                          | LOW      | **Descoped**            | Real gap; outside hardening window scope                                                                                                                                                                      |

---

## Open Questions

- **Q1 — RESOLVED:** Grammar is `<authority>/cyphr/<noun>/<verb>`. Authority
  is the domain only (`cyphr.me`, `example.com`, etc.). Protocol segment is
  `cyphr`. Confirmed by nrd 2026-04-21.
- **Q2 — RESOLVED:** The authority MUST NOT be a library constant. The
  library is a decentralized protocol implementation — hardcoding `"cyphr.me"`
  anywhere inside it couples it to a single deployment and violates the
  protocol's authority-flexibility requirement. The correct design:
  - **Library constants** are protocol-qualified suffixes only:
    `"cyphr/key/create"`, `"cyphr/commit/create"` etc.
  - **Authority is a parameter** injected by the caller at signing time.
    `FinalizeWithArrow` / `finalize_with_arrow` each gain an `authority`
    argument; they construct the full typ as `authority + "/" + suffix`.
  - The existing `Authority = "cyphr.me"` constant in `cyphr.go` is
    appropriate **only** in tests, CLI entry points, and fixture generators —
    the concrete deployment contexts where a specific authority is known.
  - Parsers remain authority-agnostic via `ends_with(suffix)` — no change
    needed there.

---

## Scope

### In Scope

1. **F1 — Deduplicate Typ constants (Go):** Merge `TypKeyCreate` etc. into
   `CozKind`; remove the parallel `Typ*` string block.
2. **F2 — Naming harmonization (Rust):** Rename internal fields
   `ps→pr`, `ks→kr`, `auth_root→ar`, `ds→dr`; rename local `cs` variables
   to `sr` throughout `principal.rs` and all dependents.
3. **F3 — State derivation helper (both):** Extract
   `recomputeState`/`recompute_state` covering the KR → AR → SR → PR chain;
   centralise all derivation sites.
4. **F4 — Go CommitBatch transitory state:** Introduce a thin wrapper type
   making intermediate principal state conventionally inaccessible during a
   batch (mirrors Rust's borrow-enforced `CommitScope`; Go convention only).
5. **F5 — Go TxRevoke → TxSelfRevoke:** Rename constant and align dispatch
   with Rust's `SelfRevoke` variant; no wire format change.
6. **F7 — typ-path consistency (both + fixtures):** Normalise all Rust typ
   constants to protocol-qualified suffixes (`"cyphr/key/create"` etc.);
   add `authority: &str` / `authority string` parameter to
   `finalize_with_arrow` / `FinalizeWithArrow` so the full typ is constructed
   as `authority + "/" + suffix` at call-site, never hardcoded; update intent
   files, CLI, and regenerate all golden fixtures via `fixture-gen`.

### Out of Scope

- Checkpoint loading parity (Go lacks `load_from_checkpoint`) — post-release
- Recovery transactions — spec not yet stable
- Level 5 features (OtherRevoke, RuleRoot) — spec not yet defined
- SPEC.md editing — handled in a separate pass by nrd/Zami

---

## Phases

> Each phase is a self-contained /core invocation. The phases are ordered by
> risk: low-blast-radius changes first, highest-blast-radius last.

1. **Phase 1: Internal naming & constant cleanup** — eliminate cognitive friction ✅
   - [x] **Go F1:** Remove `Typ*` string block from `parsed_coz.go`; rewrite
         `typSuffix()` to return `CozKind` directly rather than a parallel string.
         ParseCoz switch now matches `CozKind` values directly — indirection eliminated.
   - [x] **Go F5:** Rename `TxRevoke` → `TxSelfRevoke` throughout `go/cyphr/`;
         updated dispatch in `applyCozInternal`, principal_test.go, and error messages.
   - [x] **Rust F2:** Renamed `ps→pr`, `ks→kr`, `auth_root→ar`, `ds→dr`,
         `cs→sr` throughout `rs/cyphr/src/principal.rs`, `rs/cyphr/src/commit.rs`;
         all callers build clean; `cargo test` 125/125 pass.
   - **Commit boundary:** `refactor(go,rs/cyphr): Phase 1 structural naming cleanup`

2. **Phase 2: State derivation centralisation** — reduce derivation duplication
   - [ ] **Go F3:** Extract `recomputeStateFromKeys(p *Principal)` covering the
         full KR → AR → SR → PR chain with optional DR and CR. Replace the four
         duplicated derivation blocks in `Implicit`, `Explicit`, `finalizeCommit`,
         and `RecordAction`. Confirm `go test ./...` green.
   - [ ] **Rust F3:** Extract `recompute_state` (free function or method) in
         `principal.rs`; replace the five equivalent duplicated blocks. Confirm
         `cargo test` green.
   - **Commit boundary:** `refactor(go/cyphr): extract recomputeState helper; refactor(rs/cyphr): extract recompute_state helper`

3. **Phase 3: typ-path consistency + fixture regeneration** — protocol wire correctness

   > [!IMPORTANT]
   > This is the highest-blast-radius phase. The grammar `<authority>/cyphr/<noun>/<verb>`
   > is confirmed but **not currently used anywhere** in the codebase. Every source
   > file, every intent file, and every golden fixture must be updated. Tests will
   > not pass until all three layers are updated atomically within one commit.
   - [ ] **Rust constant normalisation:** Update `typ` module constants to be
         uniformly protocol-qualified suffixes — include the `cyphr/` protocol segment,
         exclude the authority (the caller's domain). `COMMIT_CREATE` is already correct;
         upgrade the remaining constants to match:
     - `KEY_CREATE       = "cyphr/key/create"`
     - `KEY_DELETE       = "cyphr/key/delete"`
     - `KEY_REPLACE      = "cyphr/key/replace"`
     - `KEY_REVOKE       = "cyphr/key/revoke"`
     - `PRINCIPAL_CREATE = "cyphr/principal/create"`
     - `COMMIT_CREATE    = "cyphr/commit/create"` _(value unchanged)_
   - [ ] **Rust `finalize_with_arrow` signature change:** Add `authority: &str`
         parameter. Construct the full typ as
         `format!("{}/{}", authority, typ::COMMIT_CREATE)`. Remove any hardcoded
         authority string inside the function body.
   - [ ] **Go constant normalisation:** In `parsed_coz.go` (or via
         `CozKind.String()` if F1 folds them), upgrade `Typ*` constants to
         protocol-qualified suffixes: `TypKeyCreate = "cyphr/key/create"` etc.
   - [ ] **Go `FinalizeWithArrow` signature change:** Add `authority string`
         parameter. Construct the full typ as `authority + "/" + TypCommitCreate`.
         Remove the `Authority` constant reference from `commit.go`.
   - [ ] **Intent file update:** Update all TOML/Go intent files under
         `rs/test-fixtures/` and `go/testfixtures/` that hard-code
         `"cyphr.me/key/create"` etc. to `"cyphr.me/cyphr/key/create"`. These are
         the inputs to `fixture-gen`.
   - [ ] **CLI update:** Update `rs/cyphr-cli/src/commands/key.rs` hard-coded
         strings (`"cyphr.me/key/create"`, `"cyphr.me/key/revoke"`) to use the
         library suffix constants with the CLI's concrete authority (`"cyphr.me"`).
   - [ ] **`fixture-gen` update:** Pass `"cyphr.me"` as the `authority` argument
         to `finalize_with_arrow` / `FinalizeWithArrow`. Update any intent-file
         parsing that constructs typ strings.
   - [ ] **Golden fixture regeneration:** Run `cargo run -p fixture-gen`. Verify
         all generated fixtures contain `"cyphr.me/cyphr/key/create"` and
         `"cyphr.me/cyphr/commit/create"`. Run `cargo test` and `go test ./...`.
   - **Commit boundary:** `fix(rs/cyphr,go/cyphr): inject authority at call-site, normalize typ constants to cyphr/<noun>/<verb> suffixes; fix(rs/cyphr-cli): use suffix constants with concrete authority; fix(test-fixtures,fixture-gen): update intent files for new grammar; fix(tests/golden): regenerate all fixtures`

4. **Phase 4: Go CommitBatch transitory state hardening** — safety by convention
   - [ ] **Go F4:** Evaluate whether a lightweight wrapper type around
         `CommitBatch` meaningfully reduces the surface of the transitory-state
         hazard given Go's absence of borrow checking. If so, introduce it and
         update callsites. If the analysis finds the existing doc-comment warning
         is sufficient, record the decision as "no structural change needed" in the
         deviation log and close this finding.
   - **Commit boundary:** `refactor(go/cyphr): [harden CommitBatch transitory state | document transitory state hazard — no structural change warranted]`

---

## Verification

- [ ] `go test ./...` green after each phase
- [ ] `cargo test` green after each phase
- [ ] No bare `"key/create"` or `"cyphr.me/key/create"` string literals remain
      in source or test files (only `"cyphr/key/create"` suffixes or
      `"cyphr.me/cyphr/key/create"` fully-qualified, never mixed)
- [ ] All fixtures in `tests/golden/` and `rs/tests/golden/` use
      `"cyphr.me/cyphr/commit/create"` (grep confirms zero occurrences of bare
      `"cyphr/commit/create"` or `"cyphr.me/commit/create"`)
- [ ] All transaction typs in all fixtures use `"cyphr.me/cyphr/key/create"` etc.
      (grep confirms zero occurrences of `"cyphr.me/key/create"` in fixture JSON)
- [ ] `CozKind::SelfRevoke` / `TxSelfRevoke` is the only revocation variant;
      no `TxRevoke` confusion exists
- [ ] State derivation logic appears in exactly one site per calling context per
      implementation (spot-checked against `Implicit`, `RecordAction`,
      `finalizeCommit`)
- [ ] Rust typ constants are uniformly protocol-qualified suffixes
      (`"cyphr/key/create"` etc.); `COMMIT_CREATE` is consistent with peers

---

## Technical Debt

| Item                                                | Severity | Why Introduced                                                        | Follow-Up                                                                              | Resolved |
| :-------------------------------------------------- | :------- | :-------------------------------------------------------------------- | :------------------------------------------------------------------------------------- | :------: |
| Checkpoint loading parity gap (Go)                  | MEDIUM   | Descoped from hardening window                                        | Post-release — requires protocol-level checkpoint signing spec                         |    ☐     |
| TxSelfRevoke: parse-time no-ID enforcement deferred | LOW      | e2e intent files currently emit `id == signer` for self-revoke cozies | Phase 3: update intent files to omit `target` for self-revoke; then tighten `ParseCoz` |    ☐     |

---

## Deviation Log

| Commit  | Planned                                                   | Actual                                                         | Rationale                                                                                                                                                                                                                    |
| :------ | :-------------------------------------------------------- | :------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Phase 1 | Parse-time `if pay.ID != ""` rejection for `TxSelfRevoke` | Reverted to runtime `id == signer` check in `applyCozInternal` | Existing e2e intent files use `target = signer` for self-revoke, producing a coz with `id == signer`. Strict no-ID enforcement at parse time required simultaneous Phase 3 intent-file edits. Deferred cleanly as tech debt. |

---

## Retrospective

_(Filled after execution)_

### Process

### Outcomes

### Pipeline Improvements

---

## References

- Sketch: `.sketches/2026-04-10-initial-public-release.md`
- Prior review: `brain/2ec4a39c.../artifacts/pre-release-structural-review.md`
