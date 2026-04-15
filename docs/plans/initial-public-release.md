# PLAN: Initial Public Release Preparation

<!--
  PLAN documents are structured procedures for /core execution.
  See: workflows/plan.md for the full protocol specification.
-->

## Goal

Execute the initial public offering of the Cyphr Protocol. We will establish a
clean v0.1.0 baseline by renaming the project from `Cyphrpass` to `Cyphr`,
ensuring documentation is accurate, publishing `malt` as an independent
primitive, deploying cohesive Docs and Blog sites via Sukr, and launching a
changelog pipeline using `git-cliff` with AI editorial polish.

## Constraints

- Docs (`docs.cyphr.me`) and Blog (`blog.cyphr.me`) must share a cohesive aesthetic despite separate subdomains.
- `git-cliff` handles raw changelog parsing; AI is used strictly for editorial polish of the output — not raw commit ingestion.
- Code documentation (in-code Rust/Go docs, `SPEC.md`, `docs/`) must not be overlooked; it requires a rigorous audit.
- `malt` remains in the monorepo but must be published via standard registries as an independent utility.

## Decisions

| Decision                 | Choice                          | Rationale                                                                                                                                                                                                                                                        |
| :----------------------- | :------------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Project Renaming**     | Comprehensive Structural Rename | Cyphrpass nomenclature is deeply embedded. Surface renaming creates massive technical dissonance between public brand and developer API. We will fully transition to `cyphr`.                                                                                    |
| **Intent Tag Domain**    | `cyphr.me/proto/`               | Segregates core protocol actions (e.g., `cyphr.me/proto/key/create`) from application-level actions (e.g., `cyphr.me/comment/create`) per the Section 7.2 `typ` grammar. Avoids the redundancy of `cyphr.me/cyphr/` and the genericness of `cyphr.me/protocol/`. |
| **Package Independence** | Monorepo Workspace Publishing   | Keeps `malt` maintenance centralized while allowing it to be a standalone primitive via crates.io and Go module paths natively.                                                                                                                                  |
| **Narrative Hub**        | Decoupled Sukr Deployments      | Clean separation of narrative/philosophy (`blog.`) from formal documentation (`docs.`) while maintaining identical aesthetics via a shared theme.                                                                                                                |
| **Changelog Gen**        | Git-Cliff + AI Editorial Polish | `git-cliff` parses conventional commits natively. An LLM is used strictly to polish the resulting output into a readable narrative — not to parse or summarize raw commits.                                                                                      |
| **License**              | No changes at this time         | The BOOL license structure requires further discussion with Zami before any modifications.                                                                                                                                                                       |
| **GitHub Repository**    | Rename to `Cyphrme/Cyphr`       | Confirmed. The repo will be renamed alongside the crate/module rename. Go module path becomes `github.com/cyphrme/cyphr`.                                                                                                                                        |

## Risks & Assumptions

| Risk / Assumption             | Severity | Status      | Mitigation / Evidence                                                                                                                                                             |
| :---------------------------- | :------- | :---------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Golden Fixture Corruption** | CRITICAL | Mitigated   | The rename changes `typ` strings, breaking signatures. Mitigation: update intent TOMLs, then run `fixture-gen` to regenerate golden fixtures natively. No manual fixture editing. |
| **Malt Independence**         | —        | Validated   | Grepping across `rs/malt` and `go/malt` reveals zero dependencies on or references to `cyphrpass`, confirming full decoupling.                                                    |
| **Aesthetic Drift**           | MEDIUM   | Mitigated   | Create a shared `theme/` directory in the monorepo that both `blog/` and `docs/` Sukr builds ingest or symlink.                                                                   |
| **Rename Surface Area**       | HIGH     | Unvalidated | The rename involves core strings that parsers match against. Parser logic depending on exact string matches must be meticulously tested post-rename.                              |
| **GitHub Repo Name**          | MEDIUM   | Resolved    | Confirmed: repo will be renamed. Go module path will be `github.com/cyphrme/cyphr`. GitHub provides automatic redirects from old URLs.                                            |

## Open Questions

_(Resolved)_

- **Crate/Module Naming:** `cyphr`. Rust crates: `cyphr`, `cyphr-storage`, `cyphr-cli`. Go module: `github.com/cyphrme/cyphr`.
- **Intent Tag Domain:** `cyphr.me/proto` (e.g., `cyphr.me/proto/key/create`).
- **License:** Left as BOOL pending future discussions with Zami.
- **GitHub Repository:** Confirmed rename from `Cyphrme/Cyphrpass` to `Cyphrme/Cyphr`.

## Scope

### In Scope

- Full sweeping rename of `cyphrpass` → `cyphr` across crates, modules, documentation, and GitHub repository.
- Rename of intent tag domain: `cyphr.me/cyphrpass/` → `cyphr.me/proto/`.
- Publishing `malt` to crates.io and Go module registries.
- Publishing `cyphr` crates and Go module.
- Documentation audit of `docs/`, `SPEC.md`, and in-code comments.
- CI pipeline for `git-cliff` changelog generation and CLI binary release.

### Out of Scope

- Finalizing a custom "commons capture resistance" license structure.
- Implementing Mutual State Synchronization (MSS) or other Level 5/6 features.
- GitHub organization rename (org stays `Cyphrme`).

## Phases

> [!CAUTION]
> These phases are designed to be executed step-by-step via the `/core` workflow.
> Phases 2–4 depend on Phase 1. Phases 3 and 4 are independent of each other.

1. **Phase 1: Codebase Rename & Test Remediation** — Fully purge Cyphrpass nomenclature.
   - [x] Confirm exact crate/module name with user.
   - [x] Execute GitHub repository rename (`Cyphrme/Cyphrpass` → `Cyphrme/Cyphr`).
   - [x] Execute codebase rename with the following mapping:
     - `cyphrpass` → `cyphr` (crate names, module names, struct references)
     - `Cyphrpass` → `Cyphr` (type names, doc references, prose)
     - `cyphr.me/cyphrpass/` → `cyphr.me/proto/` (intent `typ` strings)
     - `cyphrpass-storage` → `cyphr-storage`, `cyphrpass-cli` → `cyphr-cli`
     - Directory renames as needed (e.g., `rs/cyphrpass/` → `rs/cyphr/`)
   - [x] Update intent TOML files with new `typ` domain.
   - [x] Run `cargo run -p fixture-gen` to regenerate golden test fixtures.
   - [x] Verify `go test ./...` and `cargo test` pass with full parity.

2. **Phase 2: Formal Documentation Audit** — Ensure external materials match the codebase. _(Depends on Phase 1)_
   - [x] Scrub `docs/` for out-of-date plans and delete/archive irrelevancies.
   - [x] Audit `SPEC.md` and `README.md` to ensure Cyphr Protocol constraints are accurately represented with the new nomenclature.
   - [x] Standardize Rust and Go in-code documentation.

3. **Phase 3: Sukr Subdomain Provisioning** — Establish `.cyphr.me` static sites. _(Depends on Phase 1)_
   - [x] Create a shared `theme/` directory for unified CSS (`docs/sites/theme/`).
   - [x] Scaffold docs site targeting `docs.cyphr.me` (`docs/sites/docs/`).
   - [x] Scaffold blog site targeting `blog.cyphr.me` (`docs/sites/blog/`).

4. **Phase 4: Release Pipeline & Malt Publishing** — Registry publishing and release automation. _(Depends on Phase 1)_
   - [x] Establish `cliff.toml` conventional commit parser config.
   - [ ] Publish `malt` independently to crates.io and Go registries. _(manual)_
   - [ ] Publish `cyphr` crates to crates.io. _(manual)_
   - [x] Deploy GitHub Action for cross-compiling CLI binaries and generating release changelogs (`release.yml`, scoped `rs/v*` and `go/v*` tags).

## Verification

- [ ] `docs.cyphr.me` and `blog.cyphr.me` render with identical styling locally.
- [ ] `cargo publish --dry-run` runs cleanly for `malt`, `cyphr`, `cyphr-storage`, and `cyphr-cli`.
- [ ] The full `tests/golden/` suite passes in both Go and Rust implementations.
- [ ] Zero references to `cyphrpass` remain in source code (excluding git history and this plan).

## Technical Debt

| Item | Severity | Why Introduced | Follow-Up | Resolved |
| :--- | :------- | :------------- | :-------- | :------: |

## Deviation Log

| Commit | Planned | Actual | Rationale |
| :----- | :------ | :----- | :-------- |

## Retrospective

### Process

_(To be populated post-execution)_

### Outcomes

_(To be populated post-execution)_

### Pipeline Improvements

_(To be populated post-execution)_

## References

- Sketch: `.sketches/2026-04-10-initial-public-release.md`
