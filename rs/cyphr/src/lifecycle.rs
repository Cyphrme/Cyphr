//! Principal lifecycle state derivation (SPEC.md §11).

/// The six base lifecycle states a principal may occupy (SPEC.md:1946-1978,
/// §11.2 States).
///
/// `Errored` (SPEC.md §11.1) is not a variant here: it is an orthogonal flag
/// that may accompany any base state, observable separately via
/// [`crate::principal::Principal::is_errored`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    /// Normal operating state.
    Active,
    /// Frozen via `freeze/create`, not yet undone by `freeze/delete`.
    Frozen,
    /// `principal/delete` signed; no new transactions or actions possible.
    Deleted,
    /// (Level 4+) AR mutation impossible, but data actions still possible.
    Zombie,
    /// No active keys and no data-action capability remain.
    Dead,
    /// Deleted with all keys revoked or deleted; the most terminal state.
    Nuked,
}

/// Derive the base lifecycle state from the four independent SPEC §11.1
/// conditions relevant below Level 5.
///
/// `CanMutateAR` is not a parameter: SPEC.md:1990-1992 states it is
/// non-monotonic in key count only at Level 5+, so below Level 5 it always
/// equals `has_active_keys` — it is computed here rather than accepted as a
/// possibly-inconsistent input, which also makes `CanMutateAR != HasActiveKeys`
/// unreachable by construction rather than by convention.
///
/// Resolves SPEC §11.2's row overlaps by first-match precedence — Nuked,
/// Deleted, Dead, Zombie, Frozen, Active (the R5 ruling) — which is SPEC's
/// own severity/containment ordering made explicit (SPEC.md:1971-1978: Nuked
/// is "the most terminal state," a strict sub-case of both Deleted and Dead).
///
/// The same precedence also resolves the one cell SPEC's literal row
/// predicates leave undefined: `is_deleted && is_frozen`. SPEC.md states
/// these flags are mutually exclusive ("a principal cannot be frozen and
/// deleted at the same time"), so no valid input reaches this branch through
/// [`crate::principal::Principal::lifecycle_state`] — but a pure function
/// must still be total over its raw boolean domain, so it is resolved the
/// same way the SPEC already resolves every other overlap: Deleted (rank 2)
/// wins over Frozen (rank 5).
pub fn derive_lifecycle_state(
    is_deleted: bool,
    is_frozen: bool,
    has_active_keys: bool,
    can_data_action: bool,
) -> LifecycleState {
    let can_mutate_ar = has_active_keys;
    if is_deleted && !has_active_keys {
        LifecycleState::Nuked
    } else if is_deleted {
        LifecycleState::Deleted
    } else if !has_active_keys && !can_data_action {
        LifecycleState::Dead
    } else if !can_mutate_ar && can_data_action {
        LifecycleState::Zombie
    } else if is_frozen {
        LifecycleState::Frozen
    } else {
        LifecycleState::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent reference oracle built directly from SPEC.md:1950-1957's
    /// literal row predicates (NOT sharing logic with `derive_lifecycle_state`),
    /// resolved by R5 first-match precedence. Deliberately re-derives the
    /// matrix from the SPEC text rather than mirroring the implementation, so
    /// this test can catch a mis-ordered or mis-transcribed precedence chain
    /// in the implementation.
    ///
    /// `is_deleted && is_frozen` is SPEC-asserted unreachable
    /// (SPEC.md:1976-1978) and is excluded from this oracle; it is covered
    /// separately by `d_and_f_resolves_by_precedence` below.
    fn spec_row_oracle(d: bool, f: bool, k: bool, c: bool) -> Option<LifecycleState> {
        let m = k; // CanMutateAR == HasActiveKeys below Level 5.
        let rows: [(bool, LifecycleState); 6] = [
            (d && !k, LifecycleState::Nuked),
            (d && !f, LifecycleState::Deleted),
            (!k && !c, LifecycleState::Dead),
            (!m && c && !d, LifecycleState::Zombie),
            (f && !d && m && k, LifecycleState::Frozen),
            (!d && !f && m && k, LifecycleState::Active),
        ];
        rows.into_iter().find(|(matches, _)| *matches).map(|(_, s)| s)
    }

    #[test]
    fn matches_spec_matrix_over_reachable_domain() {
        for d in [false, true] {
            for f in [false, true] {
                for k in [false, true] {
                    for c in [false, true] {
                        if d && f {
                            continue; // SPEC-asserted unreachable; see below.
                        }
                        if c && !k {
                            continue; // CanDataAction implies HasActiveKeys.
                        }
                        let Some(expected) = spec_row_oracle(d, f, k, c) else {
                            panic!("oracle has no row for d={d} f={f} k={k} c={c}");
                        };
                        let actual = derive_lifecycle_state(d, f, k, c);
                        assert_eq!(
                            actual, expected,
                            "d={d} f={f} k={k} c={c}: expected {expected:?}, got {actual:?}"
                        );
                    }
                }
            }
        }
    }

    /// c-precedence targeted case: the triple-overlap cell
    /// (Deleted ∧ ¬Frozen ∧ ¬HasActiveKeys) simultaneously satisfies Nuked,
    /// Deleted, and Dead's literal row predicates. R5 precedence (Nuked
    /// first) must select Nuked.
    #[test]
    fn triple_overlap_cell_resolves_to_nuked() {
        assert_eq!(
            derive_lifecycle_state(true, false, false, false),
            LifecycleState::Nuked
        );
    }

    /// The SPEC-undefined `is_deleted && is_frozen` cell resolves via the
    /// same R5 precedence used for every other overlap: Deleted (rank 2)
    /// before Frozen (rank 5). This cell is unreachable through
    /// `Principal::lifecycle_state` (SPEC.md:1976-1978 asserts Deleted and
    /// Frozen mutually exclusive) but the pure function is still exercised
    /// directly here to prove totality.
    #[test]
    fn d_and_f_resolves_by_precedence() {
        assert_eq!(
            derive_lifecycle_state(true, true, true, false),
            LifecycleState::Deleted
        );
        assert_eq!(
            derive_lifecycle_state(true, true, true, true),
            LifecycleState::Deleted
        );
        // With no active keys, Nuked (rank 1) still outranks Deleted.
        assert_eq!(
            derive_lifecycle_state(true, true, false, false),
            LifecycleState::Nuked
        );
    }

    /// c-zombie-unreachable (pure-function level): Zombie requires
    /// `!has_active_keys && can_data_action`, but `can_data_action` is wired
    /// through `Principal::lifecycle_state` as `level() >= L4 &&
    /// has_active_keys` (SPEC.md:1990-1992 grounds `CanMutateAR ==
    /// HasActiveKeys` below Level 5, and this crate's `Level` enum caps at
    /// L4 — there is no L5 variant anywhere in `rs/`). So no input the real
    /// accessor can construct ever has `!has_active_keys && can_data_action`
    /// simultaneously true, and Zombie is unreachable via the public API.
    #[test]
    fn zombie_unreachable_when_can_data_action_implies_has_active_keys() {
        for d in [false, true] {
            for f in [false, true] {
                for k in [false, true] {
                    for c in [false, true] {
                        if c && !k {
                            continue; // the wiring invariant under test.
                        }
                        assert_ne!(
                            derive_lifecycle_state(d, f, k, c),
                            LifecycleState::Zombie,
                            "d={d} f={f} k={k} c={c} produced Zombie despite \
                             can_data_action => has_active_keys"
                        );
                    }
                }
            }
        }
    }
}
