// An exempt marker (`!`), carrying the exact same renamed-away-test
// output shape as ../renamed-test-vacuity/src/lib.rs — "0 passed;
// 0 failed" — so this fixture and that one are identical except for the
// bang. docket's vacuity detector (axiosoph/docket src/run.rs,
// `detect_vacuity`) is skipped unconditionally for an exempt marker: the
// author's marker is a deliberate, once-stated assertion that the exit
// code alone is conclusive. Measured, not assumed — see
// scripts/docket-fixtures/run for the captured result and
// .ledger/tech-debt/2026-08-04-the-marker-guard-is-unwired-and-holed.yaml
// for why this is the sharper of the two holes that record names.
//
// @docket: exempt-target! :: printf 'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n'
