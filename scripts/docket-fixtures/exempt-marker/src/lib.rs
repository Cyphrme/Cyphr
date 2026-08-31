// An exempt marker (`!`), carrying the exact same renamed-away-test
// output shape as ../renamed-test-vacuity/src/lib.rs — "0 passed;
// 0 failed" — so this fixture and that one are identical except for the
// bang. docket's vacuity detector (axiosoph/docket src/run.rs,
// `detect_vacuity`) is skipped unconditionally for an exempt marker: the
// author's marker is a deliberate, once-stated assertion that the exit
// code alone is conclusive. Measured, not assumed — see
// scripts/docket-fixtures/run for the captured result: this fixture is
// the sharper of the two silent-pass holes the exemption sigil opens,
// the other being the malformed-marker fixture alongside it.
//
// @docket: exempt-target! :: printf 'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n'
