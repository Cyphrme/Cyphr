// The marker below stands in for a test that was renamed out from under
// its own citation: `cargo test <old-name> --exact` still exits 0 (no
// test failed — none matched) and prints exactly this summary line. No
// exempt bang, so this is the case the runner's vacuity detector
// (axiosoph/docket src/run.rs, `detect_vacuity`) exists to catch — this
// is the sharpest fixture in the suite and the reason the node exists:
// a marker that stays green after the thing it names has moved must NOT
// report Pass.
//
// @docket: renamed-target :: printf 'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n'

#[test]
fn a_real_test_with_a_different_name() {}
