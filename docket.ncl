# Cyphr's docket genre configuration — the documentation gate registers
# only the genres being born by this workstream; the rest of docs/ waits
# until it earns registration on its own workstream.
#
# `docs/architecture/**` carries `requirement` claims (docket's own genre
# table: "how it fits together" answers to the `requirement` kind). It is
# the first tree this repository wires the gate to.
#
# `docs/use/**` is the user-documentation genre home a follow-on
# workstream populates. Per docket's genre table, user documentation's
# natural evaluator is an executable example, and per its own kind
# derivation (README, "Why exactly three kinds") that evaluator's axis is
# monotonicity — "an example that must keep running" — which is exactly
# what `constraint` bounds, not a fourth kind. It is registered now, with
# `constraint`, so the tree's first real document can carry claims from
# day one rather than needing a second edit to this file once content
# lands.
#
# An undeclared or not-yet-existing tree is a slot docket leaves
# unscanned, not a gap in this file — verified empirically: registering
# `docs/architecture/**` and `docs/use/**` before either directory exists
# still reports `docket check --corpus . --json` clean (empty
# claims/documents, zero findings, exit 0).
#
# docket is a sibling checkout, never vendored into this repository (see
# docs/AGENTS.md for the trade-off and the pinned invocation).
{
  genres = [
    { path = "docs/architecture/**", kinds = ["requirement"], quadrant = "reference" },
    { path = "docs/use/**", kinds = ["constraint"], quadrant = "how-to" },
  ],
}
