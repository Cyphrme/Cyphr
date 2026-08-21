# Cyphr's docket genre configuration — the documentation gate registers
# only the genres being born by this workstream; the rest of docs/ waits
# until it earns registration on its own workstream.
#
# `docs/architecture/**` carries `requirement` claims (docket's own genre
# table: "how it fits together" answers to the `requirement` kind). It is
# the first tree this repository wires the gate to.
#
# `docs/use/**` is the user-documentation genre home a follow-on
# workstream populates. An earlier revision registered it with
# `constraint`, reasoning from docket's own kind derivation (README,
# "Why exactly three kinds") that user documentation's evaluator axis
# is monotonicity. That derivation's own next sentence says what such a
# claim actually is: "they are constraints in a different genre, not a
# fourth kind" — the specification genre, a different path, not this
# one. Docket's genre table gives user documentation no claim kind of
# its own at all — its row reads "(evaluator: executable example)",
# none of `requirement`/`invariant`/`constraint` — so `constraint` here
# was a genre/path mismatch, not a valid registration.
#
# Corrected to `kinds = []`: the same shape `docs/trust-model.md` uses
# (a sibling workstream's registration, node/trust-model) and docket
# dogfoods on itself (its own docket.ncl: `README.md` gets `kinds = []`
# "so a future claim block added here is a loud C3 genre violation
# instead of silently unscanned"). A tree is registered either because
# it carries claims or because it must never carry one. Leaving the
# path unregistered instead would make it unscanned rather than
# enforced — verified against the pinned binary: an unregistered tree
# produces zero findings for any content it holds, while a `kinds = []`
# tree turns a stray claim block into a `Fail`-severity `C3` genre
# violation. Unscanned catches nothing later; `kinds = []` does.
#
# Consequence, also verified against the pinned binary: docket treats a
# bracketed-kebab-id heading (`### [id]`) as a claim *definition*
# regardless of whether the genre permits any kind (README: "a
# heading" is one of three id-declaration forms). Once this tree is
# scanned, the guide's link-anchor headings —
# `docs/use/detecting-a-split-view.md`'s `### [fixed-rule-decides-conflict]`
# among them — carry no claim block, so each is `unregistered-definition`:
# `Warn` severity, never fails `docket check` (MVP.md's exit-code
# table), but real noise on every run rather than silence.
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
    { path = "docs/use/**", kinds = [], quadrant = "how-to" },
  ],
}
