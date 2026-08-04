# Cyphr's docket genre configuration.
#
# Registers `docs/architecture/**` as the one genre permitted to carry
# `requirement` claims (docket README's genre table: architecture overview
# answers "how it fits together"). An undeclared tree is a slot docket
# leaves unscanned, not a gap in this file (see docs/AGENTS.md for the
# reasoning).
#
# `docs/trust-model.md` is declared with no permitted kinds, which is what
# makes it enforceable as definitions rather than requirements: an empty
# `kinds` bars claim blocks outright and turns an RFC-2119 keyword in the
# document's own voice into a check failure. A definitions document that
# needs "MUST" has drifted into being a specification, and this catches
# that mechanically instead of leaving it to review. The file sits at the
# `docs/` root rather than under `docs/architecture/**` because two genres
# matching one path is a configuration error, and that tree already
# permits `requirement`.
#
# docket (ssh://git@github.com/axiosoph/docket.git) is a sibling checkout,
# not vendored into this repository (see docs/AGENTS.md for the
# trade-off), so its claim-block contract must be passed explicitly. Given
# a checkout at <docket>, run from this repository's root:
#
#   <docket>/target/release/docket check --corpus . \
#     --contract <docket>/contracts/claim_apply.ncl
{
  genres = [
    { path = "docs/architecture/**", kinds = ["requirement"], quadrant = "reference" },
    { path = "docs/trust-model.md", kinds = [], quadrant = "reference" },
  ],
}
