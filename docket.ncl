# Cyphr's docket genre configuration.
#
# Registers `docs/architecture/**` as the one genre permitted to carry
# `requirement` claims (docket README's genre table: architecture overview
# answers "how it fits together"). No other tree is declared here — an
# absent genre is a slot docket leaves unscanned, not a gap in this file
# (see docs/AGENTS.md for the reasoning).
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
  ],
}
