# Isolated corpus root for the DK0 fixture suite — see
# scripts/docket-fixtures/run for what it proves. Not the repository's
# own registration; a fixture never shares state with the real corpus.
{ genres = [ { path = "docs/**", kinds = ["requirement"], quadrant = "reference" } ] }
