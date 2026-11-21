// A malformed marker: one colon where the grammar needs two. docket's
// scanner (axiosoph/docket src/marker.rs, `parse_marker_line`) requires
// the literal `::` after the id; a bare single colon fails to parse and
// the line is invisible to the scanner — indistinguishable from no
// marker at all (marker.rs's own module docs state this explicitly:
// "a line this parser cannot turn into a Marker is indistinguishable,
// to the runner, from no marker at all").
//
// @docket: malformed-target : printf 'no-op'
