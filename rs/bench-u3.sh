#!/bin/sh
# U3 scaling benches: per-operation cost against history length n, beside
# each operation's bound. Informational (wall time, bytes); the gated
# counterpart is the `u3_bounds` tests. `U3_NS=10,100,1000,10000` sets the
# history lengths (default 10,100,1000). Release profile, one table each.
set -e
cd "$(dirname "$0")"
cargo bench -p cyphr-storage --bench u3_engine
cargo bench -p cyphr-server --bench u3_server
