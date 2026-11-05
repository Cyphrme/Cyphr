#!/usr/bin/env bash
# Smoke test for a cyphr-server binary.
#
# Claim: the example config starts a working server. Scenario (end to end):
# start the binary with cyphr-server.example.toml against an empty data dir
# and expect GET /tip for an unknown principal to answer 404 with a JSON
# envelope. Red if the binary rejects any example option, never listens, or
# answers anything but a 404 envelope.
#
# Usage: packaging/smoke.sh [path-to-cyphr-server]   (default: PATH lookup)
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bin=${1:-cyphr-server}
tmp=$(mktemp -d)
pid=
cleanup() {
  [[ -n $pid ]] && kill "$pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

# Retarget the example's two environment-specific keys; everything else is
# the shipped file, so a rejected option fails here. The ephemeral port is
# reported on stdout ("listening on <addr>").
sed -e "s|^listen = .*|listen = \"127.0.0.1:0\"|" \
  -e "s|^data_dir = .*|data_dir = \"$tmp/data\"|" \
  "$here/cyphr-server.example.toml" >"$tmp/config.toml"

"$bin" --config "$tmp/config.toml" serve >"$tmp/out" 2>"$tmp/err" &
pid=$!

addr=
for _ in $(seq 1 100); do
  addr=$(sed -n 's/^listening on //p' "$tmp/out")
  [[ -n $addr ]] && break
  kill -0 "$pid" 2>/dev/null || { echo "server exited early:" >&2; cat "$tmp/err" >&2; exit 1; }
  sleep 0.1
done
[[ -n $addr ]] || { echo "server never reported a listen address" >&2; cat "$tmp/err" >&2; exit 1; }

# An unknown principal id: well-formed base64url of 32 bytes, never created.
unknown=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
status=$(curl -s -o "$tmp/body" -w '%{http_code}' "http://$addr/tip?pr=$unknown")
echo "GET /tip?pr=$unknown -> $status"
cat "$tmp/body"; echo

[[ $status == 404 ]] || { echo "expected 404, got $status" >&2; exit 1; }
python3 -I - "$tmp/body" <<'PY'
import json, sys
env = json.load(open(sys.argv[1]))
assert env.get("v") == 1 and "payload" in env and "statement" in env, env
PY
echo "smoke: ok"
