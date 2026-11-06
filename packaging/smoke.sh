#!/usr/bin/env bash
# Smoke test for a cyphr-server binary.
#
# Claim: the example config starts a working server. Scenario (end to end):
# start the binary with cyphr-server.example.toml against an empty data dir
# and expect GET /tip for an unknown principal to answer 404 with a JSON
# envelope. Red if the binary rejects any example option, never listens, or
# answers anything but a 404 envelope.
#
# Second claim: a misspelled config key is refused at startup, naming the
# key, rather than silently falling back to a default (a typo'd
# `[admission] polcy` would otherwise leave admission open). Red if the
# server starts, or exits without naming the key, on a config with one
# unknown key.
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
# the shipped file, so a rejected option fails here. (The example aligns its
# `=`, so the patterns allow any run of spaces; a pattern that matches nothing
# leaves the example's /var/lib/cyphr path in place and fails on permissions.)
# The ephemeral port is reported on stdout ("listening on <addr>").
sed -e "s|^listen *= .*|listen = \"127.0.0.1:0\"|" \
  -e "s|^data_dir *= .*|data_dir = \"$tmp/data\"|" \
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

# Release the data dir's lock: a refusal below must be for the unknown key,
# never for finding the first server still holding the store.
kill "$pid"; wait "$pid" 2>/dev/null || true; pid=

# Unknown-key case: the shipped config plus one misspelled key must not
# start. The key is injected into an existing table (a second table of the
# same name would be refused as a duplicate, for the wrong reason).
refused() {
  local label=$1 key=$2 inject=$3 cfg="$tmp/unknown-$1.toml"
  sed -e "$inject" "$tmp/config.toml" >"$cfg"
  grep -q "^$key" "$cfg" || { echo "smoke bug: '$key' not injected" >&2; return 1; }
  "$bin" --config "$cfg" serve >"$tmp/out-$label" 2>"$tmp/err-$label" &
  local p=$! up=
  for _ in $(seq 1 50); do
    grep -q '^listening on ' "$tmp/out-$label" && { up=1; break; }
    kill -0 "$p" 2>/dev/null || break
    sleep 0.1
  done
  if [[ -n $up ]]; then
    kill "$p" 2>/dev/null || true
    echo "unknown key '$key' was accepted: server started" >&2
    return 1
  fi
  if wait "$p"; then
    echo "unknown key '$key': server exited 0" >&2
    return 1
  fi
  grep -q "$key" "$tmp/err-$label" || {
    echo "refusal for '$key' does not name it:" >&2
    cat "$tmp/err-$label" >&2
    return 1
  }
}
failed=0
refused top listn '1i listn = "127.0.0.1:1"' || failed=1
refused admission polcy '/^\[admission\]/a polcy = "invite"' || failed=1
refused limits max_body_byte '/^\[limits\]/a max_body_byte = 1' || failed=1
[[ $failed == 0 ]] || exit 1
echo "smoke: ok"
