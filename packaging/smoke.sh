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
# Third claim: with a signing key, `transport_listen` brings up the Noise
# listener beside HTTP and /healthz still answers; without one the server
# refuses the transport, names why, and keeps serving HTTP. Red if the
# keyed server never reports "transport listening on", /healthz does not
# answer 200, or the keyless server reports a transport or stops serving.
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
status=$(curl -s -o "$tmp/body" -w '%{http_code}' "http://$addr/tip?pg=$unknown")
echo "GET /tip?pg=$unknown -> $status"
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
# $3 is the line to inject, $4 an optional table header regex to inject it
# after (default: the top of the file). awk and printf rather than sed's
# one-line i/a commands, whose syntax differs between GNU and BSD sed.
refused() {
  local label=$1 key=$2 line=$3 after=${4:-} cfg="$tmp/unknown-$1.toml"
  if [[ -z $after ]]; then
    { printf '%s\n' "$line"; cat "$tmp/config.toml"; } >"$cfg"
  else
    awk -v l="$line" -v re="$after" '{ print } $0 ~ re && !d { print l; d = 1 }' "$tmp/config.toml" >"$cfg"
  fi
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
refused top listn 'listn = "127.0.0.1:1"' || failed=1
refused admission polcy 'polcy = "invite"' '^[[]admission[]]' || failed=1
refused limits max_body_byte 'max_body_byte = 1' '^[[]limits[]]' || failed=1
[[ $failed == 0 ]] || exit 1

# Transport case. The signing key is an Ed25519 pair made with openssl: the
# raw key is the last 32 bytes of the PKCS#8 (seed) and SPKI (public) DER.
raw() { openssl pkey "$@" -outform DER | tail -c 32 | python3 -I -c \
  'import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).rstrip(b"=").decode())'; }
openssl genpkey -algorithm ed25519 -out "$tmp/key.pem"
printf '{"v":1,"alg":"Ed25519","pub_key":"%s","prv_key":"%s"}' \
  "$(raw -in "$tmp/key.pem" -pubout)" "$(raw -in "$tmp/key.pem")" >"$tmp/signing-key.json"

# Start a server on the example config plus the transport line, uncommented
# and retargeted to an ephemeral port; $1 is "keyed" (adds the
# signing key) or "keyless".
start_with_transport() {
  sed -e "s|^# transport_listen *= .*|transport_listen = \"127.0.0.1:0\"|" \
    -e "s|^data_dir *= .*|data_dir = \"$tmp/data-$1\"|" "$tmp/config.toml" >"$tmp/t-$1.toml"
  grep -q '^transport_listen' "$tmp/t-$1.toml" || { echo "smoke bug: transport_listen not enabled" >&2; return 1; }
  # Top-level keys go first: appended, they would land in [limits].
  if [[ $1 == keyed ]]; then
    { printf 'signing_key_path = "%s"\naudience = "smoke.example"\n' "$tmp/signing-key.json"; cat "$tmp/t-$1.toml"; } >"$tmp/t-$1.new"
    mv "$tmp/t-$1.new" "$tmp/t-$1.toml"
  fi
  "$bin" --config "$tmp/t-$1.toml" serve >"$tmp/out-t-$1" 2>"$tmp/err-t-$1" &
  pid=$!
  for _ in $(seq 1 100); do
    grep -q '^listening on ' "$tmp/out-t-$1" && return 0
    kill -0 "$pid" 2>/dev/null || { echo "server exited early:" >&2; cat "$tmp/err-t-$1" >&2; return 1; }
    sleep 0.1
  done
  echo "server never reported a listen address" >&2; return 1
}
# Rebuilt from the example so the shipped transport_listen line is the one
# tested.
sed -e "s|^listen *= .*|listen = \"127.0.0.1:0\"|" "$here/cyphr-server.example.toml" >"$tmp/config.toml"

start_with_transport keyed
for _ in $(seq 1 50); do grep -q '^transport listening on ' "$tmp/out-t-keyed" && break; sleep 0.1; done
grep -q '^transport listening on ' "$tmp/out-t-keyed" || {
  echo "keyed server did not report the transport listener:" >&2; cat "$tmp/err-t-keyed" >&2; exit 1; }
taddr=$(sed -n 's/^transport listening on //p' "$tmp/out-t-keyed")
haddr=$(sed -n 's/^listening on //p' "$tmp/out-t-keyed")
status=$(curl -s -o /dev/null -w '%{http_code}' "http://$haddr/healthz")
echo "GET /healthz -> $status; transport on $taddr"
[[ $status == 200 ]] || { echo "expected /healthz 200, got $status" >&2; exit 1; }
python3 -I -c 'import socket,sys; h,p=sys.argv[1].rsplit(":",1); socket.create_connection((h,int(p)),2).close()' "$taddr" \
  || { echo "transport address $taddr does not accept connections" >&2; exit 1; }
kill "$pid"; wait "$pid" 2>/dev/null || true; pid=

start_with_transport keyless
sleep 0.5
if grep -q '^transport listening on ' "$tmp/out-t-keyless"; then
  echo "keyless server started the transport" >&2; exit 1
fi
grep -q 'keyed server' "$tmp/err-t-keyless" || { echo "keyless refusal does not say why:" >&2; cat "$tmp/err-t-keyless" >&2; exit 1; }
haddr=$(sed -n 's/^listening on //p' "$tmp/out-t-keyless")
curl -sf -o /dev/null "http://$haddr/healthz" || { echo "keyless server stopped serving HTTP" >&2; exit 1; }
echo "smoke: ok"
