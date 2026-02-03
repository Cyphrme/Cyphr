#!/usr/bin/env bash
# Cyphrpass CLI Demo Script
# Demonstrates all available commands

set -e

CLI="cargo run -p cyphrpass-cli --"
STORE="./demo-data"
KEYSTORE="./demo-keys.json"

# Cleanup from previous runs
rm -rf "$STORE" "$KEYSTORE" ./demo-export.jsonl ./demo-import-data 2>/dev/null || true

echo "=== Cyphrpass CLI Demo ==="
echo ""

# 1. Key Generate
echo "=== 1. key generate ==="
GENESIS=$($CLI --keystore "$KEYSTORE" --store "file:$STORE" --output json key generate --algo ES256 --tag genesis | jq -r '.tmb')
echo "✅ Generated genesis key: $GENESIS"
echo ""

# 2. Key List (keystore only)
echo "=== 2. key list (keystore) ==="
$CLI --keystore "$KEYSTORE" --store "file:$STORE" key list
echo ""

# 3. TX List (genesis state - no transactions)
echo "=== 3. tx list (genesis state) ==="
$CLI --keystore "$KEYSTORE" --store "file:$STORE" tx list --identity="$GENESIS"
echo ""

# 4. Inspect (genesis state)
echo "=== 4. inspect (genesis state) ==="
$CLI --keystore "$KEYSTORE" --store "file:$STORE" inspect --identity="$GENESIS"
echo ""

# 5. Key Add (creates first transaction)
echo "=== 5. key add ==="
ADD_OUT=$($CLI --keystore "$KEYSTORE" --store "file:$STORE" --output json key add --identity="$GENESIS" --signer="$GENESIS")
SECOND=$(echo "$ADD_OUT" | jq -r '.added_key')
echo "$ADD_OUT" | jq .
echo ""

# 6. Key List (identity - after add)
echo "=== 6. key list --identity (after add) ==="
$CLI --keystore "$KEYSTORE" --store "file:$STORE" key list --identity="$GENESIS"
echo ""

# 7. Export
echo "=== 7. export ==="
$CLI --keystore "$KEYSTORE" --store "file:$STORE" export --identity="$GENESIS" --output=./demo-export.jsonl
echo ""

# 8. Import (to new store)
echo "=== 8. import ==="
$CLI --keystore "$KEYSTORE" --store "file:./demo-import-data" import --input=./demo-export.jsonl
echo ""

# 9. Verify imported identity
echo "=== 9. key list (imported store) ==="
$CLI --keystore "$KEYSTORE" --store "file:./demo-import-data" key list --identity="$GENESIS"
echo ""

# 10. Key Revoke
echo "=== 10. key revoke ==="
echo "Revoking key: $SECOND"
$CLI --keystore "$KEYSTORE" --store "file:$STORE" key revoke --identity="$GENESIS" --key="$SECOND" --signer="$GENESIS"
echo ""

# Final state
echo "=== Final State ==="
$CLI --keystore "$KEYSTORE" --store "file:$STORE" key list --identity="$GENESIS"
echo ""

# Cleanup
echo "🧹 Cleaning up demo files..."
rm -rf "$STORE" "$KEYSTORE" ./demo-export.jsonl ./demo-import-data 2>/dev/null || true

echo "✅ Demo complete!"
