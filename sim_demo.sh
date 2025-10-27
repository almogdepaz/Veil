#!/usr/bin/env bash
# test script for encrypted payment notes feature

set -e

# timing helpers
TOTAL_START=$(date +%s)
TOTAL_SEND_TIME=0
TOTAL_SCAN_TIME=0
SEND_COUNT=0
SCAN_COUNT=0

time_start() {
    STEP_START=$(date +%s.%N 2>/dev/null || echo "0")
}

time_end() {
    local step_type="$1"
    if [ "$STEP_START" != "0" ]; then
        local step_end=$(date +%s.%N)
        local duration=$(echo "$step_end - $STEP_START" | bc 2>/dev/null || echo "0")
        printf "   ⏱️  %.2fs\n" "$duration"
        
        if [[ "$step_type" == "send"* ]]; then
            TOTAL_SEND_TIME=$(echo "$TOTAL_SEND_TIME + $duration" | bc 2>/dev/null || echo "0")
            SEND_COUNT=$((SEND_COUNT + 1))
        elif [[ "$step_type" == "scan"* ]]; then
            TOTAL_SCAN_TIME=$(echo "$TOTAL_SCAN_TIME + $duration" | bc 2>/dev/null || echo "0")
            SCAN_COUNT=$((SCAN_COUNT + 1))
        fi
    fi
}

# backend selection (default: risc0)
BACKEND="${1:-risc0}"

if [[ "$BACKEND" != "risc0" && "$BACKEND" != "sp1" ]]; then
    echo "❌ invalid backend: $BACKEND"
    echo "usage: $0 [risc0|sp1]"
    exit 1
fi

# backend-specific build directory and binary path
BUILD_DIR="./target/$BACKEND"
BINARY="$BUILD_DIR/release/clvm-zk"

# check if binary exists, build if needed
if [ ! -f "$BINARY" ]; then
    echo "🔨 binary not found for $BACKEND backend, building..."
    cargo build --release --target-dir "$BUILD_DIR" --no-default-features --features "$BACKEND,testing"
    
    echo "✅ build complete: $BINARY"
    echo ""
fi

echo "🧪 testing encrypted payment notes with simulator"
echo "backend: $BACKEND"
echo "=================================================="

# clean slate
echo ""
echo "🗑️  resetting simulator state..."
$BINARY sim init --reset
echo "✅ simulator reset complete"

# create wallets
echo ""
echo "2️⃣  creating wallets (alice and bob)..."
$BINARY sim wallet alice create
$BINARY sim wallet bob create

# fund alice
echo ""
echo "3️⃣  funding alice with 3000 mojos..."
$BINARY sim faucet alice --amount 1000 --count 1
$BINARY sim faucet alice --amount 2000 --count 1

# check alice balance
echo ""
echo "4️⃣  alice's initial balance:"
$BINARY sim wallet alice balance

# alice sends to bob
echo ""
echo "5️⃣  alice sends 500 mojos to bob..."
time_start
$BINARY sim send alice bob 500 --coins auto
time_end "send_1"

# bob's balance before scan (should be 0)
echo ""
echo "6️⃣  bob's balance BEFORE scanning (should be 0):"
$BINARY sim wallet bob balance

# bob scans for encrypted notes
echo ""
echo "7️⃣  bob scans for encrypted payment notes..."
time_start
$BINARY sim scan bob
time_end "scan_1"

# bob's balance after scan (should be 500)
echo ""
echo "8️⃣  bob's balance AFTER scanning (should be 500):"
$BINARY sim wallet bob balance

# alice sends to bob again
echo ""
echo "5️⃣  alice sends 500 mojos to bob (second payment)..."
time_start
$BINARY sim send alice bob 500 --coins auto
time_end "send_2"

# bob's balance before scan (should be 500)
echo ""
echo "6️⃣  bob's balance BEFORE scanning (should be 0):"
$BINARY sim wallet bob balance

# bob scans for encrypted notes again
echo ""
echo "7️⃣  bob scans for encrypted payment notes again..."
time_start
$BINARY sim scan bob
time_end "scan_2"

# bob's balance after scan (should be 1000)
echo ""
echo "8️⃣  bob's balance AFTER scanning (should be 500):"
$BINARY sim wallet bob balance


# bob sends some back to alice
echo ""
echo "9️⃣  bob sends 200 mojos back to alice..."
time_start
$BINARY sim send bob alice 200 --coins auto
time_end "send_3"

# alice scans to receive
echo ""
echo "🔟 alice scans for her payment..."
time_start
$BINARY sim scan alice
time_end "scan_3"

# final balances
echo ""
echo "✅ final balances:"
echo ""
echo "alice:"
$BINARY sim wallet alice balance
echo ""
echo "bob:"
$BINARY sim wallet bob balance

# show status
echo ""
echo "📊 simulator status:"
$BINARY sim status

# show saved proofs
echo ""
echo "🔐 saved proofs:"
$BINARY sim proofs

TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

echo ""
echo "=================================================="
echo "✅ encrypted payment notes test complete!"
echo ""
echo "backend used: $BACKEND"
echo ""
echo "⏱️  timing summary:"
if [ "$SEND_COUNT" -gt 0 ] && [ "$TOTAL_SEND_TIME" != "0" ]; then
    AVG_SEND=$(echo "scale=2; $TOTAL_SEND_TIME / $SEND_COUNT" | bc 2>/dev/null || echo "N/A")
    printf "  - total send time: %.2fs (%d transactions, avg: %ss)\n" "$TOTAL_SEND_TIME" "$SEND_COUNT" "$AVG_SEND"
fi
if [ "$SCAN_COUNT" -gt 0 ] && [ "$TOTAL_SCAN_TIME" != "0" ]; then
    AVG_SCAN=$(echo "scale=2; $TOTAL_SCAN_TIME / $SCAN_COUNT" | bc 2>/dev/null || echo "N/A")
    printf "  - total scan time: %.2fs (%d scans, avg: %ss)\n" "$TOTAL_SCAN_TIME" "$SCAN_COUNT" "$AVG_SCAN"
fi
echo "  - total runtime: ${TOTAL_DURATION}s"
echo ""
echo "what happened:"
echo "  - alice funded with 3000, sent 1000 to bob, received 200 back"
echo "  - bob received 1000 from alice, sent 200 back"
echo "  - encrypted notes allow offline receiving"
echo "  - scan command discovers payments"
echo "  - all zk proofs saved to simulator_data/state.json"
