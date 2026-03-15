#!/usr/bin/env bash
# full e2e demo: stealth sends + CAT offer settlement
#
# usage: ./demo.sh [risc0|sp1]

set -e

BACKEND="${1:-risc0}"

if [[ "$BACKEND" != "risc0" && "$BACKEND" != "sp1" ]]; then
    echo "usage: $0 [risc0|sp1]"
    exit 1
fi

BUILD_DIR="./target/$BACKEND"
BINARY="$BUILD_DIR/release/clvm-zk"

if [ ! -f "$BINARY" ]; then
    echo "building $BACKEND backend..."
    cargo build --release --target-dir "$BUILD_DIR" --no-default-features --features "$BACKEND,testing"
fi

TOTAL_START=$(date +%s)

echo "=== VEIL E2E DEMO ($BACKEND) ==="
echo ""

# ── PHASE 1: SETUP ──────────────────────────────────────────────────────

echo "--- phase 1: setup ---"
$BINARY sim init --reset
$BINARY sim wallet alice create
$BINARY sim wallet bob create
echo ""

# ── PHASE 2: STEALTH SENDS ──────────────────────────────────────────────

echo "--- phase 2: stealth address sends ---"
echo ""

echo "funding alice with 3000 mojos..."
$BINARY sim faucet alice --amount 1000 --count 1
$BINARY sim faucet alice --amount 2000 --count 1
$BINARY sim wallet alice balance
echo ""

echo "alice sends 500 to bob (stealth)..."
$BINARY sim send alice bob 500 --coins auto
echo ""

echo "bob scans for payments..."
$BINARY sim scan bob
$BINARY sim wallet bob balance
echo ""

echo "alice sends 500 to bob again..."
$BINARY sim send alice bob 500 --coins auto
echo ""

echo "bob scans again..."
$BINARY sim scan bob
$BINARY sim wallet bob balance
echo ""

echo "bob sends 200 back to alice..."
$BINARY sim send bob alice 200 --coins auto
echo ""

echo "alice scans..."
$BINARY sim scan alice
echo ""

echo "stealth balances:"
echo "  alice:"
$BINARY sim wallet alice balance
echo "  bob:"
$BINARY sim wallet bob balance
echo ""

# ── PHASE 3: CAT OFFER SETTLEMENT ───────────────────────────────────────

echo "--- phase 3: CAT offer settlement ---"
echo ""

# fresh wallets for offer demo (reuse simulator state)
$BINARY sim wallet maker create
$BINARY sim wallet taker create

# mint CAT to maker (tail_source stored on coin for offer-create TAIL authorization)
DEMO_TAIL_SOURCE="(mod () 1)"
echo "minting 1000 CAT to maker (tail_source=$DEMO_TAIL_SOURCE)..."
$BINARY sim faucet maker --amount 1000 --count 1 --tail-source "$DEMO_TAIL_SOURCE" --delegated
echo ""

# fund taker with XCH
echo "funding taker with 500 XCH..."
$BINARY sim faucet taker --amount 500 --count 1 --delegated
echo ""

echo "pre-offer balances:"
echo "  maker:"
$BINARY sim wallet maker unspent
echo "  taker:"
$BINARY sim wallet taker unspent
echo ""

# create offer: maker offers 100 CAT, requests 50 XCH
echo "maker creates offer: 100 CAT for 50 XCH..."
$BINARY sim offer-create maker --offer 100 --request 50 --coins 0
echo ""

$BINARY sim offer-list
echo ""

# taker takes offer
echo "taker takes the offer..."
$BINARY sim offer-take taker --offer-id 0 --coins 0
echo ""

echo "post-settlement balances:"
echo "  maker:"
$BINARY sim wallet maker unspent
echo "  taker:"
$BINARY sim wallet taker unspent
echo ""

# ── SUMMARY ──────────────────────────────────────────────────────────────

echo "--- simulator state ---"
$BINARY sim status
echo ""

TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

echo "=== DEMO COMPLETE (${TOTAL_DURATION}s) ==="
echo ""
echo "phase 2: alice sent 1000 to bob, bob sent 200 back (stealth addresses)"
echo "phase 3: maker offered 100 CAT for 50 XCH, taker accepted (atomic swap)"
