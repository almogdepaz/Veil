#!/usr/bin/env bash
# CAT offer demo - demonstrates minting a CAT and creating an offer to trade it
#
# usage: ./cat_offer_demo.sh [risc0|sp1]

set -e

# backend selection (default: sp1)
BACKEND="${1:-sp1}"

if [[ "$BACKEND" != "risc0" && "$BACKEND" != "sp1" ]]; then
    echo "❌ invalid backend: $BACKEND"
    echo "usage: $0 [risc0|sp1]"
    exit 1
fi

# backend-specific paths
BUILD_DIR="./target/$BACKEND"
BINARY="$BUILD_DIR/release/clvm-zk"

# build if needed
if [ ! -f "$BINARY" ]; then
    echo "🔨 building $BACKEND backend..."
    cargo build --release --target-dir "$BUILD_DIR" --no-default-features --features "$BACKEND,testing"
    echo "✅ build complete"
    echo ""
fi

echo "=== CAT OFFER DEMO ==="
echo "backend: $BACKEND"
echo "======================"
echo ""

# clean slate
echo "🗑️  resetting simulator..."
$BINARY sim init --reset

# create wallets
echo ""
echo "👛 creating wallets..."
$BINARY sim wallet maker create
$BINARY sim wallet taker create

# === STEP 1: MINT A CAT ===
# the TAIL program defines the CAT's identity
# tail_hash = compile_hash(TAIL_program)
# for demo, we use a fixed tail_hash (would normally be computed from TAIL source)

# compute a deterministic tail_hash for demo
# this represents: compile_chialisp_template_hash_default("(mod () 1)")
DEMO_TAIL_HASH="0e68e265035b19b3cf36586a45bd978206b492895046c8d605f800a04f242a9e"

echo ""
echo "📦 STEP 1: Minting CAT to maker's wallet"
echo "   TAIL program: (mod () 1)"
echo "   tail_hash: $DEMO_TAIL_HASH"
echo ""

# use faucet with --tail to mint CAT coins
# the --delegated flag is required for offers
$BINARY sim faucet maker --amount 1000 --count 1 --tail "$DEMO_TAIL_HASH" --delegated
echo "   ✅ minted 1000 CAT mojos to maker"

# === STEP 2: FUND TAKER WITH XCH ===
echo ""
echo "💰 STEP 2: Funding taker with XCH"
$BINARY sim faucet taker --amount 500 --count 1 --delegated
echo "   ✅ funded taker with 500 XCH mojos"

# show balances
echo ""
echo "📊 Initial balances:"
echo ""
echo "maker's coins:"
$BINARY sim wallet maker unspent
echo ""
echo "taker's coins:"
$BINARY sim wallet taker unspent

# === STEP 3: CREATE OFFER ===
echo ""
echo "📝 STEP 3: Maker creates offer"
echo "   offering: 100 CAT mojos"
echo "   requesting: 50 XCH mojos"
echo ""

# note: currently offer-create uses maker's coin's tail_hash as the offered asset
# and request-tail for requested asset (XCH if omitted)
$BINARY sim offer-create maker --offer 100 --request 50 --coins 0

echo ""
echo "📋 Pending offers:"
$BINARY sim offer-list

# === STEP 4: TAKER TAKES OFFER ===
echo ""
echo "🤝 STEP 4: Taker takes the offer"
echo "   spending: 50 XCH mojos (from their coin)"
echo "   receiving: 100 CAT mojos"
echo ""

# take offer 0 using taker's coin 0
$BINARY sim offer-take taker --offer-id 0 --coins 0

# === STEP 5: VERIFY RESULTS ===
echo ""
echo "✅ SETTLEMENT COMPLETE"
echo ""
echo "📊 Final state:"
echo ""

echo "maker's coins (after receiving XCH payment + CAT change):"
$BINARY sim wallet maker unspent
echo ""
echo "taker's coins (after receiving CAT + XCH change):"
$BINARY sim wallet taker unspent

echo ""
echo "=== DEMO COMPLETE ==="
echo ""
echo "what happened:"
echo "  1. minted 1000 CAT to maker (tail_hash = $DEMO_TAIL_HASH)"
echo "  2. funded taker with 500 XCH"
echo "  3. maker created offer: 100 CAT for 50 XCH"
echo "  4. taker took the offer (atomic swap)"
echo ""
echo "key points:"
echo "  - CAT identity comes from TAIL program hash"
echo "  - offers are ConditionalSpend proofs (locked until settlement)"
echo "  - settlement proof atomically swaps assets"
echo "  - all amounts/assets hidden in commitments"
