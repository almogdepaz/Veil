#!/bin/bash
# multi_cat_demo.sh - demonstrates minting multiple different CAT types
#
# usage: ./scripts/multi_cat_demo.sh

set -e

BINARY="cargo run --release --features risc0 --"

echo "=== MULTI-CAT MINTING DEMO ==="
echo ""

# init simulator
echo "initializing simulator..."
$BINARY sim init --reset 2>/dev/null || $BINARY sim init

# create wallet
echo "creating wallet 'trader'..."
$BINARY sim wallet trader create 2>/dev/null || true

# mint XCH for fees
echo ""
echo "minting XCH for fees..."
$BINARY sim faucet trader --amount 100000 --count 1

# define our CAT types
GOLD_TAIL='(mod () 1)'
SILVER_TAIL='(mod () 2)'
BRONZE_TAIL='(mod (x) (> x 0))'

echo ""
echo "=== MINTING 3 DIFFERENT CAT TYPES ==="
echo ""

# mint GOLD
echo "minting GOLD CAT..."
echo "  TAIL: $GOLD_TAIL"
$BINARY sim mint trader --tail "$GOLD_TAIL" --amount 10000 --count 2

# mint SILVER
echo ""
echo "minting SILVER CAT..."
echo "  TAIL: $SILVER_TAIL"
$BINARY sim mint trader --tail "$SILVER_TAIL" --amount 5000 --count 3

# mint BRONZE (requires param)
echo ""
echo "minting BRONZE CAT..."
echo "  TAIL: $BRONZE_TAIL"
$BINARY sim mint trader --tail "$BRONZE_TAIL" --amount 1000 --count 5 --params "100"

# show balances
echo ""
echo "=== WALLET BALANCES ==="
$BINARY sim wallet trader coins

echo ""
echo "=== DEMO COMPLETE ==="
echo ""
echo "minted:"
echo "  - GOLD:   2 coins x 10000 = 20000 mojos"
echo "  - SILVER: 3 coins x 5000  = 15000 mojos"
echo "  - BRONZE: 5 coins x 1000  = 5000 mojos"
echo "  - XCH:    1 coin  x 100000 (for fees)"
