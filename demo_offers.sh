#!/usr/bin/env bash
# Demo script showing atomic swap (offer) functionality in the simulator
#
# Demonstrates:
# 1. Wallet creation with encryption keys
# 2. Faucet funding with XCH and CATs
# 3. Creating a conditional offer (maker)
# 4. Taking an offer via settlement proof (taker)
# 5. Verification of atomic swap completion

set -e  # exit on error

# backend selection (default: risc0)
BACKEND="${1:-risc0}"
if [[ "$BACKEND" != "risc0" && "$BACKEND" != "sp1" ]]; then
    echo "usage: $0 [risc0|sp1]"
    exit 1
fi

# colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # no color

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}         CLVM-ZK OFFERS DEMO (ATOMIC SWAPS)${NC}"
echo -e "${BLUE}           backend: ${YELLOW}${BACKEND}${BLUE}${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# start total timer
DEMO_START=$SECONDS

# setup
DATA_DIR="/tmp/clvm-zk-offers-demo"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

# build once at the start
echo "building clvm-zk ($BACKEND backend)..."
cargo build --no-default-features --features $BACKEND --release --quiet

# use pre-built binary directly (no rebuild checks on each command)
BINARY="./target/release/clvm-zk"
CARGO_CMD="$BINARY --data-dir $DATA_DIR"

echo -e "${GREEN}[1/8]${NC} initializing simulator..."
$CARGO_CMD sim init
echo ""

echo -e "${GREEN}[2/8]${NC} creating alice's wallet (maker)..."
$CARGO_CMD sim wallet alice create
echo ""

echo -e "${GREEN}[3/8]${NC} creating bob's wallet (taker)..."
$CARGO_CMD sim wallet bob create
echo ""

echo -e "${GREEN}[4/8]${NC} funding alice with XCH using delegated puzzle (required for offers)..."
PROOF_START=$SECONDS
$CARGO_CMD sim faucet alice --amount 1000 --count 1 --delegated
PROOF_TIME=$((SECONDS - PROOF_START))
echo -e "${CYAN}⏱  proof generated in ${PROOF_TIME}s${NC}"
echo ""

# generate a random tail_hash for the CAT
CAT_TAIL=$(openssl rand -hex 32)
echo -e "${YELLOW}   CAT asset ID: ${CAT_TAIL}${NC}"
echo ""

echo -e "${GREEN}[5/8]${NC} funding bob with CATs using delegated puzzle..."
PROOF_START=$SECONDS
$CARGO_CMD sim faucet bob --amount 500 --count 1 --tail "$CAT_TAIL" --delegated
PROOF_TIME=$((SECONDS - PROOF_START))
echo -e "${CYAN}⏱  proof generated in ${PROOF_TIME}s${NC}"
echo ""

echo -e "${GREEN}[6/8]${NC} alice creates offer: 100 XCH for 200 CAT..."
PROOF_START=$SECONDS
$CARGO_CMD sim offer-create alice --offer 100 --request 200 --request-tail "$CAT_TAIL" --coins 0
PROOF_TIME=$((SECONDS - PROOF_START))
echo -e "${CYAN}⏱  conditional proof generated in ${PROOF_TIME}s${NC}"
echo ""

echo -e "${GREEN}[7/8]${NC} viewing pending offers..."
$CARGO_CMD sim offer-list
echo ""

echo -e "${GREEN}[8/8]${NC} bob takes offer 0 (atomic settlement proof)..."
PROOF_START=$SECONDS
$CARGO_CMD sim offer-take bob --offer-id 0 --coins 0
PROOF_TIME=$((SECONDS - PROOF_START))
echo -e "${CYAN}⏱  settlement proof generated in ${PROOF_TIME}s${NC}"
echo ""

DEMO_TIME=$((SECONDS - DEMO_START))
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ OFFERS DEMO COMPLETE${NC}"
echo -e "${CYAN}⏱  total time: ${DEMO_TIME}s${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "what happened:"
echo "  1. alice locked 100 XCH in conditional spend proof"
echo "  2. bob created settlement proof that:"
echo "     - verified alice's conditional proof"
echo "     - spent bob's 200 CAT"
echo "     - created 4 outputs:"
echo "       • alice gets 200 CAT (goods)"
echo "       • bob gets 100 XCH (payment)"
echo "       • alice gets 900 XCH (change from 1000 input)"
echo "       • bob gets 300 CAT (change from 500 input)"
echo "  3. settlement proof atomically completes the swap"
echo "  4. neither party can back out or cheat"
echo ""
echo "privacy properties:"
echo "  - amounts are hidden in ZK proofs"
echo "  - only commitments visible on-chain"
echo "  - nullifiers prevent double-spending"
echo "  - hash-based stealth addresses hide recipient"
echo ""
echo -e "${YELLOW}view final state:${NC}"
echo "  cargo run --no-default-features --features $BACKEND -- --data-dir $DATA_DIR sim status"
echo "  cargo run --no-default-features --features $BACKEND -- --data-dir $DATA_DIR sim wallet alice show"
echo "  cargo run --no-default-features --features $BACKEND -- --data-dir $DATA_DIR sim wallet bob show"
