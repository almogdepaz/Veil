#!/bin/bash
# test script for encrypted payment notes feature

set -e

echo "🧪 testing encrypted payment notes with simulator"
echo "=================================================="

# clean slate
echo ""
echo "1️⃣  initializing simulator..."
cargo run --no-default-features --features "mock,testing" -- sim init --reset

# create wallets
echo ""
echo "2️⃣  creating wallets (alice and bob)..."
cargo run --no-default-features --features "mock,testing" -- sim wallet alice create
cargo run --no-default-features --features "mock,testing" -- sim wallet bob create

# fund alice
echo ""
echo "3️⃣  funding alice with 3000 mojos..."
cargo run --no-default-features --features "mock,testing" -- sim faucet alice --amount 1000 --count 1
cargo run --no-default-features --features "mock,testing" -- sim faucet alice --amount 2000 --count 1

# check alice balance
echo ""
echo "4️⃣  alice's initial balance:"
cargo run --no-default-features --features "mock,testing" -- sim wallet alice balance

# alice sends to bob
echo ""
echo "5️⃣  alice sends 500 mojos to bob..."
cargo run --no-default-features --features "mock,testing" -- sim send alice bob 500 --coins auto

# bob's balance before scan (should be 0)
echo ""
echo "6️⃣  bob's balance BEFORE scanning (should be 0):"
cargo run --no-default-features --features "mock,testing" -- sim wallet bob balance

# bob scans for encrypted notes
echo ""
echo "7️⃣  bob scans for encrypted payment notes..."
cargo run --no-default-features --features "mock,testing" -- sim scan bob

# bob's balance after scan (should be 500)
echo ""
echo "8️⃣  bob's balance AFTER scanning (should be 500):"
cargo run --no-default-features --features "mock,testing" -- sim wallet bob balance

# alice sends to bob
echo ""
echo "5️⃣  alice sends 500 mojos to bob..."
cargo run --no-default-features --features "mock,testing" -- sim send alice bob 500 --coins auto


# bob's balance before scan (should be 500)
echo ""
echo "6️⃣  bob's balance BEFORE scanning (should be 0):"
cargo run --no-default-features --features "mock,testing" -- sim wallet bob balance

# bob scans for encrypted notes
echo ""
echo "7️⃣  bob scans for encrypted payment notes..."
cargo run --no-default-features --features "mock,testing" -- sim scan bob

# bob's balance after scan (should be 1000)
echo ""
echo "8️⃣  bob's balance AFTER scanning (should be 500):"
cargo run --no-default-features --features "mock,testing" -- sim wallet bob balance


# bob sends some back to alice
echo ""
echo "9️⃣  bob sends 200 mojos back to alice..."
cargo run --no-default-features --features "mock,testing" -- sim send bob alice 200 --coins auto

# alice scans to receive
echo ""
echo "🔟 alice scans for her payment..."
cargo run --no-default-features --features "mock,testing" -- sim scan alice

# final balances
echo ""
echo "✅ final balances:"
echo ""
echo "alice:"
cargo run --no-default-features --features "mock,testing" -- sim wallet alice balance
echo ""
echo "bob:"
cargo run --no-default-features --features "mock,testing" -- sim wallet bob balance

# show status
echo ""
echo "📊 simulator status:"
cargo run --no-default-features --features "mock,testing" -- sim status

echo ""
echo "=================================================="
echo "✅ encrypted payment notes test complete!"
echo ""
echo "what happened:"
echo "  - alice funded with 3000, sent 1000 to bob, received 200 back"
echo "  - bob received 1000 from alice, sent 200 back"
echo "  - encrypted notes allow offline receiving"
echo "  - scan command discovers payments"
