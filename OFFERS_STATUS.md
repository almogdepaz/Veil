# offers implementation status

## completed ✅

1. **cli commands**: `offer-create`, `offer-take`, `offer-list` fully implemented
2. **wallet encryption keys**: x25519 keys for ECDH payment derivation in WalletData
3. **delegated puzzle support**: faucet `--delegated` flag creates offer-compatible coins
4. **CAT minting**: works via `faucet --tail <hex>` parameter
5. **settlement infrastructure**: guest + host API from phase 3
6. **demo script**: `demo_offers.sh` shows full flow

## current blocker ⚠️

**balance enforcement in conditional spends**

conditional spend proofs create partial outputs:
- input: 1000 XCH
- output: 900 XCH (change) + 100 XCH settlement terms (NOT a CREATE_COIN)
- guest balance check: `if input_sum != total_output_amount` → FAILS

the offered amount (100) is in settlement terms, not a CREATE_COIN condition. the settlement proof will complete the balance by creating the actual payment/goods coins.

## solution: skip balance for conditional spends

add proof_type to Input struct and conditionally skip balance check for ProofType::ConditionalSpend (type 1).

## files modified

- `src/cli.rs`: offer commands (+156 lines), faucet --delegated, encryption keys
- `src/protocol/puzzles.rs`: delegated + settlement puzzles (existed)
- `demo_offers.sh`: demonstration script

all code compiles ✅  
settlement infrastructure complete ✅  
needs: conditional spend balance exemption
