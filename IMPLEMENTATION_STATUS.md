# implementation status - stealth addresses cleanup + offers integration

## goal
1. remove broken signature mode from stealth_addresses branch
2. port working recursive settlement from offers branch
3. fix ephemeral key derivation to be deterministic
4. integrate everything with v2.0 coin commitments

## current state (stealth_addresses branch)

### ✅ working components
- [x] nullifier mode stealth addresses
- [x] coin commitment v2.0 with tail_hash
- [x] ring spend balance enforcement
- [x] announcement verification
- [x] CAT support infrastructure

### ❌ broken/incomplete
- [ ] signature mode (REMOVE - false security claims)
- [ ] ephemeral key derivation (random, should be HD)
- [ ] recursive proof verification (missing)
- [ ] settlement guest (stub only)

## current state (offers branch)

### ✅ working components from offers to port
- [x] recursive proof verification (risc0 env::verify)
- [x] settlement guest with ECDH
- [x] maker proof parsing
- [x] four-output settlement logic

### ❌ what offers is missing
- [ ] coin commitment v2.0 (still on v1.0)
- [ ] stealth addresses
- [ ] tail_hash support

## tasks breakdown

### phase 1: cleanup stealth_addresses branch ✅ COMPLETE
- [x] remove StealthMode::Signature enum
- [x] remove signature-related code from stealth.rs (773 → 457 lines)
- [x] update cli.rs to remove mode selection
- [x] fix all compile errors
- [ ] update STEALTH_ADDRESSES.md docs
- [ ] update tests

**commit checkpoint:** "remove incomplete signature mode"

### phase 2: fix ephemeral key derivation ✅ COMPLETE
- [x] add HD derivation for ephemeral keys (StealthKeys::derive_ephemeral_key)
- [x] use view_privkey + counter → ephemeral_secret (deterministic)
- [x] update stealth payment creation (create_stealth_payment_hd)
- [x] deprecate old RNG-based function
- [x] add verification tag system (derive_stealth_tag) to filter false positives
- [x] add comprehensive tests for determinism and wallet recovery

**bonus:** added try_scan_with_tag for proper nullifier-mode scanning

**commit checkpoint:** "enforce deterministic ephemeral key derivation"

### phase 3: port recursive settlement from offers ✅ COMPLETE
- [x] settlement guest already exists with v2.0 coin commitments!
- [x] recursive proof verification via risc0 env::verify()
- [x] ECDH payment address derivation
- [x] host-side prove_settlement API complete
- [x] added create_conditional_spend to Spender (v2.0 compatible)

**surprise:** settlement infrastructure was already implemented and v2.0-ready!

**what's missing for full offers:**
1. CLI commands (offer_create_command, offer_take_command) - stubs exist
2. offer puzzle generation logic
3. end-to-end integration tests

**commit checkpoint:** "add conditional spend support for offers"

### phase 4: end-to-end offers testing
- [ ] create offer with conditional spend proof
- [ ] take offer with settlement proof
- [ ] verify on-chain submission works
- [ ] add proof type validation

**commit checkpoint:** "complete offers implementation"

## file changes

### phase 1 (remove signature mode)
- `src/wallet/stealth.rs` - remove Signature variant, derive_spend_key, generate_stealth_puzzle
- `STEALTH_ADDRESSES.md` - update docs to nullifier-only
- tests using signature mode

### phase 2 (fix ephemeral derivation)
- `src/wallet/stealth.rs` - replace rng with HD derivation in create_stealth_payment_v2
- `src/wallet/hd_wallet.rs` - add ephemeral key derivation helper

### phase 3 (port settlement)
- `backends/risc0/guest_settlement/src/main.rs` - replace with offers version + v2.0 updates
- `backends/sp1/program_settlement/src/main.rs` - same for sp1
- `src/protocol/settlement.rs` - update host-side API
- `clvm_zk_core/src/types.rs` - ensure recursive types exist

### phase 4 (testing)
- `tests/test_offers_e2e.rs` - new end-to-end test
- `src/cli.rs` - offer-create, offer-take commands
- validator integration

## notes
- keep on stealth_addresses branch throughout
- offers branch has working code but outdated commitments
- settlement guest needs x25519 crate (already in offers)
- risc0 recursive verification is native, just call env::verify()

## next action
start phase 1: remove signature mode
