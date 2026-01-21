# clvm-zk: general-purpose privacy protocol for chia

## executive summary

clvm-zk enables privacy-preserving execution of arbitrary chialisp programs using zero-knowledge proofs. unlike hardcoded circuits for specific operations, it provides a general-purpose zkvm that can prove correct execution of any chialisp program without revealing inputs, program logic, or execution traces.

## background & motivation

### original vision
- enable private execution of arbitrary chialisp programs
- preserve full programmability while adding privacy
- avoid trusted setup ceremonies or centralized sequencers
- create practical privacy for the chia ecosystem

### key innovation
guest-side compilation with nullifier-based privacy:
- compile chialisp inside zkvm for deterministic program identification
- use nullifiers to prevent double-spending while hiding spend secrets
- support arbitrary program logic through general-purpose zkvm execution
- maintain chia's decentralized consensus while adding privacy layer

## technical architecture

### core components

#### 1. consensus layer
- unchanged chia proof of space and time (post)
- no sequencers, trusted committees, or consensus modifications
- existing chia validators verify zk proofs alongside regular transactions
- full decentralization preserved

#### 2. privacy model

**private program execution:**
```
1. user has chialisp program + secret inputs
2. zkvm guest compiles program to bytecode deterministically
3. zkvm executes bytecode with secret parameters
4. proof generated: "program X executed correctly with hidden inputs"
5. verifier sees program hash + output, never sees logic or inputs
```

**key properties:**
- arbitrary chialisp programs supported through general-purpose zkvm
- program logic completely hidden from verifiers
- deterministic program hashes enable consistent identification
- nullifier protocol prevents double-spending with privacy

#### 3. commitment-based output privacy

clvm-zk implements **full privacy** - hiding both inputs AND outputs. when chialisp programs create coins via CREATE_COIN conditions, the guest transforms them into opaque commitments:

**transformation process:**
```
chialisp program executes → CREATE_COIN(puzzle_hash, amount) conditions
                         ↓
guest receives output_coin_secrets from host (serial_number, serial_randomness)
                         ↓
guest computes:
  - serial_commitment = hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)
  - coin_commitment = hash("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment)
                         ↓
public output: [coin_commitment1, coin_commitment2, ...]
private output: CoinCreation details for host to encrypt
```

**dual execution modes:**

*computational programs* (no CREATE_COIN):
```chialisp
(mod (x y) (+ x y))              // returns: [5]
(mod (msg sig pk) (bls_verify))  // returns: [1] or fails
(mod (amt) (assert_my_amount amt)) // returns: [1]
```
- output = computation result or assertion
- used for: tests, signature verification, assertions
- all conditions validated in-circuit

*transactional programs* (with CREATE_COIN):
```chialisp
(mod (recipient amount)
  (create_coin recipient amount))  // returns: [coin_commitment]
```
- output = array of coin commitments (opaque hashes)
- conditions like AGG_SIG_ME, assertions validated in-circuit
- only commitments visible on-chain

**privacy guarantees:**

blockchain sees:
- program_hash (which puzzle ran)
- nullifier (which coin spent)
- coin_commitments (opaque hashes)

blockchain does NOT see:
- coin amounts
- recipients (puzzle hashes)
- signature requirements
- assertions/conditions
- program logic

**critical design choice:**

we chose "option 1: full privacy" over hybrid approaches:
- ❌ option 2: output commitments + other conditions (metadata leak)
- ❌ option 3: error on non-CREATE_COIN conditions (too restrictive)
- ✅ option 1: validate all conditions in-circuit, output only commitments

signatures (BLS/ECDSA), assertions, and announcements are verified during proof generation. if they fail, the proof fails. the blockchain never sees them, achieving maximum privacy.

#### 4. zero-knowledge proof structure

**program execution proof with serial commitment:**
```
private inputs:
- chialisp source code
- program parameters (secrets, amounts, etc)
- serial_number (unique coin identifier)
- serial_randomness (commitment opening)
- merkle authentication path
- coin_commitment (leaf in merkle tree)

public inputs:
- program hash (deterministic identifier)
- nullifier = hash(serial_number || program_hash) (prevents double-spending)
- merkle root (current tree state)
- proof output

proves:
- program compiled and executed correctly
- parameters satisfy program constraints
- serial commitment verification: hash(serial_number || serial_randomness) == serial_commitment
- merkle membership: coin_commitment exists in tree at merkle_root
- output computed correctly from hidden inputs
```

### double-spend prevention

**serial commitment nullifier protocol (v2.0):**

the protocol uses serial number commitments to bind each coin to exactly one valid spend:

**coin creation:**
```
serial_number = random(32 bytes)              // globally unique identifier
serial_randomness = random(32 bytes)          // commitment opening
serial_commitment = hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)
coin_commitment = hash("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment)
# tail_hash = [0; 32] for XCH, hash of TAIL program for CATs
```

**spending:**
```
nullifier = hash(serial_number || program_hash)  // revealed when spending
zkvm verifies:
  1. program_hash == puzzle_hash (proves running coin's puzzle)
  2. hash(serial_number || serial_randomness) == serial_commitment
  3. hash("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment) == coin_commitment
  4. coin_commitment exists in merkle tree
  5. spending conditions satisfied
```

**key properties:**
- **unique nullifier**: each coin has exactly one valid nullifier for its (serial_number, program_hash) pair
- **unlinkability**: nullifier doesn't reveal coin_commitment (different hash structure, no serial_randomness)
- **double-spend prevention**: nullifier set tracks spent coins
- **merkle membership**: proves coin exists without revealing which coin
- **commitment binding**: cryptographically impossible to forge serial_randomness
- **puzzle enforcement**: guest verifies program_hash matches coin's puzzle_hash, preventing wrong-program spends

**privacy guarantees:**
- spending reveals nullifier but not coin_commitment or serial secrets
- serial_randomness stays private, enabling commitment opening proof
- merkle path proves membership without revealing coin position
- no linkability between coin creation and spending (nullifier excludes serial_randomness)
- program_hash visible in proof output for transparency

**implementation note:**
- commitment tree can be implemented as sparse merkle tree OR merkle mountain range (MMR)
- MMR is particularly efficient for this use case: coins only appended (never removed)
- nullifier set tracks spent coins separately from commitment tree
- both provide membership proofs without revealing coin position

**critical security requirement:**
- losing serial_number or serial_randomness = permanent coin loss
- backup procedures essential (see recovery protocol below)

### stealth addresses

**dual-key stealth addresses** enable offline receiving with unlinkable payments:

**key structure:**
```rust
StealthKeys {
    view_privkey: [u8; 32],   // for scanning
    spend_privkey: [u8; 32],  // for spending
}

StealthAddress {
    view_pubkey: [u8; 33],    // compressed secp256k1
    spend_pubkey: [u8; 33],   // compressed secp256k1
}
// published address: 66 bytes total
```

**payment protocol (ecdh-based):**
```
sender:
  1. generates ephemeral secp256k1 keypair
  2. computes shared_secret = ephemeral_priv * view_pubkey (ecdh)
  3. derives puzzle_hash = hash(spend_pubkey + hash(shared_secret) * G)
  4. creates coin with derived puzzle_hash
  5. stores ephemeral_pubkey on-chain with coin

recipient:
  1. scans coins with ephemeral_pubkeys
  2. computes shared_secret = view_priv * ephemeral_pubkey (ecdh)
  3. computes expected_puzzle_hash from shared_secret
  4. if puzzle_hash matches: coin belongs to us
  5. derives spend_key = spend_priv + hash(shared_secret) to spend
```

**security properties:**
- ✅ **unlinkability**: each payment has unique puzzle_hash (can't link to stealth address)
- ✅ **forward secrecy**: compromise one derived_key reveals only that payment
- ✅ **view/spend separation**: view key can scan but not spend
- ✅ **offline receiving**: recipient doesn't need to be online
- ✅ **no note transmission**: scanning uses on-chain ephemeral_pubkey

**recovery workflow:**
```
1. user loses wallet but has seed
2. derives stealth keys (view + spend) from seed
3. scans blockchain for coins with ephemeral_pubkeys
4. finds coins belonging to wallet via view_key scanning
5. reconstructs wallet state and can spend coins
```

**view key capabilities:**
| operation | view key only | view + spend |
|-----------|---------------|--------------|
| scan for payments | ✅ | ✅ |
| see amounts | ✅ | ✅ |
| spend coins | ❌ | ✅ |

give view key to auditors without spending risk.

see [STEALTH_ADDRESSES.md](STEALTH_ADDRESSES.md) for full protocol details.

### performance characteristics

**current benchmarks:**
- proof generation: ~3 seconds (risc0), potentially faster (sp1)
- proof verification: ~282ms
- supports arbitrary chialisp complexity

**optimization strategies:**

#### 1. proof aggregation (implemented ✅)
- recursive aggregation: N base proofs → 1 aggregated proof
- constant on-chain verification cost regardless of batch size
- flat aggregation with proof commitments binding transaction outputs
- risc0 guest verifies child proofs via add_assumption mechanism

#### 2. backend flexibility
- risc0: mature with optimized precompiles
- sp1: newer, potentially faster proving times
- extensible to future zkvm backends

#### 3. template optimization
- common puzzle patterns get optimized circuits
- full chialisp interpreter for arbitrary programs
- automatic selection based on program complexity

### trade-offs & limitations

#### 1. proof size vs speed
- larger proofs enable arbitrary program complexity
- specialized circuits could reduce proof size for common patterns
- balance between generality and efficiency

#### 2. privacy vs transparency
- program hashes provide some metadata leakage
- nullifiers enable compliance monitoring if needed
- users control privacy level through program design

#### 3. scalability considerations
- proof generation requires computational resources
- verification much faster than generation
- delegation markets could enable mobile usage

## comparison analysis

### vs tornado cash

| aspect | tornado cash | clvm-zk |
|--------|--------------|---------|
| **programmability** | fixed mixing logic | arbitrary chialisp programs |
| **denomination model** | fixed amounts only | any amount/program combination |
| **trusted setup** | ceremony required | no trusted setup needed |
| **ecosystem** | new contracts | existing chia tooling |

### vs zcash

| aspect | zcash | clvm-zk |
|--------|-------|---------|
| **privacy model** | built-in protocol layer | optional application layer |
| **programmability** | limited circuits | full chialisp support |
| **consensus changes** | protocol modifications | no consensus changes |
| **adoption barrier** | new wallet requirements | gradual adoption possible |

### vs miden/polygon zkvm

| aspect | miden | clvm-zk |
|--------|-------|---------|
| **architecture** | sequencer-based rollup | decentralized consensus |
| **state model** | global state tree | individual nullifiers |
| **throughput** | 1000s tps (centralized) | chia consensus limited |
| **language** | new vm + language | existing chialisp |
| **decentralization** | sequencer dependencies | full chia decentralization |

## novel contributions

1. **general-purpose privacy**: first zkvm enabling arbitrary chialisp program privacy
2. **commitment-based output privacy**: full input AND output privacy through coin commitments
3. **guest-side compilation**: deterministic program identification through zkvm compilation
4. **serial commitment protocol**: secure nullifiers with merkle membership proofs preventing double-spend attacks
5. **stealth addresses**: unlinkable payments via ecdh-derived puzzle hashes with view/spend key separation
6. **dual execution modes**: computational programs return results, transactional programs return commitments
7. **recursive proof aggregation**: batch N transactions into 1 proof with constant verification cost
8. **preserved decentralization**: no consensus changes or trusted parties required
9. **ecosystem compatibility**: works with existing chia tools and workflows

## security analysis

### privacy guarantees
- **program secrecy**: chialisp logic completely hidden from verifiers
- **input privacy**: parameters and secrets never revealed
- **output privacy**: coin amounts and recipients hidden via commitments
- **execution privacy**: intermediate computation states hidden
- **condition privacy**: signatures, assertions, announcements validated in-circuit (not visible on-chain)
- **selective disclosure**: users control what information to reveal

### attack considerations
- **program fingerprinting**: program hashes provide some metadata
- **timing analysis**: proof generation timing may leak program complexity
- **side channel**: implementation must prevent leakage during proving
- **secret loss**: losing serial_number or serial_randomness means permanent coin loss
- **viewing key exposure**: if recipient reveals viewing private key, observer can see all received coins
- **scanning privacy**: stealth address scanning reveals interest in blockchain data (mitigated by local scanning)
- **compliance balance**: nullifiers enable monitoring without compromising core privacy

## development status

### current capabilities (implemented ✅)
- arbitrary chialisp program execution in zkvm
- risc0 and sp1 backend support with optimized precompiles
- commitment-based output privacy (full input AND output privacy)
- dual execution modes (computational vs transactional programs)
- serial commitment nullifier protocol (v2.0) preventing double-spending
- stealth addresses for unlinkable offline receiving (secp256k1 ecdh)
- commitment tree membership proofs (sparse merkle tree or MMR)
- full blockchain simulator for testing privacy applications
- bls12-381 and ecdsa signature verification (validated in-circuit)
- recursive proof aggregation for batch transactions (N→1 compression)
- comprehensive test coverage including security and fuzz testing
- clean protocol with zero backward compatibility to vulnerable old protocol

### future development directions

#### immediate optimization
- specialized circuits for common puzzle patterns
- mobile device proving through delegation
- multi-level aggregation strategies

#### ecosystem integration
- wallet integration for seamless user experience
- privacy-preserving defi application development
- compliance tools balancing privacy with regulatory needs

## use cases & applications

### financial privacy
- private transfers with hidden amounts and recipients
- confidential smart contracts and escrow systems
- privacy-preserving defi protocols

### identity & credentials
- private authentication without revealing credentials
- selective disclosure of personal information
- compliance verification without data exposure

### governance & voting
- anonymous voting with eligibility verification
- private dao participation
- confidential proposal evaluation

## research implications

clvm-zk demonstrates that general-purpose blockchain privacy is achievable without compromising decentralization. key insights:

- **zkvm flexibility**: arbitrary program logic enables novel privacy applications
- **consensus preservation**: privacy layer operates without blockchain modifications
- **ecosystem continuity**: existing tools and workflows remain compatible
- **practical performance**: usable proving times for real applications
- **secure nullifiers**: serial commitment protocol prevents double-spend attacks
- **stealth addresses**: ecdh-derived puzzles enable unlinkable offline receiving
- **scalable aggregation**: recursive proof composition enables constant verification cost

this opens new research directions in privacy-preserving computation, compliance-friendly privacy protocols, decentralized privacy infrastructure, and proof aggregation strategies for privacy-preserving systems.

## further documentation

for detailed technical specifications and implementation guides, see:

- **[SIMULATOR.md](SIMULATOR.md)**: blockchain simulator usage with serial commitment protocol
- **[STEALTH_ADDRESSES.md](STEALTH_ADDRESSES.md)**: stealth address protocol for unlinkable payments
- **[nullifier.md](nullifier.md)**: detailed nullifier protocol vulnerability analysis and design choices
- **[NULLIFIER_IMPLEMENTATION_PLAN.md](NULLIFIER_IMPLEMENTATION_PLAN.md)**: complete implementation roadmap and status (all 9 phases completed)
- **[CLAUDE.md](CLAUDE.md)**: development context, architecture details, and coding guidelines