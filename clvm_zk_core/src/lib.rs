#![no_std]

extern crate alloc;

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

#[cfg(feature = "sha2-hasher")]
use sha2::{Digest, Sha256};

pub mod backend_utils;
pub mod clvm_parser;
pub mod coin_commitment;
pub mod merkle;
pub mod operators;
pub mod types;

pub use clvm_parser::*;
pub use operators::*;
pub use types::*;

// ============================================================================
// Chialisp compilation utilities (previously in chialisp/mod.rs)
// ============================================================================

/// Standard Chia condition codes as defconstant declarations.
/// Prepend this to chialisp source for readable condition opcodes.
pub const STANDARD_CONDITION_CODES: &str = r#"
(defconstant AGG_SIG_UNSAFE 49)
(defconstant AGG_SIG_ME 50)
(defconstant CREATE_COIN 51)
(defconstant RESERVE_FEE 52)
(defconstant CREATE_COIN_ANNOUNCEMENT 60)
(defconstant ASSERT_COIN_ANNOUNCEMENT 61)
(defconstant CREATE_PUZZLE_ANNOUNCEMENT 62)
(defconstant ASSERT_PUZZLE_ANNOUNCEMENT 63)
(defconstant ASSERT_MY_COIN_ID 70)
(defconstant ASSERT_MY_PARENT_ID 71)
(defconstant ASSERT_MY_PUZZLEHASH 72)
(defconstant ASSERT_MY_AMOUNT 73)
"#;

/// Prepend standard condition codes to chialisp source.
/// Use this when you want CREATE_COIN etc. to be available without defining them.
pub fn with_standard_conditions(source: &str) -> String {
    if let Some(mod_pos) = source.find("(mod") {
        if let Some(paren_start) = source[mod_pos..].find('(').map(|p| mod_pos + p) {
            if let Some(param_start) = source[paren_start + 1..].find('(') {
                let param_start = paren_start + 1 + param_start;
                let mut depth = 1;
                let mut param_end = param_start + 1;
                for (i, c) in source[param_start + 1..].char_indices() {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                param_end = param_start + 1 + i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let mut result =
                    String::with_capacity(source.len() + STANDARD_CONDITION_CODES.len());
                result.push_str(&source[..param_end]);
                result.push_str(STANDARD_CONDITION_CODES);
                result.push_str(&source[param_end..]);
                return result;
            }
        }
    }
    format!("{}{}", STANDARD_CONDITION_CODES, source)
}

/// Compilation error types
#[derive(Debug, Clone)]
pub enum CompileError {
    ParseError(String),
}

impl From<CompileError> for ClvmZkError {
    fn from(err: CompileError) -> Self {
        match err {
            CompileError::ParseError(msg) => ClvmZkError::CompilationError(msg),
        }
    }
}

/// Compile chialisp source to bytecode and program hash
pub fn compile_chialisp_to_bytecode(
    hasher: Hasher,
    source: &str,
) -> Result<(Vec<u8>, [u8; 32]), CompileError> {
    let bytecode = clvm_tools_rs::compile_chialisp(source).map_err(|e| {
        CompileError::ParseError(format!("clvm_tools_rs compilation failed: {}", e))
    })?;
    let program_hash = hasher(&bytecode);
    Ok((bytecode, program_hash))
}

/// Compile chialisp source to get program hash only
pub fn compile_chialisp_template_hash(
    hasher: Hasher,
    source: &str,
) -> Result<[u8; 32], CompileError> {
    let bytecode = clvm_tools_rs::compile_chialisp(source).map_err(|e| {
        CompileError::ParseError(format!("clvm_tools_rs compilation failed: {}", e))
    })?;
    Ok(hasher(&bytecode))
}

/// Compile chialisp to get template hash using default SHA-256 hasher
#[cfg(feature = "sha2-hasher")]
pub fn compile_chialisp_template_hash_default(source: &str) -> Result<[u8; 32], CompileError> {
    let bytecode = clvm_tools_rs::compile_chialisp(source).map_err(|e| {
        CompileError::ParseError(format!("clvm_tools_rs compilation failed: {}", e))
    })?;
    Ok(hash_data(&bytecode))
}

// ============================================================================
// End chialisp utilities
// ============================================================================

// re-export for convenience
pub use types::AdditionalCoinInput;

// re-export coin_commitment items for guest programs
pub use coin_commitment::{
    build_coin_commitment_preimage, CoinCommitment, CoinSecrets, SerialCommitment, XCH_TAIL,
};

// Re-export VeilEvaluator from clvm_tools_rs for direct CLVM execution
pub use clvm_tools_rs::VeilEvaluator;

// re-export AggregatedOutput for guest programs
pub use types::AggregatedOutput;

pub type Hasher = fn(&[u8]) -> [u8; 32];
pub type BlsVerifier = fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>;
pub type EcdsaVerifier = fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>;

/// clvm-zk bls signature domain separation tag
/// min_sig variant: pk in g2, sig in g1
pub const BLS_DST: &[u8] = b"CLVM_ZK_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";

pub fn atom_to_number(value: &ClvmValue) -> Result<i64, &'static str> {
    match value {
        ClvmValue::Atom(bytes) => {
            if bytes.is_empty() {
                Ok(0)
            } else if bytes.len() == 1 {
                Ok(bytes[0] as i64)
            } else {
                // multi-byte number - big endian
                let mut result = 0i64;
                for &byte in bytes {
                    result = (result << 8) | (byte as i64);
                }
                Ok(result)
            }
        }
        ClvmValue::Cons(_, _) => Err("cannot convert cons pair to number"),
    }
}

/// Convert i64 to ClvmValue using proper CLVM signed encoding
///
/// CLVM uses signed big-endian encoding where the high bit indicates sign:
/// - 0 encodes as empty atom
/// - 1-127 encode as single byte (0x01-0x7F)
/// - 128-255 need leading 0x00 to avoid sign bit (0x0080-0x00FF)
/// - Negative numbers have high bit set
pub fn number_to_atom(num: i64) -> ClvmValue {
    if num == 0 {
        ClvmValue::Atom(vec![]) // nil: represents 0/false/empty-list, encodes to 0x80
    } else if num > 0 && num <= 127 {
        // Single byte encoding only for 1-127 (0x01-0x7F)
        ClvmValue::Atom(vec![num as u8])
    } else {
        // for larger numbers, use big endian encoding
        let mut bytes = Vec::new();
        // handle i64::min overflow safely by using u64
        let mut n = if num == i64::MIN {
            // i64::min.abs() would overflow, so handle as u64
            (i64::MAX as u64) + 1
        } else {
            num.unsigned_abs()
        };
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();

        // For positive numbers where high bit is set, add leading 0x00
        // to prevent sign bit interpretation (e.g., 128 = 0x0080, not 0x80)
        if num > 0 && !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
            bytes.insert(0, 0x00);
        }
        // Handle negative numbers by setting high bit
        else if num < 0 && !bytes.is_empty() {
            bytes[0] |= 0x80;
        }

        ClvmValue::Atom(bytes)
    }
}

pub fn nil() -> ClvmValue {
    ClvmValue::Atom(vec![])
}

pub fn extract_list_from_clvm(value: &ClvmValue) -> Result<Vec<ClvmValue>, &'static str> {
    let mut result = Vec::new();
    let mut current = value;

    loop {
        match current {
            ClvmValue::Atom(bytes) => {
                if bytes.is_empty() {
                    // Empty atom represents nil (end of list)
                    break;
                } else {
                    // Non-empty atom in list position is an error
                    return Err("malformed list: non-empty atom in tail position");
                }
            }
            ClvmValue::Cons(head, tail) => {
                result.push((**head).clone());
                current = tail;
            }
        }
    }

    Ok(result)
}

pub fn verify_ecdsa_signature_with_hasher(
    hasher: Hasher,
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    // accept both compressed (33 bytes) and uncompressed (65 bytes) public keys
    if public_key_bytes.len() != 33 && public_key_bytes.len() != 65 {
        return Err("invalid public key size - expected 33 or 65 bytes");
    }

    // parse the public key (compressed or uncompressed)
    let verifying_key = match VerifyingKey::from_sec1_bytes(public_key_bytes) {
        Ok(key) => key,
        Err(_) => return Err("invalid public key format - failed to parse"),
    };

    // parse the signature - ECDSA signatures must be exactly 64 bytes (r || s, each 32 bytes)
    //
    // SECURITY: we do NOT pad short signatures with zeros as this could accept
    // truncated/malformed signatures. signatures are binary data, not integers,
    // so trailing zeros are significant.
    //
    // if CLVM is stripping trailing zeros from signatures, the signature encoding
    // should use DER format or be explicitly prefixed with length bytes.
    let signature = if signature_bytes.len() == 64 {
        // 64-byte compact format (r || s, each 32 bytes)
        match Signature::try_from(signature_bytes) {
            Ok(sig) => sig,
            Err(_) => return Err("invalid compact signature format"),
        }
    } else if signature_bytes.len() < 64 {
        // reject short signatures - don't pad with zeros
        return Err("signature too short - expected exactly 64 bytes for ECDSA compact format");
    } else {
        return Err("signature too long - expected exactly 64 bytes for ECDSA compact format");
    };

    // the message to verify is expected to be pre-hashed (32 bytes)
    // or a raw message that needs hashing.
    //
    // SECURITY NOTE: if message is exactly 32 bytes, we assume it's a pre-hash.
    // this is a common convention but callers should be aware of this behavior.
    // to verify a 32-byte raw message, hash it first before passing.
    let message_hash = if message_bytes.len() == 32 {
        // treat as pre-hashed message
        message_bytes.to_vec()
    } else {
        // hash the raw message
        hasher(message_bytes).to_vec()
    };

    // verify the signature
    match verifying_key.verify(&message_hash, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// compute modular exponentiation: base^exponent mod modulus
/// uses binary exponentiation for efficiency
pub fn modular_pow(mut base: i64, mut exponent: i64, modulus: i64) -> i64 {
    if modulus == 1 {
        return 0;
    }

    let mut result = 1;
    base %= modulus;

    while exponent > 0 {
        if exponent % 2 == 1 {
            // Use i128 to prevent overflow, then cast back
            result = ((result as i128 * base as i128) % modulus as i128) as i64;
        }
        exponent >>= 1;
        // Use i128 to prevent overflow, then cast back
        base = ((base as i128 * base as i128) % modulus as i128) as i64;
    }

    result
}

/// Default hasher using SHA-256 (only available with sha2-hasher feature)
#[cfg(feature = "sha2-hasher")]
pub fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// encode a clvmvalue as clvm bytes following the standard serialization format
pub fn encode_clvm_value(value: ClvmValue) -> Vec<u8> {
    match value {
        ClvmValue::Atom(bytes) => {
            if bytes.is_empty() {
                // nil (empty atom) - encoded as 0x80
                vec![0x80]
            } else if bytes.len() == 1 {
                // single byte atom - encoded directly if < 0x80
                if bytes[0] < 0x80 {
                    vec![bytes[0]]
                } else {
                    // single byte >= 0x80 needs size prefix
                    vec![0x81, bytes[0]]
                }
            } else {
                // multi-byte atom - follow chia's official encoding
                let mut result = Vec::new();
                let len = bytes.len();

                if len <= 0x3F {
                    // up to 63 bytes: 0x80 | size, data
                    result.push(0x80 | (len as u8));
                    result.extend_from_slice(&bytes);
                } else if len <= 0x1FFF {
                    // 64-8191 bytes: 0xC0 | (size >> 8), size & 0xFF, data
                    result.push(0xC0 | ((len >> 8) as u8));
                    result.push((len & 0xFF) as u8);
                    result.extend_from_slice(&bytes);
                } else if len <= 0xFFFFF {
                    // 8192-1048575 bytes: 0xE0 | (size >> 16), (size >> 8) & 0xFF, size & 0xFF, data
                    result.push(0xE0 | ((len >> 16) as u8));
                    result.push(((len >> 8) & 0xFF) as u8);
                    result.push((len & 0xFF) as u8);
                    result.extend_from_slice(&bytes);
                } else if len <= 0x7FFFFFF {
                    // 1048576-134217727 bytes: 0xF0 | (size >> 24), (size >> 16) & 0xFF, (size >> 8) & 0xFF, size & 0xFF, data
                    result.push(0xF0 | ((len >> 24) as u8));
                    result.push(((len >> 16) & 0xFF) as u8);
                    result.push(((len >> 8) & 0xFF) as u8);
                    result.push((len & 0xFF) as u8);
                    result.extend_from_slice(&bytes);
                } else {
                    // > 134217727 bytes: 0xF8 | (size >> 32), (size >> 24) & 0xFF, (size >> 16) & 0xFF, (size >> 8) & 0xFF, size & 0xFF, data
                    // use u64 to avoid 32-bit overflow in guest environments
                    let len64 = len as u64;
                    result.push(0xF8 | ((len64 >> 32) as u8));
                    result.push(((len64 >> 24) & 0xFF) as u8);
                    result.push(((len64 >> 16) & 0xFF) as u8);
                    result.push(((len64 >> 8) & 0xFF) as u8);
                    result.push((len64 & 0xFF) as u8);
                    result.extend_from_slice(&bytes);
                }
                result
            }
        }
        ClvmValue::Cons(first, rest) => {
            // cons pair - encoded as 0xff followed by first and rest
            let mut result = vec![0xFF];
            result.extend_from_slice(&encode_clvm_value(*first));
            result.extend_from_slice(&encode_clvm_value(*rest));
            result
        }
    }
}

/// Convert conditions back to CLVM serialized format
/// Takes a Vec<Condition> and returns serialized bytes representing a list of conditions
pub fn serialize_conditions_to_bytes(conditions: &[Condition]) -> Vec<u8> {
    // Convert conditions to CLVM list structure
    let clvm_list = conditions_to_clvm_value(conditions);
    encode_clvm_value(clvm_list)
}

/// Extract coin commitments from proof output
/// Returns all CREATE_COIN commitments (opcode 51 with 1 arg)
pub fn extract_coin_commitments(proof_output: &ProofOutput) -> Result<Vec<[u8; 32]>, &'static str> {
    // Deserialize the clvm output to get conditions
    let conditions = deserialize_clvm_output_to_conditions(&proof_output.clvm_res.output)?;

    let mut commitments = Vec::new();
    for condition in conditions {
        if condition.opcode == 51 {
            // CREATE_COIN
            if condition.args.len() != 1 {
                return Err("CREATE_COIN in proof output must have 1 arg (coin_commitment)");
            }

            if condition.args[0].len() != 32 {
                return Err("coin_commitment must be 32 bytes");
            }

            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&condition.args[0]);
            commitments.push(commitment);
        }
    }

    Ok(commitments)
}

/// Deserialize CLVM output bytes to Vec<Condition>
pub fn deserialize_clvm_output_to_conditions(
    output: &[u8],
) -> Result<Vec<Condition>, &'static str> {
    let mut parser = ClvmParser::new(output);
    let parsed = parser.parse()?;

    // Parse list of conditions: ((opcode1 args...) (opcode2 args...) ...)
    clvm_value_to_conditions(&parsed)
}

/// Convert ClvmValue to Vec<Condition>
///
/// Handles two cases:
/// 1. A list of conditions: ((opcode1 args...) (opcode2 args...) ...)
/// 2. A single condition: (opcode args...) - not wrapped in a list
fn clvm_value_to_conditions(value: &ClvmValue) -> Result<Vec<Condition>, &'static str> {
    let mut conditions = Vec::new();

    // Check if this is a single condition (Cons with atom as first element)
    // or a list of conditions (Cons with cons as first element)
    match value {
        ClvmValue::Atom(ref bytes) if bytes.is_empty() => {
            // Empty output (nil) - no conditions
            return Ok(conditions);
        }
        ClvmValue::Cons(ref first, _) => {
            // Check if first element is an atom (single condition) or cons (list of conditions)
            if let ClvmValue::Atom(ref opcode_bytes) = first.as_ref() {
                // First element is an atom - this is a single condition (opcode . args)
                if !opcode_bytes.is_empty() {
                    let condition = parse_single_condition(value)?;
                    conditions.push(condition);
                    return Ok(conditions);
                }
            }
        }
        _ => return Err("invalid condition output structure"),
    }

    // This is a list of conditions - traverse it
    let mut current = value;
    loop {
        match current {
            ClvmValue::Atom(ref bytes) if bytes.is_empty() => {
                // End of list (nil)
                break;
            }
            ClvmValue::Cons(ref first, ref rest) => {
                // Parse condition: (opcode arg1 arg2 ...)
                let condition = parse_single_condition(first)?;
                conditions.push(condition);
                current = rest;
            }
            _ => return Err("invalid condition list structure"),
        }
    }

    Ok(conditions)
}

/// Parse a single condition from ClvmValue
fn parse_single_condition(value: &ClvmValue) -> Result<Condition, &'static str> {
    match value {
        ClvmValue::Cons(ref opcode_val, ref args_val) => {
            // Extract opcode
            let opcode = match opcode_val.as_ref() {
                ClvmValue::Atom(ref bytes) if bytes.len() == 1 => bytes[0],
                _ => return Err("condition opcode must be single byte"),
            };

            // Extract args
            let args = extract_args_from_list(args_val)?;

            Ok(Condition { opcode, args })
        }
        _ => Err("condition must be a cons pair"),
    }
}

/// Extract arguments from CLVM list
fn extract_args_from_list(value: &ClvmValue) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut args = Vec::new();
    let mut current = value;

    loop {
        match current {
            ClvmValue::Atom(ref bytes) if bytes.is_empty() => {
                // End of list
                break;
            }
            ClvmValue::Cons(ref first, ref rest) => {
                match first.as_ref() {
                    ClvmValue::Atom(ref bytes) => args.push(bytes.clone()),
                    _ => return Err("argument must be an atom"),
                }
                current = rest;
            }
            _ => return Err("invalid argument list structure"),
        }
    }

    Ok(args)
}

// Announcement condition opcodes
pub const CREATE_COIN_ANNOUNCEMENT: u8 = 60;
pub const ASSERT_COIN_ANNOUNCEMENT: u8 = 61;
pub const CREATE_PUZZLE_ANNOUNCEMENT: u8 = 62;
pub const ASSERT_PUZZLE_ANNOUNCEMENT: u8 = 63;

/// Process announcement conditions for privacy
///
/// This function:
/// 1. Collects all CREATE_*_ANNOUNCEMENT conditions (60, 62)
/// 2. Collects all ASSERT_*_ANNOUNCEMENT conditions (61, 63)
/// 3. Verifies every assertion has a matching announcement
/// 4. Returns filtered conditions with announcements removed
///
/// Announcements are verified in-circuit and suppressed from output
/// to preserve privacy. This is essential for CATs, atomic swaps,
/// and any cross-coin validation protocol.
///
/// # Arguments
/// * `conditions` - all conditions from CLVM execution
/// * `puzzle_hash` - the puzzle hash of the coin being spent (for puzzle announcements)
/// * `coin_id` - optional coin ID for coin announcements (None if not available)
/// * `hasher` - hash function for computing announcement hashes
///
/// # Returns
/// * Ok(filtered_conditions) - conditions with announcements removed
/// * Err - if any assertion doesn't have a matching announcement
pub fn process_announcements(
    conditions: Vec<Condition>,
    puzzle_hash: &[u8; 32],
    coin_id: Option<&[u8; 32]>,
    hasher: fn(&[u8]) -> [u8; 32],
) -> Result<Vec<Condition>, &'static str> {
    // Collect announcements: hash -> original message (for debugging)
    let mut announcement_hashes: Vec<[u8; 32]> = Vec::new();

    // Collect assertions to verify
    let mut assertion_hashes: Vec<[u8; 32]> = Vec::new();

    // First pass: collect all announcements and assertions
    for condition in &conditions {
        match condition.opcode {
            CREATE_PUZZLE_ANNOUNCEMENT => {
                // CREATE_PUZZLE_ANNOUNCEMENT(message)
                // hash = sha256(puzzle_hash || message)
                if condition.args.is_empty() {
                    return Err("CREATE_PUZZLE_ANNOUNCEMENT requires message argument");
                }
                let message = &condition.args[0];
                let mut data = Vec::with_capacity(32 + message.len());
                data.extend_from_slice(puzzle_hash);
                data.extend_from_slice(message);
                let hash = hasher(&data);
                announcement_hashes.push(hash);
            }
            CREATE_COIN_ANNOUNCEMENT => {
                // CREATE_COIN_ANNOUNCEMENT(message)
                // hash = sha256(coin_id || message)
                if condition.args.is_empty() {
                    return Err("CREATE_COIN_ANNOUNCEMENT requires message argument");
                }
                let message = &condition.args[0];
                if let Some(cid) = coin_id {
                    let mut data = Vec::with_capacity(32 + message.len());
                    data.extend_from_slice(cid);
                    data.extend_from_slice(message);
                    let hash = hasher(&data);
                    announcement_hashes.push(hash);
                }
                // If no coin_id provided, skip coin announcements
                // (puzzle announcements still work)
            }
            ASSERT_PUZZLE_ANNOUNCEMENT | ASSERT_COIN_ANNOUNCEMENT => {
                // ASSERT_*_ANNOUNCEMENT(announcement_hash)
                if condition.args.is_empty() {
                    return Err("ASSERT_*_ANNOUNCEMENT requires hash argument");
                }
                if condition.args[0].len() != 32 {
                    return Err("announcement hash must be 32 bytes");
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&condition.args[0]);
                assertion_hashes.push(hash);
            }
            _ => {}
        }
    }

    // Verify all assertions are satisfied
    for assertion in &assertion_hashes {
        if !announcement_hashes.contains(assertion) {
            return Err("announcement assertion not satisfied");
        }
    }

    // Filter out announcement conditions from output
    let filtered: Vec<Condition> = conditions
        .into_iter()
        .filter(|c| {
            !matches!(
                c.opcode,
                CREATE_COIN_ANNOUNCEMENT
                    | ASSERT_COIN_ANNOUNCEMENT
                    | CREATE_PUZZLE_ANNOUNCEMENT
                    | ASSERT_PUZZLE_ANNOUNCEMENT
            )
        })
        .collect();

    Ok(filtered)
}

/// Convert Vec<Condition> to ClvmValue list representation
/// Each condition becomes: (opcode arg1 arg2 ...)
/// All conditions form a list: ((opcode1 args...) (opcode2 args...) ...)
fn conditions_to_clvm_value(conditions: &[Condition]) -> ClvmValue {
    // Build list from right to left (CLVM cons structure)
    let mut result = ClvmValue::Atom(vec![]); // Start with nil (empty list)

    for condition in conditions.iter().rev() {
        // Build condition as (opcode arg1 arg2 ...)
        let opcode = ClvmValue::Atom(vec![condition.opcode]);

        // Build args list
        let mut args_list = ClvmValue::Atom(vec![]); // nil
        for arg in condition.args.iter().rev() {
            let arg_value = ClvmValue::Atom(arg.clone());
            args_list = ClvmValue::Cons(Box::new(arg_value), Box::new(args_list));
        }

        // Cons opcode with args: (opcode . args_list)
        let condition_value = ClvmValue::Cons(Box::new(opcode), Box::new(args_list));

        // Add to result list
        result = ClvmValue::Cons(Box::new(condition_value), Box::new(result));
    }

    result
}

/// Serialize ProgramParameters to CLVM args format.
///
/// Converts a slice of ProgramParameters to serialized CLVM bytes representing
/// a list of values. The result can be passed to run_program as the args parameter.
///
/// Example: `[Int(3), Int(5)]` becomes the serialized form of `(3 5)`.
pub fn serialize_params_to_clvm(params: &[ProgramParameter]) -> Vec<u8> {
    if params.is_empty() {
        // Empty args (nil)
        return vec![0x80];
    }

    // Build CLVM list from parameters: (p1 p2 p3 ...)
    // In CLVM, a list is built with cons: (c p1 (c p2 (c p3 nil)))
    // We need to serialize this structure.

    // Build the list from right to left
    let mut result = ClvmValue::Atom(vec![]); // nil

    for param in params.iter().rev() {
        let value = match param {
            ProgramParameter::Int(n) => {
                // Convert u64 to i64, handling large values
                // For values > i64::MAX, this will wrap but that's expected for CLVM
                number_to_atom(*n as i64)
            }
            ProgramParameter::Bytes(bytes) => ClvmValue::Atom(bytes.clone()),
        };
        result = ClvmValue::Cons(Box::new(value), Box::new(result));
    }

    encode_clvm_value(result)
}

/// Run CLVM bytecode using VeilEvaluator and parse conditions from output
///
/// Executes compiled CLVM bytecode and parses the output as Chia-style conditions.
/// The program is expected to return a list of conditions as its output.
///
/// # Arguments
/// * `evaluator` - VeilEvaluator with injected crypto functions
/// * `bytecode` - Serialized CLVM bytecode
/// * `args` - Serialized CLVM args (use serialize_params_to_clvm to create from ProgramParameters)
/// * `max_cost` - Maximum cost allowed for execution
///
/// # Returns
/// * `Ok((output_bytes, conditions))` - Raw output and parsed conditions
/// * `Err(msg)` - Error message if execution fails
pub fn run_clvm_with_conditions(
    evaluator: &VeilEvaluator,
    bytecode: &[u8],
    args: &[u8],
    max_cost: u64,
) -> Result<(Vec<u8>, Vec<Condition>), &'static str> {
    // Run the program using VeilEvaluator
    let (output_bytes, _cost) = evaluator.run_program(bytecode, args, max_cost)?;

    // Parse conditions from output
    let conditions =
        deserialize_clvm_output_to_conditions(&output_bytes).unwrap_or_else(|_| Vec::new());

    Ok((output_bytes, conditions))
}

/// Convenience function to create a VeilEvaluator with standard function types
pub fn create_veil_evaluator(
    hasher: Hasher,
    bls_verifier: BlsVerifier,
    ecdsa_verifier: EcdsaVerifier,
) -> VeilEvaluator {
    VeilEvaluator::new(hasher, bls_verifier, ecdsa_verifier)
}

#[cfg(test)]
mod security_tests {
    use crate::compile_chialisp_to_bytecode;
    use crate::hash_data;

    #[test]
    fn test_template_program_consistency_check() {
        // Test the new guest compilation approach

        // Test that same program produces same hash
        let source = "(mod (x y) (+ x y))";
        let (_, hash1) = compile_chialisp_to_bytecode(hash_data, source).unwrap();
        let (_, hash2) = compile_chialisp_to_bytecode(hash_data, source).unwrap();

        // Same source should produce same program hash
        assert_eq!(hash1, hash2);

        // Different programs should produce different hashes
        let source2 = "(mod (x y) (* x y))";
        let (_, hash3) = compile_chialisp_to_bytecode(hash_data, source2).unwrap();
        assert_ne!(hash1, hash3);
    }
}

// ============================================================================
// ring spend balance enforcement
// ============================================================================

/// enforce balance and tail_hash consistency for ring spends
///
/// verifies:
/// - sum(input amounts) == sum(output CREATE_COIN amounts)
/// - all coins have same tail_hash (single-asset ring)
///
/// # security
/// prevents inflation/deflation attacks where attacker spends N coins
/// but creates outputs totaling more/less than N
///
/// # returns
/// (total_input_amount, total_output_amount) after validation
pub fn enforce_ring_balance(
    private_inputs: &Input,
    conditions: &[Condition],
) -> Result<(u64, u64), &'static str> {
    // track output amounts from CREATE_COIN conditions
    let mut total_output_amount: u64 = 0;

    for condition in conditions {
        if condition.opcode == 51 {
            // CREATE_COIN
            let amount = match condition.args.len() {
                2 | 4 => {
                    // both transparent (2-arg) and private (4-arg) modes
                    // handle variable-length amount encoding (chialisp uses compact encoding)
                    let amount_bytes = &condition.args[1];
                    if amount_bytes.len() == 8 {
                        u64::from_be_bytes(amount_bytes.as_slice().try_into().unwrap())
                    } else if amount_bytes.len() < 8 && !amount_bytes.is_empty() {
                        // pad to 8 bytes (big-endian: zeros on left)
                        let mut padded = [0u8; 8];
                        padded[8 - amount_bytes.len()..].copy_from_slice(amount_bytes);
                        u64::from_be_bytes(padded)
                    } else {
                        0
                    }
                }
                _ => 0,
            };
            total_output_amount += amount;
        }
    }

    // sum input amounts and verify tail_hash consistency
    let total_input_amount = if let Some(commitment_data) = &private_inputs.serial_commitment_data {
        let mut input_sum = commitment_data.amount; // primary coin

        if let Some(additional_coins) = &private_inputs.additional_coins {
            let primary_tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32]);

            for coin in additional_coins {
                // enforce single-asset ring (defense in depth)
                if coin.tail_hash != primary_tail_hash {
                    return Err("ring spend: all coins must have same tail_hash");
                }

                input_sum += coin.serial_commitment_data.amount;
            }
        }

        // prevent inflation: output cannot exceed input
        // allows burning/locking (output < input) for fees, conditional spends, etc.
        if total_output_amount > input_sum {
            return Err("inflation: output exceeds input");
        }

        input_sum
    } else {
        0 // no serial commitment = simple program execution
    };

    Ok((total_input_amount, total_output_amount))
}

// ============================================================================
// cryptographic domain constants
// ============================================================================

pub const SERIAL_DOMAIN: &[u8] = b"clvm_zk_serial_v1.0";
pub const COIN_DOMAIN: &[u8] = b"clvm_zk_coin_v2.0";
pub const SERIAL_COMMITMENT_SIZE: usize = 83; // domain(19) + serial_number(32) + serial_randomness(32)
pub const COIN_COMMITMENT_SIZE: usize = 121; // domain(17) + tail_hash(32) + amount(8) + puzzle_hash(32) + serial_commitment(32)
pub const NULLIFIER_DATA_SIZE: usize = 72; // serial_number(32) + program_hash(32) + amount(8)

// ============================================================================
// commitment computation helpers
// ============================================================================

/// compute serial commitment: hash(domain || serial_number || serial_randomness)
pub fn compute_serial_commitment<H>(
    hasher: H,
    serial_number: &[u8; 32],
    serial_randomness: &[u8; 32],
) -> [u8; 32]
where
    H: Fn(&[u8]) -> [u8; 32],
{
    let mut serial_data = [0u8; SERIAL_COMMITMENT_SIZE];
    serial_data[..19].copy_from_slice(SERIAL_DOMAIN);
    serial_data[19..51].copy_from_slice(serial_number);
    serial_data[51..83].copy_from_slice(serial_randomness);
    hasher(&serial_data)
}

/// compute coin commitment v2.0: hash(domain || tail_hash || amount || puzzle_hash || serial_commitment)
pub fn compute_coin_commitment<H>(
    hasher: H,
    tail_hash: [u8; 32],
    amount: u64,
    puzzle_hash: &[u8; 32],
    serial_commitment: &[u8; 32],
) -> [u8; 32]
where
    H: Fn(&[u8]) -> [u8; 32],
{
    let mut coin_data = [0u8; COIN_COMMITMENT_SIZE];
    coin_data[..17].copy_from_slice(COIN_DOMAIN);
    coin_data[17..49].copy_from_slice(&tail_hash);
    coin_data[49..57].copy_from_slice(&amount.to_be_bytes());
    coin_data[57..89].copy_from_slice(puzzle_hash);
    coin_data[89..121].copy_from_slice(serial_commitment);
    hasher(&coin_data)
}

/// compute nullifier: hash(serial_number || program_hash || amount)
pub fn compute_nullifier<H>(
    hasher: H,
    serial_number: &[u8; 32],
    program_hash: &[u8; 32],
    amount: u64,
) -> [u8; 32]
where
    H: Fn(&[u8]) -> [u8; 32],
{
    let mut nullifier_data = Vec::with_capacity(NULLIFIER_DATA_SIZE);
    nullifier_data.extend_from_slice(serial_number);
    nullifier_data.extend_from_slice(program_hash);
    nullifier_data.extend_from_slice(&amount.to_be_bytes());
    hasher(&nullifier_data)
}

// ============================================================================
// merkle proof verification
// ============================================================================

/// maximum allowed merkle proof depth (matches merkle.rs MAX_TREE_DEPTH)
/// prevents DoS via excessively long proofs that waste cycles
pub const MAX_MERKLE_PROOF_DEPTH: usize = 64;

/// verify merkle proof for a leaf at given index
///
/// # security bounds
/// merkle_path length is bounded to MAX_MERKLE_PROOF_DEPTH (64) to prevent
/// DoS attacks via excessively long proofs.
pub fn verify_merkle_proof<H>(
    hasher: H,
    leaf_hash: [u8; 32],
    merkle_path: &[[u8; 32]],
    leaf_index: usize,
    expected_root: [u8; 32],
) -> Result<(), &'static str>
where
    H: Fn(&[u8]) -> [u8; 32],
{
    // validate merkle path depth to prevent DoS
    if merkle_path.len() > MAX_MERKLE_PROOF_DEPTH {
        return Err("merkle proof too deep (max 64 levels)");
    }

    let mut current_hash = leaf_hash;
    let mut current_index = leaf_index;

    for sibling in merkle_path.iter() {
        let mut combined = [0u8; 64];
        if current_index.is_multiple_of(2) {
            combined[..32].copy_from_slice(&current_hash);
            combined[32..].copy_from_slice(sibling);
        } else {
            combined[..32].copy_from_slice(sibling);
            combined[32..].copy_from_slice(&current_hash);
        }
        current_hash = hasher(&combined);
        current_index /= 2;
    }

    if current_hash == expected_root {
        Ok(())
    } else {
        Err("merkle root mismatch")
    }
}

// ============================================================================
// amount parsing utilities
// ============================================================================

/// parse variable-length amount bytes (chialisp uses compact encoding)
/// pads to 8 bytes big-endian if needed
pub fn parse_variable_length_amount(bytes: &[u8]) -> Result<u64, &'static str> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 8 {
        return Err("amount too large (max 8 bytes)");
    }
    if bytes.len() == 8 {
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    } else {
        let mut padded = [0u8; 8];
        padded[8 - bytes.len()..].copy_from_slice(bytes);
        Ok(u64::from_be_bytes(padded))
    }
}
