#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::BTreeMap, string::String, vec, vec::Vec};

use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::string::String;

#[cfg(feature = "sha2-hasher")]
use sha2::{Digest, Sha256};

pub mod chialisp;
pub mod operators;
pub mod parser;
pub mod types;

pub use chialisp::*;
pub use operators::*;
pub use parser::*;
pub use types::*;

/// Type alias for hash function
pub type Hasher = fn(&[u8]) -> [u8; 32];
/// Type alias for BLS signature verification function
pub type BlsVerifier = fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>;
/// Type alias for ECDSA signature verification function
pub type EcdsaVerifier = fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>;

/// Runtime function definition for CLVM execution
#[derive(Debug, Clone)]
pub struct RuntimeFunction {
    /// Function parameter names
    pub parameters: Vec<String>,
    /// Compiled function body (CLVM bytecode)
    pub body: ClvmValue,
}

/// Runtime function table for storing function definitions
#[derive(Debug, Clone)]
pub struct RuntimeFunctionTable {
    functions: BTreeMap<String, RuntimeFunction>,
}

impl RuntimeFunctionTable {
    /// Create a new empty function table
    pub fn new() -> Self {
        Self {
            functions: BTreeMap::new(),
        }
    }

    /// Add a function to the table
    pub fn add_function(&mut self, name: String, function: RuntimeFunction) {
        self.functions.insert(name, function);
    }

    /// Get a function by name
    pub fn get_function(&self, name: &str) -> Option<&RuntimeFunction> {
        self.functions.get(name)
    }

    /// Get all function names
    pub fn function_names(&self) -> Vec<&str> {
        self.functions.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a function exists
    pub fn has_function(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }
}

/// CLVM evaluator with injected dependencies for backend-specific operations
pub struct ClvmEvaluator {
    /// Hash function for general hashing operations
    pub hasher: Hasher,
    /// BLS signature verification function
    pub bls_verifier: BlsVerifier,
    /// ECDSA signature verification function
    pub ecdsa_verifier: EcdsaVerifier,
    /// Runtime function table for function calls
    pub function_table: RuntimeFunctionTable,
}

impl ClvmEvaluator {
    /// Create a new evaluator with default implementations
    pub fn new(hasher: Hasher, bls_verifier: BlsVerifier, ecdsa_verifier: EcdsaVerifier) -> Self {
        Self {
            hasher,
            bls_verifier,
            ecdsa_verifier,
            function_table: RuntimeFunctionTable::new(),
        }
    }

    /// CLVM evaluator with parameter resolution for variables
    /// returns (result_bytes, conditions)
    pub fn evaluate_clvm_program_with_params(
        &mut self,
        program: &[u8],
        parameters: &[ProgramParameter],
    ) -> Result<(Vec<u8>, Vec<Condition>), &'static str> {
        if program.is_empty() {
            return Err("program too short");
        }

        // parse the clvm program structure
        let mut parser = ClvmParser::new(program);
        let parsed = parser.parse()?;

        // evaluate the parsed structure with parameter resolution (this may generate conditions)
        let mut conditions = Vec::new();
        let result = self.evaluate(&parsed, &mut conditions, parameters)?;

        // convert result back to clvm bytes format
        Ok((encode_clvm_value(result), conditions))
    }

    /// evaluate clvm expressions with proper quote handling
    fn evaluate(
        &self,
        expr: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        match expr {
            ClvmValue::Atom(bytes) => {
                // Atoms are always literal values unless explicitly handled as environment references
                // Environment references are handled via the quote mechanism in CLVM
                Ok(ClvmValue::Atom(bytes.clone()))
            }
            ClvmValue::Cons(op, args) => {
                let op_evaluated = self.evaluate(op, conditions, parameters)?;
                self.apply_clvm_operator_with_evaluator_context(
                    &op_evaluated,
                    args,
                    conditions,
                    parameters,
                )
            }
        }
    }

    /// Apply CLVM operator
    fn apply_clvm_operator_with_evaluator_context(
        &self,
        op: &ClvmValue,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        match op {
            ClvmValue::Atom(op_bytes) => {
                if op_bytes.len() == 1 {
                    let opcode = op_bytes[0];
                    self.apply_operator_context(opcode, args, conditions, parameters)
                } else {
                    Err("operator must be single byte")
                }
            }
            _ => Err("operator must be an atom"),
        }
    }

    /// Apply CLVM operator by opcode with context awareness
    fn apply_operator_context(
        &self,
        opcode: u8,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        match ClvmOperator::from_opcode(opcode) {
            Some(operator) => match operator {
                // Standard opcodes that don't need injected dependencies
                ClvmOperator::Add => self.handle_op_add(args, conditions, parameters),
                ClvmOperator::Subtract => self.handle_op_subtract(args, conditions, parameters),
                ClvmOperator::Multiply => self.handle_op_multiply(args, conditions, parameters),
                ClvmOperator::Divide => self.handle_op_divide(args, conditions, parameters),
                ClvmOperator::Modulo => self.handle_op_modulo(args, conditions, parameters),
                ClvmOperator::Equal => self.handle_op_equal(args, conditions, parameters),
                ClvmOperator::GreaterThan => self.handle_op_greater(args, conditions, parameters),
                ClvmOperator::LessThan => self.handle_op_less(args, conditions, parameters),
                ClvmOperator::If => self.handle_op_if(args, conditions, parameters),
                ClvmOperator::Cons => self.handle_op_cons(args, conditions, parameters),
                ClvmOperator::First => self.handle_op_first(args, conditions, parameters),
                ClvmOperator::Rest => self.handle_op_rest(args, conditions, parameters),
                ClvmOperator::ListCheck => self.handle_op_listp(args, conditions, parameters),
                ClvmOperator::Quote => {
                    // Quote just returns its argument without evaluation
                    Ok(args.clone())
                }
                ClvmOperator::Apply => self.handle_op_apply(args, conditions, parameters),
                ClvmOperator::DivMod => self.handle_op_divmod(args, conditions, parameters),
                ClvmOperator::ModPow => self.handle_op_modpow(args, conditions, parameters),
                ClvmOperator::CallFunction => {
                    self.handle_op_call_function_context(args, conditions, parameters)
                }
                ClvmOperator::List => {
                    // List is host-only and shouldn't appear in guest execution
                    Err("List operator is for host compilation only")
                }

                // Signature verification using evaluator's injected verifiers
                ClvmOperator::EcdsaVerify => self.handle_ecdsa_verify(args, conditions, parameters),
                ClvmOperator::BlsVerify => self.handle_bls_verify(args, conditions, parameters),

                // Conditions
                ClvmOperator::AggSigMe => self.handle_op_agg_sig_me(args, conditions, parameters),
                ClvmOperator::AggSigUnsafe => {
                    self.handle_op_agg_sig_unsafe(args, conditions, parameters)
                }
                ClvmOperator::CreateCoin => {
                    self.handle_op_create_coin(args, conditions, parameters)
                }
                ClvmOperator::ReserveFee => {
                    self.handle_op_reserve_fee(args, conditions, parameters)
                }
                ClvmOperator::CreateCoinAnnouncement => {
                    self.handle_op_create_coin_announcement(args, conditions, parameters)
                }
                ClvmOperator::AssertCoinAnnouncement => {
                    self.handle_op_assert_coin_announcement(args, conditions, parameters)
                }
                ClvmOperator::CreatePuzzleAnnouncement => {
                    self.handle_op_create_puzzle_announcement(args, conditions, parameters)
                }
                ClvmOperator::AssertPuzzleAnnouncement => {
                    self.handle_op_assert_puzzle_announcement(args, conditions, parameters)
                }
                ClvmOperator::AssertMyCoinId => {
                    self.handle_op_assert_my_coin_id(args, conditions, parameters)
                }
                ClvmOperator::AssertMyParentId => {
                    self.handle_op_assert_my_parent_id(args, conditions, parameters)
                }
                ClvmOperator::AssertMyPuzzleHash => {
                    self.handle_op_assert_my_puzzle_hash(args, conditions, parameters)
                }
                ClvmOperator::AssertMyAmount => {
                    self.handle_op_assert_my_amount(args, conditions, parameters)
                }
                ClvmOperator::AssertConcurrentSpend => {
                    self.handle_op_assert_concurrent_spend(args, conditions, parameters)
                }
                ClvmOperator::AssertConcurrentPuzzle => {
                    self.handle_op_assert_concurrent_puzzle(args, conditions, parameters)
                }
            },
            None => {
                // Handle opcodes not in the enum (like SHA-256) using evaluator
                match opcode {
                    // SHA-256 using evaluator's injected hasher
                    2 => self.handle_sha256(args, conditions, parameters),
                    _ => {
                        #[cfg(feature = "std")]
                        eprintln!("MAIN PATH: unknown opcode {}", opcode);
                        Err("unknown opcode")
                    }
                }
            }
        }
    }

    /// Handle SHA-256 using evaluator's injected hasher
    fn handle_sha256(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let arg_value = self.extract_single_clvm_arg_with_params(args, conditions, parameters)?;
        let data_bytes = match arg_value {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("hash argument must be an atom"),
        };

        // Use evaluator's injected hasher
        let hash_result = (self.hasher)(&data_bytes);
        Ok(ClvmValue::Atom(hash_result.to_vec()))
    }

    /// Handle ECDSA verification using evaluator's injected verifier
    fn handle_ecdsa_verify(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (pk_v, msg_v, sig_v) =
            self.extract_ternary_clvm_args_with_params(args, conditions, parameters)?;

        let pk_bytes = match pk_v {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("public key must be an atom"),
        };
        let msg_bytes = match msg_v {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("message must be an atom"),
        };
        let sig_bytes = match sig_v {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("signature must be an atom"),
        };

        // Use evaluator's injected ECDSA verifier
        match (self.ecdsa_verifier)(&pk_bytes, &msg_bytes, &sig_bytes) {
            Ok(true) => Ok(ClvmValue::Atom(vec![1])),
            Ok(false) => Ok(ClvmValue::Atom(vec![])), // empty atom = false
            Err(e) => Err(e),
        }
    }

    /// Handle BLS verification using evaluator's injected verifier
    fn handle_bls_verify(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (pk_v, msg_v, sig_v) =
            self.extract_ternary_clvm_args_with_params(args, conditions, parameters)?;

        let pk_bytes = match pk_v {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("public key must be an atom"),
        };
        let msg_bytes = match msg_v {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("message must be an atom"),
        };
        let sig_bytes = match sig_v {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("signature must be an atom"),
        };

        #[cfg(feature = "std")]
        println!(
            "BLS verify handler - pk: {} bytes, msg: {} bytes, sig: {} bytes",
            pk_bytes.len(),
            msg_bytes.len(),
            sig_bytes.len()
        );

        // Use evaluator's injected BLS verifier
        match (self.bls_verifier)(&pk_bytes, &msg_bytes, &sig_bytes) {
            Ok(true) => Ok(ClvmValue::Atom(vec![1])),
            Ok(false) => Ok(ClvmValue::Atom(vec![])), // empty atom = false
            Err(e) => Err(e),
        }
    }

    /// Extract a single argument from CLVM cons structure with parameter evaluation
    pub fn extract_single_clvm_arg_with_params(
        &self,
        cons: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        match cons {
            ClvmValue::Cons(first_arg, _) => self.evaluate(first_arg, conditions, parameters),
            _ => Err("expected cons structure for argument"),
        }
    }

    /// Extract two arguments from CLVM cons structure with parameter evaluation
    pub fn extract_binary_clvm_args_with_params(
        &self,
        cons: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<(ClvmValue, ClvmValue), &'static str> {
        match cons {
            ClvmValue::Cons(first_arg, rest) => {
                let arg1 = self.evaluate(first_arg, conditions, parameters)?;

                match rest.as_ref() {
                    ClvmValue::Cons(second_arg, _) => {
                        let arg2 = self.evaluate(second_arg, conditions, parameters)?;
                        Ok((arg1, arg2))
                    }
                    _ => Err("expected second argument"),
                }
            }
            _ => Err("expected cons structure for arguments"),
        }
    }

    /// Extract two arguments from CLVM cons structure without evaluation
    fn extract_binary_clvm_args(
        &self,
        cons: &ClvmValue,
    ) -> Result<(ClvmValue, ClvmValue), &'static str> {
        match cons {
            ClvmValue::Cons(first_arg, rest) => match rest.as_ref() {
                ClvmValue::Cons(second_arg, _) => {
                    Ok(((**first_arg).clone(), (**second_arg).clone()))
                }
                _ => Err("expected second argument"),
            },
            _ => Err("expected cons structure for arguments"),
        }
    }

    /// Extract three arguments from CLVM cons structure with parameter evaluation
    pub fn extract_ternary_clvm_args_with_params(
        &self,
        cons: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<(ClvmValue, ClvmValue, ClvmValue), &'static str> {
        match cons {
            ClvmValue::Cons(first_arg, rest1) => {
                let arg1 = self.evaluate(first_arg, conditions, parameters)?;

                match rest1.as_ref() {
                    ClvmValue::Cons(second_arg, rest2) => {
                        let arg2 = self.evaluate(second_arg, conditions, parameters)?;

                        match rest2.as_ref() {
                            ClvmValue::Cons(third_arg, _) => {
                                let arg3 = self.evaluate(third_arg, conditions, parameters)?;
                                Ok((arg1, arg2, arg3))
                            }
                            _ => Err("expected third argument"),
                        }
                    }
                    _ => Err("expected second argument"),
                }
            }
            _ => Err("expected cons structure for arguments"),
        }
    }

    // === OPCODE HANDLER METHODS ===

    /// Handle if condition: (if condition then_val else_val)
    pub fn handle_op_if(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (condition, then_val, else_val) =
            self.extract_ternary_clvm_args_with_params(args, conditions, parameters)?;
        if atom_to_number(&condition)? != 0 {
            Ok(then_val)
        } else {
            Ok(else_val)
        }
    }

    /// Handle cons operation: (cons first second)
    pub fn handle_op_cons(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (first, second) =
            self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        Ok(ClvmValue::Cons(Box::new(first), Box::new(second)))
    }

    /// Handle first operation: (first pair)
    pub fn handle_op_first(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let arg = self.extract_single_clvm_arg_with_params(args, conditions, parameters)?;
        match arg {
            ClvmValue::Cons(first, _) => Ok(*first),
            _ => Err("f on atom"),
        }
    }

    /// Handle rest operation: (rest pair)
    pub fn handle_op_rest(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let arg = self.extract_single_clvm_arg_with_params(args, conditions, parameters)?;
        match arg {
            ClvmValue::Cons(_, rest) => Ok(*rest),
            _ => Err("r on atom"),
        }
    }

    /// Handle listp operation: check if value is a list
    pub fn handle_op_listp(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let arg = self.extract_single_clvm_arg_with_params(args, conditions, parameters)?;
        Ok(if matches!(arg, ClvmValue::Cons(_, _)) {
            number_to_atom(1) // return 1 for lists/cons pairs
        } else {
            nil() // return nil (empty list) for atoms - clvm spec compliant
        })
    }

    /// Handle addition: (+ a b)
    pub fn handle_op_add(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b) = self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        let a_num = atom_to_number(&a)?;
        let b_num = atom_to_number(&b)?;
        Ok(number_to_atom(a_num + b_num))
    }

    /// Handle subtraction: (- a b)
    pub fn handle_op_subtract(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b) = self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        Ok(number_to_atom(atom_to_number(&a)? - atom_to_number(&b)?))
    }

    /// Handle multiplication: (* a b)
    pub fn handle_op_multiply(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b) = self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        Ok(number_to_atom(atom_to_number(&a)? * atom_to_number(&b)?))
    }

    /// Handle division: (/ a b)
    pub fn handle_op_divide(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b) = self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        let num_b = atom_to_number(&b)?;
        if num_b == 0 {
            return Err("division by zero");
        }
        Ok(number_to_atom(atom_to_number(&a)? / num_b))
    }

    /// Handle modulo: (% a b)
    pub fn handle_op_modulo(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b) = self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        let num_b = atom_to_number(&b)?;
        if num_b == 0 {
            return Err("division by zero");
        }
        Ok(number_to_atom(atom_to_number(&a)? % num_b))
    }

    /// Handle divmod: (divmod a b) returns (quotient . remainder)
    pub fn handle_op_divmod(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (dividend_v, divisor_v) =
            self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        let divisor = atom_to_number(&divisor_v)?;
        if divisor == 0 {
            return Err("division by zero");
        }
        let dividend = atom_to_number(&dividend_v)?;
        Ok(ClvmValue::Cons(
            Box::new(number_to_atom(dividend / divisor)),
            Box::new(number_to_atom(dividend % divisor)),
        ))
    }

    /// Handle greater than: (> a b)
    pub fn handle_op_greater(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b) = self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        Ok(number_to_atom(
            if atom_to_number(&a)? > atom_to_number(&b)? {
                1
            } else {
                0
            },
        ))
    }

    /// Handle less than: (< a b)
    pub fn handle_op_less(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b) = self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        Ok(number_to_atom(
            if atom_to_number(&a)? < atom_to_number(&b)? {
                1
            } else {
                0
            },
        ))
    }

    /// Handle equality: (= a b)
    pub fn handle_op_equal(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b) = self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;
        Ok(number_to_atom(
            if atom_to_number(&a)? == atom_to_number(&b)? {
                1
            } else {
                0
            },
        ))
    }

    /// Handle modular exponentiation: (modpow base exp mod)
    pub fn handle_op_modpow(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (base_v, exp_v, mod_v) =
            self.extract_ternary_clvm_args_with_params(args, conditions, parameters)?;
        let base = atom_to_number(&base_v)?;
        let exponent = atom_to_number(&exp_v)?;
        let modulus = atom_to_number(&mod_v)?;

        if modulus <= 0 {
            return Err("modulus must be positive");
        }
        if exponent < 0 {
            return Err("negative exponents not supported");
        }

        let result = modular_pow(base, exponent, modulus);
        Ok(number_to_atom(result))
    }

    /// Handle apply operation: (apply program args)
    /// Apply operator: execute a program with arguments
    /// (a program env) -> execute program with env as environment
    ///
    /// In CLVM, the program is evaluated with env as the value that references to `1` resolve to
    pub fn handle_op_apply(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        // Apply takes two arguments: BOTH need evaluation
        // The program argument is usually quoted, so evaluating it returns the actual program
        // The env argument might be quoted or computed
        let (program, env) =
            self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;

        // Now execute the program with the evaluated env
        self.evaluate_with_environment(&program, &env, conditions)
    }

    /// Evaluate a CLVM program with an explicit environment
    /// In this mode, the atom `1` refers to the environment value
    fn evaluate_with_environment(
        &self,
        expr: &ClvmValue,
        env: &ClvmValue,
        conditions: &mut Vec<Condition>,
    ) -> Result<ClvmValue, &'static str> {
        #[cfg(feature = "std")]
        {
            use crate::encode_clvm_value;
            eprintln!(
                "eval_with_env: expr={:?}, env={:?}",
                encode_clvm_value(expr.clone()),
                encode_clvm_value(env.clone())
            );
        }

        match expr {
            ClvmValue::Atom(bytes) => {
                // Check if this is the environment reference (atom with value 1)
                if bytes.len() == 1 && bytes[0] == 1 {
                    #[cfg(feature = "std")]
                    eprintln!("  -> returning env");
                    Ok(env.clone())
                } else {
                    #[cfg(feature = "std")]
                    eprintln!("  -> returning atom");
                    Ok(ClvmValue::Atom(bytes.clone()))
                }
            }
            ClvmValue::Cons(op, args) => {
                let op_evaluated = self.evaluate_with_environment(op, env, conditions)?;
                #[cfg(feature = "std")]
                {
                    use crate::encode_clvm_value;
                    eprintln!(
                        "  -> op evaluated to {:?}, now applying",
                        encode_clvm_value(op_evaluated.clone())
                    );
                }
                self.apply_operator_with_env(&op_evaluated, args, env, conditions)
            }
        }
    }

    /// Apply operator in environment evaluation mode
    fn apply_operator_with_env(
        &self,
        op: &ClvmValue,
        args: &ClvmValue,
        env: &ClvmValue,
        conditions: &mut Vec<Condition>,
    ) -> Result<ClvmValue, &'static str> {
        #[cfg(feature = "std")]
        {
            use crate::encode_clvm_value;
            eprintln!(
                "apply_operator_with_env: op={:?}",
                encode_clvm_value(op.clone())
            );
        }

        match op {
            ClvmValue::Atom(op_bytes) => {
                if op_bytes.len() == 1 {
                    let opcode = op_bytes[0];
                    self.apply_operator_with_env_opcode(opcode, args, env, conditions)
                } else {
                    Err("operator must be single byte")
                }
            }
            _ => {
                #[cfg(feature = "std")]
                eprintln!("ENV MODE: operator must be an atom, got cons");
                Err("operator must be an atom")
            }
        }
    }

    /// Apply operator by opcode in environment mode
    fn apply_operator_with_env_opcode(
        &self,
        opcode: u8,
        args: &ClvmValue,
        env: &ClvmValue,
        conditions: &mut Vec<Condition>,
    ) -> Result<ClvmValue, &'static str> {
        match ClvmOperator::from_opcode(opcode) {
            Some(operator) => match operator {
                ClvmOperator::Quote => {
                    // Quote returns argument without evaluation
                    Ok(args.clone())
                }
                ClvmOperator::First => {
                    // Extract the single argument from the cons structure
                    // args is (arg . nil), extract arg
                    match args {
                        ClvmValue::Cons(arg_expr, _) => {
                            // Evaluate the argument expression
                            let arg_value =
                                self.evaluate_with_environment(arg_expr, env, conditions)?;
                            // Extract first from the result
                            match &arg_value {
                                ClvmValue::Cons(first, _) => Ok((**first).clone()),
                                _ => Err("f on atom"),
                            }
                        }
                        _ => Err("expected cons for first operator arguments"),
                    }
                }
                ClvmOperator::Rest => {
                    // Extract the single argument from the cons structure
                    // args is (arg . nil), extract arg
                    match args {
                        ClvmValue::Cons(arg_expr, _) => {
                            // Evaluate the argument expression
                            let arg_value =
                                self.evaluate_with_environment(arg_expr, env, conditions)?;
                            // Extract rest from the result
                            match &arg_value {
                                ClvmValue::Cons(_, rest) => Ok((**rest).clone()),
                                _ => Err("r on atom"),
                            }
                        }
                        _ => Err("expected cons for rest operator arguments"),
                    }
                }
                ClvmOperator::Cons => {
                    let (first, rest) =
                        self.extract_binary_clvm_args_evaled_with_env(args, env, conditions)?;
                    Ok(ClvmValue::Cons(Box::new(first), Box::new(rest)))
                }
                ClvmOperator::Apply => {
                    // Nested apply
                    let (program, new_env) =
                        self.extract_binary_clvm_args_evaled_with_env(args, env, conditions)?;
                    self.evaluate_with_environment(&program, &new_env, conditions)
                }
                // Arithmetic operators
                ClvmOperator::Add
                | ClvmOperator::Subtract
                | ClvmOperator::Multiply
                | ClvmOperator::Divide
                | ClvmOperator::Modulo => {
                    let (left, right) =
                        self.extract_binary_clvm_args_evaled_with_env(args, env, conditions)?;
                    let a = atom_to_number(&left)?;
                    let b = atom_to_number(&right)?;
                    let result = match operator {
                        ClvmOperator::Add => a.checked_add(b).ok_or("addition overflow")?,
                        ClvmOperator::Subtract => a.checked_sub(b).ok_or("subtraction overflow")?,
                        ClvmOperator::Multiply => {
                            a.checked_mul(b).ok_or("multiplication overflow")?
                        }
                        ClvmOperator::Divide => {
                            if b == 0 {
                                return Err("division by zero");
                            }
                            a.checked_div(b).ok_or("division overflow")?
                        }
                        ClvmOperator::Modulo => {
                            if b == 0 {
                                return Err("modulo by zero");
                            }
                            a.checked_rem(b).ok_or("modulo overflow")?
                        }
                        _ => unreachable!(),
                    };
                    Ok(number_to_atom(result))
                }
                // Comparison operators
                ClvmOperator::Equal => {
                    let (left, right) =
                        self.extract_binary_clvm_args_evaled_with_env(args, env, conditions)?;
                    Ok(if left == right {
                        ClvmValue::Atom(vec![1])
                    } else {
                        ClvmValue::Atom(vec![])
                    })
                }
                ClvmOperator::GreaterThan => {
                    let (left, right) =
                        self.extract_binary_clvm_args_evaled_with_env(args, env, conditions)?;
                    let a = atom_to_number(&left)?;
                    let b = atom_to_number(&right)?;
                    Ok(if a > b {
                        ClvmValue::Atom(vec![1])
                    } else {
                        ClvmValue::Atom(vec![])
                    })
                }
                ClvmOperator::LessThan => {
                    let (left, right) =
                        self.extract_binary_clvm_args_evaled_with_env(args, env, conditions)?;
                    let a = atom_to_number(&left)?;
                    let b = atom_to_number(&right)?;
                    Ok(if a < b {
                        ClvmValue::Atom(vec![1])
                    } else {
                        ClvmValue::Atom(vec![])
                    })
                }
                ClvmOperator::If => {
                    let (cond_expr, rest) = self.extract_binary_clvm_args(args)?;
                    let condition = self.evaluate_with_environment(&cond_expr, env, conditions)?;
                    let (then_expr, else_expr) = self.extract_binary_clvm_args(&rest)?;

                    if self.is_truthy(&condition) {
                        self.evaluate_with_environment(&then_expr, env, conditions)
                    } else {
                        self.evaluate_with_environment(&else_expr, env, conditions)
                    }
                }
                ClvmOperator::ListCheck => {
                    let arg = self.evaluate_with_environment(args, env, conditions)?;
                    Ok(if matches!(arg, ClvmValue::Cons(_, _)) {
                        ClvmValue::Atom(vec![1])
                    } else {
                        ClvmValue::Atom(vec![])
                    })
                }
                ClvmOperator::DivMod => {
                    let (dividend, divisor) =
                        self.extract_binary_clvm_args_evaled_with_env(args, env, conditions)?;
                    let divisor_num = atom_to_number(&divisor)?;
                    if divisor_num == 0 {
                        return Err("division by zero");
                    }
                    let dividend_num = atom_to_number(&dividend)?;
                    Ok(ClvmValue::Cons(
                        Box::new(number_to_atom(dividend_num / divisor_num)),
                        Box::new(number_to_atom(dividend_num % divisor_num)),
                    ))
                }
                ClvmOperator::ModPow => {
                    let (base_expr, rest) = self.extract_binary_clvm_args(args)?;
                    let base = self.evaluate_with_environment(&base_expr, env, conditions)?;
                    let (exp_expr, mod_expr) = self.extract_binary_clvm_args(&rest)?;
                    let exponent = self.evaluate_with_environment(&exp_expr, env, conditions)?;
                    let modulus_val = self.evaluate_with_environment(&mod_expr, env, conditions)?;

                    let base_num = atom_to_number(&base)?;
                    let exp_num = atom_to_number(&exponent)?;
                    let mod_num = atom_to_number(&modulus_val)?;

                    if mod_num <= 0 {
                        return Err("modulus must be positive");
                    }
                    if exp_num < 0 {
                        return Err("negative exponents not supported");
                    }

                    let result = modular_pow(base_num, exp_num, mod_num);
                    Ok(number_to_atom(result))
                }
                _ => {
                    // For other operators that don't need environment context,
                    // evaluate arguments with environment first then apply operator
                    Err("operator not yet supported in environment mode")
                }
            },
            None => {
                // SHA-256 and other opcodes
                match opcode {
                    2 => {
                        let arg = self.evaluate_with_environment(args, env, conditions)?;
                        let data_bytes = match arg {
                            ClvmValue::Atom(bytes) => bytes,
                            _ => return Err("hash argument must be an atom"),
                        };
                        let hash_result = (self.hasher)(&data_bytes);
                        Ok(ClvmValue::Atom(hash_result.to_vec()))
                    }
                    _ => {
                        #[cfg(feature = "std")]
                        eprintln!("unknown opcode {} in environment mode", opcode);
                        Err("unknown opcode in environment mode")
                    }
                }
            }
        }
    }

    /// Helper to extract and evaluate two arguments with environment
    fn extract_binary_clvm_args_evaled_with_env(
        &self,
        args: &ClvmValue,
        env: &ClvmValue,
        conditions: &mut Vec<Condition>,
    ) -> Result<(ClvmValue, ClvmValue), &'static str> {
        let (first_expr, second_expr) = self.extract_binary_clvm_args(args)?;
        let first = self.evaluate_with_environment(&first_expr, env, conditions)?;
        let second = self.evaluate_with_environment(&second_expr, env, conditions)?;
        Ok((first, second))
    }

    /// Check if a value is truthy (non-empty)
    fn is_truthy(&self, value: &ClvmValue) -> bool {
        match value {
            ClvmValue::Atom(bytes) => !bytes.is_empty(),
            ClvmValue::Cons(_, _) => true,
        }
    }

    /// Handle unsafe aggregate signature verification
    pub fn handle_op_agg_sig_unsafe(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (pk_v, msg_v, sig_v) =
            self.extract_ternary_clvm_args_with_params(args, conditions, parameters)?;

        let pk_bytes = match pk_v {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("public_key must be an atom"),
        };
        let msg_bytes = match msg_v {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("message must be an atom"),
        };
        let sig_bytes = match sig_v {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("signature must be an atom"),
        };

        // verify the signature within the zk proof using evaluator's ECDSA verifier
        let is_valid = (self.ecdsa_verifier)(&pk_bytes, &msg_bytes, &sig_bytes)?;

        if !is_valid {
            return Err("agg_sig_unsafe: signature verification failed");
        }

        // create the condition for the verified signature
        conditions.push(Condition::new(49, vec![pk_bytes, msg_bytes, sig_bytes]));
        Ok(nil())
    }

    /// Helper to handle single argument conditions
    fn handle_single_arg_condition(
        &self,
        opcode: u8,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let arg_value = self.extract_single_clvm_arg_with_params(args, conditions, parameters)?;
        let arg_bytes = match arg_value {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("condition argument must be an atom"),
        };
        conditions.push(Condition::new(opcode, vec![arg_bytes]));
        Ok(nil())
    }

    /// Helper to handle binary argument conditions
    fn handle_binary_arg_condition(
        &self,
        opcode: u8,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b) = self.extract_binary_clvm_args_with_params(args, conditions, parameters)?;

        let a_bytes = match a {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("condition argument must be an atom"),
        };
        let b_bytes = match b {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("condition argument must be an atom"),
        };

        conditions.push(Condition::new(opcode, vec![a_bytes, b_bytes]));
        Ok(nil())
    }

    /// Handle aggregate signature me condition
    pub fn handle_op_agg_sig_me(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_ternary_arg_condition(50, args, conditions, parameters)
    }

    /// Helper to handle ternary argument conditions
    fn handle_ternary_arg_condition(
        &self,
        opcode: u8,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let (a, b, c) = self.extract_ternary_clvm_args_with_params(args, conditions, parameters)?;

        let a_bytes = match a {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("condition argument must be an atom"),
        };
        let b_bytes = match b {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("condition argument must be an atom"),
        };
        let c_bytes = match c {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("condition argument must be an atom"),
        };

        conditions.push(Condition::new(opcode, vec![a_bytes, b_bytes, c_bytes]));
        Ok(nil())
    }

    /// Handle create coin condition
    pub fn handle_op_create_coin(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_binary_arg_condition(51, args, conditions, parameters)
    }

    /// Handle reserve fee condition
    pub fn handle_op_reserve_fee(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        let arg_value = self.extract_single_clvm_arg_with_params(args, conditions, parameters)?;
        let arg_bytes = match arg_value {
            ClvmValue::Atom(bytes) => bytes,
            _ => return Err("fee argument must be an atom"),
        };

        // Check if fee is positive by examining the bytes directly
        if arg_bytes.is_empty() || arg_bytes.iter().all(|&b| b == 0) {
            // Empty atom or all zeros = 0, which is not positive
            return Err("reserve_fee amount must be positive");
        }

        if arg_bytes[0] & 0x80 != 0 {
            // First bit set = negative number
            return Err("reserve_fee amount must be positive");
        }

        conditions.push(Condition::new(52, vec![arg_bytes]));
        Ok(nil())
    }

    /// Handle assert concurrent spend condition
    pub fn handle_op_assert_concurrent_spend(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(64, args, conditions, parameters)
    }

    /// Handle assert concurrent puzzle condition
    pub fn handle_op_assert_concurrent_puzzle(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(65, args, conditions, parameters)
    }

    /// Handle assert my coin id condition
    pub fn handle_op_assert_my_coin_id(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(70, args, conditions, parameters)
    }

    /// Handle assert my parent id condition
    pub fn handle_op_assert_my_parent_id(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(71, args, conditions, parameters)
    }

    /// Handle assert my puzzle hash condition
    pub fn handle_op_assert_my_puzzle_hash(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(72, args, conditions, parameters)
    }

    /// Handle assert my amount condition
    pub fn handle_op_assert_my_amount(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(73, args, conditions, parameters)
    }

    /// Handle create coin announcement condition
    pub fn handle_op_create_coin_announcement(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(74, args, conditions, parameters)
    }

    /// Handle assert coin announcement condition
    pub fn handle_op_assert_coin_announcement(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(75, args, conditions, parameters)
    }

    /// Handle create puzzle announcement condition
    pub fn handle_op_create_puzzle_announcement(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(76, args, conditions, parameters)
    }

    /// Handle assert puzzle announcement condition
    pub fn handle_op_assert_puzzle_announcement(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_single_arg_condition(77, args, conditions, parameters)
    }

    /// Handle runtime function call
    pub fn handle_op_call_function(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        self.handle_op_call_function_context(args, conditions, parameters)
    }

    /// Handle runtime function call
    fn handle_op_call_function_context(
        &self,
        args: &ClvmValue,
        conditions: &mut Vec<Condition>,
        parameters: &[ProgramParameter],
    ) -> Result<ClvmValue, &'static str> {
        // Parse arguments: function_name followed by function arguments
        let args_list = extract_list_from_clvm(args)?;
        if args_list.is_empty() {
            return Err("call_function requires at least function name");
        }

        // First argument is the function name as a literal atom - don't evaluate
        let function_name_value = &args_list[0];
        let function_name = match function_name_value {
            ClvmValue::Atom(bytes) => {
                String::from_utf8(bytes.clone()).map_err(|_| "invalid function name encoding")?
            }
            ClvmValue::Cons(_, _) => return Err("function name must be a string"),
        };

        // TODO: Add recursion depth checking if needed

        // Look up function
        let function = self
            .function_table
            .get_function(&function_name)
            .ok_or("function not found")?;

        // Validate argument count
        let function_args = &args_list[1..];
        if function_args.len() != function.parameters.len() {
            return Err("function argument count mismatch");
        }

        // Evaluate function arguments in current context
        let mut evaluated_args = Vec::new();
        for arg in function_args {
            let evaluated_arg = self.evaluate(arg, conditions, parameters)?;
            evaluated_args.push(evaluated_arg);
        }

        // Create new parameter context for function execution
        let function_parameters: Vec<ProgramParameter> = evaluated_args
            .into_iter()
            .map(|arg| {
                // Try to convert to number first (works for both atoms and evaluated expressions)
                if let Ok(value) = clvm_value_to_number(&arg) {
                    if value >= 0 {
                        ProgramParameter::Int(value as u64)
                    } else {
                        // Negative numbers must use bytes representation
                        match arg {
                            ClvmValue::Atom(bytes) => ProgramParameter::Bytes(bytes),
                            ClvmValue::Cons(_, _) => {
                                ProgramParameter::Bytes(encode_clvm_value(arg))
                            }
                        }
                    }
                } else {
                    // Fallback to bytes representation
                    match arg {
                        ClvmValue::Atom(bytes) => ProgramParameter::Bytes(bytes),
                        ClvmValue::Cons(_, _) => ProgramParameter::Bytes(encode_clvm_value(arg)),
                    }
                }
            })
            .collect();

        // Execute function body with new parameters
        // Create a temporary evaluator to avoid mutability issues during recursive calls
        let temp_evaluator = ClvmEvaluator {
            hasher: self.hasher,
            bls_verifier: self.bls_verifier,
            ecdsa_verifier: self.ecdsa_verifier,
            function_table: self.function_table.clone(),
        };

        temp_evaluator.evaluate(&function.body, conditions, &function_parameters)
    }
}

/// convert a clvmvalue atom to an integer for arithmetic operations
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

/// convert an integer to a clvmvalue atom
pub fn number_to_atom(num: i64) -> ClvmValue {
    if num == 0 {
        ClvmValue::Atom(vec![0]) // keep compatibility with existing tests
    } else if num > 0 && num <= 255 {
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
        ClvmValue::Atom(bytes)
    }
}

/// create a nil value (empty atom)
pub fn nil() -> ClvmValue {
    ClvmValue::Atom(vec![])
}

/// Extract a list of values from a ClvmValue cons structure
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

/// verify ecdsa signature using provided hasher
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

    // parse the signature - handle variable length by padding if needed
    let signature = if signature_bytes.len() == 64 {
        // 64-byte compact format (r || s, each 32 bytes)
        match Signature::try_from(signature_bytes) {
            Ok(sig) => sig,
            Err(_) => return Err("invalid compact signature format"),
        }
    } else if signature_bytes.len() < 64 {
        // Pad with trailing zeros to get to 64 bytes (CLVM may have stripped trailing zeros)
        let mut padded = signature_bytes.to_vec();
        padded.resize(64, 0); // pad to 64 bytes with trailing zeros
        match Signature::try_from(padded.as_slice()) {
            Ok(sig) => sig,
            Err(_) => return Err("invalid padded signature format"),
        }
    } else {
        return Err("signature too long - expected at most 64 bytes");
    };

    // check if message is already a hash (32 bytes) or raw message
    let message_hash = if message_bytes.len() == 32 {
        // assume it's already a hash, use directly
        message_bytes.to_vec()
    } else {
        // hash the message using the provided hasher
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

/// compute sha-256 hash - unified interface
pub fn hash_data(data: &[u8]) -> [u8; 32] {
    hash_data_impl(data)
}

/// generate nullifier using canonical algorithm - works in both risc0 and sp1
pub fn generate_nullifier(
    hasher: Hasher,
    spend_secret: &[u8; 32],
    puzzle_hash: &[u8; 32],
) -> [u8; 32] {
    let mut combined = Vec::with_capacity(64 + 32);
    combined.extend_from_slice(b"clvm_zk_nullifier_v1.0");
    combined.extend_from_slice(spend_secret);
    combined.extend_from_slice(puzzle_hash);
    hasher(&combined)
}

// Note: Custom hash functions are now injected through the evaluator pattern
// See handle_op_sha256_with_evaluator for the implementation

/// compute sha-256 hash - uses default hasher
fn hash_data_impl(data: &[u8]) -> [u8; 32] {
    #[cfg(feature = "sha2-hasher")]
    {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
    #[cfg(not(feature = "sha2-hasher"))]
    {
        // fallback for when sha2 is not available
        [0u8; 32]
    }
}

/// default hasher implementation
pub fn hash_data_default(data: &[u8]) -> [u8; 32] {
    hash_data_impl(data)
}

/// default ecdsa verifier using standard hasher
pub fn default_ecdsa_verifier(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, &'static str> {
    verify_ecdsa_signature_with_hasher(hash_data_default, pk, msg, sig)
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

#[cfg(test)]
mod security_tests {
    use crate::chialisp::compile_chialisp_to_bytecode;
    use crate::hash_data;
    use crate::ProgramParameter;
    #[test]
    fn test_template_program_consistency_check() {
        // Test the new guest compilation approach

        // Test that same program produces same hash
        let source = "(mod (x y) (+ x y))";
        let (_, hash1) = compile_chialisp_to_bytecode(
            hash_data,
            source,
            &[ProgramParameter::Int(5), ProgramParameter::Int(3)],
        )
        .unwrap();
        let (_, hash2) = compile_chialisp_to_bytecode(
            hash_data,
            source,
            &[ProgramParameter::Int(10), ProgramParameter::Int(20)],
        )
        .unwrap();

        // Same source should produce same program hash regardless of parameters
        assert_eq!(hash1, hash2);

        // Different programs should produce different hashes
        let source2 = "(mod (x y) (* x y))";
        let (_, hash3) = compile_chialisp_to_bytecode(
            hash_data,
            source2,
            &[ProgramParameter::Int(5), ProgramParameter::Int(3)],
        )
        .unwrap();
        assert_ne!(hash1, hash3);
    }
}
