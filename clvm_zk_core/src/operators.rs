//! Shared CLVM operator definitions and mappings
//! This ensures host compilation and guest evaluation use the same opcodes

extern crate alloc;
use core::str::FromStr;

/// CLVM operators supported by both host and guest
/// This is the single source of truth for all supported operations
#[derive(Debug, Clone, PartialEq)]
pub enum ClvmOperator {
    // Arithmetic operators (ASCII codes)
    Add,      // 43 (+)
    Subtract, // 45 (-)
    Multiply, // 42 (*)
    Divide,   // 47 (/)
    Modulo,   // 37 (%)

    // Comparison operators (ASCII codes)
    Equal,       // 61 (=)
    GreaterThan, // 62 (>)
    // Note: LessThan removed - not in standard Chialisp, use (> b a) instead

    // CLVM primitives (ASCII codes)
    If,        // 105 (i)
    First,     // 102 (f)
    Rest,      // 114 (r)
    Cons,      // 99 (c)
    ListCheck, // 108 (l)
    Quote,     // 113 (q)
    Apply,     // 97 (a)

    // Extended operations (condition opcodes)
    DivMod, // 80
    ModPow, // 81

    // Signature operations
    AggSigUnsafe, // 49
    AggSigMe,     // 50
    EcdsaVerify,  // 200 (custom opcode for ECDSA verification)
    BlsVerify,    // 201 (custom opcode for BLS signature verification)

    // Output/Messaging
    Remark, // 1 (arbitrary output data)

    // Coin operations
    CreateCoin, // 51
    ReserveFee, // 52

    // Announcements
    CreateCoinAnnouncement,   // 60
    AssertCoinAnnouncement,   // 61
    CreatePuzzleAnnouncement, // 62
    AssertPuzzleAnnouncement, // 63

    // Concurrency
    AssertConcurrentSpend,  // 64
    AssertConcurrentPuzzle, // 65

    // Messaging
    SendMessage,    // 66
    ReceiveMessage, // 67

    // Assertions
    AssertMyCoinId,     // 70
    AssertMyParentId,   // 71
    AssertMyPuzzleHash, // 72
    AssertMyAmount,     // 73

    // Runtime function calls
    CallFunction, // 250 (custom opcode for runtime function calls)

    // Host-only helpers (not real CLVM opcodes)
    List, // Host-only: expands to nested cons operations
}

impl ClvmOperator {
    /// Get the opcode byte for this operator
    /// Uses Chia-standard CLVM opcodes for compatibility with clvmr
    pub fn opcode(&self) -> u8 {
        match self {
            // Core CLVM opcodes (Chia standard)
            ClvmOperator::Quote => 1,     // q
            ClvmOperator::Apply => 2,     // a
            ClvmOperator::If => 3,        // i
            ClvmOperator::Cons => 4,      // c
            ClvmOperator::First => 5,     // f
            ClvmOperator::Rest => 6,      // r
            ClvmOperator::ListCheck => 7, // l
            // 8 = raise
            ClvmOperator::Equal => 9,     // =
            ClvmOperator::GreaterThan => 21, // >

            // Arithmetic (Chia standard)
            ClvmOperator::Add => 16,      // +
            ClvmOperator::Subtract => 17, // -
            ClvmOperator::Multiply => 18, // *
            ClvmOperator::Divide => 19,   // /
            ClvmOperator::DivMod => 20,   // divmod
            ClvmOperator::Modulo => 61,   // %  (mod opcode in Chia)

            // Extended operations
            ClvmOperator::ModPow => 60,   // modpow

            // Signature operations (Chia condition opcodes)
            ClvmOperator::AggSigUnsafe => 49,
            ClvmOperator::AggSigMe => 50,
            
            // Custom signature verification (use BLS opcode 59 for bls_verify)
            ClvmOperator::BlsVerify => 59,
            // ECDSA uses 4-byte opcode in clvmr, but we use 200 for now
            ClvmOperator::EcdsaVerify => 200,

            // Output/Messaging
            ClvmOperator::Remark => 1,

            // Coin operations (Chia condition opcodes)
            ClvmOperator::CreateCoin => 51,
            ClvmOperator::ReserveFee => 52,

            // Announcements
            ClvmOperator::CreateCoinAnnouncement => 60,
            ClvmOperator::AssertCoinAnnouncement => 61,
            ClvmOperator::CreatePuzzleAnnouncement => 62,
            ClvmOperator::AssertPuzzleAnnouncement => 63,

            // Concurrency
            ClvmOperator::AssertConcurrentSpend => 64,
            ClvmOperator::AssertConcurrentPuzzle => 65,

            // Messaging
            ClvmOperator::SendMessage => 66,
            ClvmOperator::ReceiveMessage => 67,

            // Assertions
            ClvmOperator::AssertMyCoinId => 70,
            ClvmOperator::AssertMyParentId => 71,
            ClvmOperator::AssertMyPuzzleHash => 72,
            ClvmOperator::AssertMyAmount => 73,

            // Runtime function calls (Veil extension)
            ClvmOperator::CallFunction => 150,

            // Host-only helpers - these should never be compiled to opcodes
            ClvmOperator::List => panic!("List is a host-only helper and has no opcode"),
        }
    }

    /// Check if this operator is a Chia condition (should be compiled as data, not operator call)
    /// Condition operators create condition values that are returned as program output
    pub fn is_condition_operator(&self) -> bool {
        matches!(
            self,
            ClvmOperator::Remark
                | ClvmOperator::AggSigUnsafe
                | ClvmOperator::AggSigMe
                | ClvmOperator::CreateCoin
                | ClvmOperator::ReserveFee
                | ClvmOperator::CreateCoinAnnouncement
                | ClvmOperator::AssertCoinAnnouncement
                | ClvmOperator::CreatePuzzleAnnouncement
                | ClvmOperator::AssertPuzzleAnnouncement
                | ClvmOperator::AssertConcurrentSpend
                | ClvmOperator::AssertConcurrentPuzzle
                | ClvmOperator::SendMessage
                | ClvmOperator::ReceiveMessage
                | ClvmOperator::AssertMyCoinId
                | ClvmOperator::AssertMyParentId
                | ClvmOperator::AssertMyPuzzleHash
                | ClvmOperator::AssertMyAmount
        )
    }

    /// Parse operator from string (used by host for Chialisp parsing)
    pub fn parse_operator(s: &str) -> Option<Self> {
        match s {
            // Arithmetic
            "+" => Some(ClvmOperator::Add),
            "-" => Some(ClvmOperator::Subtract),
            "*" => Some(ClvmOperator::Multiply),
            "/" => Some(ClvmOperator::Divide),
            "%" => Some(ClvmOperator::Modulo),

            // Comparison
            "=" => Some(ClvmOperator::Equal),
            ">" => Some(ClvmOperator::GreaterThan),

            // CLVM primitives
            "i" => Some(ClvmOperator::If),
            "if" => Some(ClvmOperator::If), // 'if' is just syntax sugar for 'i'
            "f" => Some(ClvmOperator::First),
            "r" => Some(ClvmOperator::Rest),
            "c" => Some(ClvmOperator::Cons),
            "l" => Some(ClvmOperator::ListCheck),
            "q" => Some(ClvmOperator::Quote),
            "a" => Some(ClvmOperator::Apply),

            // Extended operations
            "divmod" => Some(ClvmOperator::DivMod),
            "modpow" => Some(ClvmOperator::ModPow),

            // Signature operations
            "agg_sig_unsafe" => Some(ClvmOperator::AggSigUnsafe),
            "agg_sig_me" => Some(ClvmOperator::AggSigMe),
            "ecdsa_verify" => Some(ClvmOperator::EcdsaVerify),
            "bls_verify" => Some(ClvmOperator::BlsVerify),

            // Output/Messaging
            "remark" => Some(ClvmOperator::Remark),

            // Coin operations
            "create_coin" => Some(ClvmOperator::CreateCoin),
            "reserve_fee" => Some(ClvmOperator::ReserveFee),

            // Announcements
            "create_coin_announcement" => Some(ClvmOperator::CreateCoinAnnouncement),
            "assert_coin_announcement" => Some(ClvmOperator::AssertCoinAnnouncement),
            "create_puzzle_announcement" => Some(ClvmOperator::CreatePuzzleAnnouncement),
            "assert_puzzle_announcement" => Some(ClvmOperator::AssertPuzzleAnnouncement),

            // Concurrency
            "assert_concurrent_spend" => Some(ClvmOperator::AssertConcurrentSpend),
            "assert_concurrent_puzzle" => Some(ClvmOperator::AssertConcurrentPuzzle),

            // Messaging
            "send_message" => Some(ClvmOperator::SendMessage),
            "receive_message" => Some(ClvmOperator::ReceiveMessage),

            // Assertions
            "assert_my_coin_id" => Some(ClvmOperator::AssertMyCoinId),
            "assert_my_parent_id" => Some(ClvmOperator::AssertMyParentId),
            "assert_my_puzzle_hash" => Some(ClvmOperator::AssertMyPuzzleHash),
            "assert_my_amount" => Some(ClvmOperator::AssertMyAmount),

            // Host-only helpers
            "list" => Some(ClvmOperator::List),

            _ => None,
        }
    }

    /// Parse operator from opcode byte (used by guest for bytecode evaluation)
    pub fn from_opcode(opcode: u8) -> Option<Self> {
        match opcode {
            // Arithmetic (ASCII codes)
            // Core CLVM opcodes (Chia standard)
            1 => Some(ClvmOperator::Quote),
            2 => Some(ClvmOperator::Apply),
            3 => Some(ClvmOperator::If),
            4 => Some(ClvmOperator::Cons),
            5 => Some(ClvmOperator::First),
            6 => Some(ClvmOperator::Rest),
            7 => Some(ClvmOperator::ListCheck),
            9 => Some(ClvmOperator::Equal),
            21 => Some(ClvmOperator::GreaterThan),

            // Arithmetic (Chia standard)
            16 => Some(ClvmOperator::Add),
            17 => Some(ClvmOperator::Subtract),
            18 => Some(ClvmOperator::Multiply),
            19 => Some(ClvmOperator::Divide),
            20 => Some(ClvmOperator::DivMod),
            61 => Some(ClvmOperator::Modulo),

            // Extended operations
            60 => Some(ClvmOperator::ModPow),

            // Signature operations (Chia condition opcodes)
            49 => Some(ClvmOperator::AggSigUnsafe),
            50 => Some(ClvmOperator::AggSigMe),
            59 => Some(ClvmOperator::BlsVerify),
            200 => Some(ClvmOperator::EcdsaVerify),

            // Coin operations (Chia condition opcodes)
            51 => Some(ClvmOperator::CreateCoin),
            52 => Some(ClvmOperator::ReserveFee),

            // Concurrency
            64 => Some(ClvmOperator::AssertConcurrentSpend),
            65 => Some(ClvmOperator::AssertConcurrentPuzzle),

            // Assertions
            70 => Some(ClvmOperator::AssertMyCoinId),
            71 => Some(ClvmOperator::AssertMyParentId),
            72 => Some(ClvmOperator::AssertMyPuzzleHash),
            73 => Some(ClvmOperator::AssertMyAmount),

            // Runtime function calls (Veil extension)
            150 => Some(ClvmOperator::CallFunction),

            _ => None,
        }
    }

    /// Get expected argument count for this operator
    pub fn arity(&self) -> Option<usize> {
        match self {
            // Binary operators (2 arguments)
            ClvmOperator::Add
            | ClvmOperator::Subtract
            | ClvmOperator::Multiply
            | ClvmOperator::Divide
            | ClvmOperator::Modulo
            | ClvmOperator::Equal
            | ClvmOperator::GreaterThan
            | ClvmOperator::Cons
            | ClvmOperator::Apply
            | ClvmOperator::DivMod
            | ClvmOperator::CreateCoin => Some(2),

            // Unary operators (1 argument)
            ClvmOperator::First
            | ClvmOperator::Rest
            | ClvmOperator::ListCheck
            | ClvmOperator::Quote
            | ClvmOperator::Remark
            | ClvmOperator::AssertMyCoinId
            | ClvmOperator::AssertMyParentId
            | ClvmOperator::AssertMyPuzzleHash
            | ClvmOperator::AssertMyAmount
            | ClvmOperator::ReserveFee
            | ClvmOperator::CreateCoinAnnouncement
            | ClvmOperator::AssertCoinAnnouncement
            | ClvmOperator::CreatePuzzleAnnouncement
            | ClvmOperator::AssertPuzzleAnnouncement
            | ClvmOperator::AssertConcurrentSpend
            | ClvmOperator::AssertConcurrentPuzzle
            | ClvmOperator::SendMessage
            | ClvmOperator::ReceiveMessage => Some(1),

            // Ternary operators (3 arguments)
            ClvmOperator::If
            | ClvmOperator::ModPow
            | ClvmOperator::AggSigUnsafe
            | ClvmOperator::AggSigMe
            | ClvmOperator::EcdsaVerify
            | ClvmOperator::BlsVerify => Some(3),

            // Variable arity operators (any number of arguments)
            ClvmOperator::CallFunction => None, // Function calls can take any number of arguments
            ClvmOperator::List => None,         // List can take any number of arguments
        }
    }

    /// Get the string representation (for host compilation)
    pub fn as_str(&self) -> &'static str {
        match self {
            ClvmOperator::Add => "+",
            ClvmOperator::Subtract => "-",
            ClvmOperator::Multiply => "*",
            ClvmOperator::Divide => "/",
            ClvmOperator::Modulo => "%",
            ClvmOperator::Equal => "=",
            ClvmOperator::GreaterThan => ">",
            ClvmOperator::If => "i",
            ClvmOperator::First => "f",
            ClvmOperator::Rest => "r",
            ClvmOperator::Cons => "c",
            ClvmOperator::ListCheck => "l",
            ClvmOperator::Quote => "q",
            ClvmOperator::Apply => "a",
            ClvmOperator::DivMod => "divmod",
            ClvmOperator::ModPow => "modpow",
            ClvmOperator::AggSigUnsafe => "agg_sig_unsafe",
            ClvmOperator::AggSigMe => "agg_sig_me",
            ClvmOperator::EcdsaVerify => "ecdsa_verify",
            ClvmOperator::BlsVerify => "bls_verify",
            ClvmOperator::Remark => "remark",
            ClvmOperator::CreateCoin => "create_coin",
            ClvmOperator::ReserveFee => "reserve_fee",
            ClvmOperator::CreateCoinAnnouncement => "create_coin_announcement",
            ClvmOperator::AssertCoinAnnouncement => "assert_coin_announcement",
            ClvmOperator::CreatePuzzleAnnouncement => "create_puzzle_announcement",
            ClvmOperator::AssertPuzzleAnnouncement => "assert_puzzle_announcement",
            ClvmOperator::AssertConcurrentSpend => "assert_concurrent_spend",
            ClvmOperator::AssertConcurrentPuzzle => "assert_concurrent_puzzle",
            ClvmOperator::SendMessage => "send_message",
            ClvmOperator::ReceiveMessage => "receive_message",
            ClvmOperator::AssertMyCoinId => "assert_my_coin_id",
            ClvmOperator::AssertMyParentId => "assert_my_parent_id",
            ClvmOperator::AssertMyPuzzleHash => "assert_my_puzzle_hash",
            ClvmOperator::AssertMyAmount => "assert_my_amount",
            ClvmOperator::CallFunction => "call_function",
            ClvmOperator::List => "list",
        }
    }
}

/// Implement the standard FromStr trait for ClvmOperator
impl FromStr for ClvmOperator {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_operator(s).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_function_opcode_mapping() {
        // Test opcode to operator
        let op = ClvmOperator::from_opcode(150);
        assert!(op.is_some(), "Opcode 150 should map to some operator");

        if let Some(operator) = op {
            assert!(
                matches!(operator, ClvmOperator::CallFunction),
                "Opcode 150 should map to CallFunction"
            );
        }

        // Test operator to opcode
        let opcode = ClvmOperator::CallFunction.opcode();
        assert_eq!(opcode, 150, "CallFunction should map to opcode 150");
    }

    #[test]
    fn test_operator_roundtrip() {
        // Test that string -> operator -> opcode -> operator works
        // Note: Using Chia-standard opcodes now
        let ops = [
            "+",
            "-",
            "*",
            "/",
            "%",
            "=",
            ">",
            "i",
            "f",
            "r",
            "c",
            "l",
            "q",
            "a",
            "divmod",
            "modpow",
            "agg_sig_unsafe",
            "create_coin",
            "assert_my_coin_id",
        ];

        for op_str in &ops {
            let op = ClvmOperator::parse_operator(op_str)
                .unwrap_or_else(|| panic!("Failed to parse {}", op_str));
            let opcode = op.opcode();
            let op2 = ClvmOperator::from_opcode(opcode)
                .unwrap_or_else(|| panic!("Failed to parse opcode {}", opcode));
            assert_eq!(op, op2);
            assert_eq!(op.as_str(), *op_str);
        }
    }

    #[test]
    fn test_arity_validation() {
        assert_eq!(ClvmOperator::Add.arity(), Some(2));
        assert_eq!(ClvmOperator::First.arity(), Some(1));
        assert_eq!(ClvmOperator::If.arity(), Some(3));
    }
}
