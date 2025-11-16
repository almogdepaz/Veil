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
    AssertMyCoinId,         // 70
    AssertMyParentId,       // 71
    AssertMyPuzzleHash,     // 72
    AssertMyAmount,         // 73

    // Runtime function calls
    CallFunction, // 250 (custom opcode for runtime function calls)

    // Host-only helpers (not real CLVM opcodes)
    List, // Host-only: expands to nested cons operations
}

impl ClvmOperator {
    /// Get the opcode byte for this operator
    /// This is used by both host compilation and guest evaluation
    pub fn opcode(&self) -> u8 {
        match self {
            // Arithmetic (ASCII codes)
            ClvmOperator::Add => 43,      // '+'
            ClvmOperator::Subtract => 45, // '-'
            ClvmOperator::Multiply => 42, // '*'
            ClvmOperator::Divide => 47,   // '/'
            ClvmOperator::Modulo => 37,   // '%'

            // Comparison (ASCII codes)
            ClvmOperator::Equal => 61,       // '='
            ClvmOperator::GreaterThan => 62, // '>'

            // CLVM primitives (ASCII codes)
            ClvmOperator::If => 105,        // 'i'
            ClvmOperator::First => 102,     // 'f'
            ClvmOperator::Rest => 114,      // 'r'
            ClvmOperator::Cons => 99,       // 'c'
            ClvmOperator::ListCheck => 108, // 'l'
            ClvmOperator::Quote => 113,     // 'q'
            ClvmOperator::Apply => 97,      // 'a'

            // Extended operations (condition opcodes)
            ClvmOperator::DivMod => 80,
            ClvmOperator::ModPow => 81,

            // Signature operations
            ClvmOperator::AggSigUnsafe => 49,
            ClvmOperator::AggSigMe => 50,
            ClvmOperator::EcdsaVerify => 200,
            ClvmOperator::BlsVerify => 201,

            // Output/Messaging
            ClvmOperator::Remark => 1,

            // Coin operations
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

            // Runtime function calls
            ClvmOperator::CallFunction => 150,

            // Host-only helpers - these should never be compiled to opcodes
            ClvmOperator::List => panic!("List is a host-only helper and has no opcode"),
        }
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
            43 => Some(ClvmOperator::Add),
            45 => Some(ClvmOperator::Subtract),
            42 => Some(ClvmOperator::Multiply),
            47 => Some(ClvmOperator::Divide),
            37 => Some(ClvmOperator::Modulo),

            // Comparison (ASCII codes)
            61 => Some(ClvmOperator::Equal),
            62 => Some(ClvmOperator::GreaterThan),

            // CLVM primitives (ASCII codes)
            105 => Some(ClvmOperator::If),
            102 => Some(ClvmOperator::First),
            114 => Some(ClvmOperator::Rest),
            99 => Some(ClvmOperator::Cons),
            108 => Some(ClvmOperator::ListCheck),
            113 => Some(ClvmOperator::Quote),
            97 => Some(ClvmOperator::Apply),

            // Extended operations (condition opcodes)
            80 => Some(ClvmOperator::DivMod),
            81 => Some(ClvmOperator::ModPow),

            // Signature operations
            49 => Some(ClvmOperator::AggSigUnsafe),
            50 => Some(ClvmOperator::AggSigMe),
            200 => Some(ClvmOperator::EcdsaVerify),
            201 => Some(ClvmOperator::BlsVerify),

            // Output/Messaging
            1 => Some(ClvmOperator::Remark),

            // Coin operations
            51 => Some(ClvmOperator::CreateCoin),
            52 => Some(ClvmOperator::ReserveFee),

            // Note: Announcement conditions (60-63) are NOT in from_opcode() because they
            // conflict with CLVM operators (60='<', 61='=', 62='>'). Their opcode() mappings
            // are used by handlers to create condition structures.

            // Concurrency
            64 => Some(ClvmOperator::AssertConcurrentSpend),
            65 => Some(ClvmOperator::AssertConcurrentPuzzle),

            // Note: Messaging conditions (66-67) not in from_opcode() to avoid conflicts

            // Assertions
            70 => Some(ClvmOperator::AssertMyCoinId),
            71 => Some(ClvmOperator::AssertMyParentId),
            72 => Some(ClvmOperator::AssertMyPuzzleHash),
            73 => Some(ClvmOperator::AssertMyAmount),

            // Runtime function calls
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
        let ops = [
            "+",
            "-",
            "*",
            "/",
            "%",
            "=",
            ">",
            "<",
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
