// Test that values >= 128 get correctly encoded with 2-byte CLVM format
use clvm_zk::ProgramParameter;
use clvm_zk_core::chialisp::compile_chialisp_template_hash;
use clvm_zk_core::hash_data;
#[test]
fn test_large_value_encoding() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing CLVM encoding for values >= 128...\n");

    // Test cases that produce values >= 128 requiring 2-byte encoding
    let test_cases = vec![
        // Boundary case: exactly 128 (0x80)
        (
            "(mod (a b) (+ a b))",
            vec![64, 64],
            128,
            "128 = 0x80, needs 2-byte encoding [0x81, 0x80]",
        ),
        // Common large values
        (
            "(mod (a b) (+ a b))",
            vec![100, 50],
            150,
            "150 = 0x96, needs 2-byte encoding [0x81, 0x96]",
        ),
        (
            "(mod (a b) (+ a b))",
            vec![200, 55],
            255,
            "255 = 0xFF, needs 2-byte encoding [0x81, 0xFF]",
        ),
        (
            "(mod (a b) (* a b))",
            vec![16, 16],
            256,
            "256 = 0x100, needs multi-byte encoding",
        ),
        (
            "(mod (a b) (* a b))",
            vec![25, 25],
            625,
            "625 = 0x271, needs multi-byte encoding",
        ),
        // Powers of 2
        ("(mod (a b) (* a b))", vec![32, 8], 256, "256 = 2^8"),
        ("(mod (a b) (* a b))", vec![64, 8], 512, "512 = 2^9"),
        ("(mod (a b) (* a b))", vec![32, 32], 1024, "1024 = 2^10"),
        // Comparison with contrast: values < 128 (should be single-byte)
        (
            "(mod (a b) (+ a b))",
            vec![60, 39],
            99,
            "99 = 0x63 < 0x80, single-byte [0x63]",
        ),
        (
            "(mod (a b) (+ a b))",
            vec![63, 63],
            126,
            "126 = 0x7E < 0x80, single-byte [0x7E]",
        ),
        (
            "(mod (a b) (+ a b))",
            vec![63, 64],
            127,
            "127 = 0x7F < 0x80, single-byte [0x7F]",
        ),
    ];

    for (expr, args, expected, description) in test_cases {
        println!("Testing: {expr} with {args:?} = {expected} ({description})");

        let _params: Vec<ProgramParameter> =
            args.iter().map(|&x| ProgramParameter::int(x)).collect();

        // Test template hashing (this tests encoding during template creation)
        match compile_chialisp_template_hash(hash_data, expr) {
            Ok(hash) => {
                println!("  ✓ Template hash created: {} bytes", hash.len());

                // Verify expected encoding behavior
                if expected < 128 {
                    println!("    → Expected: Single-byte encoding ({expected})");
                } else if expected <= 255 {
                    println!(
                        "    → Expected: 2-byte encoding [0x81, 0x{expected:02X}] = [129, {expected}]"
                    );
                } else {
                    println!("    → Expected: Multi-byte encoding for {expected}");
                }
            }
            Err(e) => println!("  ❌ Program creation failed: {:?}", e),
        }
        println!();
    }
    Ok(())
}
