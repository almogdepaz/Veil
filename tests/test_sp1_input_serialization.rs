#![cfg(feature = "sp1")]

use clvm_zk::{CoinMode, Input, ProgramParameter};

#[test]
fn input_round_trips_through_sp1_bincode() {
    let input = Input {
        chialisp_source: "(mod (x) x)".to_string(),
        program_parameters: vec![ProgramParameter::Int(42)],
        coin_mode: CoinMode::Execute,
        tail_hash: None,
        tail_source: None,
        tail_params: vec![],
        additional_coins: None,
    };

    let encoded = clvm_zk_sp1::bincode::serialize(&input).expect("SP1 host input should serialize");
    let decoded: Input =
        clvm_zk_sp1::bincode::deserialize(&encoded).expect("SP1 guest input should deserialize");

    assert_eq!(decoded.chialisp_source, input.chialisp_source);
    assert!(matches!(decoded.coin_mode, CoinMode::Execute));
}
