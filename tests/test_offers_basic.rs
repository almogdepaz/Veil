/// basic tests for unlinkable offer types and structures
use clvm_zk::protocol::{ConditionalOffer, OfferMetadata, ProofType, PrivateSpendBundle};

#[test]
#[cfg(feature = "mock")]
fn test_proof_type_enum() {
    assert_eq!(ProofType::Transaction as u8, 0);
    assert_eq!(ProofType::ConditionalSpend as u8, 1);
    assert_eq!(ProofType::Settlement as u8, 2);
}

#[test]
#[cfg(feature = "mock")]
fn test_spend_bundle_proof_types() {
    let bundle = PrivateSpendBundle::new(vec![0x01], [0x42; 32], vec![0x03]);

    // default type is Transaction
    assert!(bundle.is_submittable());
    assert!(!bundle.is_conditional());

    let conditional = PrivateSpendBundle::new_with_type(
        vec![0x01],
        [0x42; 32],
        vec![0x03],
        ProofType::ConditionalSpend,
    );

    assert!(!conditional.is_submittable());
    assert!(conditional.is_conditional());
}

#[test]
#[cfg(feature = "mock")]
fn test_conditional_offer_creation() {
    let proof = vec![0x01, 0x02, 0x03];
    let pubkey = [0x02; 33]; // compressed pubkey format

    let offer = ConditionalOffer::new(proof.clone(), 500, 1000, pubkey);

    assert_eq!(offer.conditional_proof, proof);
    assert_eq!(offer.offered_amount, 500);
    assert_eq!(offer.requested_amount, 1000);
    assert_eq!(offer.maker_payment_pubkey, pubkey);
    assert!(offer.validate().is_ok());
}

#[test]
#[cfg(feature = "mock")]
fn test_offer_with_metadata() {
    let proof = vec![0x01, 0x02, 0x03];
    let pubkey = [0x03; 33];

    let metadata = OfferMetadata {
        offered_asset_type: "token_a".to_string(),
        requested_asset_type: "token_b".to_string(),
        description: "swap 500 token_a for 1000 token_b".to_string(),
        expires_at: Some(100000),
    };

    let offer = ConditionalOffer::new(proof, 500, 1000, pubkey)
        .with_metadata(metadata);

    assert!(offer.metadata.is_some());
    let meta = offer.metadata.unwrap();
    assert_eq!(meta.offered_asset_type, "token_a");
    assert_eq!(meta.expires_at, Some(100000));
}

#[test]
#[cfg(feature = "mock")]
fn test_offer_validation() {
    // valid offer
    let valid = ConditionalOffer::new(vec![0x01], 500, 1000, [0x02; 33]);
    assert!(valid.validate().is_ok());

    // invalid: empty proof
    let invalid = ConditionalOffer::new(vec![], 500, 1000, [0x02; 33]);
    assert!(invalid.validate().is_err());

    // invalid: zero offered amount
    let invalid = ConditionalOffer::new(vec![0x01], 0, 1000, [0x02; 33]);
    assert!(invalid.validate().is_err());

    // invalid: zero requested amount
    let invalid = ConditionalOffer::new(vec![0x01], 500, 0, [0x02; 33]);
    assert!(invalid.validate().is_err());

    // invalid: zero pubkey
    let invalid = ConditionalOffer::new(vec![0x01], 500, 1000, [0x00; 33]);
    assert!(invalid.validate().is_err());
}
